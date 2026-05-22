// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provision a K3s cluster on Hetzner Cloud with in-cluster builder
//! and ghcr.io as the container registry.
//!
//! Requires `HCLOUD_TOKEN`, `GHCR_TOKEN`, and the `hetzner-k3s` CLI tool.
//!
//! Usage: cargo run --bin provision-hetzner-k3s
//!
//! # Alternative container runtimes
//!
//! The test worker pool is provisioned with three containerd runtimes
//! registered alongside the stock `runc`:
//!
//!   * `runsc` (gVisor): user-space kernel sandbox, no host dependencies
//!     beyond the runsc + containerd-shim binaries.
//!   * `sysbox-runc`: OCI-compatible runc drop-in that virtualises
//!     namespaces so pods look like full VMs.  Pair with `hostUsers:
//!     false` at the pod level so containerd sets up a user namespace.
//!
//! kata-containers is deliberately not installed here.  Kata needs
//! hardware-assisted virtualisation (`/dev/kvm`), which Hetzner Cloud
//! does not expose on shared-vCPU instances; tests that want kata
//! should use the EKS provisioner (c8i.large with
//! NestedVirtualization enabled).
//!
//! Tests select a runtime with `cargo xtest --executor hetzner
//! --runtime <name>`.  Anything but `runc` is written into
//! `cloud/hetzner/rumpelpod.json` as `kubernetes.runtimeClassName`,
//! which rumpelpod then sets on every pod it launches.
//!
//! # AppArmor note (Ubuntu 24.04)
//!
//! Ubuntu 24.04 ships AppArmor patches that block unprivileged
//! user-namespace mounts -- the sysbox hot path.  Cloud-init flips
//! `kernel.apparmor_restrict_unprivileged_userns=0` before
//! `systemctl restart k3s-agent` so sysbox pods can create their
//! userns without tripping the LSM.

use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use base64::Engine;
use indoc::{formatdoc, indoc};

/// Contents of `/etc/rancher/k3s/registries.yaml` written on every
/// node.  `mirrors: "*": {}` matches what hetzner-k3s renders when
/// `embedded_registry_mirror.enabled: true` -- this opts the
/// cluster into spegel for all registries.  `configs` attaches the
/// ghcr.io basic-auth credentials at the containerd layer, the
/// standard k3s way to let every pod in every namespace pull from
/// a private registry without per-namespace `imagePullSecrets`.
const REGISTRIES_YAML_TEMPLATE: &str = indoc! {r#"
    mirrors:
      "*": {}
    configs:
      "ghcr.io":
        auth:
          username: __GHCR_USER__
          password: __GHCR_TOKEN__
"#};

/// Resolve the GitHub username associated with a classic token.
fn ghcr_username(token: &str) -> Result<String> {
    let output = Command::new("curl")
        .args([
            "-s",
            "-H",
            &format!("Authorization: Bearer {token}"),
            "https://api.github.com/user",
        ])
        .output()
        .context("requesting GitHub user info")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!("GitHub API request failed"));
    }
    let body = String::from_utf8(output.stdout).context("GitHub API response is not UTF-8")?;
    // Minimal JSON extraction -- avoid pulling in serde just for this.
    let login = body
        .lines()
        .find_map(|line| {
            let line = line.trim();
            let rest = line.strip_prefix("\"login\":")?;
            let rest = rest.trim().trim_start_matches('"');
            let end = rest.find('"')?;
            Some(rest[..end].to_string())
        })
        .context("could not find 'login' in GitHub API response -- is GHCR_TOKEN valid?")?;
    Ok(login)
}

/// Indent every line of `s` by `prefix`, leaving blank lines alone.
fn indent(s: &str, prefix: &str) -> String {
    s.lines()
        .map(|l| {
            if l.is_empty() {
                String::new()
            } else {
                format!("{prefix}{l}")
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Hetzner K3s cluster configuration template.  `__UPPERCASE__`
/// markers are substituted at runtime in `run()`.
const CONFIG_TEMPLATE: &str = indoc! {r#"
    ---
    # Hetzner K3s cluster configuration for rumpelpod.
    #
    # Dynamic values (surrounded by __double_underscores__) are substituted
    # at runtime.  Edit the static values here to change cluster shape,
    # instance types, scaling behaviour etc.

    hetzner_token: __HCLOUD_TOKEN__

    cluster_name: rumpelpod
    kubeconfig_path: __KUBECONFIG_PATH__
    k3s_version: v1.34.5+k3s1

    networking:
      ssh:
        port: 22
        use_agent: false
        public_key_path: __SSH_PUBKEY_PATH__
        private_key_path: __SSH_PRIVKEY_PATH__
      allowed_networks:
        ssh:
          - 0.0.0.0/0
        api:
          - 0.0.0.0/0
      public_network:
        ipv4: true
        ipv6: true
      private_network:
        enabled: true
        subnet: 10.0.0.0/16
      cni:
        enabled: true
        mode: flannel

    image: ubuntu-24.04
    schedule_workloads_on_masters: true
    protect_against_deletion: false

    embedded_registry_mirror:
      enabled: true

    # ghcr.io basic-auth credentials live at the containerd layer
    # via /etc/rancher/k3s/registries.yaml so any pod in any
    # namespace can pull from ghcr without per-namespace
    # imagePullSecrets.  Workers also gain the sysbox and gVisor
    # containerd runtimes here so tests can opt into them via
    # runtimeClassName.  The master skips everything: it is
    # re-entering the provision while hetzner-k3s is still applying
    # addons through its API server, and bouncing k3s mid-apply breaks
    # the provision.  The master never pulls from ghcr (tests are
    # pinned to workers via pool=test nodeSelector and buildkitd
    # uses docker.io), so a stale registries.yaml on the master is
    # harmless.
    additional_post_k3s_commands:
      - |
        set -eux
        mkdir -p /etc/rancher/k3s
        cat > /etc/rancher/k3s/registries.yaml <<'REG'
        __REGISTRIES_YAML__
        REG
        if ! systemctl list-unit-files 2>/dev/null | grep -q '^k3s-agent\.service'; then
          exit 0
        fi

        # gVisor: user-space kernel sandbox.  Binaries land in
        # /usr/local/bin; the containerd runtime entry references
        # the runsc shim directly, so no further wiring needed.
        GVARCH=$(uname -m)
        curl -fsSL -o /tmp/runsc \
          "https://storage.googleapis.com/gvisor/releases/release/latest/${GVARCH}/runsc"
        curl -fsSL -o /tmp/containerd-shim-runsc-v1 \
          "https://storage.googleapis.com/gvisor/releases/release/latest/${GVARCH}/containerd-shim-runsc-v1"
        install -m 0755 /tmp/runsc /usr/local/bin/runsc
        install -m 0755 /tmp/containerd-shim-runsc-v1 /usr/local/bin/containerd-shim-runsc-v1

        # sysbox-runc: runc drop-in that virtualises namespaces.
        # v0.7.0 implements containerd 2.x's `features` subcommand
        # (stock v0.6.7 does not, which is why K3s 1.34 rejected it).
        curl -fsSL -o /tmp/sysbox.deb __SYSBOX_DEB_URL__
        apt-get update -qq
        apt-get install -y /tmp/sysbox.deb || apt-get install -y -f

        # Ubuntu 24.04 blocks unprivileged userns mounts via AppArmor
        # by default; flip the sysctl so sysbox can create its userns.
        # Harmless on Debian (the key is absent; `|| true` swallows it).
        sysctl -w kernel.apparmor_restrict_unprivileged_userns=0 || true
        printf 'kernel.apparmor_restrict_unprivileged_userns = 0\n' \
          > /etc/sysctl.d/99-sysbox-userns.conf

        mkdir -p /var/lib/rancher/k3s/agent/etc/containerd
        cat > /var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl <<'TMPL'
        {{ template "base" . }}

        # sysbox-runc needs BinaryName pointing at the installed
        # sysbox binary.  No SystemdCgroup=true: sysbox v0.7.0
        # receives the raw cgroupfs path from containerd and rejects
        # systemd-formatted input with 'expected slice:prefix:name'.
        [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.sysbox-runc]
          runtime_type = "io.containerd.runc.v2"
        [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.sysbox-runc.options]
          BinaryName = "/usr/bin/sysbox-runc"

        [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc]
          runtime_type = "io.containerd.runsc.v1"
        [plugins."io.containerd.cri.v1.runtime".containerd.runtimes.runsc.options]
          TypeUrl = "io.containerd.runsc.v1.options"
        TMPL

        systemctl restart k3s-agent

    # Single master, cx33: 4 shared vCPU, 8 GB RAM (~5.49 EUR/month).
    # Low-mid range -- enough headroom for API-heavy workloads without
    # blowing the budget.
    masters_pool:
      instance_type: cx33
      instance_count: 1
      locations:
        - nbg1

    worker_node_pools:
      # Integration-test runners.
      # Privileged containers are supported out of the box by K3s.
      - name: test
        instance_type: cpx32
        location: nbg1
        labels:
          - key: pool
            value: test
        taints:
          - key: pool
            value: "test:NoSchedule"
        autoscaling:
          enabled: true
          min_instances: 0
          max_instances: 2

      # Development / Rust compilation nodes.
      - name: dev
        instance_type: cpx42
        location: nbg1
        labels:
          - key: pool
            value: dev
        taints:
          - key: pool
            value: "dev:NoSchedule"
        autoscaling:
          enabled: true
          min_instances: 0
          max_instances: 1

    # Idle nodes are removed after one hour, not immediately.
    cluster_autoscaler_args:
      - "--scale-down-unneeded-time=1h"

    addons:
      cluster_autoscaler:
        enabled: true
"#};

const SYSBOX_DEB_URL: &str =
    "https://downloads.nestybox.com/sysbox/releases/v0.7.0/sysbox-ce_0.7.0-0.linux_amd64.deb";

// RuntimeClass manifests for the alternative runtimes installed on
// test workers.  Kata is intentionally omitted: Hetzner Cloud
// shared-vCPU instances do not expose /dev/kvm, so kata has no
// viable path here.  Users who want to test under kata should use
// the EKS provisioner instead (c8i.large + NestedVirtualization).
const RUNTIME_CLASSES: &str = indoc! {"
    apiVersion: node.k8s.io/v1
    kind: RuntimeClass
    metadata:
      name: sysbox-runc
    handler: sysbox-runc
    scheduling:
      nodeSelector:
        pool: test
    ---
    apiVersion: node.k8s.io/v1
    kind: RuntimeClass
    metadata:
      name: runsc
    handler: runsc
    scheduling:
      nodeSelector:
        pool: test
"};

const BUILDER_MANIFEST: &str = indoc! {r#"
    # In-cluster buildkitd for building container images.
    #
    # rumpelpod connects to buildkitd via port-forward and uses
    # docker buildx (remote driver) to build and push images to ghcr.io.
    # Registry credentials are forwarded from the client, so the builder
    # itself needs no auth configuration.
    #
    # The builder runs on the master so it is always available, even when
    # all worker nodes have scaled to zero.
    apiVersion: v1
    kind: Namespace
    metadata:
      name: buildkit
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: buildkitd
      namespace: buildkit
    spec:
      replicas: 1
      selector:
        matchLabels:
          app: buildkitd
      template:
        metadata:
          labels:
            app: buildkitd
        spec:
          tolerations:
            - key: CriticalAddonsOnly
              operator: Exists
            - key: node-role.kubernetes.io/control-plane
              operator: Exists
            - key: node-role.kubernetes.io/master
              operator: Exists
          nodeSelector:
            node-role.kubernetes.io/control-plane: "true"
          containers:
            - name: buildkitd
              image: moby/buildkit:v0.21.1
              args:
                - --addr
                - tcp://0.0.0.0:1234
              ports:
                - containerPort: 1234
                  name: buildkit
              securityContext:
                privileged: true
              volumeMounts:
                - name: cache
                  mountPath: /var/lib/buildkit
          volumes:
            # hostPath persists the layer cache across pod restarts.
            # Safe because buildkitd is pinned to the control-plane node.
            - name: cache
              hostPath:
                path: /var/lib/buildkitd-cache
                type: DirectoryOrCreate
    ---
    apiVersion: v1
    kind: Service
    metadata:
      name: buildkitd
      namespace: buildkit
    spec:
      selector:
        app: buildkitd
      ports:
        - port: 1234
          targetPort: 1234
"#};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let hcloud_token = std::env::var("HCLOUD_TOKEN").map_err(|_| {
        anyhow::anyhow!(
            "HCLOUD_TOKEN environment variable is not set.\n\n\
             Create an API token at:\n  \
             https://console.hetzner.cloud/ -> your project -> Security -> API Tokens\n\n\
             Then: export HCLOUD_TOKEN=<your-token>"
        )
    })?;

    let ghcr_token = std::env::var("GHCR_TOKEN").map_err(|_| {
        anyhow::anyhow!(
            "GHCR_TOKEN environment variable is not set.\n\n\
             Create a classic Personal Access Token with write:packages scope at:\n  \
             https://github.com/settings/tokens\n\n\
             Then: export GHCR_TOKEN=<your-token>"
        )
    })?;

    eprintln!("==> Resolving GitHub username from GHCR_TOKEN...");
    let ghcr_user = ghcr_username(&ghcr_token)?;
    eprintln!("    GitHub user: {ghcr_user}");

    let registry = format!("ghcr.io/{ghcr_user}/rumpelpod");

    let repo_root = tools::repo_root()?;
    let resource_dir = repo_root.join("cloud/hetzner");
    let ssh_key = std::env::var("SSH_KEY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| resource_dir.join("id_ed25519"));

    std::fs::create_dir_all(&resource_dir)
        .with_context(|| format!("creating {}", resource_dir.display()))?;

    if !ssh_key.exists() {
        let key_path = ssh_key.display();
        eprintln!("==> Generating SSH keypair at {key_path}...");
        tools::run(Command::new("ssh-keygen").args([
            "-t",
            "ed25519",
            "-f",
            ssh_key.to_str().unwrap(),
            "-N",
            "",
            "-C",
            "rumpelpod-cloud",
        ]))?;
    }

    let config_path = resource_dir.join("hetzner-k3s-config.yaml");
    let kubeconfig_path = resource_dir.join("kubeconfig");
    let ssh_pub = format!("{}.pub", ssh_key.display());

    // The marker sits on its own line inside the
    // `additional_post_k3s_commands` block scalar at 4-space
    // indent (after indoc! strips 4 common spaces).  Replace the
    // whole marker line with a 4-space-indented rendered block so
    // the YAML block scalar still parses and its base-indent strip
    // puts the registries.yaml body at column 0 in the shell
    // script.
    let registries_yaml = REGISTRIES_YAML_TEMPLATE
        .replace("__GHCR_USER__", &ghcr_user)
        .replace("__GHCR_TOKEN__", &ghcr_token);
    let registries_block = indent(registries_yaml.trim_end(), "    ");

    let config = CONFIG_TEMPLATE
        .replace("__HCLOUD_TOKEN__", &hcloud_token)
        .replace("__SSH_PUBKEY_PATH__", &ssh_pub)
        .replace("__SSH_PRIVKEY_PATH__", ssh_key.to_str().unwrap())
        .replace("__KUBECONFIG_PATH__", kubeconfig_path.to_str().unwrap())
        .replace("__SYSBOX_DEB_URL__", SYSBOX_DEB_URL)
        .replace("    __REGISTRIES_YAML__", &registries_block);
    std::fs::write(&config_path, &config)
        .with_context(|| format!("writing {}", config_path.display()))?;

    eprintln!("==> Creating K3s cluster on Hetzner Cloud...");
    eprintln!("    This takes 2-3 minutes.");
    tools::run(Command::new("hetzner-k3s").args([
        "create",
        "--config",
        config_path.to_str().unwrap(),
    ]))?;

    let kube_context = tools::output(
        Command::new("kubectl")
            .args(["config", "current-context"])
            .env("KUBECONFIG", kubeconfig_path.to_str().unwrap()),
    )
    .unwrap_or_default();

    // -- Deploy in-cluster builder -----------------------------------------------

    eprintln!("==> Registering RuntimeClasses (sysbox-runc, runsc)...");
    kubectl_apply_stdin(&kubeconfig_path, RUNTIME_CLASSES)?;

    eprintln!("==> Deploying in-cluster builder...");
    kubectl_apply_stdin(&kubeconfig_path, BUILDER_MANIFEST)?;

    eprintln!("    Waiting for buildkitd pod...");
    tools::run(
        Command::new("kubectl")
            .args([
                "-n",
                "buildkit",
                "rollout",
                "status",
                "deployment/buildkitd",
                "--timeout=120s",
            ])
            .env("KUBECONFIG", kubeconfig_path.to_str().unwrap()),
    )?;

    // -- Write docker config.json for ghcr.io auth --------------------------------

    let docker_dir = resource_dir.join("docker");
    std::fs::create_dir_all(&docker_dir)
        .with_context(|| format!("creating {}", docker_dir.display()))?;

    let auth_value =
        base64::engine::general_purpose::STANDARD.encode(format!("{ghcr_user}:{ghcr_token}"));
    let docker_config = formatdoc! {r#"
        {{
          "auths": {{
            "ghcr.io": {{
              "auth": "{auth_value}"
            }}
          }}
        }}
    "#};
    let docker_config_path = docker_dir.join("config.json");
    std::fs::write(&docker_config_path, &docker_config)
        .with_context(|| format!("writing {}", docker_config_path.display()))?;

    // -- Status output -----------------------------------------------------------

    let kubeconfig_display = kubeconfig_path.display();
    let config_display = config_path.display();

    eprintln!();
    eprintln!("============================================");
    eprintln!(" Hetzner K3s cluster ready!");
    eprintln!("============================================");
    eprintln!(" Kubeconfig       : {kubeconfig_display}");
    if !kube_context.is_empty() {
        eprintln!(" kubectl context  : {kube_context}");
    } else {
        eprintln!(" kubectl context  : <see kubeconfig>");
    }
    eprintln!(" Registry         : {registry}");
    eprintln!(" Builder          : buildkitd.buildkit (port 1234)");
    eprintln!();
    eprintln!(" Master (always on):");
    eprintln!("   cx33  -- 4 shared vCPU, 8 GB   (~5.49 EUR/month)");
    eprintln!();
    eprintln!(" Worker pools (scale 0 -> N, idle timeout 1 h):");
    eprintln!("   test: cpx32 -- 4 dedicated vCPU, 8 GB   (0-2 nodes)");
    eprintln!("   dev:  cpx42 -- 8 dedicated vCPU, 16 GB  (0-1 nodes)");
    eprintln!();

    // -- Write rumpelpod.json -------------------------------------------------
    let rumpelpod_json = formatdoc! {r#"
        {{
          "kubernetes": {{
            "context": "{kube_context}",
            "registry": "{registry}",
            "builder": "buildkitd",
            "nodeSelector": {{
              "pool": "test"
            }},
            "tolerations": [
              {{
                "key": "pool",
                "value": "test",
                "effect": "NoSchedule"
              }}
            ]
          }}
        }}
    "#};
    let rumpelpod_json_path = resource_dir.join("rumpelpod.json");
    std::fs::write(&rumpelpod_json_path, &rumpelpod_json)
        .with_context(|| format!("writing {}", rumpelpod_json_path.display()))?;

    // Buildx builder config for the remote driver.  The endpoint matches
    // the fixed local port used by xtest's kubectl port-forward.
    let instances_dir = resource_dir.join("buildx/instances");
    std::fs::create_dir_all(&instances_dir)
        .with_context(|| format!("creating {}", instances_dir.display()))?;
    let builder_json = r#"{"Name":"buildkitd","Driver":"remote","Nodes":[{"Name":"buildkitd0","Endpoint":"tcp://127.0.0.1:1234"}]}"#;
    let builder_path = instances_dir.join("buildkitd");
    std::fs::write(&builder_path, builder_json)
        .with_context(|| format!("writing {}", builder_path.display()))?;

    let resource_dir_display = resource_dir.display();
    eprintln!(" Resource dir: {resource_dir_display}");
    eprintln!();
    eprintln!(" Run tests:    cargo xtest --executor hetzner -- k8s --ignored");
    eprintln!();
    eprintln!(" To deprovision:");
    eprintln!("   hetzner-k3s delete --config {config_display}");
    eprintln!();

    Ok(ExitCode::SUCCESS)
}

fn kubectl_apply_stdin(kubeconfig: &std::path::Path, manifest: &str) -> Result<()> {
    use std::io::Write;
    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .env("KUBECONFIG", kubeconfig.to_str().unwrap())
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawning kubectl apply")?;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(manifest.as_bytes())
        .context("writing manifest to kubectl stdin")?;
    let status = child.wait().context("waiting for kubectl apply")?;
    if !status.success() {
        anyhow::bail!("kubectl apply failed");
    }
    Ok(())
}
