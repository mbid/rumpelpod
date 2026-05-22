// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provision a Hetzner Cloud K3s *dev* cluster.
//!
//! Sibling to provision_hetzner_k3s (the integration-test cluster).
//! The dev cluster is optimised for long-lived interactive development
//! against rumpelpod and other projects rather than for batch testing:
//!
//!   * The master is the cheapest non-deprecated x86 shared-vCPU instance
//!     in nbg1 (cx23: 2 vCPU, 4 GB, ~4.75 EUR/month).  It only runs the
//!     control plane; no workloads are scheduled on it.
//!   * There is a single dev worker pool on the top shared-vCPU AMD
//!     instance (cpx62: 16 vCPU, 32 GB, 640 GB disk).  The autoscaler
//!     scales it 0 -> 1 and idle nodes are released after one hour, so
//!     you only pay for the dev VM while you are actively using it.
//!   * Nodes run Debian 13 (Trixie) instead of Ubuntu.  Ubuntu 24.04
//!     carries Canonical-specific AppArmor hardening that blocks
//!     sysbox's userns mount path; Debian's stock kernel has none of
//!     that.  For a K3s host there is no reason to prefer Ubuntu.
//!   * Sysbox v0.7.0 is installed on every worker node via cloud-init,
//!     and a RuntimeClass `sysbox-runc` is registered in the cluster.
//!     The BuildKit DS runs under sysbox (runtimeClassName + hostUsers:
//!     false), which gives user-namespace isolation without privileged
//!     mode.  Sysbox is NOT installed on the master because system pods
//!     need host namespaces that sysbox deliberately blocks.
//!   * BuildKit runs as a DaemonSet on dev nodes, exposed on tcp:1234
//!     via a Service.  You reach it from your laptop with `kubectl
//!     port-forward` and point `docker buildx` at the forwarded port.
//!     The client forwards your local `~/.docker/config.json`
//!     credentials on every build, so the pod itself has no registry
//!     auth configuration.
//!   * Spegel (K3s embedded registry mirror) is enabled and scoped to
//!     ghcr.io + docker.io, so when a dev node scales back up after a
//!     restart any image that already lives on the master is pulled
//!     from the peer instead of the upstream.
//!
//! # Sysbox: why Debian 13 and v0.7.0
//!
//! Getting sysbox to work on K3s required two specific choices:
//!
//!   * **Debian 13 over Ubuntu 24.04.** Ubuntu's kernel carries
//!     Canonical-specific AppArmor LSM patches that block unprivileged
//!     userns mounts.  Even with the sysctl flipped off and all
//!     AppArmor profiles unloaded, sysbox-runc still tripped EPERM on
//!     Ubuntu 24.04.  Debian's upstream kernel has none of that.
//!   * **Sysbox v0.7.0 over v0.6.7.** K3s 1.34 ships containerd 2.x,
//!     which queries runtimes via a `features` subcommand.  Stock
//!     sysbox-runc 0.6.7 does not implement it, so containerd never
//!     puts the pod in a user namespace, and sysfs mounts fail with
//!     EPERM.  v0.7.0 (tagged 2026-03-03, nestybox/sysbox-runc#106)
//!     adds the `features` command and was explicitly tested on K3s by
//!     a Rancher engineer.  Pods must set `hostUsers: false` so K8s
//!     actually requests the userns from containerd.
//!
//! The sysbox-deploy-k8s DaemonSet that Nestybox publishes does NOT
//! support K3s (it tries to reconfigure kubelet as a standalone binary,
//! which K3s bundles).  Instead we install the .deb via cloud-init and
//! patch K3s's containerd template directly -- the same approach the
//! K3s+sysbox blog post recommends.
//!
//! The client does not need GHCR_TOKEN: the user is expected to have a
//! working ~/.docker/config.json that is already authenticated against
//! ghcr.io for pushing.
//!
//! Requires `HCLOUD_TOKEN` and the `hetzner-k3s` CLI.

use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use indoc::{formatdoc, indoc};

// hetzner-k3s config template.  `__double_underscore__` markers are
// replaced at runtime with absolute paths / tokens; static values live
// here.
//
// additional_post_k3s_commands runs as cloud-init on every node after
// K3s has installed, which means scale-up nodes produced by the cluster
// autoscaler go through the same setup.  The script drops a spegel
// registries.yaml on every node and, on workers only, installs sysbox
// and patches K3s's containerd config template to register sysbox-runc
// as an additional runtime.  K3s is restarted at the end to pick up
// both changes.
const CONFIG_TEMPLATE: &str = indoc! {r#"
    ---
    hetzner_token: __HCLOUD_TOKEN__

    cluster_name: rumpelpod-dev
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

    image: debian-13
    schedule_workloads_on_masters: false
    protect_against_deletion: false

    embedded_registry_mirror:
      enabled: true

    # cx23: cheapest non-deprecated x86 shared instance in nbg1 (2 vCPU
    # Intel, 4 GB, 40 GB disk, ~4.75 EUR/month).  Enough headroom for a
    # single-user K3s control plane once idle.
    masters_pool:
      instance_type: cx23
      instance_count: 1
      locations:
        - nbg1

    worker_node_pools:
      # cpx62: top of the "new" shared-vCPU AMD line (16 vCPU, 32 GB,
      # 640 GB disk, ~60 EUR/month when running).  The large disk is the
      # main reason to prefer cpx62 over cpx51: Rust target/ directories
      # chew through storage fast.  Autoscale 0 -> 1 keeps the bill at
      # ~5 EUR/month (master only) whenever nobody is on the cluster.
      - name: dev
        instance_type: cpx62
        location: nbg1
        labels:
          - key: pool
            value: dev
        autoscaling:
          enabled: true
          min_instances: 0
          max_instances: 1

    # Release idle dev nodes after one hour so short pauses don't trigger
    # a cold-boot penalty the next time you come back.
    cluster_autoscaler_args:
      - "--scale-down-unneeded-time=1h"

    addons:
      cluster_autoscaler:
        enabled: true

    additional_post_k3s_commands:
      - |
        set -eux
        mkdir -p /etc/rancher/k3s
        cat > /etc/rancher/k3s/registries.yaml <<'REG'
        mirrors:
          ghcr.io: {}
          docker.io: {}
        REG
        # Workers only: install sysbox and register it as an additional
        # containerd runtime.  Master skips this -- system pods need
        # host namespaces that sysbox blocks.
        if systemctl list-unit-files 2>/dev/null | grep -q '^k3s-agent\.service'; then
          curl -fsSL -o /tmp/sysbox.deb __SYSBOX_DEB_URL__
          apt-get update -qq
          apt-get install -y /tmp/sysbox.deb || apt-get install -y -f
          mkdir -p /var/lib/rancher/k3s/agent/etc/containerd
          cat > /var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl <<'TMPL'
        {{ template "base" . }}

        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sysbox-runc]
          runtime_type = "io.containerd.runc.v2"

        [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.sysbox-runc.options]
          BinaryName = "/usr/bin/sysbox-runc"
          SystemdCgroup = true
        TMPL
          systemctl restart k3s-agent
        else
          systemctl restart k3s
        fi
"#};

const SYSBOX_DEB_URL: &str =
    "https://downloads.nestybox.com/sysbox/releases/v0.7.0/sysbox-ce_0.7.0-0.linux_amd64.deb";

// Cluster manifests applied via kubectl after `hetzner-k3s create` returns.
// Kept as one multi-document YAML so everything is applied atomically and
// re-running the provisioner is idempotent (`kubectl apply` updates in
// place).
//
// The RuntimeClass is scoped to dev-pool nodes via nodeSelector because
// sysbox is only installed there (cloud-init skips the master).
//
// The BuildKit DS runs under sysbox with hostUsers: false.  No
// privileged: true needed -- sysbox virtualises everything BuildKit
// wanted CAP_SYS_ADMIN for.  Cache volume is hostPath so builds stay
// warm across pod restarts within a dev session.
//
// Resource requests are intentionally tiny so the builder does NOT keep
// an otherwise-idle dev node alive on its own.
//
// The readiness probe is a plain TCP dial on 1234.  An exec probe
// (`buildctl debug workers`) would be more accurate but it trips a
// cgroup path issue in kubelet+containerd 2.x; TCP dial sidesteps
// that and still tells us the daemon is accepting connections.
const CLUSTER_MANIFEST: &str = indoc! {r#"
    apiVersion: node.k8s.io/v1
    kind: RuntimeClass
    metadata:
      name: sysbox-runc
    handler: sysbox-runc
    scheduling:
      nodeSelector:
        pool: dev
    ---
    apiVersion: v1
    kind: Namespace
    metadata:
      name: buildkit
    ---
    apiVersion: v1
    kind: Namespace
    metadata:
      name: dev
    ---
    apiVersion: apps/v1
    kind: DaemonSet
    metadata:
      name: buildkitd
      namespace: buildkit
    spec:
      selector:
        matchLabels:
          app: buildkitd
      template:
        metadata:
          labels:
            app: buildkitd
        spec:
          runtimeClassName: sysbox-runc
          hostUsers: false
          nodeSelector:
            pool: dev
          containers:
            - name: buildkitd
              image: moby/buildkit:v0.21.1
              args:
                - --addr
                - tcp://0.0.0.0:1234
              ports:
                - containerPort: 1234
                  name: buildkit
              resources:
                requests:
                  cpu: 10m
                  memory: 64Mi
              readinessProbe:
                tcpSocket:
                  port: 1234
                initialDelaySeconds: 5
                periodSeconds: 30
              volumeMounts:
                - name: cache
                  mountPath: /var/lib/buildkit
          volumes:
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

// Strategic-merge patch applied to hetzner-k3s's hcloud-csi-controller
// Deployment after cluster creation.  hetzner-k3s installs the upstream
// CSI manifest verbatim and the upstream controller ships with zero
// tolerations, so it cannot land on our master (which carries the
// CriticalAddonsOnly=true:NoExecute taint from schedule_workloads_on_masters:
// false).  It therefore gets scheduled on the dev worker -- and then
// pins the worker alive forever, because cluster-autoscaler refuses to
// evict a single-replica non-DaemonSet pod that has nowhere else to go,
// defeating the whole point of a 0->1 autoscaling dev pool.
//
// The fix is to force the controller onto the master.  nodeSelector on
// node-role.kubernetes.io/control-plane is a hard constraint (the master
// is the only node that carries that label), and the CriticalAddonsOnly
// toleration lets the pod actually schedule there.
const HCLOUD_CSI_CONTROLLER_PATCH: &str = r#"{"spec":{"template":{"spec":{"nodeSelector":{"node-role.kubernetes.io/control-plane":"true"},"tolerations":[{"key":"CriticalAddonsOnly","operator":"Exists","effect":"NoExecute"}]}}}}"#;

// Minimal job that exists only to trigger cluster-autoscaler.  Schedules
// onto the dev pool via nodeSelector; when no dev node is up, the
// autoscaler will provision one within a couple of minutes.  The job
// itself does nothing and self-cleans after 60 s.
const WAKE_JOB: &str = indoc! {r#"
    apiVersion: batch/v1
    kind: Job
    metadata:
      name: wake-dev
      namespace: dev
    spec:
      ttlSecondsAfterFinished: 60
      backoffLimit: 0
      template:
        spec:
          restartPolicy: Never
          nodeSelector:
            pool: dev
          containers:
            - name: wake
              image: busybox:stable
              command:
                - sh
                - -c
                - echo woke dev node; sleep 5
              resources:
                requests:
                  cpu: 10m
                  memory: 16Mi
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

/// Parse `~/.docker/config.json` and return the ghcr.io username.
///
/// Format:
///     { "auths": { "ghcr.io": { "auth": "base64(user:token)" } } }
///
/// Using a hand-rolled parser (rather than serde_json) to match the
/// style of provision_hetzner_k3s.rs, which also avoids pulling extra
/// deps into a provisioning binary.
fn ghcr_user_from_docker_config() -> Result<String> {
    use base64::Engine;

    let path = dirs::home_dir()
        .context("HOME not set")?
        .join(".docker/config.json");
    let content =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;

    // Find the ghcr.io block and the `auth` value within it.
    let auths_idx = content
        .find("\"ghcr.io\"")
        .context("no ghcr.io entry in ~/.docker/config.json -- run `docker login ghcr.io`")?;
    let tail = &content[auths_idx..];
    let auth_idx = tail
        .find("\"auth\"")
        .context("ghcr.io entry has no `auth` field")?;
    let after_auth = &tail[auth_idx + "\"auth\"".len()..];
    let quote_start = after_auth
        .find('"')
        .context("malformed ghcr.io auth entry")?;
    let rest = &after_auth[quote_start + 1..];
    let quote_end = rest.find('"').context("malformed ghcr.io auth entry")?;
    let auth_b64 = &rest[..quote_end];

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(auth_b64)
        .context("decoding ghcr.io auth base64")?;
    let auth_str = String::from_utf8(decoded).context("ghcr.io auth is not UTF-8")?;
    let user = auth_str
        .split_once(':')
        .map(|(u, _)| u.to_string())
        .context("ghcr.io auth is not in user:token form")?;
    Ok(user)
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

    let ghcr_user = match std::env::var("GHCR_USER") {
        Ok(u) => u,
        Err(_) => ghcr_user_from_docker_config().context(
            "could not determine GitHub username: set GHCR_USER, or run \
             `docker login ghcr.io` so it appears in ~/.docker/config.json",
        )?,
    };
    eprintln!("==> Using ghcr.io user: {ghcr_user}");

    let registry = format!("ghcr.io/{ghcr_user}/rumpelpod");

    let repo_root = tools::repo_root()?;
    let resource_dir = repo_root.join("cloud/hetzner-dev");
    // Use a dedicated SSH key for this cluster: Hetzner stores SSH keys
    // by fingerprint, and hetzner-k3s insists on a key named after the
    // cluster.  Sharing a keypair with cloud/hetzner/ (the integration
    // test cluster) hits a fingerprint collision: hetzner-k3s refuses
    // to create a second key with the same fingerprint under a new
    // name, which ends up breaking the autoscaler's SSH access.
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

    let config = CONFIG_TEMPLATE
        .replace("__HCLOUD_TOKEN__", &hcloud_token)
        .replace("__SSH_PUBKEY_PATH__", &ssh_pub)
        .replace("__SSH_PRIVKEY_PATH__", ssh_key.to_str().unwrap())
        .replace("__KUBECONFIG_PATH__", kubeconfig_path.to_str().unwrap())
        .replace("__SYSBOX_DEB_URL__", SYSBOX_DEB_URL);
    std::fs::write(&config_path, &config)
        .with_context(|| format!("writing {}", config_path.display()))?;

    eprintln!("==> Creating K3s cluster on Hetzner Cloud...");
    eprintln!("    This takes 2-3 minutes.");
    tools::run(Command::new("hetzner-k3s").args([
        "create",
        "--config",
        config_path.to_str().unwrap(),
    ]))?;

    let kubeconfig_str = kubeconfig_path.to_str().unwrap();
    let kube_context = tools::output(
        Command::new("kubectl")
            .args(["config", "current-context"])
            .env("KUBECONFIG", kubeconfig_str),
    )
    .unwrap_or_default();

    eprintln!("==> Pinning hcloud-csi-controller to the master node...");
    tools::run(
        Command::new("kubectl")
            .env("KUBECONFIG", kubeconfig_str)
            .args([
                "-n",
                "kube-system",
                "patch",
                "deploy",
                "hcloud-csi-controller",
                "--type=strategic",
                "--patch",
                HCLOUD_CSI_CONTROLLER_PATCH,
            ]),
    )?;

    eprintln!("==> Applying RuntimeClass, namespaces, and builder DaemonSet...");
    kubectl_apply_stdin(&kubeconfig_path, CLUSTER_MANIFEST)?;

    // Write the wake-up Job to the resource dir so users can
    // `kubectl apply -f` it without needing to remember the manifest.
    let wake_path = resource_dir.join("wake-dev.yaml");
    std::fs::write(&wake_path, WAKE_JOB)
        .with_context(|| format!("writing {}", wake_path.display()))?;

    // -- Generate a rumpelpod.json for the dev cluster -----------------------

    let rumpelpod_json = formatdoc! {r#"
        // Generated by provision-hetzner-dev.  Workloads scheduled through
        // rumpelpod land in the `dev` namespace on dev worker nodes.
        {{
          "kubernetes": {{
            "context": "{kube_context}",
            "namespace": "dev",
            "registry": "{registry}",
            "builder": "buildkitd",
            "nodeSelector": {{
              "pool": "dev"
            }}
          }}
        }}
    "#};
    let rumpelpod_json_path = resource_dir.join("rumpelpod.json");
    std::fs::write(&rumpelpod_json_path, &rumpelpod_json)
        .with_context(|| format!("writing {}", rumpelpod_json_path.display()))?;

    // -- Write a buildx builder descriptor ---------------------------------

    // `docker buildx build --builder buildkitd` looks up this file under
    // $HOME/.docker/buildx/instances/ (or here in the repo when a
    // project pins its own BUILDX_CONFIG).  The endpoint matches the
    // local port used by the port-forward command documented below.
    let instances_dir = resource_dir.join("buildx/instances");
    std::fs::create_dir_all(&instances_dir)
        .with_context(|| format!("creating {}", instances_dir.display()))?;
    let builder_json = r#"{"Name":"buildkitd","Driver":"remote","Nodes":[{"Name":"buildkitd0","Endpoint":"tcp://127.0.0.1:1234"}]}"#;
    let builder_path = instances_dir.join("buildkitd");
    std::fs::write(&builder_path, builder_json)
        .with_context(|| format!("writing {}", builder_path.display()))?;

    // -- Status output -----------------------------------------------------

    let kubeconfig_display = kubeconfig_path.display();
    let config_display = config_path.display();
    let resource_dir_display = resource_dir.display();
    let wake_display = wake_path.display();
    let rumpelpod_json_display = rumpelpod_json_path.display();

    eprintln!();
    eprintln!("============================================");
    eprintln!(" Hetzner dev cluster ready!");
    eprintln!("============================================");
    eprintln!(" Kubeconfig       : {kubeconfig_display}");
    if !kube_context.is_empty() {
        eprintln!(" kubectl context  : {kube_context}");
    } else {
        eprintln!(" kubectl context  : <see kubeconfig>");
    }
    eprintln!(" Registry         : {registry}");
    eprintln!(" Builder          : buildkitd (namespace: buildkit, svc/buildkitd:1234)");
    eprintln!();
    eprintln!(" Master (always on):");
    eprintln!("   cx23   -- 2 shared Intel vCPU, 4 GB          (~4.75 EUR/month)");
    eprintln!();
    eprintln!(" Dev pool (autoscale 0 -> 1, idle timeout 1 h):");
    eprintln!("   cpx62  -- 16 shared AMD vCPU, 32 GB, 640 GB  (~60 EUR/month while on)");
    eprintln!();
    eprintln!(" Nodes            : Debian 13 (trixie)");
    eprintln!(" Sysbox           : v0.7.0 on workers, RuntimeClass `sysbox-runc`");
    eprintln!(" Spegel           : enabled, mirrors ghcr.io + docker.io");
    eprintln!();
    eprintln!(" Resource dir     : {resource_dir_display}");
    eprintln!(" Rumpelpod config : {rumpelpod_json_display}");
    eprintln!();
    eprintln!(" == Waking up the dev node =========================================");
    eprintln!(" Apply the pre-written dummy Job to force the autoscaler to");
    eprintln!(" provision a fresh dev VM (takes ~60-90 s to become Ready):");
    eprintln!();
    eprintln!("   KUBECONFIG={kubeconfig_display} \\");
    eprintln!("     kubectl apply -f {wake_display}");
    eprintln!("   KUBECONFIG={kubeconfig_display} \\");
    eprintln!(
        "     kubectl -n dev wait --for=condition=Ready pod -l job-name=wake-dev --timeout=5m"
    );
    eprintln!();
    eprintln!(" The job self-cleans after 60 s (ttlSecondsAfterFinished) and the");
    eprintln!(" node will be released again ~1 h after the last scheduled pod.");
    eprintln!();
    eprintln!(" == buildx via port-forward ========================================");
    eprintln!(" In one terminal, open a port-forward to the in-cluster builder:");
    eprintln!();
    eprintln!("   KUBECONFIG={kubeconfig_display} \\");
    eprintln!("     kubectl -n buildkit port-forward service/buildkitd 1234:1234");
    eprintln!();
    eprintln!(" In another, tell docker/buildx to use it (one-time setup):");
    eprintln!();
    eprintln!("   docker buildx create --name buildkitd --driver remote \\");
    eprintln!("     --use tcp://127.0.0.1:1234");
    eprintln!();
    eprintln!(" Then build and push as normal -- the client forwards your local");
    eprintln!(" ~/.docker/config.json auth to the remote builder on each build:");
    eprintln!();
    eprintln!("   docker buildx build --push -t {registry}:latest .");
    eprintln!();
    eprintln!(" == Tearing down ===================================================");
    eprintln!("   hetzner-k3s delete --config {config_display}");
    eprintln!();

    Ok(ExitCode::SUCCESS)
}

fn kubectl_apply_stdin(kubeconfig: &Path, manifest: &str) -> Result<()> {
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
