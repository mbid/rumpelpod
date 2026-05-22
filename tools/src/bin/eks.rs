// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provision and deprovision an AWS EKS cluster for integration testing.
//!
//! Usage:
//!   cargo run --bin eks -- provision
//!   cargo run --bin eks -- deprovision
//!
//! # Nested virtualization and kata
//!
//! The node group runs on `c8i.large` (8th-gen Intel, Sapphire Rapids)
//! because c8i/m8i/r8i are the only EC2 families that expose nested
//! virtualization to their guests, and nested virtualization is the
//! prerequisite for kata-containers (which spin up a QEMU microVM per
//! pod via `/dev/kvm`).  Nested virtualization is disabled by default
//! on new instances; it must be enabled via `CpuOptions.NestedVirtualization:
//! enabled` at instance-launch time.
//!
//! There is no clean eksctl or EKS-API path for this: managed node
//! groups generate their own launch template and silently drop the
//! `CpuOptions` block from any user-provided LT (the EKS API strips
//! non-standard fields).  After the node group is created we find
//! the EKS-owned launch template (the one the ASG references in its
//! MixedInstancesPolicy), publish a new version with `CpuOptions.
//! NestedVirtualization=enabled`, point the ASG at it, and trigger
//! an instance refresh.  The replacement instance comes up with
//! `/dev/kvm` exposed.
//!
//! After the cluster is up we apply the upstream kata-deploy
//! manifests (RBAC + DaemonSet + RuntimeClasses).  kata-deploy
//! targets nodes carrying the label `katacontainers.io/kata-runtime`,
//! which the node group sets at creation time, so no per-node
//! post-hoc labeling is needed.  runc remains the default runtime;
//! kata is opt-in per pod via `runtimeClassName: kata`, which xtest
//! can inject with `--runtime kata`.

use std::io::Write;
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use indoc::{formatdoc, indoc};

const CLUSTER_NAME: &str = "rumpelpod-test";
// eu-central-1 (Frankfurt) rather than the historical eu-west-1
// (Ireland): c8i.large is offered in Frankfurt today but not in
// Ireland, and Frankfurt is also the AWS region closest to Hetzner's
// nbg1 dc so cross-provider latency stays comparable with the test
// cluster.
const REGION: &str = "eu-central-1";
const ECR_REPO: &str = "rumpelpod-test";
// c8i.large: 2 vCPU, 4 GB, nested-virt-capable.  Smallest Gen-8i
// Intel size; m8i/r8i variants are drop-in if a workload needs more
// memory per vCPU.
const NODE_TYPE: &str = "c8i.large";
const NODE_COUNT: &str = "1";
const NODE_MAX: &str = "10";
// kata-containers release tag.  Starting with 3.27 the project
// ships kata-deploy only as a Helm chart tarball (the old
// kata-deploy/base/*.yaml tree is gone), so the installer below
// `helm template`s the chart and pipes the output through kubectl
// apply to keep our existing shell-style installer flow.
const KATA_VERSION: &str = "3.28.0";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an EKS cluster, ECR repository, and write credentials to .env.
    Provision,
    /// Tear down the EKS cluster and clean up AWS resources.
    Deprovision,
}

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
    let cli = Cli::parse();
    match cli.command {
        Cmd::Provision => provision(),
        Cmd::Deprovision => deprovision(),
    }
}

fn provision() -> Result<ExitCode> {
    let repo_root = tools::repo_root()?;
    let resource_dir = repo_root.join("cloud/eks");
    let state_file = resource_dir.join("state");
    let kubeconfig_path = resource_dir.join("kubeconfig");

    // -- Pre-flight checks ----------------------------------------------------

    if state_file.exists() {
        let path = state_file.display();
        anyhow::bail!(
            "a cluster state file already exists at {path}\n\
             Run `eks deprovision` first, or remove the file if the cluster is already gone."
        );
    }

    tools::require_tool(
        "aws",
        "Install it: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
    )?;
    tools::require_tool("eksctl", "Install it: https://eksctl.io/installation/")?;

    tools::run_quiet(Command::new("aws").args(["sts", "get-caller-identity"]))
        .context("AWS credentials not configured. Run 'aws configure' first.")?;

    let account_id = tools::output(Command::new("aws").args([
        "sts",
        "get-caller-identity",
        "--query",
        "Account",
        "--output",
        "text",
    ]))?;
    let ecr_uri = format!("{account_id}.dkr.ecr.{REGION}.amazonaws.com/{ECR_REPO}");

    std::fs::create_dir_all(&resource_dir)
        .with_context(|| format!("creating {}", resource_dir.display()))?;

    // -- Create ECR repository ------------------------------------------------

    eprintln!("==> Creating ECR repository {ECR_REPO} in {REGION}...");
    tools::run_quiet(Command::new("aws").args([
        "ecr",
        "create-repository",
        "--repository-name",
        ECR_REPO,
        "--region",
        REGION,
    ]))?;

    // -- Create EKS cluster ---------------------------------------------------

    eprintln!("==> Creating EKS cluster {CLUSTER_NAME} (type={NODE_TYPE}, nodes={NODE_COUNT}, max={NODE_MAX})...");
    eprintln!("    This takes 15-20 minutes.");
    let eksctl_config = formatdoc! {r#"
        apiVersion: eksctl.io/v1alpha5
        kind: ClusterConfig
        metadata:
          name: {CLUSTER_NAME}
          region: {REGION}
        managedNodeGroups:
          - name: ng
            instanceType: {NODE_TYPE}
            minSize: {NODE_COUNT}
            desiredCapacity: {NODE_COUNT}
            maxSize: {NODE_MAX}
            labels:
              pool: "test"
              # kata-deploy DaemonSet's nodeSelector is
              # `katacontainers.io/kata-runtime: "true"` upstream.
              # Labelling nodes at the node-group level makes the DS
              # roll out automatically as nodes join.
              katacontainers.io/kata-runtime: "true"
    "#};
    let config_path = resource_dir.join("eksctl-config.yaml");
    std::fs::write(&config_path, &eksctl_config)
        .with_context(|| format!("writing {}", config_path.display()))?;
    tools::run(Command::new("eksctl").args([
        "create",
        "cluster",
        "-f",
        config_path.to_str().unwrap(),
    ]))?;

    // -- Create ServiceAccount with static token ------------------------------
    // The default eksctl kubeconfig uses `aws eks get-token` as an exec
    // plugin.  A static token makes the kubeconfig self-contained.

    let sa_namespace = "kube-system";
    let sa_name = "rumpelpod-admin";

    eprintln!("==> Creating cluster-admin ServiceAccount...");
    tools::run(Command::new("kubectl").args([
        "create",
        "serviceaccount",
        sa_name,
        "-n",
        sa_namespace,
    ]))?;
    tools::run(Command::new("kubectl").args([
        "create",
        "clusterrolebinding",
        sa_name,
        "--clusterrole=cluster-admin",
        &format!("--serviceaccount={sa_namespace}:{sa_name}"),
    ]))?;

    let secret_yaml = formatdoc! {"
        apiVersion: v1
        kind: Secret
        metadata:
          name: {sa_name}-token
          namespace: {sa_namespace}
          annotations:
            kubernetes.io/service-account.name: {sa_name}
        type: kubernetes.io/service-account-token
    "};
    let mut kubectl = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawning kubectl apply")?;
    kubectl
        .stdin
        .take()
        .unwrap()
        .write_all(secret_yaml.as_bytes())
        .context("writing secret yaml to kubectl stdin")?;
    let status = kubectl.wait().context("waiting for kubectl apply")?;
    if !status.success() {
        anyhow::bail!("kubectl apply failed");
    }

    // Wait for the token controller to populate the secret.
    let mut sa_token = String::new();
    for _ in 0..30 {
        if let Ok(tok) = tools::output(Command::new("kubectl").args([
            "get",
            "secret",
            &format!("{sa_name}-token"),
            "-n",
            sa_namespace,
            "-o",
            "jsonpath={.data.token}",
        ])) {
            if !tok.is_empty() {
                sa_token = tok;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    if sa_token.is_empty() {
        anyhow::bail!("timed out waiting for ServiceAccount token to be populated");
    }

    // The token in the secret is base64-encoded; decode it.
    let sa_token =
        tools::output(Command::new("sh").args(["-c", &format!("echo '{sa_token}' | base64 -d")]))?;

    let eks_endpoint = tools::output(Command::new("aws").args([
        "eks",
        "describe-cluster",
        "--name",
        CLUSTER_NAME,
        "--region",
        REGION,
        "--query",
        "cluster.endpoint",
        "--output",
        "text",
    ]))?;
    let eks_ca = tools::output(Command::new("aws").args([
        "eks",
        "describe-cluster",
        "--name",
        CLUSTER_NAME,
        "--region",
        REGION,
        "--query",
        "cluster.certificateAuthority.data",
        "--output",
        "text",
    ]))?;

    let kubeconfig = formatdoc! {"
        apiVersion: v1
        kind: Config
        clusters:
        - cluster:
            server: {eks_endpoint}
            certificate-authority-data: {eks_ca}
          name: {CLUSTER_NAME}
        contexts:
        - context:
            cluster: {CLUSTER_NAME}
            user: {sa_name}
          name: {CLUSTER_NAME}
        current-context: {CLUSTER_NAME}
        users:
        - name: {sa_name}
          user:
            token: {sa_token}
    "};
    std::fs::write(&kubeconfig_path, &kubeconfig)
        .with_context(|| format!("writing {}", kubeconfig_path.display()))?;

    // -- Grant ECR push access to node role -----------------------------------
    // EKS managed node groups get AmazonEC2ContainerRegistryReadOnly by
    // default.  For buildx pushes the node role also needs write access.

    // eksctl generates the nodegroup name; query it rather than assuming.
    let nodegroup_name = tools::output(Command::new("aws").args([
        "eks",
        "list-nodegroups",
        "--cluster-name",
        CLUSTER_NAME,
        "--region",
        REGION,
        "--query",
        "nodegroups[0]",
        "--output",
        "text",
    ]))?;

    let nodegroup_role = tools::output(Command::new("aws").args([
        "eks",
        "describe-nodegroup",
        "--cluster-name",
        CLUSTER_NAME,
        "--nodegroup-name",
        &nodegroup_name,
        "--region",
        REGION,
        "--query",
        "nodegroup.nodeRole",
        "--output",
        "text",
    ]))?;
    let nodegroup_role_name = Path::new(&nodegroup_role)
        .file_name()
        .context("extracting role name from ARN")?
        .to_str()
        .context("role name is not valid UTF-8")?;

    eprintln!("==> Granting ECR push access to node role...");
    tools::run(Command::new("aws").args([
        "iam",
        "attach-role-policy",
        "--role-name",
        nodegroup_role_name,
        "--policy-arn",
        "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser",
    ]))?;

    // -- Label nodegroup -------------------------------------------------------
    // Integration tests schedule pods with nodeSelector pool=test.
    // Set the label on the nodegroup so autoscaled nodes inherit it.

    eprintln!("==> Labeling nodegroup with pool=test...");
    tools::run(Command::new("aws").args([
        "eks",
        "update-nodegroup-config",
        "--cluster-name",
        CLUSTER_NAME,
        "--nodegroup-name",
        &nodegroup_name,
        "--region",
        REGION,
        "--labels",
        r#"{"addOrUpdateLabels":{"pool":"test"}}"#,
    ]))?;

    // -- Install Cluster Autoscaler -------------------------------------------
    // The autoscaler watches for pending pods and scales the ASG up/down.
    // It discovers the ASG via well-known tags on the ASG resource.

    install_cluster_autoscaler(nodegroup_role_name, &nodegroup_name)?;

    // -- Enable nested virtualization on the node group ----------------------

    enable_nested_virt(&nodegroup_name)?;

    // -- Install kata-containers ---------------------------------------------

    install_kata()?;

    // -- Save state -----------------------------------------------------------

    let state = formatdoc! {"
        CLUSTER_NAME={CLUSTER_NAME}
        REGION={REGION}
        ECR_REPO={ECR_REPO}
        ACCOUNT_ID={account_id}
        NODEGROUP_ROLE_NAME={nodegroup_role_name}
    "};
    std::fs::write(&state_file, &state)
        .with_context(|| format!("writing {}", state_file.display()))?;

    // -- Write docker config for ECR credential helper -----------------------
    // rumpelpod's registry client looks up credentials in
    // ~/.docker/config.json (credHelpers, credsStore, or auths).  ECR
    // tokens are short-lived so we use `credHelpers` -- every pull
    // shells out to `docker-credential-ecr-login` and gets a fresh
    // AWS-minted password.  The helper binary is placed on PATH by
    // xtest's `apply_eks`.
    let docker_dir = resource_dir.join("docker");
    std::fs::create_dir_all(&docker_dir)
        .with_context(|| format!("creating {}", docker_dir.display()))?;
    let ecr_host = format!("{account_id}.dkr.ecr.{REGION}.amazonaws.com");
    let docker_config = formatdoc! {r#"
        {{
          "credHelpers": {{
            "{ecr_host}": "ecr-login"
          }}
        }}
    "#};
    let docker_config_path = docker_dir.join("config.json");
    std::fs::write(&docker_config_path, &docker_config)
        .with_context(|| format!("writing {}", docker_config_path.display()))?;

    // -- Create test namespace ------------------------------------------------

    eprintln!("==> Creating namespace {CLUSTER_NAME}...");
    // Ignore errors in case it already exists.
    let _ = Command::new("kubectl")
        .args(["create", "namespace", CLUSTER_NAME])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();

    // -- Write rumpelpod.json -------------------------------------------------

    let rumpelpod_json = formatdoc! {r#"
        {{
          "kubernetes": {{
            "context": "{CLUSTER_NAME}",
            "namespace": "{CLUSTER_NAME}",
            "registry": "{ecr_uri}",
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

    let kubeconfig_display = kubeconfig_path.display();
    let state_display = state_file.display();
    let resource_dir_display = resource_dir.display();
    eprintln!();
    eprintln!("============================================");
    eprintln!(" EKS cluster ready!");
    eprintln!("============================================");
    eprintln!(" Cluster        : {CLUSTER_NAME}");
    eprintln!(" Region         : {REGION}");
    eprintln!(" ECR repository : {ECR_REPO}");
    eprintln!(" ECR URI        : {ecr_uri}");
    eprintln!(" kubectl context: {CLUSTER_NAME}");
    eprintln!(" Kubeconfig     : {kubeconfig_display}");
    eprintln!();
    eprintln!(" Resource dir   : {resource_dir_display}");
    eprintln!(" State saved to : {state_display}");
    eprintln!();
    eprintln!(" ECR docker login (required before running tests,");
    eprintln!(" expires after 12 hours):");
    eprintln!();
    eprintln!("   aws ecr get-login-password --region {REGION} \\");
    eprintln!("     | docker login --username AWS --password-stdin {ecr_uri}");
    eprintln!();
    eprintln!(" Run tests:     cargo xtest --executor eks -- k8s --ignored");
    eprintln!(" Deprovision:   cargo run --bin eks -- deprovision");
    eprintln!();

    Ok(ExitCode::SUCCESS)
}

fn deprovision() -> Result<ExitCode> {
    let repo_root = tools::repo_root()?;
    let resource_dir = repo_root.join("cloud/eks");
    let state_file = resource_dir.join("state");

    if !state_file.exists() {
        let path = state_file.display();
        anyhow::bail!(
            "no cluster state file found at {path}\n\
             Nothing to deprovision."
        );
    }

    let state = tools::parse_state_file(&state_file)?;

    let cluster_name = state
        .get("CLUSTER_NAME")
        .context("CLUSTER_NAME not set in state file")?;
    let region = state
        .get("REGION")
        .context("REGION not set in state file")?;

    // Remove IAM policies we attached during provisioning.
    if let Some(role_name) = state.get("NODEGROUP_ROLE_NAME") {
        eprintln!("==> Detaching IAM policies from node role...");
        // Best-effort: the role may already be gone if the cluster was
        // partially cleaned up.
        let _ = Command::new("aws")
            .args([
                "iam",
                "detach-role-policy",
                "--role-name",
                role_name,
                "--policy-arn",
                "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPowerUser",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = Command::new("aws")
            .args([
                "iam",
                "delete-role-policy",
                "--role-name",
                role_name,
                "--policy-name",
                "ClusterAutoscalerPolicy",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }

    if let Some(ecr_repo) = state.get("ECR_REPO") {
        eprintln!("==> Deleting ECR repository {ecr_repo}...");
        tools::run_quiet(Command::new("aws").args([
            "ecr",
            "delete-repository",
            "--repository-name",
            ecr_repo,
            "--region",
            region,
            "--force",
        ]))?;
    }

    eprintln!("==> Deleting EKS cluster {cluster_name}...");
    eprintln!("    This takes a few minutes.");
    tools::run(Command::new("eksctl").args([
        "delete",
        "cluster",
        "--name",
        cluster_name,
        "--region",
        region,
    ]))?;

    // Remove the resource directory.
    let _ = std::fs::remove_dir_all(&resource_dir);

    let ecr_repo = state.get("ECR_REPO").map(|s| s.as_str()).unwrap_or("");
    let resource_dir_display = resource_dir.display();
    eprintln!();
    eprintln!("============================================");
    eprintln!(" EKS cluster deprovisioned");
    eprintln!("============================================");
    eprintln!(" Cluster {cluster_name} and ECR repository {ecr_repo} deleted.");
    eprintln!(" Resource directory removed: {resource_dir_display}");
    eprintln!();

    Ok(ExitCode::SUCCESS)
}

fn install_cluster_autoscaler(nodegroup_role_name: &str, nodegroup_name: &str) -> Result<()> {
    eprintln!("==> Installing Cluster Autoscaler...");

    // Tag the ASG so the autoscaler can discover it.
    let asg_name = tools::output(Command::new("aws").args([
        "eks",
        "describe-nodegroup",
        "--cluster-name",
        CLUSTER_NAME,
        "--nodegroup-name",
        nodegroup_name,
        "--region",
        REGION,
        "--query",
        "nodegroup.resources.autoScalingGroups[0].name",
        "--output",
        "text",
    ]))?;
    tools::run(Command::new("aws").args([
        "autoscaling",
        "create-or-update-tags",
        "--tags",
        &format!(
            "ResourceId={asg_name},ResourceType=auto-scaling-group,\
                 Key=k8s.io/cluster-autoscaler/enabled,Value=true,PropagateAtLaunch=true"
        ),
        &format!(
            "ResourceId={asg_name},ResourceType=auto-scaling-group,\
                 Key=k8s.io/cluster-autoscaler/{CLUSTER_NAME},Value=owned,PropagateAtLaunch=true"
        ),
        "--region",
        REGION,
    ]))?;

    // Grant the node role permission to call autoscaling APIs.
    let cas_policy = formatdoc! {r#"
        {{
          "Version": "2012-10-17",
          "Statement": [
            {{
              "Effect": "Allow",
              "Action": [
                "autoscaling:DescribeAutoScalingGroups",
                "autoscaling:DescribeAutoScalingInstances",
                "autoscaling:DescribeLaunchConfigurations",
                "autoscaling:DescribeScalingActivities",
                "autoscaling:DescribeTags",
                "autoscaling:SetDesiredCapacity",
                "autoscaling:TerminateInstanceInAutoScalingGroup",
                "ec2:DescribeImages",
                "ec2:DescribeInstanceTypes",
                "ec2:DescribeLaunchTemplateVersions",
                "ec2:GetInstanceTypesFromInstanceRequirements",
                "eks:DescribeNodegroup"
              ],
              "Resource": "*"
            }}
          ]
        }}
    "#};
    let mut put_policy = Command::new("aws")
        .args([
            "iam",
            "put-role-policy",
            "--role-name",
            nodegroup_role_name,
            "--policy-name",
            "ClusterAutoscalerPolicy",
            "--policy-document",
            "file:///dev/stdin",
        ])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawning aws iam put-role-policy")?;
    put_policy
        .stdin
        .take()
        .unwrap()
        .write_all(cas_policy.as_bytes())
        .context("writing policy document")?;
    let status = put_policy.wait().context("waiting for put-role-policy")?;
    if !status.success() {
        anyhow::bail!("aws iam put-role-policy failed");
    }

    // Deploy the autoscaler workload.
    let manifest = formatdoc! {"
        apiVersion: v1
        kind: ServiceAccount
        metadata:
          name: cluster-autoscaler
          namespace: kube-system
        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRole
        metadata:
          name: cluster-autoscaler
        rules:
          - apiGroups: ['']
            resources: [events, endpoints]
            verbs: [create, patch]
          - apiGroups: ['']
            resources: [pods/eviction]
            verbs: [create]
          - apiGroups: ['']
            resources: [pods/status]
            verbs: [update]
          - apiGroups: ['']
            resources: [endpoints]
            resourceNames: [cluster-autoscaler]
            verbs: [get, update]
          - apiGroups: ['']
            resources: [nodes]
            verbs: [watch, list, get, update]
          - apiGroups: ['']
            resources: [namespaces, pods, services, replicationcontrollers, persistentvolumeclaims, persistentvolumes]
            verbs: [watch, list, get]
          - apiGroups: ['']
            resources: [configmaps]
            verbs: [watch, list, get, create, update, patch, delete]
          - apiGroups: [extensions]
            resources: [replicasets, daemonsets]
            verbs: [watch, list, get]
          - apiGroups: [policy]
            resources: [poddisruptionbudgets]
            verbs: [watch, list]
          - apiGroups: [apps]
            resources: [statefulsets, replicasets, daemonsets]
            verbs: [watch, list, get]
          - apiGroups: [storage.k8s.io]
            resources: [storageclasses, csinodes, csidrivers, csistoragecapacities, volumeattachments]
            verbs: [watch, list, get]
          - apiGroups: [batch, extensions]
            resources: [jobs]
            verbs: [get, list, watch, patch]
          - apiGroups: [coordination.k8s.io]
            resources: [leases]
            verbs: [create]
          - apiGroups: [coordination.k8s.io]
            resources: [leases]
            resourceNames: [cluster-autoscaler]
            verbs: [get, update]
        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: ClusterRoleBinding
        metadata:
          name: cluster-autoscaler
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
          name: cluster-autoscaler
        subjects:
          - kind: ServiceAccount
            name: cluster-autoscaler
            namespace: kube-system
        ---
        apiVersion: apps/v1
        kind: Deployment
        metadata:
          name: cluster-autoscaler
          namespace: kube-system
        spec:
          replicas: 1
          selector:
            matchLabels:
              app: cluster-autoscaler
          template:
            metadata:
              labels:
                app: cluster-autoscaler
            spec:
              serviceAccountName: cluster-autoscaler
              containers:
                - image: registry.k8s.io/autoscaling/cluster-autoscaler:v1.32.0
                  name: cluster-autoscaler
                  resources:
                    limits:
                      cpu: 100m
                      memory: 600Mi
                    requests:
                      cpu: 100m
                      memory: 600Mi
                  command:
                    - ./cluster-autoscaler
                    - --v=4
                    - --stderrthreshold=info
                    - --cloud-provider=aws
                    - --skip-nodes-with-local-storage=false
                    - --expander=least-waste
                    - --node-group-auto-discovery=asg:tag=k8s.io/cluster-autoscaler/enabled,k8s.io/cluster-autoscaler/{CLUSTER_NAME}
                    - --scale-down-delay-after-add=2m
                    - --scale-down-unneeded-time=2m
                  env:
                    - name: AWS_REGION
                      value: {REGION}
    "};
    let mut kubectl = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .context("spawning kubectl apply for cluster-autoscaler")?;
    kubectl
        .stdin
        .take()
        .unwrap()
        .write_all(manifest.as_bytes())
        .context("writing autoscaler manifest")?;
    let status = kubectl.wait().context("waiting for kubectl apply")?;
    if !status.success() {
        anyhow::bail!("kubectl apply for cluster-autoscaler failed");
    }

    // Wait for the autoscaler pod to become ready.
    tools::run(Command::new("kubectl").args([
        "-n",
        "kube-system",
        "rollout",
        "status",
        "deployment/cluster-autoscaler",
        "--timeout=60s",
    ]))?;

    eprintln!("    Cluster Autoscaler running (min={NODE_COUNT}, max={NODE_MAX}).");
    Ok(())
}

/// Enable nested virtualization on the EKS-generated launch template
/// and roll the node group so the new instances pick it up.
///
/// EKS managed node groups generate their own launch template (named
/// `eks-<uuid>`) from the node group configuration.  The
/// CreateNodegroup API accepts a user-provided LT but copies only a
/// known set of fields into the EKS-generated LT, silently dropping
/// `CpuOptions`.  The workaround is to publish a new version of the
/// EKS-generated LT with the CpuOptions block added, point the ASG's
/// MixedInstancesPolicy at that version, and instance-refresh.
fn enable_nested_virt(nodegroup_name: &str) -> Result<()> {
    eprintln!("==> Enabling nested virtualization on node group...");

    let asg_name = tools::output(Command::new("aws").args([
        "eks",
        "describe-nodegroup",
        "--cluster-name",
        CLUSTER_NAME,
        "--nodegroup-name",
        nodegroup_name,
        "--region",
        REGION,
        "--query",
        "nodegroup.resources.autoScalingGroups[0].name",
        "--output",
        "text",
    ]))?;
    let lt_id = tools::output(Command::new("aws").args([
        "autoscaling",
        "describe-auto-scaling-groups",
        "--auto-scaling-group-names",
        &asg_name,
        "--region",
        REGION,
        "--query",
        "AutoScalingGroups[0].MixedInstancesPolicy.LaunchTemplate.LaunchTemplateSpecification.LaunchTemplateId",
        "--output",
        "text",
    ]))?;
    eprintln!("    ASG: {asg_name}, LT: {lt_id}");

    // Read the current LT data, add CpuOptions, publish a new
    // version.  describe-launch-template-versions returns a full
    // object; we patch it in-place so every other field (AMI, user
    // data, security groups, ...) carries over unchanged.
    let current = tools::output(Command::new("aws").args([
        "ec2",
        "describe-launch-template-versions",
        "--launch-template-id",
        &lt_id,
        "--region",
        REGION,
        "--query",
        "LaunchTemplateVersions[0].LaunchTemplateData",
        "--output",
        "json",
    ]))?;
    let mut data: serde_json::Value =
        serde_json::from_str(&current).context("parsing current LT data")?;
    data.as_object_mut()
        .context("LT data is not an object")?
        .insert(
            "CpuOptions".to_string(),
            serde_json::json!({ "NestedVirtualization": "enabled" }),
        );
    let patched = serde_json::to_string(&data).context("serializing patched LT data")?;
    let new_version = tools::output(Command::new("aws").args([
        "ec2",
        "create-launch-template-version",
        "--launch-template-id",
        &lt_id,
        "--region",
        REGION,
        "--launch-template-data",
        &patched,
        "--query",
        "LaunchTemplateVersion.VersionNumber",
        "--output",
        "text",
    ]))?;
    eprintln!("    Created LT version {new_version}");

    // Point the ASG at the new version.  EKS uses MixedInstancesPolicy
    // for managed node groups, so rewrite that block.  Omitting
    // InstancesDistribution keeps the defaults EKS already set.
    let mip = formatdoc! {r#"
        {{
          "LaunchTemplate": {{
            "LaunchTemplateSpecification": {{
              "LaunchTemplateId": "{lt_id}",
              "Version": "{new_version}"
            }}
          }}
        }}
    "#};
    tools::run(Command::new("aws").args([
        "autoscaling",
        "update-auto-scaling-group",
        "--auto-scaling-group-name",
        &asg_name,
        "--region",
        REGION,
        "--mixed-instances-policy",
        mip.trim(),
    ]))?;

    // Replace the existing instance (launched before the refresh
    // from v1 of the LT, without CpuOptions).  MinHealthyPercentage=0
    // lets the refresh proceed with our single-instance baseline.
    eprintln!("    Instance-refreshing ASG...");
    let refresh_id = tools::output(Command::new("aws").args([
        "autoscaling",
        "start-instance-refresh",
        "--auto-scaling-group-name",
        &asg_name,
        "--preferences",
        r#"{"MinHealthyPercentage":0,"InstanceWarmup":60}"#,
        "--region",
        REGION,
        "--query",
        "InstanceRefreshId",
        "--output",
        "text",
    ]))?;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(600);
    loop {
        let status = tools::output(Command::new("aws").args([
            "autoscaling",
            "describe-instance-refreshes",
            "--auto-scaling-group-name",
            &asg_name,
            "--region",
            REGION,
            "--instance-refresh-ids",
            &refresh_id,
            "--query",
            "InstanceRefreshes[0].Status",
            "--output",
            "text",
        ]))?;
        match status.as_str() {
            "Successful" => {
                eprintln!("    Instance refresh complete.");
                return Ok(());
            }
            "Failed" | "Cancelled" => anyhow::bail!("instance refresh {status}"),
            _ => {}
        }
        if std::time::Instant::now() > deadline {
            anyhow::bail!("instance refresh did not finish within 10 minutes");
        }
        std::thread::sleep(std::time::Duration::from_secs(30));
    }
}

/// Apply kata-containers kata-deploy on the cluster.
///
/// kata-deploy is a DaemonSet that, on every node matching its
/// nodeSelector, drops the kata binaries + containerd shim into
/// `/opt/kata/`, patches `/etc/containerd/config.toml` with new
/// runtime entries (`kata-qemu`, `kata-clh`, etc.), and restarts
/// containerd.  It also installs the matching RuntimeClasses
/// (`kata-qemu` etc.) cluster-wide.
///
/// Upstream ships the whole thing as a Helm chart tarball attached
/// to the release; we download it, `helm template` it against our
/// values, and apply the rendered YAML with kubectl so we avoid
/// adding Helm release state to the cluster.  Chart nodeSelector
/// matches our `pool=test` label so kata is not installed on
/// non-test nodes.
///
/// After the chart applies we add a standalone `kata` RuntimeClass
/// (handler `kata-qemu`) so tests that reference `runtimeClassName:
/// kata` work without per-test suffix knowledge of which hypervisor
/// is in use.  Upstream only creates the shim-specific classes.
fn install_kata() -> Result<()> {
    eprintln!("==> Installing kata-containers (kata-deploy v{KATA_VERSION})...");
    tools::require_tool("helm", "Install it: https://helm.sh/docs/intro/install/")?;

    let tarball_url = format!(
        "https://github.com/kata-containers/kata-containers/releases/download/\
         {KATA_VERSION}/kata-deploy-{KATA_VERSION}.tgz"
    );
    let tmp = tempfile::tempdir().context("creating tempdir for kata chart")?;
    let tarball_path = tmp.path().join("kata-deploy.tgz");
    tools::run(Command::new("curl").args([
        "-fsSL",
        "-o",
        tarball_path.to_str().unwrap(),
        &tarball_url,
    ]))?;
    tools::run(
        Command::new("tar")
            .args(["xzf", tarball_path.to_str().unwrap()])
            .current_dir(tmp.path()),
    )?;

    // `helm template` renders the chart to stdout without touching
    // cluster-side Helm state (no Secret in kube-system for the
    // release).  nodeSelector pins the DaemonSet to the test pool so
    // kata is not installed on any future non-test nodegroup.
    let chart_dir = tmp.path().join("kata-deploy");
    let rendered = tools::output(Command::new("helm").args([
        "template",
        "kata",
        chart_dir.to_str().unwrap(),
        "--namespace",
        "kube-system",
        "--set",
        "nodeSelector.pool=test",
    ]))?;
    kubectl_apply_stdin(&rendered)?;

    // First-install race: the DaemonSet controller can create its
    // pod a tick before the ClusterRoleBinding for `kata-deploy-sa`
    // is fully bound.  The kubelet then mounts a projected token
    // that returns 401 on every API call, and the pod stays stuck
    // in CrashLoopBackOff forever (the projected token volume is
    // not re-minted mid-pod).  Force a pod restart once the RBAC
    // has settled so the replacement pod picks up a working token.
    let _ = Command::new("kubectl")
        .args([
            "-n",
            "kube-system",
            "delete",
            "pod",
            "-l",
            "name=kata-deploy",
            "--ignore-not-found",
            "--wait=false",
        ])
        .stdout(std::process::Stdio::null())
        .status();

    eprintln!("    Waiting for kata-deploy DaemonSet to roll out...");
    tools::run(Command::new("kubectl").args([
        "-n",
        "kube-system",
        "rollout",
        "status",
        "daemonset/kata-deploy",
        "--timeout=300s",
    ]))?;

    // Standalone `kata` RuntimeClass -- upstream creates only
    // shim-specific classes (kata-qemu, kata-clh, ...), so point
    // `kata` at the qemu shim as the sensible default.  Scheduling
    // nodeSelector ensures pods using it land on a kata-enabled
    // node rather than silently falling back to runc.
    let kata_rc = indoc! {r#"
        apiVersion: node.k8s.io/v1
        kind: RuntimeClass
        metadata:
          name: kata
        handler: kata-qemu
        scheduling:
          nodeSelector:
            pool: test
    "#};
    kubectl_apply_stdin(kata_rc)?;

    Ok(())
}

fn kubectl_apply_stdin(manifest: &str) -> Result<()> {
    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
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
