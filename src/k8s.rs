use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, AttachParams, DeleteParams, ListParams, PostParams};
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Client, Config};
use log::{info, trace};
use tokio::io::AsyncReadExt;

use crate::async_runtime::block_on;
use crate::daemon::protocol::PodStatus;

/// Label applied to all pods created by rumpelpod for identification.
const LABEL_MANAGED_BY: &str = "app.kubernetes.io/managed-by";
const LABEL_MANAGED_BY_VALUE: &str = "rumpelpod";
/// Label storing the repo path hash for filtering pods by repository.
const LABEL_REPO_HASH: &str = "rumpelpod/repo-hash";
/// Label storing the human-readable pod name.
const LABEL_POD_NAME: &str = "rumpelpod/pod-name";
/// Annotation storing the creation timestamp (ISO 8601).
const ANNOTATION_CREATED: &str = "rumpelpod/created";

/// Client for Kubernetes operations, scoped to a specific context and namespace.
pub struct K8sClient {
    client: Client,
    namespace: String,
}

/// Architecture of a container's OS/platform.
pub enum ContainerArch {
    Amd64,
    Arm64,
}

impl ContainerArch {
    fn from_uname(s: &str) -> Result<Self> {
        match s.trim() {
            "x86_64" => Ok(Self::Amd64),
            "aarch64" => Ok(Self::Arm64),
            other => Err(anyhow::anyhow!(
                "unsupported container architecture '{}'",
                other
            )),
        }
    }

    /// Filename for the cross-arch binary, e.g. "rumpel-linux-amd64".
    pub fn binary_name(&self) -> &'static str {
        match self {
            Self::Amd64 => "rumpel-linux-amd64",
            Self::Arm64 => "rumpel-linux-arm64",
        }
    }
}

/// Options for creating a Kubernetes pod beyond the basics (image, labels, etc.).
pub struct K8sPodOptions {
    pub volumes: Vec<K8sVolumeMount>,
    pub privileged: bool,
    pub cap_add: Vec<String>,
    pub seccomp_unconfined: bool,
    pub apparmor_unconfined: bool,
    pub override_command: bool,
    pub resource_requests: Option<K8sResourceRequests>,
    pub node_selector: Option<BTreeMap<String, String>>,
    pub tolerations: Option<Vec<crate::config::K8sToleration>>,
}

impl Default for K8sPodOptions {
    fn default() -> Self {
        Self {
            volumes: Vec::new(),
            privileged: false,
            cap_add: Vec::new(),
            seccomp_unconfined: false,
            apparmor_unconfined: false,
            override_command: true,
            resource_requests: None,
            node_selector: None,
            tolerations: None,
        }
    }
}

/// A volume mount for a Kubernetes pod (backed by emptyDir).
pub struct K8sVolumeMount {
    /// Volume name, e.g. "vol-0", "vol-1".
    pub name: String,
    /// Mount path inside the container.
    pub mount_path: String,
    /// Whether the mount is read-only.
    pub read_only: bool,
    /// "Memory" for tmpfs-backed emptyDir, None for disk-backed.
    pub medium: Option<String>,
}

/// Resource requests for a Kubernetes pod.
pub struct K8sResourceRequests {
    /// CPU request, e.g. "4" for 4 cores.
    pub cpu: Option<String>,
    /// Memory request, e.g. "4Gi".
    pub memory: Option<String>,
}

/// Compute a short hash of the repo path for use as a label value.
/// Label values must be <= 63 chars and match [a-z0-9A-Z._-].
pub fn repo_path_hash(repo_path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(repo_path.to_string_lossy().as_bytes());
    let hash = hasher.finalize();
    hex::encode(&hash[..8])
}

/// Build the Kubernetes pod name from the rumpelpod pod name and repo hash.
/// k8s pod names must be DNS-compatible: lowercase alphanumeric and hyphens,
/// max 63 chars, start and end with alphanumeric.
pub fn k8s_pod_name(pod_name: &str, repo_path: &std::path::Path) -> String {
    let hash = repo_path_hash(repo_path);
    let lower = pod_name.to_lowercase();
    let prefix = format!("rp-{lower}");
    // Truncate prefix to leave room for the hash suffix
    let max_prefix = 63 - 1 - hash.len(); // 1 for the hyphen
    let prefix = if prefix.len() > max_prefix {
        &prefix[..max_prefix]
    } else {
        &prefix
    };
    format!("{prefix}-{hash}")
}

impl K8sClient {
    /// Create a new Kubernetes client for the given context and namespace.
    pub fn new(context: &str, namespace: &str) -> Result<Self> {
        let client = block_on(async {
            let kubeconfig = Kubeconfig::read().context("reading kubeconfig")?;
            let config = Config::from_custom_kubeconfig(
                kubeconfig,
                &KubeConfigOptions {
                    context: Some(context.to_string()),
                    ..Default::default()
                },
            )
            .await
            .context("building kube config from kubeconfig")?;
            Client::try_from(config).context("creating kube client")
        })?;

        Ok(Self {
            client,
            namespace: namespace.to_string(),
        })
    }

    /// Create a Kubernetes pod running the given image.
    ///
    /// When `options.override_command` is true, the container command is set to
    /// `["sleep", "infinity"]` (overriding the image CMD).  When false, the
    /// image's own CMD is used.
    #[allow(clippy::too_many_arguments)]
    pub fn create_pod(
        &self,
        name: &str,
        image: &str,
        labels: BTreeMap<String, String>,
        mut annotations: BTreeMap<String, String>,
        container_user: Option<&str>,
        env: &[(String, String)],
        options: &K8sPodOptions,
    ) -> Result<()> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);

        // Build volume mounts and volume definitions from options
        let mut volume_mounts: Vec<serde_json::Value> = options
            .volumes
            .iter()
            .map(|v| {
                serde_json::json!({
                    "name": v.name,
                    "mountPath": v.mount_path,
                    "readOnly": v.read_only,
                })
            })
            .collect();

        let mut volumes: Vec<serde_json::Value> = options
            .volumes
            .iter()
            .map(|v| {
                let empty_dir = match &v.medium {
                    Some(medium) => serde_json::json!({ "medium": medium }),
                    None => serde_json::json!({}),
                };
                serde_json::json!({
                    "name": v.name,
                    "emptyDir": empty_dir,
                })
            })
            .collect();

        // Always include a writable emptyDir for the rumpel binary so we
        // can write to /opt/rumpelpod/bin as a non-root user.
        volume_mounts.push(serde_json::json!({
            "name": "rumpelpod-bin",
            "mountPath": "/opt/rumpelpod/bin",
        }));
        volumes.push(serde_json::json!({
            "name": "rumpelpod-bin",
            "emptyDir": {},
        }));

        let mut container = serde_json::json!({
            "name": "main",
            "image": image,
            "env": env.iter().map(|(k, v)| serde_json::json!({
                "name": k,
                "value": v,
            })).collect::<Vec<_>>(),
            "volumeMounts": volume_mounts,
        });

        if options.override_command {
            container["command"] = serde_json::json!(["sleep", "infinity"]);
        }

        // Build securityContext
        let mut sec_ctx = serde_json::Map::new();

        if let Some(user) = container_user {
            if let Ok(uid) = user.parse::<i64>() {
                sec_ctx.insert("runAsUser".to_string(), serde_json::json!(uid));
            }
        }

        if options.privileged {
            sec_ctx.insert("privileged".to_string(), serde_json::json!(true));
        }

        if !options.cap_add.is_empty() {
            sec_ctx.insert(
                "capabilities".to_string(),
                serde_json::json!({ "add": options.cap_add }),
            );
        }

        if options.seccomp_unconfined {
            sec_ctx.insert(
                "seccompProfile".to_string(),
                serde_json::json!({ "type": "Unconfined" }),
            );
        }

        if !sec_ctx.is_empty() {
            container["securityContext"] = serde_json::Value::Object(sec_ctx);
        }

        // Build resource requests
        if let Some(ref reqs) = options.resource_requests {
            let mut requests = serde_json::Map::new();
            if let Some(ref cpu) = reqs.cpu {
                requests.insert("cpu".to_string(), serde_json::json!(cpu));
            }
            if let Some(ref memory) = reqs.memory {
                requests.insert("memory".to_string(), serde_json::json!(memory));
            }
            if !requests.is_empty() {
                container["resources"] = serde_json::json!({
                    "requests": serde_json::Value::Object(requests),
                });
            }
        }

        // AppArmor unconfined via annotation
        if options.apparmor_unconfined {
            annotations.insert(
                "container.apparmor.security.beta.kubernetes.io/main".to_string(),
                "unconfined".to_string(),
            );
        }

        let mut pod_spec = serde_json::json!({
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {
                "name": name,
                "labels": labels,
                "annotations": annotations,
            },
            "spec": {
                "containers": [container],
                "volumes": volumes,
                "restartPolicy": "Never",
            }
        });

        if let Some(ref ns) = options.node_selector {
            pod_spec["spec"]["nodeSelector"] = serde_json::json!(ns);
        }

        if let Some(ref tolerations) = options.tolerations {
            let vals: Vec<serde_json::Value> = tolerations
                .iter()
                .map(|t| {
                    let mut obj = serde_json::Map::new();
                    obj.insert("key".to_string(), serde_json::json!(t.key));
                    obj.insert("effect".to_string(), serde_json::json!(t.effect));
                    if let Some(ref v) = t.value {
                        obj.insert("value".to_string(), serde_json::json!(v));
                    }
                    obj.insert(
                        "operator".to_string(),
                        serde_json::json!(t.operator.as_deref().unwrap_or("Equal")),
                    );
                    serde_json::Value::Object(obj)
                })
                .collect();
            pod_spec["spec"]["tolerations"] = serde_json::json!(vals);
        }

        let pod: Pod = serde_json::from_value(pod_spec).context("serializing pod spec")?;

        block_on(async {
            pods.create(&PostParams::default(), &pod)
                .await
                .context("creating pod")?;
            Ok::<_, anyhow::Error>(())
        })?;

        info!("Created k8s pod '{name}'");
        Ok(())
    }

    /// Wait for a pod to reach the Running phase.
    /// Polls with a short sleep interval. Fails after the timeout.
    pub fn wait_running(&self, name: &str, timeout: std::time::Duration) -> Result<()> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let deadline = std::time::Instant::now() + timeout;

        loop {
            let pod = block_on(pods.get(name)).with_context(|| format!("getting pod '{name}'"))?;

            let phase = pod
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("Unknown");

            match phase {
                "Running" => return Ok(()),
                "Pending" => {
                    // Check for container errors (e.g. ImagePullBackOff)
                    if let Some(ref status) = pod.status {
                        if let Some(ref statuses) = status.container_statuses {
                            for cs in statuses {
                                if let Some(waiting) =
                                    cs.state.as_ref().and_then(|s| s.waiting.as_ref())
                                {
                                    let reason = waiting.reason.as_deref().unwrap_or("Unknown");
                                    if reason.contains("Err") || reason.contains("BackOff") {
                                        let msg = waiting.message.as_deref().unwrap_or("");
                                        return Err(anyhow::anyhow!(
                                            "Pod '{}' failed to start: {} {}",
                                            name,
                                            reason,
                                            msg
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
                "Failed" | "Succeeded" => {
                    return Err(anyhow::anyhow!(
                        "Pod '{}' is in terminal phase '{}'",
                        name,
                        phase
                    ));
                }
                _ => {}
            }

            if std::time::Instant::now() > deadline {
                return Err(anyhow::anyhow!(
                    "Timed out waiting for pod '{}' to reach Running phase (current: {})",
                    name,
                    phase
                ));
            }

            std::thread::sleep(std::time::Duration::from_millis(500));
        }
    }

    /// Delete a pod. Does not wait for termination.
    pub fn delete_pod(&self, name: &str) -> Result<()> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        block_on(async {
            pods.delete(
                name,
                &DeleteParams {
                    grace_period_seconds: Some(0),
                    ..Default::default()
                },
            )
            .await
            .context("deleting pod")?;
            Ok::<_, anyhow::Error>(())
        })?;

        info!("Deleted k8s pod '{name}'");
        Ok(())
    }

    /// Get the status of a pod, mapped to PodStatus.
    pub fn get_pod_status(&self, name: &str) -> Result<PodStatus> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let pod = match block_on(pods.get_opt(name)).context("getting pod status")? {
            Some(pod) => pod,
            None => return Ok(PodStatus::Gone),
        };

        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_deref())
            .unwrap_or("Unknown");

        Ok(match phase {
            "Running" => PodStatus::Running,
            "Pending" => PodStatus::Stopped,
            "Failed" | "Succeeded" => PodStatus::Gone,
            _ => PodStatus::Disconnected,
        })
    }

    /// List pods matching the rumpelpod label selector for a given repo path.
    #[allow(dead_code)]
    pub fn list_pods(
        &self,
        repo_path: &std::path::Path,
    ) -> Result<Vec<(String, PodStatus, String)>> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let hash = repo_path_hash(repo_path);
        let selector = format!(
            "{}={},{}={}",
            LABEL_MANAGED_BY, LABEL_MANAGED_BY_VALUE, LABEL_REPO_HASH, hash,
        );

        let list = block_on(pods.list(&ListParams::default().labels(&selector)))
            .context("listing pods")?;

        let mut results = Vec::new();
        for pod in list.items {
            let labels = pod.metadata.labels.as_ref();
            let annotations = pod.metadata.annotations.as_ref();

            let pod_name = labels
                .and_then(|l| l.get(LABEL_POD_NAME))
                .cloned()
                .unwrap_or_default();

            let created = annotations
                .and_then(|a| a.get(ANNOTATION_CREATED))
                .cloned()
                .unwrap_or_default();

            let phase = pod
                .status
                .as_ref()
                .and_then(|s| s.phase.as_deref())
                .unwrap_or("Unknown");

            let status = match phase {
                "Running" => PodStatus::Running,
                "Pending" => PodStatus::Stopped,
                "Failed" | "Succeeded" => PodStatus::Gone,
                _ => PodStatus::Disconnected,
            };

            results.push((pod_name, status, created));
        }

        Ok(results)
    }

    /// Execute a command in a pod and return stdout as bytes.
    /// Used for non-interactive operations like copying files or detecting arch.
    pub fn exec_output(&self, name: &str, cmd: &[&str]) -> Result<Vec<u8>> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let cmd: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();

        block_on(async {
            let mut attached = pods
                .exec(
                    name,
                    cmd,
                    &AttachParams::default()
                        .stdout(true)
                        .stderr(true)
                        .stdin(false),
                )
                .await
                .context("exec in pod")?;

            let mut stdout_buf = Vec::new();
            if let Some(mut stdout) = attached.stdout() {
                stdout.read_to_end(&mut stdout_buf).await?;
            }

            let status = attached
                .take_status()
                .unwrap()
                .await
                .context("waiting for exec status")?;

            if let Some(reason) = status.reason {
                if reason != "Completed" && reason != "ExitCode" {
                    return Err(anyhow::anyhow!("exec failed: {reason}"));
                }
            }

            Ok(stdout_buf)
        })
    }

    /// Execute a command in a pod, writing stdin and returning stdout.
    /// Used for operations like copying a binary into the pod.
    pub fn exec_with_stdin(&self, name: &str, cmd: &[&str], stdin_data: &[u8]) -> Result<()> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let cmd: Vec<String> = cmd.iter().map(|s| s.to_string()).collect();
        let data = stdin_data.to_vec();

        block_on(async {
            let mut attached = pods
                .exec(
                    name,
                    cmd,
                    &AttachParams::default()
                        .stdout(true)
                        .stderr(true)
                        .stdin(true),
                )
                .await
                .context("exec in pod")?;

            if let Some(mut stdin) = attached.stdin() {
                use tokio::io::AsyncWriteExt;
                stdin.write_all(&data).await?;
                stdin.shutdown().await?;
            }

            let status = attached
                .take_status()
                .unwrap()
                .await
                .context("waiting for exec status")?;

            if let Some(reason) = status.reason {
                if reason != "Completed" && reason != "ExitCode" {
                    return Err(anyhow::anyhow!("exec with stdin failed: {reason}"));
                }
            }

            Ok(())
        })
    }

    /// Start a detached background process in the pod.
    /// Uses nohup + background to detach from the exec session.
    pub fn exec_detached(&self, name: &str, cmd: &str) -> Result<()> {
        let wrapped = format!("nohup {cmd} </dev/null >/dev/null 2>&1 &");
        self.exec_output(name, &["sh", "-c", &wrapped])?;
        Ok(())
    }

    /// Detect the CPU architecture of a running pod.
    pub fn get_pod_arch(&self, name: &str) -> Result<ContainerArch> {
        let output = self.exec_output(name, &["uname", "-m"])?;
        let arch_str = String::from_utf8_lossy(&output);
        ContainerArch::from_uname(&arch_str)
    }

    /// Start a multiplexed TCP tunnel into a pod.
    ///
    /// Runs `rumpel tunnel-server` inside the pod via kubectl exec and
    /// bridges frames to local TCP connections to `target_addr`.
    /// The tunnel exposes the host's git HTTP server on a loopback port
    /// inside the pod.
    pub fn start_tunnel(
        &self,
        k8s_name: &str,
        target_addr: &str,
    ) -> Result<crate::tunnel::TunnelHandle> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        block_on(crate::tunnel::start_tunnel(pods, k8s_name, target_addr))
    }

    /// Set up port forwarding from a local port to a pod port.
    /// Returns the local port that was bound.
    pub fn port_forward(&self, name: &str, remote_port: u16) -> Result<PortForwardHandle> {
        let pods: Api<Pod> = Api::namespaced(self.client.clone(), &self.namespace);
        let name_owned = name.to_string();

        let (local_port, cancel_tx) = block_on(async {
            let mut forwarder = pods
                .portforward(&name_owned, &[remote_port])
                .await
                .context("setting up port forward")?;

            // Grab the stream for the requested port
            let mut port_stream = forwarder
                .take_stream(remote_port)
                .context("taking port forward stream")?;

            // Bind a local TCP listener on an ephemeral port
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .context("binding local port for forwarding")?;
            let local_addr = listener.local_addr()?;
            let local_port = local_addr.port();

            let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);

            // Spawn a task that accepts connections and forwards them.
            // For simplicity, we handle one connection at a time (the
            // container-serve HTTP server uses keep-alive so a single
            // connection is typical).
            let pods_clone = pods.clone();
            tokio::spawn(async move {
                // The Portforwarder must stay alive as long as its stream is
                // in use -- dropping it aborts the underlying WebSocket.
                let mut _active_forwarder = forwarder;
                loop {
                    tokio::select! {
                        accept = listener.accept() => {
                            match accept {
                                Ok((mut tcp_stream, _)) => {
                                    let _ = tokio::io::copy_bidirectional(
                                        &mut tcp_stream,
                                        &mut port_stream,
                                    ).await;
                                    // After the connection closes, get a fresh
                                    // port-forward stream for the next connection.
                                    match pods_clone.portforward(&name_owned, &[remote_port]).await {
                                        Ok(mut pf) => {
                                            match pf.take_stream(remote_port) {
                                                Some(s) => {
                                                    port_stream = s;
                                                    _active_forwarder = pf;
                                                }
                                                None => break,
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        _ = cancel_rx.changed() => {
                            break;
                        }
                    }
                }
            });

            Ok::<_, anyhow::Error>((local_port, cancel_tx))
        })?;

        trace!(
            "Port forward established: 127.0.0.1:{} -> {}:{}",
            local_port,
            name,
            remote_port
        );

        Ok(PortForwardHandle {
            local_port,
            _cancel_tx: cancel_tx,
        })
    }

    /// Build standard labels for a rumpelpod-managed k8s pod.
    pub fn pod_labels(pod_name: &str, repo_path: &std::path::Path) -> BTreeMap<String, String> {
        let mut labels = BTreeMap::new();
        labels.insert(
            LABEL_MANAGED_BY.to_string(),
            LABEL_MANAGED_BY_VALUE.to_string(),
        );
        labels.insert(LABEL_REPO_HASH.to_string(), repo_path_hash(repo_path));
        labels.insert(LABEL_POD_NAME.to_string(), pod_name.to_string());
        labels
    }

    /// Build standard annotations for a rumpelpod-managed k8s pod.
    pub fn pod_annotations() -> BTreeMap<String, String> {
        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_CREATED.to_string(),
            chrono::Utc::now().to_rfc3339(),
        );
        annotations
    }
}

/// Handle for an active port-forward. Dropping this cancels the forward.
pub struct PortForwardHandle {
    pub local_port: u16,
    /// Dropping this sender signals the forwarding task to stop.
    _cancel_tx: tokio::sync::watch::Sender<bool>,
}

/// Convert a devcontainer-style memory string (e.g. "4gb", "512mb") to
/// Kubernetes resource quantity format (e.g. "4Gi", "512Mi").
///
/// Returns None if the string cannot be parsed.
pub fn convert_memory_to_k8s(s: &str) -> Option<String> {
    let s = s.trim().to_lowercase();

    let suffixes: &[(&str, &str)] = &[("tb", "Ti"), ("gb", "Gi"), ("mb", "Mi"), ("kb", "Ki")];

    for (suffix, k8s_suffix) in suffixes {
        if let Some(num_str) = s.strip_suffix(suffix) {
            let num: u64 = num_str.trim().parse().ok()?;
            return Some(format!("{num}{k8s_suffix}"));
        }
    }

    // No suffix -- treat as raw bytes
    let bytes: u64 = s.parse().ok()?;
    Some(format!("{bytes}"))
}

/// Resolve the rumpel binary path for a given container architecture.
/// Mirrors resolve_rumpel_binary in daemon.rs.
pub fn resolve_rumpel_binary(arch: &ContainerArch) -> Result<PathBuf> {
    let current_exe = std::env::current_exe().context("failed to get current executable path")?;
    let exe_dir = current_exe
        .parent()
        .context("executable has no parent directory")?;

    let binary_path = exe_dir.join(arch.binary_name());
    if binary_path.exists() {
        Ok(binary_path)
    } else {
        Err(anyhow::anyhow!(
            "Cross-architecture binary '{}' not found at {}",
            arch.binary_name(),
            exe_dir.display()
        ))
    }
}
