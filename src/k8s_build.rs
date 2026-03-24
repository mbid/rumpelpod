//! Remote image building via an in-cluster buildkitd.
//!
//! When a Kubernetes host has `builder_pod` configured, image builds are
//! sent to the in-cluster buildkitd instance via `docker buildx` (remote
//! driver) instead of building locally.  The builder pushes directly to
//! the in-cluster registry so images are available to all cluster nodes.

use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use log::info;

/// Handle for a buildx builder backed by an in-cluster buildkitd.
///
/// Sets up `kubectl port-forward` to the buildkitd pod and creates a
/// `docker buildx` builder using the "remote" driver pointed at the
/// forwarded port.  Dropping this kills the port-forward and removes
/// the buildx builder.
pub struct RemoteBuilder {
    name: String,
    _port_forward: std::process::Child,
}

/// Default buildkitd port inside the builder pod.
const BUILDKITD_PORT: u16 = 1234;

impl RemoteBuilder {
    /// Connect to a buildkitd pod and set up a docker buildx builder.
    pub fn connect(k8s_context: &str, builder_namespace: &str, builder_pod: &str) -> Result<Self> {
        // Bind to an ephemeral port for the port-forward.
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .context("binding ephemeral port for buildkit port-forward")?;
        let local_port = listener.local_addr()?.port();
        drop(listener);

        let mut pf_child = Command::new("kubectl")
            .args(["--context", k8s_context])
            .args(["-n", builder_namespace])
            .args([
                "port-forward",
                builder_pod,
                &format!("{local_port}:{BUILDKITD_PORT}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("starting kubectl port-forward to buildkitd")?;

        info!("Waiting for kubectl port-forward on 127.0.0.1:{local_port}...");

        // Wait for the port-forward to accept connections.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if std::net::TcpStream::connect(format!("127.0.0.1:{local_port}")).is_ok() {
                break;
            }
            if std::time::Instant::now() > deadline {
                // Check if kubectl is still alive
                let status = pf_child.try_wait().context("checking kubectl status")?;
                let detail = match status {
                    Some(exit) => {
                        let mut stderr_str = String::new();
                        if let Some(mut stderr) = pf_child.stderr.take() {
                            use std::io::Read;
                            let _ = stderr.read_to_string(&mut stderr_str);
                        }
                        format!("kubectl exited with {exit}: {stderr_str}")
                    }
                    None => "kubectl still running but port not accepting connections".to_string(),
                };
                return Err(anyhow::anyhow!(
                    "kubectl port-forward to buildkitd did not become ready: {detail}"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        info!("Port-forward ready on 127.0.0.1:{local_port}");

        let addr = format!("tcp://127.0.0.1:{local_port}");
        let name = format!("rumpelpod-k8s-{local_port}");

        // Remove any stale builder with this name (ignore errors).
        let _ = Command::new("docker")
            .args(["buildx", "rm", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let output = Command::new("docker")
            .args([
                "buildx", "create", "--name", &name, "--driver", "remote", &addr,
            ])
            .output()
            .context("creating buildx remote builder")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!(
                "docker buildx create --driver remote failed: {stderr}"
            ));
        }

        info!("Connected to in-cluster buildkitd via port {local_port}");

        Ok(Self {
            name,
            _port_forward: pf_child,
        })
    }

    /// Build an image from a context directory and push it to the registry.
    ///
    /// `registry_tag` is the full image reference including registry,
    /// e.g. "10.43.0.100:5000/rumpelpod:rumpelpod-prepared-abc123".
    pub fn build_and_push(
        &self,
        context_dir: &Path,
        dockerfile_path: &Path,
        registry_tag: &str,
        build_args: &[(&str, &str)],
        on_output: Option<crate::image::BuildOutputFn>,
    ) -> Result<()> {
        let mut cmd = Command::new("docker");
        cmd.args(["buildx", "build"]);
        cmd.args(["--builder", &self.name]);
        cmd.args(["--push"]);
        // Disable attestation manifests -- they produce manifest lists
        // that confuse some containerd versions when pulling.
        cmd.args(["--provenance=false", "--sbom=false"]);
        cmd.args(["-t", registry_tag]);

        let dockerfile_path = dockerfile_path.display();
        cmd.arg(format!("-f={dockerfile_path}"));

        for (k, v) in build_args {
            cmd.arg("--build-arg").arg(format!("{k}={v}"));
        }

        cmd.arg(context_dir.display().to_string());

        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.spawn().context("starting docker buildx build")?;

        let child_stdout = child.stdout.take().expect("stdout was piped");
        let child_stderr = child.stderr.take().expect("stderr was piped");

        use std::io::{BufRead, BufReader};
        let callback = on_output.map(|cb| std::sync::Arc::new(std::sync::Mutex::new(cb)));
        let callback_for_stderr = callback.clone();

        let stdout_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let stdout_buf_clone = stdout_buf.clone();
        let stderr_buf_clone = stderr_buf.clone();

        let stdout_thread = std::thread::spawn(move || {
            for line in BufReader::new(child_stdout).lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                stdout_buf_clone.lock().unwrap().push_str(&line);
                stdout_buf_clone.lock().unwrap().push('\n');
                if let Some(ref cb) = callback {
                    cb.lock().unwrap()(crate::image::OutputLine::Stdout(line));
                }
            }
        });

        let stderr_thread = std::thread::spawn(move || {
            for line in BufReader::new(child_stderr).lines() {
                let line = match line {
                    Ok(l) => l,
                    Err(_) => break,
                };
                stderr_buf_clone.lock().unwrap().push_str(&line);
                stderr_buf_clone.lock().unwrap().push('\n');
                if let Some(ref cb) = callback_for_stderr {
                    cb.lock().unwrap()(crate::image::OutputLine::Stderr(line));
                }
            }
        });

        let status = child.wait()?;
        stdout_thread.join().expect("stdout reader panicked");
        stderr_thread.join().expect("stderr reader panicked");

        if !status.success() {
            let stdout = stdout_buf.lock().unwrap();
            let stderr = stderr_buf.lock().unwrap();
            return Err(anyhow::anyhow!(
                "Remote build failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
            ));
        }

        Ok(())
    }

    /// Build an image with a named build context (e.g. for gateway bind-mount
    /// replacement) and push it to the registry.
    pub fn build_with_named_context_and_push(
        &self,
        context_dir: &Path,
        dockerfile_path: &Path,
        registry_tag: &str,
        build_args: &[(&str, &str)],
        named_contexts: &[(&str, &Path)],
    ) -> Result<()> {
        let mut cmd = Command::new("docker");
        cmd.args(["buildx", "build"]);
        cmd.args(["--builder", &self.name]);
        cmd.args(["--push"]);
        cmd.args(["--provenance=false", "--sbom=false"]);
        cmd.args(["-t", registry_tag]);

        let dockerfile_path = dockerfile_path.display();
        cmd.arg(format!("-f={dockerfile_path}"));

        for (k, v) in build_args {
            cmd.arg("--build-arg").arg(format!("{k}={v}"));
        }

        for (name, path) in named_contexts {
            let path = path.display();
            cmd.arg(format!("--build-context={name}={path}"));
        }

        cmd.arg(context_dir.display().to_string());

        use crate::CommandExt;
        cmd.success().context("remote build with named context")?;

        Ok(())
    }
}

/// Check whether an image tag already exists in the cluster registry.
///
/// Sends a lightweight HTTP request from inside the cluster to the
/// registry v2 manifest endpoint.  Returns false on any error so
/// callers fall through to building.
///
/// Uses the registry pod directly (namespace "registry") because the
/// buildkitd container's privileged cgroup setup prevents kubectl exec.
pub fn registry_tag_exists(k8s_context: &str, registry_tag: &str) -> bool {
    // Parse "host:port/repo:tag".  The tag is always after the last
    // colon that follows a slash (distinguishing it from the port).
    let (image_ref, tag) = match registry_tag.rsplit_once(':') {
        Some((r, t)) if r.contains('/') => (r, t),
        _ => return false,
    };
    let (_host_port, repo) = match image_ref.split_once('/') {
        Some(pair) => pair,
        None => return false,
    };

    // Find a registry pod to exec into.  This avoids the cgroup issue
    // with the privileged buildkitd container.
    let pod_output = Command::new("kubectl")
        .args(["--context", k8s_context, "-n", "registry"])
        .args([
            "get",
            "pod",
            "-l",
            "app=registry",
            "-o",
            "jsonpath={.items[0].metadata.name}",
        ])
        .output();
    let registry_pod = match pod_output {
        Ok(ref o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return false,
    };
    if registry_pod.is_empty() {
        return false;
    }

    // The registry API requires the correct Accept header for OCI
    // image indices (buildx pushes these even with --provenance=false).
    let url = format!("http://localhost:5000/v2/{repo}/manifests/{tag}");
    let accept = "Accept: application/vnd.oci.image.index.v1+json, \
                  application/vnd.docker.distribution.manifest.v2+json, \
                  application/vnd.docker.distribution.manifest.list.v2+json";

    Command::new("kubectl")
        .args(["--context", k8s_context, "-n", "registry"])
        .args(["exec", &registry_pod, "--"])
        .args(["wget", "-q", "-O", "/dev/null", "--header", accept, &url])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

impl Drop for RemoteBuilder {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["buildx", "rm", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self._port_forward.kill();
        let _ = self._port_forward.wait();
    }
}
