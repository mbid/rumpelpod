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

use crate::k8s::K8sClient;

/// Handle for a buildx builder backed by an in-cluster buildkitd.
///
/// Creates a `docker buildx` builder using the "remote" driver,
/// connecting through a kube port-forward to the buildkitd pod.
/// Dropping this handle removes the buildx builder and the
/// port-forward.
pub struct RemoteBuilder {
    name: String,
    _port_forward: crate::k8s::PortForwardHandle,
}

/// Default buildkitd port inside the builder pod.
const BUILDKITD_PORT: u16 = 1234;

impl RemoteBuilder {
    /// Connect to a buildkitd pod and set up a docker buildx builder.
    pub fn connect(k8s_context: &str, builder_namespace: &str, builder_pod: &str) -> Result<Self> {
        let client = K8sClient::new(k8s_context, builder_namespace)?;

        let pf = client
            .port_forward(builder_pod, BUILDKITD_PORT)
            .context("port-forwarding to buildkitd")?;
        let local_port = pf.local_port;
        let addr = format!("tcp://127.0.0.1:{local_port}");

        let name = format!("rumpelpod-k8s-{local_port}");

        // Remove any stale builder with this name (ignore errors).
        let _ = Command::new("docker")
            .args(["buildx", "rm", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        let status = Command::new("docker")
            .args([
                "buildx", "create", "--name", &name, "--driver", "remote", &addr,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("creating buildx remote builder")?;
        if !status.success() {
            return Err(anyhow::anyhow!(
                "docker buildx create --driver remote failed (exit {status})"
            ));
        }

        info!("Connected to in-cluster buildkitd via port {local_port}");

        Ok(Self {
            name,
            _port_forward: pf,
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

impl Drop for RemoteBuilder {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["buildx", "rm", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}
