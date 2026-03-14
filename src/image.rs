//! Docker image resolution and building.
//!
//! This module handles resolving Docker images for pods, including building
//! images from devcontainer.json specifications when needed.

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::Host;
use crate::devcontainer::{BuildOptions, DevContainer};

/// A line of Docker build output, tagged with the stream it came from.
pub enum OutputLine {
    Stdout(String),
    Stderr(String),
}

/// Callback invoked with each line of Docker build output.
pub type BuildOutputFn = Box<dyn FnMut(OutputLine) + Send>;

// Re-export so callers can use image::Image
pub use crate::daemon::protocol::Image;

/// Result of a build attempt, indicating whether a build actually ran.
pub struct BuildResult {
    pub image: Image,
    pub built: bool,
}

/// Optional flags that control Docker build behavior.
#[derive(Default)]
pub struct BuildFlags {
    /// Pass `--no-cache` to disable Docker layer caching.
    pub no_cache: bool,
    /// Pass `--pull` to pull the base image before building.
    pub pull: bool,
}

/// Resolve a Docker image, building from devcontainer.json 'build' if necessary.
///
/// The DevContainer's build paths must already be resolved to repo-root-relative
/// paths (via `resolve_build_paths`) before calling this.
pub fn resolve_image(
    devcontainer: &DevContainer,
    docker_host: &Host,
    repo_root: &Path,
    on_output: Option<BuildOutputFn>,
) -> Result<BuildResult> {
    if let Host::Kubernetes { registry, .. } = docker_host {
        if devcontainer.has_build() && registry.is_none() {
            return Err(anyhow::anyhow!(
                "Building images for Kubernetes requires a registry.\n\
                 Set 'registry' in the [k8s] section of .rumpelpod.toml, \
                 or use --k8s-registry."
            ));
        }
    }

    // For k8s with a build section, use buildx with the kubernetes driver
    // to build in-cluster and push directly to the registry.
    if let Host::Kubernetes {
        context,
        registry: Some(ref push_reg),
        ref pull_registry,
        ..
    } = docker_host
    {
        if let Some(build) = &devcontainer.build {
            let pull_reg = pull_registry.as_deref().unwrap_or(push_reg);
            return buildx_build(
                build,
                context,
                pull_reg,
                repo_root,
                &BuildFlags::default(),
                on_output,
            );
        }
    }

    let build_host = match docker_host {
        Host::Kubernetes { .. } => &Host::Localhost,
        other => other,
    };

    if let Some(build) = &devcontainer.build {
        // Skip the build if the image already exists on the target host, avoiding
        // the overhead of sending build context (potentially the whole repo) over
        // the network to a remote Docker daemon.
        let image_name = compute_image_tag(
            build,
            &repo_root.join(
                build
                    .dockerfile
                    .as_deref()
                    .expect("resolved build must have dockerfile"),
            ),
        )?;
        if image_exists(&image_name, build_host) {
            return Ok(BuildResult {
                image: Image(image_name),
                built: false,
            });
        }
        build_devcontainer_image(
            build,
            build_host,
            repo_root,
            &BuildFlags::default(),
            on_output,
        )
    } else {
        Ok(BuildResult {
            image: Image(
                devcontainer
                    .image
                    .clone()
                    .expect("either image or build must be set"),
            ),
            built: false,
        })
    }
}

/// Build a Docker image from devcontainer.json build configuration.
pub fn build_devcontainer_image(
    build: &BuildOptions,
    docker_host: &Host,
    repo_root: &Path,
    flags: &BuildFlags,
    on_output: Option<BuildOutputFn>,
) -> Result<BuildResult> {
    let dockerfile = build
        .dockerfile
        .as_deref()
        .expect("resolved build must have dockerfile");
    let context = build
        .context
        .as_deref()
        .expect("resolved build must have context");

    let dockerfile_path = repo_root.join(dockerfile);
    if !dockerfile_path.exists() {
        let path = dockerfile_path.display();
        return Err(anyhow::anyhow!(
            "Devcontainer Dockerfile '{path}' not found"
        ));
    }

    let context_path = repo_root.join(context);

    // Compute a deterministic hash of the build configuration
    let image_name = compute_image_tag(build, &dockerfile_path)?;

    // Build the Docker image
    let mut cmd = Command::new("docker");

    if let Some(uri) = docker_host.docker_host_uri() {
        cmd.args(["-H", &uri]);
    }

    cmd.arg("build").arg("--rm");
    if flags.no_cache {
        cmd.arg("--no-cache");
    }
    if flags.pull {
        cmd.arg("--pull");
    }
    cmd.arg(format!("-t={image_name}"));
    let dockerfile = dockerfile_path.display();
    cmd.arg(format!("-f={dockerfile}"));

    if let Some(args) = &build.args {
        for (k, v) in args {
            cmd.arg("--build-arg").arg(format!("{k}={v}"));
        }
    }

    if let Some(target) = &build.target {
        cmd.arg("--target").arg(target);
    }

    if let Some(cache_from) = &build.cache_from {
        match cache_from {
            crate::devcontainer::StringOrArray::String(s) => {
                cmd.arg("--cache-from").arg(s);
            }
            crate::devcontainer::StringOrArray::Array(arr) => {
                for s in arr {
                    cmd.arg("--cache-from").arg(s);
                }
            }
        }
    }

    if let Some(options) = &build.options {
        cmd.args(options);
    }

    cmd.arg(context_path.display().to_string());

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    let child_stdout = child.stdout.take().expect("stdout was piped");
    let child_stderr = child.stderr.take().expect("stderr was piped");

    // Shared callback protected by a mutex so both reader threads can call it
    let callback = on_output.map(|cb| std::sync::Arc::new(std::sync::Mutex::new(cb)));
    let callback_for_stderr = callback.clone();

    // Collect all output for the error message if the build fails
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
                cb.lock().unwrap()(OutputLine::Stdout(line));
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
                cb.lock().unwrap()(OutputLine::Stderr(line));
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
            "Docker build failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
        ));
    }

    Ok(BuildResult {
        image: Image(image_name),
        built: true,
    })
}

/// Pull a Docker image from its registry.
///
/// Inherits stdout/stderr so the user sees download progress.
pub fn pull_image(image_name: &str, docker_host: &Host) -> Result<()> {
    let mut cmd = Command::new("docker");
    if let Some(uri) = docker_host.docker_host_uri() {
        cmd.args(["-H", &uri]);
    }
    cmd.args(["pull", image_name]);

    let status = cmd.status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("docker pull failed with status {status}"));
    }
    Ok(())
}

/// Deterministic builder name for a k8s context.
fn buildx_builder_name(context: &str) -> String {
    format!("rumpelpod-{context}")
}

/// Extract "host:port" from a registry string like "host:port/repo/path".
fn registry_host(registry: &str) -> &str {
    match registry.find('/') {
        Some(pos) => &registry[..pos],
        None => registry,
    }
}

/// Create or reuse a docker buildx builder backed by the kubernetes driver.
///
/// The builder pod lives in the `default` namespace so it persists across
/// builds regardless of which namespace the workload pods use.
///
/// TODO: This stores builder config in ~/.docker/buildx/. Consider using
/// BUILDX_CONFIG or --config to avoid polluting the user's Docker config.
fn ensure_buildx_builder(context: &str, registry: &str) -> Result<String> {
    let name = buildx_builder_name(context);

    // Check if builder already exists.
    let status = Command::new("docker")
        .args(["buildx", "inspect", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("running docker buildx inspect")?;

    if status.success() {
        return Ok(name);
    }

    // Write a buildkitd config that allows pushing to the registry over
    // plain HTTP.  In-cluster registries typically lack TLS.
    let host = registry_host(registry);
    let config_content = format!("[registry.\"{host}\"]\n  http = true\n  insecure = true\n");
    let config_dir = std::env::temp_dir().join("rumpelpod-buildx");
    std::fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join(format!("{name}.toml"));
    std::fs::write(&config_path, &config_content)?;
    let config_path = config_path.display().to_string();

    // Rootless buildkitd does not auto-discover /etc/buildkit/buildkitd.toml
    // because rootlesskit remounts the filesystem.  Pass --config explicitly.
    let output = Command::new("docker")
        .args([
            "buildx",
            "create",
            "--driver",
            "kubernetes",
            "--driver-opt",
            "namespace=default,rootless=true",
            "--name",
            &name,
            "--buildkitd-config",
            &config_path,
            "--buildkitd-flags",
            "--config /etc/buildkit/buildkitd.toml",
        ])
        .output()
        .context("running docker buildx create")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow::anyhow!("docker buildx create failed: {stderr}"));
    }

    Ok(name)
}

/// Build a Docker image using buildx with the kubernetes driver, pushing
/// directly to an in-cluster registry.
///
/// The buildkitd pod runs inside the cluster, so `registry` must be the
/// in-cluster address (the same address pods use to pull).
pub fn buildx_build(
    build: &BuildOptions,
    k8s_context: &str,
    registry: &str,
    repo_root: &Path,
    flags: &BuildFlags,
    on_output: Option<BuildOutputFn>,
) -> Result<BuildResult> {
    let dockerfile = build
        .dockerfile
        .as_deref()
        .expect("resolved build must have dockerfile");
    let build_context = build
        .context
        .as_deref()
        .expect("resolved build must have context");

    let dockerfile_path = repo_root.join(dockerfile);
    if !dockerfile_path.exists() {
        let path = dockerfile_path.display();
        return Err(anyhow::anyhow!(
            "Devcontainer Dockerfile '{path}' not found"
        ));
    }

    let context_path = repo_root.join(build_context);
    let image_tag = compute_image_tag(build, &dockerfile_path)?;

    // Buildx pushes from inside the cluster, so use the in-cluster
    // registry address as the push destination.
    let dest = format!("{registry}:{image_tag}");

    let builder = ensure_buildx_builder(k8s_context, registry)?;

    let mut cmd = Command::new("docker");
    cmd.args(["buildx", "build"]);
    cmd.args(["--builder", &builder]);
    cmd.arg(format!("--output=type=image,name={dest},push=true"));
    let dockerfile = dockerfile_path.display();
    cmd.arg(format!("-f={dockerfile}"));

    if flags.no_cache {
        cmd.arg("--no-cache");
    }
    if flags.pull {
        cmd.arg("--pull");
    }

    if let Some(args) = &build.args {
        for (k, v) in args {
            cmd.arg("--build-arg").arg(format!("{k}={v}"));
        }
    }

    if let Some(target) = &build.target {
        cmd.arg("--target").arg(target);
    }

    if let Some(cache_from) = &build.cache_from {
        match cache_from {
            crate::devcontainer::StringOrArray::String(s) => {
                cmd.arg("--cache-from").arg(s);
            }
            crate::devcontainer::StringOrArray::Array(arr) => {
                for s in arr {
                    cmd.arg("--cache-from").arg(s);
                }
            }
        }
    }

    if let Some(options) = &build.options {
        cmd.args(options);
    }

    cmd.arg(context_path.display().to_string());

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn()?;

    let child_stdout = child.stdout.take().expect("stdout was piped");
    let child_stderr = child.stderr.take().expect("stderr was piped");

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
                cb.lock().unwrap()(OutputLine::Stdout(line));
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
                cb.lock().unwrap()(OutputLine::Stderr(line));
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
            "docker buildx build failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
        ));
    }

    // The image was pushed by buildx; pods pull from the same registry.
    Ok(BuildResult {
        image: Image(dest),
        built: true,
    })
}

/// Check whether a Docker image already exists on the target host.
fn image_exists(image_name: &str, docker_host: &Host) -> bool {
    let mut cmd = Command::new("docker");
    if let Some(uri) = docker_host.docker_host_uri() {
        cmd.args(["-H", &uri]);
    }
    cmd.args(["image", "inspect", image_name]);
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    cmd.status().is_ok_and(|s| s.success())
}

/// Compute a deterministic image tag based on the build configuration.
fn compute_image_tag(build: &BuildOptions, dockerfile_path: &Path) -> Result<String> {
    let mut f = File::open(dockerfile_path)?;
    let mut content = Vec::new();
    f.read_to_end(&mut content)?;

    let context = build
        .context
        .as_deref()
        .expect("resolved build must have context");

    let mut hasher = Sha256::new();
    hasher.update(&content);
    hasher.update(context.as_bytes());

    if let Some(args) = &build.args {
        let mut keys: Vec<&String> = args.keys().collect();
        keys.sort();
        for k in keys {
            hasher.update(k.as_bytes());
            hasher.update(args[k].as_bytes());
        }
    }

    if let Some(target) = &build.target {
        hasher.update(target.as_bytes());
    }

    if let Some(options) = &build.options {
        for opt in options {
            hasher.update(opt.as_bytes());
        }
    }

    if let Some(cache_from) = &build.cache_from {
        match cache_from {
            crate::devcontainer::StringOrArray::String(s) => hasher.update(s.as_bytes()),
            crate::devcontainer::StringOrArray::Array(arr) => {
                for s in arr {
                    hasher.update(s.as_bytes());
                }
            }
        }
    }

    let hash = hex::encode(&hasher.finalize()[..8]);
    Ok(format!("rumpelpod-devcontainer-{hash}"))
}
