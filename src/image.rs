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

    // For k8s with a buildx builder, build and push via that builder.
    if let Host::Kubernetes {
        ref registry,
        ref push_registry,
        ref builder,
        ..
    } = docker_host
    {
        if let (Some(build), Some(registry), Some(builder)) =
            (&devcontainer.build, registry, builder)
        {
            let push_reg = push_registry.as_deref().unwrap_or(registry);
            return resolve_image_via_buildx(
                build, repo_root, builder, push_reg, registry, on_output,
            );
        }
    }

    let (build_host, push_reg) = match docker_host {
        Host::Kubernetes {
            push_registry: Some(ref reg),
            ..
        } => (&Host::Localhost, Some(reg.as_str())),
        Host::Kubernetes {
            registry: Some(ref reg),
            ..
        } => (&Host::Localhost, Some(reg.as_str())),
        Host::Kubernetes { .. } => (&Host::Localhost, None),
        other => (other, None),
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
            if let Some(push_reg) = push_reg {
                let dest = push_to_registry(&image_name, push_reg)?;
                return Ok(BuildResult {
                    image: Image(dest),
                    built: false,
                });
            }
            return Ok(BuildResult {
                image: Image(image_name),
                built: false,
            });
        }
        let result = build_devcontainer_image(
            build,
            build_host,
            repo_root,
            &BuildFlags::default(),
            on_output,
        )?;
        if let Some(push_reg) = push_reg {
            let dest = push_to_registry(&result.image.0, push_reg)?;
            return Ok(BuildResult {
                image: Image(dest),
                built: result.built,
            });
        }
        Ok(result)
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

/// Build a devcontainer image via a named docker buildx builder and
/// push it to the registry.
///
/// `push_registry` is where images are pushed; `pull_registry` is
/// what pods use to pull (may differ for in-cluster registries).
fn resolve_image_via_buildx(
    build: &BuildOptions,
    repo_root: &Path,
    builder: &str,
    push_registry: &str,
    pull_registry: &str,
    on_output: Option<BuildOutputFn>,
) -> Result<BuildResult> {
    let dockerfile = build
        .dockerfile
        .as_deref()
        .expect("resolved build must have dockerfile");
    let dockerfile_path = repo_root.join(dockerfile);
    let image_name = compute_image_tag(build, &dockerfile_path)?;
    let push_tag = format!("{push_registry}:{image_name}");
    let pull_tag = format!("{pull_registry}:{image_name}");

    // Check if the image already exists locally.
    if image_exists(&image_name, &Host::Localhost) {
        let _ = push_to_registry(&image_name, push_registry);
        return Ok(BuildResult {
            image: Image(pull_tag),
            built: false,
        });
    }

    let context = build
        .context
        .as_deref()
        .expect("resolved build must have context");
    let context_path = repo_root.join(context);

    let mut cmd = Command::new("docker");
    cmd.args(["buildx", "build"]);
    cmd.args(["--builder", builder]);
    cmd.args(["--push"]);
    cmd.args(["--provenance=false", "--sbom=false"]);
    cmd.args(["-t", &push_tag]);

    let dockerfile_display = dockerfile_path.display();
    cmd.arg(format!("-f={dockerfile_display}"));

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
            "buildx build failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
        ));
    }

    Ok(BuildResult {
        image: Image(pull_tag),
        built: true,
    })
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

/// Tag a locally-built image for a remote registry and push it.
///
/// Returns the full registry reference (`{registry}:{local_tag}`) that
/// pods will use to pull the image.
pub(crate) fn push_to_registry(local_tag: &str, registry: &str) -> Result<String> {
    let dest = format!("{registry}:{local_tag}");

    let status = Command::new("docker")
        .args(["tag", local_tag, &dest])
        .status()
        .context("tagging image for registry")?;
    if !status.success() {
        return Err(anyhow::anyhow!("docker tag failed with status {status}"));
    }

    let status = Command::new("docker")
        .args(["push", &dest])
        .status()
        .context("pushing image to registry")?;
    if !status.success() {
        return Err(anyhow::anyhow!("docker push failed with status {status}"));
    }

    Ok(dest)
}

/// Check whether a Docker image already exists on the target host.
pub(crate) fn image_exists(image_name: &str, docker_host: &Host) -> bool {
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
