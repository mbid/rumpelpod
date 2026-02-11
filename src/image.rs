//! Docker image resolution and building.
//!
//! This module handles resolving Docker images for sandboxes, including building
//! images from devcontainer.json specifications when needed.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use crate::config::DockerHost;
use crate::devcontainer::{BuildOptions, DevContainer};

// Re-export so callers can use image::Image
pub use crate::daemon::protocol::Image;

/// Resolve a Docker image, building from devcontainer.json 'build' if necessary.
///
/// The DevContainer's build paths must already be resolved to repo-root-relative
/// paths (via `resolve_build_paths`) before calling this.
pub fn resolve_image(
    devcontainer: &DevContainer,
    docker_host: &DockerHost,
    repo_root: &Path,
) -> Result<Image> {
    if let Some(build) = &devcontainer.build {
        build_devcontainer_image(build, docker_host, repo_root)
    } else {
        Ok(Image(
            devcontainer
                .image
                .clone()
                .expect("either image or build must be set"),
        ))
    }
}

/// Build a Docker image from devcontainer.json build configuration.
fn build_devcontainer_image(
    build: &BuildOptions,
    docker_host: &DockerHost,
    repo_root: &Path,
) -> Result<Image> {
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
        bail!(
            "Devcontainer Dockerfile '{}' not found",
            dockerfile_path.display()
        );
    }

    let context_path = repo_root.join(context);

    // Compute a deterministic hash of the build configuration
    let image_name = compute_image_tag(build, &dockerfile_path)?;

    // Skip the build if the image already exists on the target host, avoiding
    // the overhead of sending build context (potentially the whole repo) over
    // the network to a remote Docker daemon.
    if image_exists(&image_name, docker_host) {
        return Ok(Image(image_name));
    }

    // Build the Docker image
    let mut cmd = Command::new("docker");

    if let Some(uri) = docker_host.docker_host_uri() {
        cmd.args(["-H", &uri]);
    }

    cmd.arg("build").arg("--rm");
    cmd.arg(format!("-t={}", image_name));
    cmd.arg(format!("-f={}", dockerfile_path.display()));

    if let Some(args) = &build.args {
        for (k, v) in args {
            cmd.arg("--build-arg").arg(format!("{}={}", k, v));
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

    let output = cmd.output()?;

    if !output.status.success() {
        bail!(
            "Docker build failed:\nSTDOUT: {}\nSTDERR: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(Image(image_name))
}

/// Check whether a Docker image already exists on the target host.
fn image_exists(image_name: &str, docker_host: &DockerHost) -> bool {
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
    Ok(format!("sandbox-devcontainer-{}", hash))
}
