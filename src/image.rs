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

use crate::config::{ImageRecipe, RemoteDocker};
use crate::daemon::protocol::Image;

/// Resolve a Docker image, building from devcontainer.json 'build' if necessary.
///
/// If an image recipe is specified, this will:
/// 1. Hash the Dockerfile and build configuration to create a deterministic image tag
/// 2. Build the Docker image using the specified build settings
/// 3. Return the built image name
///
/// Otherwise, returns the pre-configured image name.
pub fn resolve_image(
    image: &str,
    recipe: Option<&ImageRecipe>,
    remote_host: Option<&str>,
    repo_root: &Path,
) -> Result<Image> {
    if let Some(recipe) = recipe {
        build_devcontainer_image(recipe, remote_host, repo_root)
    } else {
        Ok(Image(image.to_string()))
    }
}

/// Build a Docker image from devcontainer.json build configuration.
fn build_devcontainer_image(
    recipe: &ImageRecipe,
    remote_host: Option<&str>,
    repo_root: &Path,
) -> Result<Image> {
    let dockerfile_path = repo_root.join(&recipe.dockerfile);
    if !dockerfile_path.exists() {
        bail!(
            "Devcontainer Dockerfile '{}' not found",
            dockerfile_path.display()
        );
    }

    let context_path = repo_root.join(&recipe.context);

    // Compute a deterministic hash of the build configuration
    let image_name = compute_image_tag(recipe, &dockerfile_path)?;

    // Build the Docker image
    let mut cmd = Command::new("docker");

    if let Some(remote_str) = remote_host {
        let remote = RemoteDocker::parse(remote_str)?;
        let remote_uri = format!("ssh://{}:{}", remote.destination, remote.port);
        cmd.args(["-H", &remote_uri]);
    }

    cmd.arg("build").arg("--rm");
    cmd.arg(format!("-t={}", image_name));
    cmd.arg(format!("-f={}", dockerfile_path.display()));

    if let Some(args) = &recipe.args {
        for (k, v) in args {
            cmd.arg("--build-arg").arg(format!("{}={}", k, v));
        }
    }

    if let Some(target) = &recipe.target {
        cmd.arg("--target").arg(target);
    }

    if let Some(cache_from) = &recipe.cache_from {
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

    if let Some(options) = &recipe.options {
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

/// Compute a deterministic image tag based on the build configuration.
///
/// The tag is created by hashing:
/// - The Dockerfile content
/// - The build context path
/// - All build arguments (sorted by key)
/// - The target stage (if specified)
/// - Additional build options
/// - Cache-from specifications
fn compute_image_tag(recipe: &ImageRecipe, dockerfile_path: &Path) -> Result<String> {
    let mut f = File::open(dockerfile_path)?;
    let mut content = Vec::new();
    f.read_to_end(&mut content)?;

    let mut hasher = Sha256::new();
    hasher.update(&content);
    hasher.update(recipe.context.as_bytes());

    if let Some(args) = &recipe.args {
        let mut keys: Vec<&String> = args.keys().collect();
        keys.sort();
        for k in keys {
            hasher.update(k.as_bytes());
            hasher.update(args[k].as_bytes());
        }
    }

    if let Some(target) = &recipe.target {
        hasher.update(target.as_bytes());
    }

    if let Some(options) = &recipe.options {
        for opt in options {
            hasher.update(opt.as_bytes());
        }
    }

    if let Some(cache_from) = &recipe.cache_from {
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
