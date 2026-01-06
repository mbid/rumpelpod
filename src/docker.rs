use anyhow::{bail, Context, Result};
use log::{debug, info};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::{Command, Stdio};

use crate::config::{hash_file, UserInfo};

/// Check if a Docker image with the given tag exists.
pub fn image_exists(tag: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["image", "inspect", tag])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker image inspect")?;

    Ok(output.success())
}

/// Build a Docker image from a Dockerfile.
/// The image is tagged with a hash of the Dockerfile contents.
/// Returns the image tag.
pub fn build_image(dockerfile_path: &Path, context: &Path, user_info: &UserInfo) -> Result<String> {
    let dockerfile_hash = hash_file(dockerfile_path)?;
    let image_tag = format!("sandbox:{}", dockerfile_hash);

    // Check if image already exists
    if image_exists(&image_tag)? {
        debug!("Using existing image: {}", image_tag);
        return Ok(image_tag);
    }

    info!("Building Docker image: {}", image_tag);

    let status = Command::new("docker")
        .args([
            "build",
            "-f",
            &dockerfile_path.to_string_lossy(),
            "-t",
            &image_tag,
            "--build-arg",
            &format!("USER_NAME={}", user_info.username),
            "--build-arg",
            &format!("USER_ID={}", user_info.uid),
            "--build-arg",
            &format!("GROUP_ID={}", user_info.gid),
            &context.to_string_lossy(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker build")?;

    if !status.success() {
        bail!("Docker build failed");
    }

    Ok(image_tag)
}

/// Check if a container with the given name exists and is running.
pub fn container_is_running(name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["container", "inspect", "-f", "{{.State.Running}}", name])
        .output()
        .context("Failed to run docker container inspect")?;

    if !output.status.success() {
        return Ok(false);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.trim() == "true")
}

/// Check if a container with the given name exists (running or stopped).
pub fn container_exists(name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["container", "inspect", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker container inspect")?;

    Ok(output.success())
}

/// Remove a container by name.
pub fn remove_container(name: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["rm", "-f", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker rm")?;

    if !status.success() {
        bail!("Failed to remove container: {}", name);
    }

    Ok(())
}

/// List all Docker volumes with a specific prefix.
pub fn list_volumes_with_prefix(prefix: &str) -> Result<Vec<String>> {
    let output = Command::new("docker")
        .args([
            "volume",
            "ls",
            "-q",
            "--filter",
            &format!("name={}", prefix),
        ])
        .output()
        .context("Failed to list Docker volumes")?;

    if !output.status.success() {
        bail!("Failed to list Docker volumes");
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.lines().map(String::from).collect())
}

/// Remove a Docker volume.
pub fn remove_volume(name: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["volume", "rm", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker volume rm")?;

    if !status.success() {
        bail!("Failed to remove volume: {}", name);
    }

    Ok(())
}

/// Attach to a running container and execute a command.
pub fn exec_in_container(
    name: &str,
    command: &[&str],
    env_vars: &[(String, String)],
) -> Result<()> {
    use std::io::IsTerminal;

    let mut args = vec!["exec".to_string()];

    // Only use -it flags when stdin is a TTY
    if std::io::stdin().is_terminal() {
        args.push("-it".to_string());
    }

    for (k, v) in env_vars {
        args.push("-e".to_string());
        args.push(format!("{}={}", k, v));
    }

    args.push(name.to_string());
    args.extend(command.iter().map(|s| s.to_string()));

    let status = Command::new("docker")
        .args(&args)
        .status()
        .context("Failed to exec in container")?;

    if !status.success() {
        bail!("Container exec failed");
    }

    Ok(())
}

/// Stop a running container. Silently succeeds if container is already stopped.
pub fn stop_container(name: &str) -> Result<()> {
    // Use -t 0 to skip the graceful shutdown period. Our containers run
    // `sleep infinity` which ignores SIGTERM anyway, so waiting is pointless.
    let status = Command::new("docker")
        .args(["stop", "-t", "0", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker stop")?;

    // We don't check status.success() because stopping an already-stopped
    // container is fine - we just want it stopped.
    let _ = status;
    Ok(())
}

/// Start a stopped container.
pub fn start_container(name: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["start", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker start")?;

    if !status.success() {
        bail!("Failed to start container: {}", name);
    }

    Ok(())
}

/// Wait for a container to stop.
pub fn wait_container(name: &str) -> Result<()> {
    let status = Command::new("docker")
        .args(["wait", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker wait")?;

    if !status.success() {
        anyhow::bail!("docker wait failed for container '{}'", name);
    }
    Ok(())
}

/// Check if a Docker network exists.
pub fn network_exists(name: &str) -> Result<bool> {
    let output = Command::new("docker")
        .args(["network", "inspect", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker network inspect")?;

    Ok(output.success())
}

/// Create a Docker network if it doesn't exist. Returns the gateway IP address.
pub fn ensure_network(name: &str) -> Result<std::net::IpAddr> {
    if !network_exists(name)? {
        info!("Creating Docker network: {}", name);
        let status = Command::new("docker")
            .args(["network", "create", name])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .status()
            .context("Failed to run docker network create")?;

        if !status.success() {
            bail!("Failed to create Docker network: {}", name);
        }
    }

    // Get the gateway IP for the network
    let output = Command::new("docker")
        .args([
            "network",
            "inspect",
            name,
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ])
        .output()
        .context("Failed to get network gateway IP")?;

    if !output.status.success() {
        bail!("Failed to inspect Docker network: {}", name);
    }

    let gateway_ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
    gateway_ip
        .parse()
        .with_context(|| format!("Invalid gateway IP from network {}: {}", name, gateway_ip))
}

/// Remove a Docker network.
pub fn remove_network(name: &str) -> Result<()> {
    if !network_exists(name)? {
        return Ok(());
    }

    debug!("Removing Docker network: {}", name);
    let status = Command::new("docker")
        .args(["network", "rm", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("Failed to run docker network rm")?;

    if !status.success() {
        bail!("Failed to remove network: {}", name);
    }

    Ok(())
}

/// Build a sandbox image with the repository checkout baked into the image layer.
///
/// This creates a new image based on the provided base image, with the repository
/// cloned from meta.git and checked out to the specified commit on a branch named
/// after the sandbox.
///
/// # Arguments
/// * `base_image` - The base Docker image tag to build from
/// * `meta_git_path` - Path to the meta.git bare repository on the host
/// * `checkout_path` - Path inside the container where the repo should be cloned
/// * `sandbox_name` - Name of the sandbox (used for branch name)
/// * `commit_sha` - The commit SHA to checkout
/// * `git_http_url` - URL of the git HTTP server for the sandbox remote
pub fn build_sandbox_image(
    base_image: &str,
    meta_git_path: &Path,
    checkout_path: &Path,
    sandbox_name: &str,
    commit_sha: &str,
    git_http_url: &str,
    uid: u32,
    gid: u32,
) -> Result<String> {
    // Generate a deterministic image tag based on inputs
    // Include uid/gid so different users get separate images with correct ownership
    let mut hasher = Sha256::new();
    hasher.update(base_image.as_bytes());
    hasher.update(commit_sha.as_bytes());
    hasher.update(sandbox_name.as_bytes());
    hasher.update(checkout_path.to_string_lossy().as_bytes());
    hasher.update(uid.to_le_bytes());
    hasher.update(gid.to_le_bytes());
    let hash = hex::encode(&hasher.finalize()[..16]);
    let image_tag = format!("sandbox-checkout:{}", hash);

    // Check if image already exists
    if image_exists(&image_tag)? {
        debug!("Using existing sandbox image: {}", image_tag);
        return Ok(image_tag);
    }

    info!("Building sandbox image with checkout: {}", image_tag);

    // Create a temporary directory for the Dockerfile
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory for Dockerfile")?;
    let dockerfile_path = temp_dir.path().join("Dockerfile");

    // Write the Dockerfile
    // We use BuildKit's RUN --mount=type=bind to mount meta.git read-only during the clone
    // The post-commit hook is written using printf with escaped newlines to avoid Dockerfile parsing issues
    //
    // TODO: This USER instruction assumes the base image runs as root, which is a breaking change
    // for images that configure a non-root USER. To fix properly, we should use `docker inspect`
    // to query the base image's configured USER and only add this instruction if needed.
    //
    // We use GIT_CONFIG_GLOBAL to point to a config with safe.directory='*' during clone/fetch,
    // bypassing ownership checks for /meta.git which has different ownership than our user.
    //
    // Note: We add origin pointing to /meta.git for the initial clone, then switch to HTTP remote.
    // We fetch the refs from meta.git before switching so that sandbox/master etc. are available.
    let dockerfile_content = format!(
        r##"# syntax=docker/dockerfile:1
FROM {base_image}
USER {uid}:{gid}
# Clone the repository from the mounted meta.git (read-only bind mount during build)
RUN --mount=type=bind,from=metagit,source=/,target=/meta.git,readonly \
    export GIT_CONFIG_GLOBAL=/tmp/gitconfig && \
    printf '[safe]\n\tdirectory = *\n' > "$GIT_CONFIG_GLOBAL" && \
    git clone /meta.git {checkout_path} && \
    cd {checkout_path} && \
    git checkout {commit_sha} && \
    git checkout -b {sandbox_name} && \
    (git branch | grep -v '{sandbox_name}' | xargs -r git branch -D 2>/dev/null || true) && \
    git remote rename origin sandbox && \
    git fetch sandbox && \
    git remote set-url sandbox {git_http_url} && \
    rm "$GIT_CONFIG_GLOBAL" && \
    git config uploadpack.allowAnySHA1InWant true && \
    mkdir -p .git/hooks && \
    printf '#!/bin/sh\ngit push --force --quiet "{git_http_url}" "HEAD:refs/heads/{sandbox_name}" 2>/dev/null || true\n' > .git/hooks/post-commit && \
    chmod +x .git/hooks/post-commit
WORKDIR {checkout_path}
"##,
        base_image = base_image,
        checkout_path = checkout_path.display(),
        commit_sha = commit_sha,
        sandbox_name = sandbox_name,
        git_http_url = git_http_url,
        uid = uid,
        gid = gid,
    );

    std::fs::write(&dockerfile_path, dockerfile_content)
        .context("Failed to write Dockerfile for sandbox image")?;

    // Build the image with meta.git as a named build context
    let output = Command::new("docker")
        .env("DOCKER_BUILDKIT", "1")
        .args([
            "build",
            "-f",
            &dockerfile_path.to_string_lossy(),
            "-t",
            &image_tag,
            // Provide meta.git as a named build context that can be used in RUN --mount
            "--build-context",
            &format!("metagit={}", meta_git_path.display()),
            // Use the temp directory as the main build context
            &temp_dir.path().to_string_lossy(),
        ])
        .output()
        .context("Failed to run docker build for sandbox image")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to build sandbox image: {}", stderr);
    }

    Ok(image_tag)
}
