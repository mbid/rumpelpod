use anyhow::{bail, Context, Result};
use indoc::formatdoc;
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
    let image_tag = format!("sandbox:{dockerfile_hash}");

    // Check if image already exists
    if image_exists(&image_tag)? {
        debug!("Using existing image: {}", image_tag);
        return Ok(image_tag);
    }

    info!("Building Docker image: {}", image_tag);

    let (username, uid, gid) = (&user_info.username, user_info.uid, user_info.gid);
    let status = Command::new("docker")
        .args([
            "build",
            "-f",
            &dockerfile_path.to_string_lossy(),
            "-t",
            &image_tag,
            "--build-arg",
            &format!("USER_NAME={username}"),
            "--build-arg",
            &format!("USER_ID={uid}"),
            "--build-arg",
            &format!("GROUP_ID={gid}"),
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
        .args(["volume", "ls", "-q", "--filter", &format!("name={prefix}")])
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
///
/// If `username` is provided, the command runs as that user with all their groups.
/// When specifying the user explicitly via `-u`, Docker looks up the user in the
/// container's /etc/passwd and applies all their groups (primary and secondary).
/// This is necessary because containers started with `--user uid:gid` only have
/// the primary group set by default.
pub fn exec_in_container(
    name: &str,
    command: &[&str],
    env_vars: &[(String, String)],
    username: Option<&str>,
) -> Result<()> {
    use std::io::IsTerminal;

    let mut args = vec!["exec".to_string()];

    // Only use -it flags when stdin is a TTY
    if std::io::stdin().is_terminal() {
        args.push("-it".to_string());
    }

    // Run as the specified user - Docker will look up the user in /etc/passwd
    // and apply all their groups (primary and secondary)
    if let Some(user) = username {
        args.push("-u".to_string());
        args.push(user.to_string());
    }

    for (k, v) in env_vars {
        args.push("-e".to_string());
        args.push(format!("{k}={v}"));
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
        .with_context(|| format!("Invalid gateway IP from network {name}: {gateway_ip}"))
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

/// A resolved copy entry for copying directories into the image.
/// Contains absolute paths after resolution.
#[derive(Debug, Clone)]
pub struct ResolvedCopyEntry {
    /// Absolute path on the host filesystem.
    pub host_path: std::path::PathBuf,
    /// Absolute path inside the container.
    pub guest_path: std::path::PathBuf,
}

/// Build a sandbox-ready image with the repository checkout baked in.
///
/// This creates an image based on the provided base image, with the repository
/// cloned from meta.git. The checkout has:
/// - All branches from meta.git as remote-tracking branches (sandbox/*)
/// - No local branches
/// - A "sandbox" remote with a NULL URL (to be set at container start)
///
/// This image can be shared across multiple sandboxes for the same project.
/// Per-sandbox initialization (branch creation, hook setup) happens at container start.
///
/// # Arguments
/// * `base_image` - The base Docker image tag to build from
/// * `meta_git_path` - Path to the meta.git bare repository on the host
/// * `checkout_path` - Path inside the container where the repo should be cloned
/// * `uid` - User ID for file ownership
/// * `gid` - Group ID for file ownership
/// * `copies` - Directories to copy into the image
pub fn build_sandbox_ready_image(
    base_image: &str,
    meta_git_path: &Path,
    checkout_path: &Path,
    uid: u32,
    gid: u32,
    copies: &[ResolvedCopyEntry],
) -> Result<String> {
    // Generate a deterministic image tag based on inputs.
    // Note: We intentionally don't include the meta.git refs in the hash.
    // The image contains the checkout structure but new commits/branches
    // are fetched at container initialization time.
    let mut hasher = Sha256::new();
    hasher.update(base_image.as_bytes());
    hasher.update(checkout_path.to_string_lossy().as_bytes());
    hasher.update(uid.to_le_bytes());
    hasher.update(gid.to_le_bytes());
    // Include copy entries in hash (paths affect the image)
    for copy in copies {
        hasher.update(copy.host_path.to_string_lossy().as_bytes());
        hasher.update(copy.guest_path.to_string_lossy().as_bytes());
    }
    let hash = hex::encode(&hasher.finalize()[..16]);
    let image_tag = format!("sandbox-ready:{hash}");

    // Check if image already exists
    if image_exists(&image_tag)? {
        debug!("Using existing sandbox-ready image: {}", image_tag);
        return Ok(image_tag);
    }

    info!("Building sandbox-ready image: {}", image_tag);

    // Create a temporary directory for the Dockerfile
    let temp_dir = tempfile::tempdir().context("Failed to create temp directory for Dockerfile")?;
    let dockerfile_path = temp_dir.path().join("Dockerfile");

    // Build COPY instructions for copy entries.
    // Each entry uses the parent directory as build context and specifies the
    // source name explicitly. This works for both files and directories.
    let mut copy_instructions = String::new();
    let mut copy_contexts: Vec<(&Path, &std::ffi::OsStr)> = Vec::new();
    for copy in copies {
        let parent = copy
            .host_path
            .parent()
            .context("Copy host path has no parent directory")?;
        let name = copy
            .host_path
            .file_name()
            .context("Copy host path has no file name")?;
        copy_contexts.push((parent, name));
    }
    for (i, (copy, (_parent, name))) in copies.iter().zip(copy_contexts.iter()).enumerate() {
        let guest_path = copy.guest_path.display();
        let name = name.to_string_lossy();
        // COPY from a named build context using the specific file/dir name.
        // The trailing slash on guest_path ensures correct behavior for directories.
        // Use --chown to set correct ownership (COPY defaults to root otherwise).
        copy_instructions.push_str(&format!(
            "COPY --chown={uid}:{gid} --from=copy{i} /{name} {guest_path}\n"
        ));
    }

    // Write the Dockerfile
    // We clone from meta.git, set up remote-tracking branches, then:
    // - Detach HEAD (so we can delete all local branches)
    // - Delete all local branches
    // - Rename origin to sandbox
    // - Set sandbox remote URL to an invalid placeholder (will be set at container start)
    //
    // We use GIT_CONFIG_GLOBAL to bypass ownership checks for /meta.git during build.
    // Directory copies happen after USER is set so files are owned by the correct user.
    let checkout_path = checkout_path.display();
    let dockerfile_content = formatdoc! {r##"
        # syntax=docker/dockerfile:1
        FROM {base_image}
        USER {uid}:{gid}
        # Clone the repository from the mounted meta.git (read-only bind mount during build)
        RUN --mount=type=bind,from=metagit,source=/,target=/meta.git,readonly \
            export GIT_CONFIG_GLOBAL=/tmp/gitconfig && \
            printf '[safe]\n\tdirectory = *\n' > "$GIT_CONFIG_GLOBAL" && \
            git clone /meta.git {checkout_path} && \
            cd {checkout_path} && \
            git remote rename origin sandbox && \
            git fetch sandbox && \
            git remote set-url sandbox "file:///dev/null" && \
            git checkout --detach HEAD && \
            for branch in $(git branch | sed 's/^[* ]*//'); do \
                git branch -D "$branch" 2>/dev/null || true; \
            done && \
            rm "$GIT_CONFIG_GLOBAL" && \
            git config uploadpack.allowAnySHA1InWant true
        {copy_instructions}WORKDIR {checkout_path}
    "##};

    std::fs::write(&dockerfile_path, dockerfile_content)
        .context("Failed to write Dockerfile for sandbox-ready image")?;

    // Build the image with meta.git and dir entries as named build contexts.
    // BuildKit requires relative paths for --build-context, so we run docker from
    // the parent directory of meta.git and use relative paths.
    let meta_git_parent = meta_git_path
        .parent()
        .context("meta_git_path has no parent directory")?;
    let meta_git_name = meta_git_path
        .file_name()
        .context("meta_git_path has no file name")?
        .to_string_lossy();

    let mut args = vec![
        "build".to_string(),
        "-f".to_string(),
        dockerfile_path.to_string_lossy().to_string(),
        "-t".to_string(),
        image_tag.clone(),
        "--build-context".to_string(),
        format!("metagit={meta_git_name}"),
    ];

    // Add build contexts for copy entries (using parent directories)
    for (i, (parent, _name)) in copy_contexts.iter().enumerate() {
        let parent = parent.display();
        args.push("--build-context".to_string());
        args.push(format!("copy{i}={parent}"));
    }

    // Add the main build context (temp directory with Dockerfile)
    args.push(temp_dir.path().to_string_lossy().to_string());

    let output = Command::new("docker")
        .current_dir(meta_git_parent)
        .env("DOCKER_BUILDKIT", "1")
        .args(&args)
        .output()
        .context("Failed to run docker build for sandbox-ready image")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("Failed to build sandbox-ready image: {}", stderr);
    }

    Ok(image_tag)
}

/// Initialize the sandbox checkout inside a running container.
///
/// This performs per-sandbox setup that couldn't be done at image build time:
/// - Sets the sandbox remote URL to the git HTTP server
/// - Fetches the required commit from meta.git
/// - Creates and checks out the sandbox branch
/// - Adds a `host` remote for fetching host branches
/// - Adds the post-commit hook for automatic sync
///
/// # Arguments
/// * `container_name` - Name of the running container
/// * `checkout_path` - Path to the checkout inside the container
/// * `sandbox_name` - Name of the sandbox (used for branch name)
/// * `commit_sha` - The commit SHA to checkout
/// * `git_http_url` - URL of the git HTTP server for the sandbox remote
pub fn initialize_sandbox_checkout(
    container_name: &str,
    checkout_path: &Path,
    sandbox_name: &str,
    commit_sha: &str,
    git_http_url: &str,
) -> Result<()> {
    info!(
        "Initializing sandbox checkout in container '{}' for branch '{}'",
        container_name, sandbox_name
    );

    // Build a shell script to run inside the container
    // This script:
    // 1. Sets the sandbox remote URL
    // 2. Adds a `host` remote for fetching host branches
    // 3. Fetches the required commit
    // 4. Creates and checks out the sandbox branch (only if it doesn't exist)
    // 5. Sets up the post-commit hook
    //
    // Note: We use printf for the hook to avoid heredoc quoting issues.
    // Note: We only create the branch on first initialization. On resume,
    //       the branch already exists and we preserve the user's work.
    //
    // The post-commit hook computes the correct target ref based on branch name:
    // - If branch = sandbox_name: push to sandbox/<sandbox_name>
    // - Otherwise: push to sandbox/<branch>@<sandbox_name>
    let checkout_path = checkout_path.display();
    let script = formatdoc! {r#"
        set -e
        cd {checkout_path}

        # Set the sandbox remote URL
        git remote set-url sandbox "{git_http_url}"

        # Add host remote for fetching host branches (if it doesn't exist)
        if ! git remote get-url host >/dev/null 2>&1; then
            git remote add host "{git_http_url}"
        else
            git remote set-url host "{git_http_url}"
        fi
        # Configure fetch refspec for host remote to get host/* branches
        git config remote.host.fetch "+refs/heads/host/*:refs/remotes/host/*"

        # Fetch the required commit (it may be newer than what's in the image)
        git fetch sandbox

        # Create and checkout the sandbox branch only if it doesn't exist yet
        # (This preserves user's work when resuming a stopped container)
        if ! git show-ref --verify --quiet "refs/heads/{sandbox_name}"; then
            git checkout -B "{sandbox_name}" "{commit_sha}"
        else
            # Branch exists, just make sure we're on it
            git checkout "{sandbox_name}"
        fi

        # Set up the post-commit hook for automatic sync
        # The hook computes the correct target ref based on branch name:
        # - Primary branch (name = sandbox_name) -> sandbox/<sandbox_name>
        # - Other branches -> sandbox/<branch>@<sandbox_name>
        mkdir -p .git/hooks
        cat > .git/hooks/post-commit << 'HOOK_EOF'
#!/bin/sh
branch=$(git symbolic-ref --short HEAD 2>/dev/null) || exit 0
sandbox_name="{sandbox_name}"
if [ "$branch" = "$sandbox_name" ]; then
    target="sandbox/$sandbox_name"
else
    target="sandbox/$branch@$sandbox_name"
fi
git push --force --quiet "{git_http_url}" "HEAD:refs/heads/$target" 2>/dev/null || true
HOOK_EOF
        chmod +x .git/hooks/post-commit
    "#};

    let output = Command::new("docker")
        .args(["exec", container_name, "sh", "-c", &script])
        .output()
        .context("Failed to initialize sandbox checkout")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        bail!(
            "Failed to initialize sandbox checkout:\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );
    }

    debug!("Sandbox checkout initialized successfully");
    Ok(())
}

/// Resolve the Docker image tag from config, building if necessary.
///
/// This handles two cases:
/// 1. An explicit image tag in config -> use it directly
/// 2. A Dockerfile path in config -> build from that Dockerfile
pub fn resolve_image_tag(
    repo_root: &Path,
    image_config: &crate::sandbox_config::ImageConfig,
    user_info: &crate::config::UserInfo,
) -> Result<String> {
    use crate::sandbox_config::ImageConfig;

    match image_config {
        ImageConfig::Tag(tag) => Ok(tag.clone()),
        ImageConfig::Build {
            dockerfile,
            context,
        } => {
            let dockerfile_path = repo_root.join(dockerfile);
            if !dockerfile_path.exists() {
                bail!("Dockerfile not found at {}", dockerfile_path.display());
            }
            let context_path = context
                .as_ref()
                .map(|p| repo_root.join(p))
                .unwrap_or_else(|| repo_root.to_path_buf());
            build_image(&dockerfile_path, &context_path, user_info)
        }
    }
}
