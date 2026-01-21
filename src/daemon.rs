pub mod db;
pub mod protocol;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use indoc::indoc;
use log::error;
use tokio::net::UnixListener;

use crate::command_ext::CommandExt;
use crate::config::{Network, Runtime};
use crate::gateway;
use crate::git_http_server;
use protocol::{
    ContainerId, ConversationSummary, Daemon, GetConversationResponse, Image, LaunchResult,
    SandboxInfo, SandboxName, SandboxStatus,
};
use rusqlite::Connection;
use std::sync::Mutex;

/// Environment variable to override the daemon socket path for testing.
pub const SOCKET_PATH_ENV: &str = "SANDBOX_DAEMON_SOCKET";

/// Get the daemon socket path.
/// Uses $SANDBOX_DAEMON_SOCKET if set, otherwise $XDG_RUNTIME_DIR/sandbox.sock.
pub fn socket_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(SOCKET_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").context(indoc! {"
        XDG_RUNTIME_DIR not set. This usually means you're not running in a
        systemd user session. The sandbox daemon requires systemd for socket activation.
    "})?;
    Ok(PathBuf::from(runtime_dir).join("sandbox.sock"))
}

use std::collections::HashMap;

struct DaemonServer {
    /// SQLite connection for conversation history.
    db: Mutex<Connection>,
    /// Active git HTTP servers: network_name -> (port, token)
    active_git_servers: Mutex<HashMap<String, (u16, String)>>,
}

/// Label key used to store the repository path on containers and networks.
const REPO_PATH_LABEL: &str = "dev.sandbox.repo_path";

/// Label key used to store the sandbox name on containers and networks.
const SANDBOX_NAME_LABEL: &str = "dev.sandbox.name";

/// Generate a unique docker resource name from repo path and sandbox name.
/// Used for both the container and network (they can share the same name).
/// Format: "<repo_dir>-<sandbox_name>-<hash_prefix>"
/// where hash is sha256(repo_path + sandbox_name) truncated to 12 hex chars.
fn docker_name(repo_path: &Path, sandbox_name: &SandboxName) -> String {
    use sha2::{Digest, Sha256};

    let repo_dir = repo_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("repo");

    let mut hasher = Sha256::new();
    hasher.update(repo_path.as_os_str().as_encoded_bytes());
    hasher.update(sandbox_name.0.as_bytes());
    let hash = hex::encode(hasher.finalize());
    let hash_prefix = &hash[..12];

    format!("{}-{}-{}", repo_dir, sandbox_name.0, hash_prefix)
}

/// Container state returned by docker inspect.
struct ContainerState {
    status: String,
    image: String,
    id: String,
}

/// Get the USER directive from a Docker image.
/// Returns None if the image has no USER set (defaults to root).
fn get_image_user(image: &str) -> Result<Option<String>> {
    let output = Command::new("docker")
        .args(["inspect", "--format", "{{.Config.User}}", image])
        .output()
        .context("Failed to execute docker inspect on image")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Failed to inspect image '{}': {}", image, stderr.trim());
    }

    let user = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if user.is_empty() {
        Ok(None)
    } else {
        Ok(Some(user))
    }
}

/// Resolve the user for a sandbox.
///
/// If `user` is provided, it is used directly.
/// Otherwise, the image's USER directive is used.
/// Returns an error if no user is specified and the image has no USER or uses root.
fn resolve_user(user: Option<String>, image: &str) -> Result<String> {
    if let Some(user) = user {
        return Ok(user);
    }

    let image_user = get_image_user(image)?;

    match image_user {
        Some(user) if user != "root" && !user.starts_with("0:") && user != "0" => Ok(user),
        Some(user) => {
            anyhow::bail!(
                "Image '{}' has USER set to '{}' (root). \
                 For security, sandboxes must run as a non-root user.\n\
                 Either set 'user' in .sandbox.toml, or change the image's USER directive.",
                image,
                user
            );
        }
        None => {
            anyhow::bail!(
                "Image '{}' has no USER directive (defaults to root). \
                 For security, sandboxes must run as a non-root user.\n\
                 Either set 'user' in .sandbox.toml, or add a USER directive to the Dockerfile.",
                image
            );
        }
    }
}

/// Inspect an existing container by name. Returns None if container doesn't exist.
fn inspect_container(container_name: &str) -> Result<Option<ContainerState>> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{.State.Status}} {{.Config.Image}} {{.Id}}",
            container_name,
        ])
        .output()
        .context("Failed to execute docker inspect")?;

    if !output.status.success() {
        // Container doesn't exist
        return Ok(None);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let parts: Vec<&str> = stdout.trim().splitn(3, ' ').collect();
    if parts.len() != 3 {
        anyhow::bail!("Unexpected docker inspect output: {}", stdout);
    }

    Ok(Some(ContainerState {
        status: parts[0].to_string(),
        image: parts[1].to_string(),
        id: parts[2].to_string(),
    }))
}

/// Start a stopped container.
fn start_container(container_name: &str) -> Result<()> {
    Command::new("docker")
        .args(["start", container_name])
        .success()
        .context("starting container")?;
    Ok(())
}

/// Compute a /29 subnet in 172.16.0.0/12 range from the network name's hash.
///
/// Docker by default assigns /16 or /20 subnets from the 172.17.0.0/12 range,
/// which quickly exhausts available IP space when running many tests. By using
/// /29 subnets (8 IPs each), we can support ~1M networks in the same IP range.
///
/// The subnet is derived deterministically from the network name's hash to
/// ensure the same sandbox always gets the same subnet. The `attempt` parameter
/// allows trying different subnets if the first one collides.
/// Subnet and gateway configuration for a docker network.
struct SubnetConfig {
    subnet: String,
    gateway: String,
}

fn compute_subnet(name: &str, attempt: u32) -> SubnetConfig {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update(attempt.to_le_bytes());
    let hash = hasher.finalize();

    // Use first 20 bits of hash to select a /29 subnet within 172.16.0.0/12
    // 172.16.0.0/12 spans 172.16.0.0 - 172.31.255.255 (20 bits of host space)
    // With /29 subnets (3 bits for hosts), we have 17 bits for network selection
    // But we'll use 20 bits and mask to /29 boundaries for simplicity
    //
    // Layout: 172.(16 + high_nibble).(byte2).(byte3 & 0xF8)/29
    // where high_nibble is 0-15 (4 bits), giving us 172.16.x.x to 172.31.x.x
    //
    // In a /29 subnet, the first usable IP (base + 1) is the gateway.

    let high_nibble = (hash[0] >> 4) & 0x0F; // 0-15, maps to 172.16-172.31
    let byte2 = hash[1];
    let byte3 = hash[2] & 0xF8; // Align to /29 boundary (multiples of 8)

    let octet2 = 16 + high_nibble;
    SubnetConfig {
        subnet: format!("172.{}.{}.{}/29", octet2, byte2, byte3),
        gateway: format!("172.{}.{}.{}", octet2, byte2, byte3 + 1),
    }
}

/// Maximum number of subnet collision retries before giving up.
const MAX_SUBNET_RETRIES: u32 = 10;

/// Create a docker network for the sandbox.
/// If the network already exists, returns success.
fn create_network(name: &str, sandbox_name: &SandboxName, repo_path: &Path) -> Result<()> {
    // Check if network already exists
    let check = Command::new("docker")
        .args(["network", "inspect", name])
        .output()
        .context("Failed to execute docker network inspect")?;

    if check.status.success() {
        return Ok(());
    }

    // Try creating the network with different subnets if we hit collisions
    for attempt in 0..MAX_SUBNET_RETRIES {
        let config = compute_subnet(name, attempt);

        let output = Command::new("docker")
            .args([
                "network",
                "create",
                "--subnet",
                &config.subnet,
                "--gateway",
                &config.gateway,
                "--label",
                &format!("{}={}", REPO_PATH_LABEL, repo_path.display()),
                "--label",
                &format!("{}={}", SANDBOX_NAME_LABEL, sandbox_name.0),
                name,
            ])
            .output()
            .context("Failed to execute docker network create")?;

        if output.status.success() {
            return Ok(());
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        // Retry on subnet collision, fail on other errors
        if !stderr.contains("Pool overlaps") {
            error!("docker network create failed: {}", stderr);
            anyhow::bail!("docker network create failed: {}", stderr);
        }
    }

    anyhow::bail!(
        "docker network create failed: could not find non-overlapping subnet after {} attempts",
        MAX_SUBNET_RETRIES
    );
}

/// Delete a docker network.
fn delete_network(name: &str) -> Result<()> {
    let output = Command::new("docker")
        .args(["network", "rm", name])
        .combined_output()
        .context("Failed to execute docker network rm")?;

    if !output.status.success() {
        // Ignore "not found" errors (already deleted or never existed)
        if !output.combined_output.contains("not found") {
            error!("docker network rm failed: {}", output.combined_output);
            anyhow::bail!(
                "docker network rm failed: {}",
                output.combined_output.trim()
            );
        }
    }

    Ok(())
}

/// Clean up gateway refs for a deleted sandbox.
///
/// Removes all refs matching `sandbox/*@<sandbox_name>` from both the gateway
/// and host repos, including the alias symref `sandbox/<sandbox_name>`.
fn cleanup_sandbox_refs(gateway_path: &Path, repo_path: &Path, sandbox_name: &SandboxName) {
    // Find all refs matching sandbox/*@<sandbox_name> in gateway
    let pattern = format!("refs/heads/sandbox/*@{}", sandbox_name.0);
    if let Ok(output) = Command::new("git")
        .args(["for-each-ref", "--format=%(refname)", &pattern])
        .current_dir(gateway_path)
        .output()
    {
        if output.status.success() {
            let refs = String::from_utf8_lossy(&output.stdout);
            for ref_name in refs.lines().filter(|s| !s.is_empty()) {
                // Delete from gateway
                let _ = Command::new("git")
                    .args(["update-ref", "-d", ref_name])
                    .current_dir(gateway_path)
                    .output();

                // Delete corresponding remote-tracking ref from host
                let branch = ref_name.strip_prefix("refs/heads/").unwrap_or(ref_name);
                let _ = Command::new("git")
                    .args(["update-ref", "-d", &format!("refs/remotes/{}", branch)])
                    .current_dir(repo_path)
                    .output();
            }
        }
    }

    // Delete the alias symref (sandbox/<name> -> sandbox/<name>@<name>)
    let alias_ref = format!("refs/heads/sandbox/{}", sandbox_name.0);
    let _ = Command::new("git")
        .args(["symbolic-ref", "--delete", &alias_ref])
        .current_dir(gateway_path)
        .output();

    // Delete the alias remote-tracking ref from host
    let alias_remote_ref = format!("refs/remotes/sandbox/{}", sandbox_name.0);
    let _ = Command::new("git")
        .args(["update-ref", "-d", &alias_remote_ref])
        .current_dir(repo_path)
        .output();
}

/// Spawn a git HTTP server for the container and return the access URL.
fn spawn_git_http_server(
    active_git_servers: &Mutex<HashMap<String, (u16, String)>>,
    gateway_path: &Path,
    network_name: &str,
    sandbox_name: &SandboxName,
    container_id: &str,
    network_config: Network,
) -> Result<(String, String)> {
    // Check if we already have a server for this network
    {
        let servers = active_git_servers.lock().unwrap();
        if let Some((port, token)) = servers.get(network_name) {
            let ip = match network_config {
                Network::UnsafeHost => "127.0.0.1".to_string(),
                Network::Default => git_http_server::get_network_gateway_ip(network_name)?,
            };
            return Ok((git_http_server::git_http_url(&ip, *port), token.clone()));
        }
    }

    let (bind_ip, bind_port) = match network_config {
        Network::UnsafeHost => ("127.0.0.1".to_string(), 0),
        Network::Default => {
            let gateway_ip = git_http_server::get_network_gateway_ip(network_name)?;
            (gateway_ip, git_http_server::GIT_HTTP_PORT)
        }
    };

    let result = git_http_server::spawn_git_http_server(
        gateway_path,
        &bind_ip,
        bind_port,
        &sandbox_name.0,
        container_id,
    );

    let (port, token) = match result {
        Ok((port, token)) => (port, token),
        Err(e) => {
            if network_config == Network::UnsafeHost {
                error!("Failed to spawn git HTTP server for unsafe-host: {}. Continuing without git sync.", e);
                return Err(e);
            } else {
                return Err(e).context("starting git HTTP server");
            }
        }
    };

    // Store the port so we don't try to bind again for this network
    active_git_servers
        .lock()
        .unwrap()
        .insert(network_name.to_string(), (port, token.clone()));

    Ok((git_http_server::git_http_url(&bind_ip, port), token))
}

/// Check that the .git directory inside the container is owned by the expected user.
/// Returns an error with a helpful message if ownership doesn't match.
fn check_git_directory_ownership(
    container_id: &str,
    container_repo_path: &Path,
    user: &str,
) -> Result<()> {
    let git_dir = container_repo_path.join(".git");
    let git_dir_str = git_dir.to_string_lossy();

    // Get the owner of the .git directory
    let owner_output = Command::new("docker")
        .args(["exec", container_id, "stat", "-c", "%U", &git_dir_str])
        .success()
        .with_context(|| format!("checking ownership of {}", git_dir_str))?;

    let owner = String::from_utf8_lossy(&owner_output).trim().to_string();

    // Extract just the username part if user is in "user:group" format
    let expected_user = user.split(':').next().unwrap_or(user);

    if owner != expected_user {
        anyhow::bail!(
            "Git directory {} is owned by '{}', but sandbox is configured to run as '{}'.\n\
             Please ensure the repository inside the container is owned by the configured user.\n\
             You can fix this by running: chown -R {} {}",
            git_dir_str,
            owner,
            expected_user,
            user,
            container_repo_path.display()
        );
    }

    Ok(())
}

/// Set up git remotes and hooks inside the container for the gateway repository.
/// Adds "host" and "sandbox" remotes pointing to the git HTTP server.
/// Git commands are run as the specified user to avoid permission issues.
///
/// The "host" remote is configured with a custom fetch refspec that maps
/// `host/*` branches from the gateway to `host/*` remote refs in the sandbox.
/// This way, when the host's `main` branch is stored as `host/main` in the
/// gateway, it appears as `host/main` (not `host/host/main`) after fetching.
///
/// The "sandbox" remote is configured with a push refspec that maps local branches
/// to `sandbox/<branch>@<sandbox_name>` in the gateway, allowing multiple sandboxes
/// to push branches without conflicts.
///
/// A post-commit hook is installed to automatically push commits to the gateway.
///
/// If `host_branch` is provided (only on first entry), the primary branch's upstream
/// will be set to `host/<host_branch>`. This allows `git pull` and `git status` to
/// show meaningful tracking information relative to the host branch.
fn setup_git_remotes(
    container_id: &str,
    git_http_url: &str,
    token: &str,
    container_repo_path: &Path,
    sandbox_name: &SandboxName,
    user: &str,
    host_branch: Option<&str>,
) -> Result<()> {
    check_git_directory_ownership(container_id, container_repo_path, user)?;

    let repo_path_str = container_repo_path.to_string_lossy();

    // Helper to run a git command inside the container
    let run_git = |args: &[&str]| -> Result<Vec<u8>> {
        Command::new("docker")
            .args(["exec", "--user", user, container_id])
            .arg("git")
            .arg("-C")
            .arg(&*repo_path_str)
            .args(args)
            .success()
    };

    // Configure Bearer authentication
    run_git(&[
        "config",
        "http.extraHeader",
        &format!("Authorization: Bearer {}", token),
    ])
    .context("configuring git http.extraHeader")?;

    // Add "host" remote (or update if exists)
    match run_git(&["remote", "add", "host", &git_http_url]) {
        Ok(_) => {}
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("already exists") {
                run_git(&["remote", "set-url", "host", &git_http_url])
                    .context("updating host remote URL")?;
            } else {
                return Err(e).context("adding host remote");
            }
        }
    }

    // Configure fetch refspec: map gateway's host/* branches to host/* remote refs.
    // This strips the "host/" prefix from the gateway branch names, so the host's
    // "main" branch (stored as "host/main" in gateway) becomes "host/main" in sandbox.
    run_git(&[
        "config",
        "remote.host.fetch",
        "+refs/heads/host/*:refs/remotes/host/*",
    ])
    .context("configuring host remote fetch refspec")?;

    // Disable pushing to the host remote - it's fetch-only.
    run_git(&["config", "remote.host.pushurl", "PUSH_DISABLED"])
        .context("disabling push for host remote")?;

    // Add "sandbox" remote (same URL, for pushing sandbox commits to gateway)
    match run_git(&["remote", "add", "sandbox", &git_http_url]) {
        Ok(_) => {}
        Err(e) => {
            let error_msg = e.to_string();
            if error_msg.contains("already exists") {
                run_git(&["remote", "set-url", "sandbox", &git_http_url])
                    .context("updating sandbox remote URL")?;
            } else {
                return Err(e).context("adding sandbox remote");
            }
        }
    }

    // Configure push refspec: map local branches to sandbox/<branch>@<sandbox_name>.
    // This namespaces sandbox branches to avoid conflicts between different sandboxes.
    let push_refspec = format!("+refs/heads/*:refs/heads/sandbox/*@{}", sandbox_name.0);
    run_git(&["config", "remote.sandbox.push", &push_refspec])
        .context("configuring sandbox remote push refspec")?;

    // Fetch all refs from the host remote so sandboxes have access to host branches.
    run_git(&["fetch", "host"]).context("fetching from host remote")?;

    // Install reference-transaction hook to auto-push to gateway on any ref update.
    // We install the hook first because we use its presence to detect whether this
    // is the first entry (hook not installed) or a re-entry (hook already installed).
    let is_first_entry = install_sandbox_reference_transaction_hook(
        container_id,
        container_repo_path,
        sandbox_name,
        user,
    )?;

    // Create and checkout a branch named after the sandbox, pointing to host/HEAD.
    // Only do this on initial setup to avoid disrupting work in progress.
    if is_first_entry {
        let branch_name = &sandbox_name.0;
        let branch_exists = run_git(&[
            "show-ref",
            "--verify",
            "--quiet",
            &format!("refs/heads/{}", branch_name),
        ])
        .is_ok();

        if branch_exists {
            // Branch exists (e.g., from the image) - reset it to host/HEAD.
            // Use --no-track to prevent git from auto-setting upstream.
            run_git(&["branch", "-f", "--no-track", branch_name, "host/HEAD"])
                .with_context(|| format!("resetting branch '{}' to host/HEAD", branch_name))?;
        } else {
            // Create the branch pointing to host/HEAD.
            // Use --no-track to prevent git from auto-setting upstream based on
            // the remote-tracking ref. We'll set the proper upstream explicitly
            // below if host_branch is provided.
            run_git(&["branch", "--no-track", branch_name, "host/HEAD"])
                .with_context(|| format!("creating branch '{}'", branch_name))?;
        }

        // Checkout the branch
        run_git(&["checkout", branch_name])
            .with_context(|| format!("checking out branch '{}'", branch_name))?;

        // Set upstream to host/<host_branch> if a branch was checked out on the host.
        // This enables `git status` to show tracking info and `git pull` to work.
        if let Some(host_branch) = host_branch {
            let upstream = format!("host/{}", host_branch);
            run_git(&["branch", "--set-upstream-to", &upstream, branch_name]).with_context(
                || format!("setting upstream of '{}' to '{}'", branch_name, upstream),
            )?;
        }
    }

    Ok(())
}

/// Reference-transaction hook script for sandbox repos that pushes branch updates to the gateway.
///
/// This hook is invoked whenever any reference is updated (commits, branch creation,
/// deletion, resets, etc). It runs in the "committed" state after the reference
/// transaction has been committed.
const SANDBOX_REFERENCE_TRANSACTION_HOOK: &str = indoc::indoc! {r#"
    #!/bin/sh
    # Installed by sandbox to sync branch updates to the gateway repository.
    # This allows the host to pull sandbox changes.
    # This hook runs on reference-transaction events.

    # Only process after the transaction is committed
    [ "$1" = "committed" ] || exit 0

    # Process each ref update from stdin
    while read oldvalue newvalue refname; do
        # Only handle local branches (refs/heads/*)
        case "$refname" in
            refs/heads/*)
                branch="${refname#refs/heads/}"
                if [ "$newvalue" = "0000000000000000000000000000000000000000" ]; then
                    # Branch deleted - remove from gateway
                    git push sandbox --delete "$branch" --quiet 2>/dev/null || true
                else
                    # Branch updated or created - push to gateway
                    git push sandbox "$branch" --force --quiet 2>/dev/null || true
                fi
                ;;
        esac
    done
"#};

/// Install the reference-transaction hook in the sandbox repository.
/// Returns true if this is the first installation (first entry), false if already installed.
fn install_sandbox_reference_transaction_hook(
    container_id: &str,
    container_repo_path: &Path,
    _sandbox_name: &SandboxName,
    user: &str,
) -> Result<bool> {
    let hooks_dir = container_repo_path.join(".git").join("hooks");
    let hook_path = hooks_dir.join("reference-transaction");
    let hooks_dir_str = hooks_dir.to_string_lossy();
    let hook_path_str = hook_path.to_string_lossy();

    // Ensure hooks directory exists
    Command::new("docker")
        .args(["exec", "--user", user, container_id])
        .args(["mkdir", "-p", &hooks_dir_str])
        .success()
        .context("creating hooks directory")?;

    // Check if hook already exists and contains our signature
    let existing_hook = Command::new("docker")
        .args(["exec", "--user", user, container_id])
        .args(["cat", &hook_path_str])
        .success()
        .ok()
        .map(|b| String::from_utf8_lossy(&b).to_string());

    let hook_signature = "Installed by sandbox to sync branch updates";

    let final_hook = match existing_hook {
        Some(existing) if existing.contains(hook_signature) => {
            // Already installed - this is a re-entry
            return Ok(false);
        }
        Some(existing) => {
            // Append to existing hook
            format!(
                "{}\n\n{}",
                existing.trim_end(),
                SANDBOX_REFERENCE_TRANSACTION_HOOK
            )
        }
        None => SANDBOX_REFERENCE_TRANSACTION_HOOK.to_string(),
    };

    // Write the hook using sh -c with echo to avoid stdin piping issues
    // Use printf to handle the hook content properly
    let escaped_hook = final_hook.replace('\\', "\\\\").replace('\'', "'\\''");
    Command::new("docker")
        .args(["exec", "--user", user, container_id])
        .args([
            "sh",
            "-c",
            &format!("printf '%s' '{}' > '{}'", escaped_hook, hook_path_str),
        ])
        .success()
        .context("writing reference-transaction hook")?;

    // Make hook executable
    Command::new("docker")
        .args(["exec", "--user", user, container_id])
        .args(["chmod", "+x", &hook_path_str])
        .success()
        .context("making reference-transaction hook executable")?;

    // First installation - this is the first entry
    Ok(true)
}

/// Returns the docker runtime name to pass to `docker run --runtime`.
fn docker_runtime_flag(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::Runsc => "runsc",
        Runtime::Runc => "runc",
        Runtime::SysboxRunc => "sysbox-runc",
    }
}

/// Create a new container with docker run.
fn create_container(
    name: &str,
    sandbox_name: &SandboxName,
    image: &Image,
    repo_path: &Path,
    runtime: Runtime,
    network_config: Network,
) -> Result<ContainerId> {
    let network_arg = match network_config {
        Network::UnsafeHost => "host",
        Network::Default => name,
    };

    let output = Command::new("docker")
        .args([
            "run",
            "-d", // Detach to get container ID
            "--runtime",
            docker_runtime_flag(runtime),
            "--name",
            name,
            "--hostname",
            &sandbox_name.0,
            "--network",
            network_arg,
            "--label",
            &format!("{}={}", REPO_PATH_LABEL, repo_path.display()),
            "--label",
            &format!("{}={}", SANDBOX_NAME_LABEL, sandbox_name.0),
            &image.0,
            "sleep",
            "infinity", // Keep container running
        ])
        .success()
        .context("creating container")?;

    // Container ID is printed to stdout (without trailing newline)
    let container_id = String::from_utf8_lossy(&output).trim().to_string();

    Ok(ContainerId(container_id))
}

/// List all sandbox containers for a given repository path.
fn list_sandboxes_for_repo(repo_path: &Path) -> Result<Vec<SandboxInfo>> {
    // Use docker ps with filter by label to find containers for this repo
    let output = Command::new("docker")
        .args([
            "ps",
            "-a", // Include stopped containers
            "--filter",
            &format!("label={}={}", REPO_PATH_LABEL, repo_path.display()),
            "--format",
            // Output: name, status, created timestamp, sandbox_name label
            "{{.Names}}\t{{.Status}}\t{{.CreatedAt}}\t{{.Label \"dev.sandbox.name\"}}",
        ])
        .success()
        .context("listing containers")?;

    let stdout = String::from_utf8_lossy(&output);
    let mut sandboxes = Vec::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() < 4 {
            continue;
        }

        let status_str = parts[1];
        let status = if status_str.starts_with("Up") {
            SandboxStatus::Running
        } else {
            SandboxStatus::Stopped
        };

        // Parse created timestamp (format: "2026-01-09 12:58:00 +0000 UTC")
        // We only want "2026-01-09 12:58"
        let created_raw = parts[2];
        let created = if let Some((date_time, _rest)) = created_raw.split_once(" +") {
            // date_time is "2026-01-09 12:58:00", we want "2026-01-09 12:58"
            // Find last colon and truncate
            if let Some(last_colon_idx) = date_time.rfind(':') {
                date_time[..last_colon_idx].to_string()
            } else {
                date_time.to_string()
            }
        } else {
            created_raw.to_string()
        };

        let sandbox_name = parts[3].to_string();

        sandboxes.push(SandboxInfo {
            name: sandbox_name,
            status,
            created,
        });
    }

    Ok(sandboxes)
}

impl Daemon for DaemonServer {
    fn launch_sandbox(
        &self,
        sandbox_name: SandboxName,
        image: Image,
        repo_path: PathBuf,
        container_repo_path: PathBuf,
        user: Option<String>,
        runtime: Runtime,
        network: Network,
        host_branch: Option<String>,
    ) -> Result<LaunchResult> {
        // Validate network configuration
        if network == Network::UnsafeHost && runtime != Runtime::Runc {
            anyhow::bail!("network='unsafe-host' is only supported with runtime='runc'");
        }

        // Resolve the user first, before any container operations
        let user = resolve_user(user, &image.0)?;

        // Set up gateway for git synchronization (idempotent)
        gateway::setup_gateway(&repo_path)?;

        let name = docker_name(&repo_path, &sandbox_name);
        let gateway_path = gateway::gateway_path(&repo_path)?;

        // TODO: There's a potential race condition between inspect and
        // start/run. Another process could stop/remove the container after we
        // inspect it. For robustness, we'd need to retry on specific failures,
        // but that adds complexity. For now, we accept this limitation.

        if let Some(state) = inspect_container(&name)? {
            // Container exists - check if it has the expected image
            if state.image != image.0 {
                anyhow::bail!(
                    "Container '{}' exists with image '{}', but requested image is '{}'",
                    name,
                    state.image,
                    image.0
                );
            }

            if state.status != "running" {
                // Container exists but is stopped - restart it
                start_container(&name)?;
            }

            // Already running (or just restarted).
            // Spawn git HTTP server in case daemon was restarted while container was running.
            let git_url_result = spawn_git_http_server(
                &self.active_git_servers,
                &gateway_path,
                &name,
                &sandbox_name,
                &state.id,
                network,
            );

            match git_url_result {
                Ok((url, token)) => {
                    // On re-entry, don't pass host_branch - we don't want to change
                    // the upstream of an existing branch.
                    setup_git_remotes(
                        &state.id,
                        &url,
                        &token,
                        &container_repo_path,
                        &sandbox_name,
                        &user,
                        None,
                    )?;
                }
                Err(e) => {
                    if network == Network::UnsafeHost {
                        error!("Failed to spawn git HTTP server: {}. Continuing...", e);
                    } else {
                        return Err(e);
                    }
                }
            }

            return Ok(LaunchResult {
                container_id: ContainerId(state.id),
                user,
            });
        }

        // Create network (only for isolated network)
        if network == Network::Default {
            create_network(&name, &sandbox_name, &repo_path)?;
        }

        let container_id =
            create_container(&name, &sandbox_name, &image, &repo_path, runtime, network)?;
        let git_url_result = spawn_git_http_server(
            &self.active_git_servers,
            &gateway_path,
            &name,
            &sandbox_name,
            &container_id.0,
            network,
        );

        match git_url_result {
            Ok((url, token)) => {
                setup_git_remotes(
                    &container_id.0,
                    &url,
                    &token,
                    &container_repo_path,
                    &sandbox_name,
                    &user,
                    host_branch.as_deref(),
                )?;
            }
            Err(e) => {
                if network == Network::UnsafeHost {
                    error!("Failed to spawn git HTTP server: {}. Continuing...", e);
                } else {
                    return Err(e);
                }
            }
        }

        Ok(LaunchResult { container_id, user })
    }

    fn delete_sandbox(&self, sandbox_name: SandboxName, repo_path: PathBuf) -> Result<()> {
        let name = docker_name(&repo_path, &sandbox_name);

        // Stop the container with immediate SIGKILL (-t 0) because containers typically
        // run `sleep infinity` which won't handle SIGTERM gracefully anyway.
        // TODO: For sysbox/systemd containers that don't invoke the provided run command,
        // we should allow a graceful shutdown period.
        let _ = Command::new("docker")
            .args(["stop", "-t", "0", &name])
            .combined_output();

        // Remove the container
        let output = Command::new("docker")
            .args(["rm", "-f", &name])
            .combined_output()
            .context("Failed to execute docker rm")?;

        if !output.status.success() {
            // Ignore "No such container" errors (already deleted)
            if !output.combined_output.contains("No such container") {
                error!("docker rm failed: {}", output.combined_output);
                anyhow::bail!("docker rm failed: {}", output.combined_output.trim());
            }
        }

        // Remove the network (must be done after removing the container)
        delete_network(&name)?;

        // Remove from active git servers
        self.active_git_servers.lock().unwrap().remove(&name);

        // Clean up gateway refs for this sandbox
        if let Ok(gateway_path) = gateway::gateway_path(&repo_path) {
            cleanup_sandbox_refs(&gateway_path, &repo_path, &sandbox_name);
        }

        // Delete conversation history for this sandbox
        let conn = self.db.lock().unwrap();
        db::delete_conversations(&conn, &repo_path, &sandbox_name.0)?;

        Ok(())
    }

    fn list_sandboxes(&self, repo_path: PathBuf) -> Result<Vec<SandboxInfo>> {
        list_sandboxes_for_repo(&repo_path)
    }

    fn save_conversation(
        &self,
        id: Option<i64>,
        repo_path: PathBuf,
        sandbox_name: String,
        model: String,
        provider: String,
        history: serde_json::Value,
    ) -> Result<i64> {
        let conn = self.db.lock().unwrap();
        db::save_conversation(
            &conn,
            id,
            &repo_path,
            &sandbox_name,
            &model,
            &provider,
            &history,
        )
    }

    fn list_conversations(
        &self,
        repo_path: PathBuf,
        sandbox_name: String,
    ) -> Result<Vec<ConversationSummary>> {
        let conn = self.db.lock().unwrap();
        let summaries = db::list_conversations(&conn, &repo_path, &sandbox_name)?;
        Ok(summaries
            .into_iter()
            .map(|s| ConversationSummary {
                id: s.id,
                model: s.model,
                provider: s.provider,
                updated_at: s.updated_at,
            })
            .collect())
    }

    fn get_conversation(&self, id: i64) -> Result<Option<GetConversationResponse>> {
        let conn = self.db.lock().unwrap();
        let conv = db::get_conversation(&conn, id)?;
        Ok(conv.map(|c| GetConversationResponse {
            model: c.model,
            provider: c.provider,
            history: c.history,
        }))
    }
}

pub fn run_daemon() -> Result<()> {
    let socket = socket_path()?;

    // Remove stale socket file if it exists
    if socket.exists() {
        std::fs::remove_file(&socket)?;
    }

    // Initialize database
    let db_path = db::db_path()?;
    let db_conn = db::open_db(&db_path)?;

    // Enter the runtime context so UnixListener::bind can register with the reactor
    let _guard = crate::r#async::RUNTIME.enter();

    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("Failed to bind to {}", socket.display()))?;

    let daemon = DaemonServer {
        db: Mutex::new(db_conn),
        active_git_servers: Mutex::new(HashMap::new()),
    };
    protocol::serve_daemon(daemon, listener);
}
