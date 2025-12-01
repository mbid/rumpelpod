use anyhow::{Context, Result};
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::docker;
use crate::git;
use crate::sandbox::SandboxInfo;

/// Run the sync daemon, watching for changes in the sandbox clone and fetching
/// them into the host repo. Exits when the container stops.
///
/// Errors are logged to `sandbox_dir/sync.log`.
pub fn run_sync_daemon(info: &SandboxInfo) -> Result<()> {
    let log_path = info.sandbox_dir.join("sync.log");
    let mut log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .with_context(|| format!("Failed to open log file: {}", log_path.display()))?;

    let remote_name = format!("sandbox-{}", info.name);

    log(
        &mut log_file,
        &format!("Sync daemon started for sandbox '{}'", info.name),
    );
    log(
        &mut log_file,
        &format!("Watching: {}", info.clone_dir.display()),
    );
    log(
        &mut log_file,
        &format!(
            "Fetching to: {} remote '{}'",
            info.repo_root.display(),
            remote_name
        ),
    );

    let (tx, rx) = mpsc::channel();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        Config::default().with_poll_interval(Duration::from_secs(1)),
    )
    .context("Failed to create file watcher")?;

    // Watch the sandbox clone's .git directory
    let sandbox_git = info.clone_dir.join(".git");
    if sandbox_git.exists() {
        watcher
            .watch(&sandbox_git, RecursiveMode::Recursive)
            .with_context(|| format!("Failed to watch: {}", sandbox_git.display()))?;
    } else {
        log(
            &mut log_file,
            &format!(
                "Warning: .git directory not found at {}",
                sandbox_git.display()
            ),
        );
    }

    let debounce = Duration::from_millis(500);
    let container_check_interval = Duration::from_secs(5);
    let mut last_sync = Instant::now();
    let mut last_container_check = Instant::now();
    let mut pending_sync = false;

    loop {
        // Check for file system events with a timeout
        match rx.recv_timeout(Duration::from_millis(100)) {
            Ok(result) => {
                if let Ok(event) = result {
                    // Filter out access-only events
                    if event.kind.is_access() {
                        continue;
                    }
                    pending_sync = true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // No events, continue
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                log(&mut log_file, "Watcher channel disconnected, exiting");
                break;
            }
        }

        let now = Instant::now();

        // Perform sync if we have pending changes and debounce period has passed
        if pending_sync && now.duration_since(last_sync) > debounce {
            if let Err(e) = git::fetch_branch(&info.repo_root, &remote_name, &info.name) {
                log(&mut log_file, &format!("Fetch error: {}", e));
            }
            last_sync = now;
            pending_sync = false;
        }

        // Periodically check if container is still running
        if now.duration_since(last_container_check) > container_check_interval {
            match docker::container_is_running(&info.container_name) {
                Ok(true) => {
                    // Container still running, continue
                }
                Ok(false) => {
                    log(&mut log_file, "Container stopped, exiting sync daemon");
                    break;
                }
                Err(e) => {
                    log(
                        &mut log_file,
                        &format!("Error checking container status: {}", e),
                    );
                    // Continue anyway, might be transient
                }
            }
            last_container_check = now;
        }
    }

    log(&mut log_file, "Sync daemon exiting");
    Ok(())
}

fn log(file: &mut std::fs::File, message: &str) {
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
    let _ = writeln!(file, "[{}] {}", timestamp, message);
}
