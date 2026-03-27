//! Shared test utilities and fixtures.

// Not all test files use all helpers, but we want them available.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use indoc::formatdoc;
use rumpelpod::CommandExt;
use tempfile::TempDir;

/// Standard test user name used in test images.
pub const TEST_USER: &str = "testuser";

/// Standard test user UID used in test images.
pub const TEST_USER_UID: u32 = 1007;

/// Standard repository path inside test containers.
pub const TEST_REPO_PATH: &str = "/home/testuser/workspace";

/// Environment variable used to configure the daemon socket path.
pub const SOCKET_PATH_ENV: &str = "RUMPELPOD_DAEMON_SOCKET";

/// Environment variable for XDG state directory (where rumpelpod data is stored).
const XDG_STATE_HOME_ENV: &str = "XDG_STATE_HOME";

/// Isolated HOME directory for a test.
///
/// Created before the executor setup and daemon so that both can write
/// into it (e.g. SSH config, Claude config) and the daemon inherits it
/// as `$HOME`.
pub struct TestHome {
    dir: TempDir,
}

impl TestHome {
    pub fn new() -> Self {
        let dir =
            TempDir::with_prefix("rumpelpod-test-home-").expect("Failed to create test home dir");
        TestHome { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// A test daemon that manages pods for integration tests.
///
/// Uses the [`TestHome`] as `$HOME` and stores its socket, state, and
/// runtime directories under it.  On drop the daemon process is killed.
pub struct TestDaemon {
    pub socket_path: PathBuf,
    process: Child,
    /// Separate short-path temp dir for the runtime directory on macOS,
    /// where Unix socket paths must be under 104 bytes.
    #[allow(dead_code)]
    runtime_temp_dir: Option<TempDir>,
}

impl TestDaemon {
    pub fn start(home: &TestHome) -> Self {
        Self::start_inner(home, false)
    }

    /// Start a daemon that can detect host LLM CLIs (Claude, Codex).
    ///
    /// Most tests should use `start()`, which hides these binaries
    /// to avoid downloading large packages into every prepared image.
    pub fn start_with_host_llm_clis(home: &TestHome) -> Self {
        Self::start_inner(home, true)
    }

    fn start_inner(home: &TestHome, host_claude: bool) -> Self {
        let home_path = home.path();
        let socket_path = home_path.join("rumpelpod.sock");
        let state_dir = home_path.join("state");

        // macOS limits Unix socket paths to 104 bytes. The default TMPDIR
        // on macOS is ~51 chars, making our socket paths too long. Use a
        // short-prefix temp dir under /tmp for the runtime directory.
        let (runtime_dir, runtime_temp_dir) = if cfg!(target_os = "macos") {
            let rt =
                TempDir::with_prefix_in("rp-", "/tmp").expect("Failed to create runtime temp dir");
            let path = rt.path().to_path_buf();
            (path, Some(rt))
        } else {
            (home_path.join("runtime"), None)
        };

        // Ensure runtime directory exists, including the 'rumpelpod' subdirectory that
        // the daemon expects for the git socket.
        std::fs::create_dir_all(runtime_dir.join("rumpelpod"))
            .expect("Failed to create runtime dir");

        let path = if host_claude {
            std::env::var("PATH").unwrap_or_default()
        } else {
            path_without_llm_clis()
        };

        let mut cmd = Command::new("rumpel");
        cmd.env("HOME", home_path)
            .env("PATH", &path)
            .env(SOCKET_PATH_ENV, &socket_path)
            .env(XDG_STATE_HOME_ENV, &state_dir)
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            .env(
                "RUMPELPOD_SSH_CONFIG",
                home_path.join(".ssh/config").as_os_str(),
            );

        // Enable deterministic PIDs for test reproducibility.
        // K8s pods run unprivileged and cannot write ns_last_pid.
        if super::executor::executor_supports_deterministic_ids() {
            cmd.env("RUMPELPOD_TEST_DETERMINISTIC_IDS", "1");
        }

        let process = cmd
            .arg("daemon")
            .stdin(Stdio::null())
            .spawn_with_logging("DAEMON")
            .expect("Failed to spawn daemon");

        // Wait for socket to exist
        let timeout = std::time::Duration::from_secs(10);
        let start = std::time::Instant::now();
        while !socket_path.exists() {
            if start.elapsed() > timeout {
                panic!(
                    "Daemon socket did not appear within {:?}: {}",
                    timeout,
                    socket_path.display()
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        TestDaemon {
            socket_path,
            process,
            runtime_temp_dir,
        }
    }

    /// Kill the daemon process and wait for it to exit.
    pub fn kill(&mut self) {
        self.process.kill().expect("failed to kill daemon");
        self.process.wait().expect("failed to wait for daemon");
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// A temporary directory initialized as a git repository for tests, cleaned up on drop.
pub struct TestRepo {
    dir: TempDir,
}

impl TestRepo {
    pub fn new() -> Self {
        Self::new_with_prefix("rumpelpod-test-repo-")
    }

    /// Create a test repo whose temp directory name starts with `prefix`.
    /// Useful for testing behavior when the repo path contains special characters.
    pub fn new_with_prefix(prefix: &str) -> Self {
        let dir = TempDir::with_prefix(prefix).expect("Failed to create temp directory");

        // Initialize as a git repository with an initial commit
        Command::new("git")
            .args(["init"])
            .current_dir(dir.path())
            .success()
            .expect("git init failed");

        Command::new("git")
            .args(["config", "user.email", "test@example.com"])
            .current_dir(dir.path())
            .success()
            .expect("git config user.email failed");

        Command::new("git")
            .args(["config", "user.name", "Test User"])
            .current_dir(dir.path())
            .success()
            .expect("git config user.name failed");

        create_commit(dir.path(), "Initial commit");

        TestRepo { dir }
    }

    /// Create a temporary directory without git initialization.
    /// Useful for testing behavior outside of a git repository.
    pub fn new_without_git() -> Self {
        let dir =
            TempDir::with_prefix("rumpelpod-test-repo-").expect("Failed to create temp directory");
        TestRepo { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        // Skip cleanup if requested (useful for debugging).
        if std::env::var("RUMPELPOD_TEST_NO_CLEANUP").is_ok() {
            return;
        }

        // Try to clean up any Docker containers created for this repo.
        if let Some(name) = self.dir.path().file_name().and_then(|n| n.to_str()) {
            // Container names are sanitized (non-ASCII replaced with '-'),
            // so we must search using the sanitized form to match.
            let sanitized: String = name
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect();

            // Find containers associated with this repo.
            // Container names start with the (sanitized) repo directory name.
            let output = Command::new("docker")
                .args([
                    "ps",
                    "-a",
                    "--filter",
                    &format!("name={}", sanitized),
                    "--format",
                    "{{.Names}}",
                ])
                .output();

            if let Ok(output) = output {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let containers: Vec<&str> = stdout
                    .lines()
                    .map(|l| l.trim())
                    .filter(|line| line.starts_with(&sanitized))
                    .collect();

                if !containers.is_empty() {
                    // Best effort cleanup, ignore errors
                    let _ = Command::new("docker")
                        .arg("rm")
                        .arg("-f")
                        .args(&containers)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
            }
        }
    }
}

/// Create a commit with a fixed timestamp to ensure deterministic directory hashes.
pub fn create_commit(repo_path: &Path, message: &str) {
    Command::new("git")
        .args(["commit", "--allow-empty", "-m", message])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(repo_path)
        .success()
        .expect("git commit failed");
}

/// Create a Command for the rumpel binary, pre-configured for testing.
pub fn pod_command(repo: &TestRepo, daemon: &TestDaemon) -> Command {
    let mut cmd = Command::new("rumpel");
    cmd.current_dir(repo.path())
        .env(SOCKET_PATH_ENV, &daemon.socket_path);

    // Default to offline mode for tests unless explicitly configured.
    // This ensures tests don't accidentally depend on ambient API keys.
    if std::env::var("RUMPELPOD_TEST_LLM_OFFLINE").is_err() {
        cmd.env("RUMPELPOD_TEST_LLM_OFFLINE", "1");
    }

    cmd
}

/// Return PATH with directories containing `claude` or `codex` binaries removed.
///
/// Prevents the daemon from detecting these host CLIs and
/// downloading large binaries into every prepared image.
fn path_without_llm_clis() -> String {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .filter(|dir| {
            let d = Path::new(dir);
            !d.join("claude").is_file() && !d.join("codex").is_file()
        })
        .collect::<Vec<_>>()
        .join(":")
}

/// Write a standard test devcontainer.json with a Dockerfile build section.
///
/// Creates a Dockerfile that installs git, creates the test user, and
/// COPYs the repo.  The devcontainer.json uses a build section so the
/// image is built on first `rumpel enter` (with buildkit layer caching).
///
/// `extra_dockerfile` is inserted after COPY (user and workspace exist)
/// but before USER, so commands still run as root.
/// `extra_json` is spliced into the devcontainer.json object (include
/// a leading comma if non-empty).
pub fn write_test_devcontainer(repo: &TestRepo, extra_dockerfile: &str, extra_json: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    // Mark safe.directory so extra_dockerfile can run git as root on
    // the testuser-owned workspace without "dubious ownership" errors.
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        RUN git config --global --add safe.directory {TEST_REPO_PATH}
        {extra_dockerfile}
        USER {TEST_USER}
    "#};
    std::fs::write(devcontainer_dir.join("Dockerfile"), dockerfile)
        .expect("Failed to write Dockerfile");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"]{extra_json}
        }}
    "#};
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}
