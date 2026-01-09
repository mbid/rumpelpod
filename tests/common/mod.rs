//! Shared test utilities and fixtures.

// Not all test files use all helpers, but we want them available.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use tempfile::TempPath;

/// Environment variable used to configure the daemon socket path.
pub const SOCKET_PATH_ENV: &str = "SANDBOX_DAEMON_SOCKET";

/// Environment variable for XDG state directory (where sandbox data is stored).
const XDG_STATE_HOME_ENV: &str = "XDG_STATE_HOME";

/// A test daemon that manages sandboxes for integration tests.
/// Each test gets its own daemon with an isolated socket and state directory
/// to enable parallel execution without interference.
/// On drop, the daemon process is terminated.
pub struct TestDaemon {
    pub socket_path: PathBuf,
    process: Child,
    #[allow(dead_code)]
    temp_dir: TempPath,
}

impl TestDaemon {
    /// Start a new test daemon with an isolated socket and state directory.
    pub fn start() -> Self {
        let temp_dir = TempPath::from_path(
            std::env::temp_dir().join(format!("sandbox-test-{}", std::process::id())),
        );
        std::fs::create_dir_all(&temp_dir).expect("Failed to create temp directory");

        let socket_path = temp_dir.join("sandbox.sock");
        let state_dir = temp_dir.join("state");

        let process = Command::new(assert_cmd::cargo::cargo_bin!("sandbox"))
            .env(SOCKET_PATH_ENV, &socket_path)
            .env(XDG_STATE_HOME_ENV, &state_dir)
            .arg("daemon")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
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
            temp_dir,
        }
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

/// A temporary directory for tests, cleaned up on drop.
pub struct TestRepo {
    #[allow(dead_code)]
    dir: TempPath,
}

impl TestRepo {
    pub fn new() -> Self {
        let dir = TempPath::from_path(
            std::env::temp_dir().join(format!("sandbox-test-repo-{}", std::process::id())),
        );
        std::fs::create_dir_all(&dir).expect("Failed to create temp directory");
        TestRepo { dir }
    }

    pub fn path(&self) -> &Path {
        &self.dir
    }
}
