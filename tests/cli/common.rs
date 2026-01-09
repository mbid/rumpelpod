//! Shared test utilities and fixtures.

// Not all test files use all helpers, but we want them available.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{bail, Context};
use sandbox::CommandExt;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

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
    temp_dir: TempDir,
}

impl TestDaemon {
    /// Start a new test daemon with an isolated socket and state directory.
    pub fn start() -> Self {
        let temp_dir =
            TempDir::with_prefix("sandbox-test-").expect("Failed to create temp directory");

        let socket_path = temp_dir.path().join("sandbox.sock");
        let state_dir = temp_dir.path().join("state");

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

/// A temporary directory initialized as a git repository for tests, cleaned up on drop.
pub struct TestRepo {
    dir: TempDir,
}

impl TestRepo {
    pub fn new() -> Self {
        let dir =
            TempDir::with_prefix("sandbox-test-repo-").expect("Failed to create temp directory");

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

        Command::new("git")
            .args(["commit", "--allow-empty", "-m", "Initial commit"])
            .current_dir(dir.path())
            .success()
            .expect("git commit failed");

        TestRepo { dir }
    }

    /// Create a temporary directory without git initialization.
    /// Useful for testing behavior outside of a git repository.
    pub fn new_without_git() -> Self {
        let dir =
            TempDir::with_prefix("sandbox-test-repo-").expect("Failed to create temp directory");
        TestRepo { dir }
    }

    pub fn path(&self) -> &Path {
        self.dir.path()
    }
}

/// Create a Command for the sandbox binary, pre-configured for testing.
pub fn sandbox_command(repo: &TestRepo, daemon: &TestDaemon) -> Command {
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("sandbox"));
    cmd.current_dir(repo.path())
        .env(SOCKET_PATH_ENV, &daemon.socket_path);
    cmd
}

/// Configuration for building a custom Docker image.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct DockerBuild {
    /// The contents of the Dockerfile.
    pub dockerfile: String,
    /// Optional path to use as the build context. If None, an empty temp directory is used.
    pub build_context: Option<PathBuf>,
}

/// Label key used to identify images built by this test infrastructure.
const TEST_IMAGE_LABEL: &str = "dev.sandbox.test.dockerfile_hash";

/// Global cache for built docker images, keyed by DockerBuild configuration.
/// The mutex ensures only one build happens at a time (avoiding parallel builds
/// of the same image) and enables caching of results.
/// We use Arc to share results since anyhow::Error is not Clone.
static DOCKER_IMAGE_CACHE: Mutex<Option<BTreeMap<DockerBuild, Arc<anyhow::Result<String>>>>> =
    Mutex::new(None);

/// Compute a SHA256 hash of the DockerBuild configuration for use as an image label.
fn compute_dockerfile_hash(build: &DockerBuild) -> String {
    let mut hasher = Sha256::new();
    hasher.update(build.dockerfile.as_bytes());
    if let Some(ref context) = build.build_context {
        hasher.update(context.to_string_lossy().as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// Check if an image with the given label value already exists.
/// Returns the image ID if found.
fn find_existing_image(label_value: &str) -> Option<String> {
    let output = Command::new("docker")
        .args([
            "images",
            "--filter",
            &format!("label={}={}", TEST_IMAGE_LABEL, label_value),
            "--format",
            "{{.ID}}",
        ])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let id = stdout.lines().next()?.trim();
    if id.is_empty() {
        None
    } else {
        Some(id.to_string())
    }
}

/// Build a Docker image from the given DockerBuild configuration.
///
/// This function:
/// 1. Computes a hash of the dockerfile configuration
/// 2. Checks if an image with that hash already exists (from previous test runs)
/// 3. If not, builds the image with the hash as a label
/// 4. Caches the result in memory for subsequent calls within the same test run
///
/// Only one build runs at a time to avoid duplicate work.
pub fn build_docker_image(build: DockerBuild) -> anyhow::Result<String> {
    let mut cache_guard = DOCKER_IMAGE_CACHE.lock().unwrap();
    let cache = cache_guard.get_or_insert_with(BTreeMap::new);

    // Check in-memory cache first
    if let Some(result) = cache.get(&build) {
        return match result.as_ref() {
            Ok(id) => Ok(id.clone()),
            Err(e) => bail!("{e}"),
        };
    }

    let dockerfile_hash = compute_dockerfile_hash(&build);

    // Check if an image with this hash already exists (from a previous test run)
    if let Some(image_id) = find_existing_image(&dockerfile_hash) {
        cache.insert(build, Arc::new(Ok(image_id.clone())));
        return Ok(image_id);
    }

    // Need to build the image
    let result = do_build_docker_image(&build, &dockerfile_hash);
    let result_arc = Arc::new(match &result {
        Ok(id) => Ok(id.clone()),
        Err(e) => Err(anyhow::anyhow!("{e}")),
    });
    cache.insert(build, result_arc);
    result
}

/// Actually perform the docker build.
fn do_build_docker_image(build: &DockerBuild, dockerfile_hash: &str) -> anyhow::Result<String> {
    // Set up build context directory
    let temp_context: Option<TempDir>;
    let context_path: &Path = if let Some(ref path) = build.build_context {
        path.as_path()
    } else {
        temp_context = Some(TempDir::with_prefix("sandbox-docker-build-")?);
        temp_context.as_ref().unwrap().path()
    };

    // Write the Dockerfile to the context directory
    let dockerfile_path = context_path.join("Dockerfile");
    std::fs::write(&dockerfile_path, &build.dockerfile).context("writing Dockerfile")?;

    let label = format!("{TEST_IMAGE_LABEL}={dockerfile_hash}");
    let dockerfile_path_str = dockerfile_path.to_string_lossy();
    let context_path_str = context_path.to_string_lossy();

    // Build the image
    let output = Command::new("docker")
        .args([
            "build",
            "--label",
            &label,
            "-q", // Quiet mode, only output image ID
            "-f",
            &dockerfile_path_str,
            &context_path_str,
        ])
        .output()
        .context("executing docker build")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("docker build failed: {stderr}");
    }

    let image_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if image_id.is_empty() {
        bail!("docker build returned empty image ID");
    }

    Ok(image_id)
}
