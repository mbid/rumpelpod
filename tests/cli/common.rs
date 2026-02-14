//! Shared test utilities and fixtures.

// Not all test files use all helpers, but we want them available.
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs::FileType;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{bail, Context, Error};
use indoc::formatdoc;
use rumpelpod::CommandExt;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use walkdir::WalkDir;

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

/// A test daemon that manages pods for integration tests.
/// Each test gets its own daemon with an isolated socket and state directory
/// to enable parallel execution without interference.
/// On drop, the daemon process is terminated.
pub struct TestDaemon {
    pub socket_path: PathBuf,
    process: Child,
    #[allow(dead_code)]
    temp_dir: TempDir,
    /// Separate short-path temp dir for the runtime directory on macOS,
    /// where Unix socket paths must be under 104 bytes.
    #[allow(dead_code)]
    runtime_temp_dir: Option<TempDir>,
}

/// Environment variable for custom SSH config file (must match ssh_forward.rs).
const SSH_CONFIG_FILE_ENV: &str = "SSH_CONFIG_FILE";

impl TestDaemon {
    /// Start a new test daemon with an isolated socket and state directory.
    pub fn start() -> Self {
        Self::start_internal(None)
    }

    /// Start a new test daemon with a custom SSH config file.
    ///
    /// This is used for testing SSH remote Docker functionality. The daemon
    /// will use the specified SSH config file for all SSH connections.
    pub fn start_with_ssh_config(ssh_config: &Path) -> Self {
        Self::start_internal(Some(ssh_config))
    }

    fn start_internal(ssh_config: Option<&Path>) -> Self {
        let temp_dir =
            TempDir::with_prefix("rumpelpod-test-").expect("Failed to create temp directory");

        let socket_path = temp_dir.path().join("rumpelpod.sock");
        let state_dir = temp_dir.path().join("state");

        // macOS limits Unix socket paths to 104 bytes. The default TMPDIR
        // on macOS is ~51 chars, making our socket paths too long. Use a
        // short-prefix temp dir under /tmp for the runtime directory.
        let (runtime_dir, runtime_temp_dir) = if cfg!(target_os = "macos") {
            let rt =
                TempDir::with_prefix_in("rp-", "/tmp").expect("Failed to create runtime temp dir");
            let path = rt.path().to_path_buf();
            (path, Some(rt))
        } else {
            (temp_dir.path().join("runtime"), None)
        };

        // Ensure runtime directory exists, including the 'rumpelpod' subdirectory that
        // the daemon expects for the git socket.
        std::fs::create_dir_all(runtime_dir.join("rumpelpod"))
            .expect("Failed to create runtime dir");

        let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("rumpel"));
        cmd.env(SOCKET_PATH_ENV, &socket_path)
            .env(XDG_STATE_HOME_ENV, &state_dir)
            .env("XDG_RUNTIME_DIR", &runtime_dir)
            // Enable deterministic PIDs for test reproducibility
            .env("RUMPELPOD_TEST_DETERMINISTIC_IDS", "1")
            // Write directly to .git/config instead of invoking `git config`
            // to avoid flaky lock failures on overlay2 under heavy parallelism
            .env("RUMPELPOD_TEST_DIRECT_GIT_CONFIG", "1");

        if let Some(config_path) = ssh_config {
            cmd.env(SSH_CONFIG_FILE_ENV, config_path);
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
            temp_dir,
            runtime_temp_dir,
        }
    }

    /// Get the path to the daemon's temporary directory.
    ///
    /// Useful for creating isolated test resources that need to live alongside
    /// the daemon (e.g., deterministic PID files).
    pub fn temp_dir(&self) -> &Path {
        self.temp_dir.path()
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
    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("rumpel"));
    cmd.current_dir(repo.path())
        .env(SOCKET_PATH_ENV, &daemon.socket_path);

    // Default to offline mode for tests unless explicitly configured.
    // This ensures tests don't accidentally depend on ambient API keys.
    if std::env::var("RUMPELPOD_TEST_LLM_OFFLINE").is_err() {
        cmd.env("RUMPELPOD_TEST_LLM_OFFLINE", "1");
    }

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

/// A Docker image ID.
#[derive(Debug, Clone)]
pub struct ImageId(pub String);

impl std::fmt::Display for ImageId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Label key used to identify images built by this test infrastructure.
const TEST_IMAGE_LABEL: &str = "dev.rumpelpod.test.dockerfile_hash";

/// Global cache for built docker images, keyed by the hash of the DockerBuild configuration.
/// The mutex ensures that we can safely insert into the map.
/// The OnceLock ensures that we only build each image once, even if multiple
/// tests request it concurrently.
type ImageCache = BTreeMap<[u8; 32], Arc<OnceLock<anyhow::Result<ImageId>>>>;
#[allow(clippy::type_complexity)]
static DOCKER_IMAGE_CACHE: Mutex<Option<ImageCache>> = Mutex::new(None);

/// Encode a file type as a single byte for hashing.
fn file_type_byte(ft: FileType) -> u8 {
    if ft.is_file() {
        b'f'
    } else if ft.is_dir() {
        b'd'
    } else if ft.is_symlink() {
        b'l'
    } else {
        b'?'
    }
}

/// Compute a SHA256 hash of a directory's contents.
///
/// This walks the directory recursively and hashes:
/// - Relative paths (relative to the walk root)
/// - File types (file, directory, symlink)
/// - Permission modes (Unix)
/// - File contents (for regular files)
/// - Symlink targets (as relative paths within the directory)
///
/// Symlinks are allowed only if they point to a location within the directory being hashed.
/// Returns an error if a symlink points outside the directory.
///
/// Note: Symlinks with absolute or non-normalized paths (e.g., containing `..`) may resolve
/// to the same target as other symlinks with different textual representations. We currently
/// hash the raw link target, so such symlinks would produce different hashes even if they
/// resolve to the same file. This is a known limitation.
pub fn hash_directory(path: &Path) -> std::io::Result<[u8; 32]> {
    let canonical_root = path.canonicalize()?;
    let mut hasher = Sha256::new();

    for entry in WalkDir::new(path).sort_by_file_name() {
        let entry = entry?;

        // Get path relative to the walk root.
        let relative_path = entry
            .path()
            .strip_prefix(path)
            .expect("entry path should start with walk root");

        // Hash the relative path.
        hasher.update(relative_path.to_string_lossy().as_bytes());
        hasher.update(b"\0");

        // Hash the file type.
        hasher.update([file_type_byte(entry.file_type())]);

        // Hash the permission mode.
        let metadata = entry.metadata()?;
        let mode = metadata.permissions().mode();
        hasher.update(mode.to_le_bytes());

        // Hash file contents for regular files.
        if entry.file_type().is_file() {
            let contents = std::fs::read(entry.path())?;
            hasher.update(&contents);
        }

        // For symlinks, validate they point within the directory and hash the target.
        if entry.file_type().is_symlink() {
            let link_target = std::fs::read_link(entry.path())?;

            // Resolve the target relative to the symlink's parent directory.
            let symlink_dir = entry.path().parent().unwrap_or(path);
            let resolved_target = symlink_dir.join(&link_target).canonicalize()?;

            // Verify the resolved target is within the directory being hashed.
            if !resolved_target.starts_with(&canonical_root) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!(
                        "symlink {:?} points outside the directory: {:?}",
                        entry.path(),
                        link_target
                    ),
                ));
            }

            // Hash the relative path of the symlink target within the directory.
            let target_relative = resolved_target
                .strip_prefix(&canonical_root)
                .expect("resolved target should start with canonical root");
            hasher.update(target_relative.to_string_lossy().as_bytes());
            hasher.update(b"\0");
        }
    }

    Ok(hasher.finalize().into())
}

/// Compute a SHA256 hash of the DockerBuild configuration for use as an image label.
fn hash_docker_build(build: &DockerBuild) -> anyhow::Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    hasher.update(build.dockerfile.as_bytes());
    if let Some(ref context) = build.build_context {
        let dir_hash = hash_directory(context)?;
        hasher.update(dir_hash);
    }
    Ok(hasher.finalize().into())
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

/// Build a standardized test image from a host repo directory.
///
/// This creates a Docker image that:
/// - Is based on debian:13 with git installed
/// - Has a non-root user (TEST_USER) with UID TEST_USER_UID
/// - COPYs the host_repo_dir contents to TEST_REPO_PATH, owned by TEST_USER
/// - Sets USER to TEST_USER
/// - Optionally applies extra_dockerfile_lines before the USER directive
///
/// The host repo (including its .git directory) is copied into the container,
/// so the container has a working git repository.
pub fn build_test_image(
    host_repo_dir: &Path,
    extra_dockerfile_lines: &str,
) -> anyhow::Result<ImageId> {
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
        {extra_dockerfile_lines}
    "#};

    build_docker_image(DockerBuild {
        dockerfile,
        build_context: Some(host_repo_dir.to_path_buf()),
    })
}

/// Build a test image without a USER directive.
///
/// Similar to `build_test_image`, but does NOT set the USER directive.
/// Use this to test behavior when the image has no USER set.
pub fn build_test_image_without_user(
    host_repo_dir: &Path,
    extra_dockerfile_lines: &str,
) -> anyhow::Result<ImageId> {
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        {extra_dockerfile_lines}
    "#};

    build_docker_image(DockerBuild {
        dockerfile,
        build_context: Some(host_repo_dir.to_path_buf()),
    })
}

/// Write test configuration files (devcontainer.json + .rumpelpod.toml).
///
/// devcontainer.json gets image, workspaceFolder, and runArgs (runtime=runc).
/// .rumpelpod.toml gets only the runtime setting.
///
/// The user is not specified, so the pod will use the image's USER directive.
/// Use `write_test_pod_config_with_user` if you need to specify a user explicitly.
pub fn write_test_pod_config(repo: &TestRepo, image_id: &ImageId) {
    write_test_devcontainer_json(repo, image_id, "");
    write_test_pod_toml(repo, "");
}

/// Write test configuration files with an explicit containerUser.
pub fn write_test_pod_config_with_user(repo: &TestRepo, image_id: &ImageId, user: &str) {
    let extra = format!(r#","containerUser": "{user}""#);
    write_test_devcontainer_json(repo, image_id, &extra);
    write_test_pod_toml(repo, "");
}

/// Write test configuration files with explicit network configuration.
///
/// The network value ("unsafe-host") is passed via devcontainer.json runArgs
/// (`--network=host`), matching the devcontainer spec.
pub fn write_test_pod_config_with_network(repo: &TestRepo, image_id: &ImageId, network: &str) {
    let run_args = match network {
        "unsafe-host" => r#"["--runtime=runc", "--network=host"]"#,
        _ => r#"["--runtime=runc"]"#,
    };
    write_test_devcontainer_json_with_run_args(repo, image_id, run_args, "");
    write_test_pod_toml(repo, "");
}

/// Write a devcontainer.json for tests. `extra_json` is spliced as additional
/// top-level JSON fields (include a leading comma if non-empty).
fn write_test_devcontainer_json(repo: &TestRepo, image_id: &ImageId, extra_json: &str) {
    write_test_devcontainer_json_with_run_args(repo, image_id, r#"["--runtime=runc"]"#, extra_json);
}

/// Write a devcontainer.json with custom runArgs and optional extra JSON fields.
fn write_test_devcontainer_json_with_run_args(
    repo: &TestRepo,
    image_id: &ImageId,
    run_args: &str,
    extra_json: &str,
) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_id}",
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": {run_args}{extra_json}
        }}
    "#};
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

/// Write a .rumpelpod.toml for tests. `extra_toml` is appended after the
/// default content (which is currently empty, since runtime comes from
/// devcontainer.json's runArgs).
fn write_test_pod_toml(repo: &TestRepo, extra_toml: &str) {
    let config = format!("{extra_toml}\n");
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
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
pub fn build_docker_image(build: DockerBuild) -> anyhow::Result<ImageId> {
    let build_hash = hash_docker_build(&build)?;

    let cell = {
        let mut cache_guard = DOCKER_IMAGE_CACHE.lock().unwrap();
        let cache = cache_guard.get_or_insert_with(BTreeMap::new);
        cache
            .entry(build_hash)
            .or_insert_with(|| Arc::new(OnceLock::new()))
            .clone()
    };

    let result = cell.get_or_init(|| {
        let build_hash_hex = hex::encode(build_hash);

        // Check if an image with this hash already exists (from a previous test run).
        if let Some(image_id) = find_existing_image(&build_hash_hex) {
            return Ok(ImageId(image_id));
        }

        // Need to build the image.
        do_build_docker_image(&build, &build_hash_hex)
    });

    match result {
        Ok(id) => Ok(id.clone()),
        Err(e) => Err(Error::msg(e.to_string())),
    }
}

/// Actually perform the docker build.
fn do_build_docker_image(build: &DockerBuild, dockerfile_hash: &str) -> anyhow::Result<ImageId> {
    // Set up build context directory
    let temp_context: Option<TempDir>;
    let context_path: &Path = if let Some(ref path) = build.build_context {
        path.as_path()
    } else {
        temp_context = Some(TempDir::with_prefix("rumpelpod-docker-build-")?);
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

    Ok(ImageId(image_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn hash_directory_identical_trees_produce_same_hash() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        // Create identical file structures in both directories.
        fs::write(dir1.path().join("file.txt"), "hello world").unwrap();
        fs::write(dir2.path().join("file.txt"), "hello world").unwrap();

        fs::create_dir(dir1.path().join("subdir")).unwrap();
        fs::create_dir(dir2.path().join("subdir")).unwrap();

        fs::write(dir1.path().join("subdir/nested.txt"), "nested content").unwrap();
        fs::write(dir2.path().join("subdir/nested.txt"), "nested content").unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_directory_different_content_produces_different_hash() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        fs::write(dir1.path().join("file.txt"), "hello world").unwrap();
        fs::write(dir2.path().join("file.txt"), "hello universe").unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_directory_different_filenames_produces_different_hash() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        fs::write(dir1.path().join("file_a.txt"), "same content").unwrap();
        fs::write(dir2.path().join("file_b.txt"), "same content").unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_directory_different_permissions_produces_different_hash() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        let path1 = dir1.path().join("file.txt");
        let path2 = dir2.path().join("file.txt");

        fs::write(&path1, "same content").unwrap();
        fs::write(&path2, "same content").unwrap();

        // Set different permissions.
        fs::set_permissions(&path1, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(&path2, fs::Permissions::from_mode(0o755)).unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_directory_different_structure_produces_different_hash() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        // dir1: file at root level.
        fs::write(dir1.path().join("file.txt"), "content").unwrap();

        // dir2: same file but in a subdirectory.
        fs::create_dir(dir2.path().join("subdir")).unwrap();
        fs::write(dir2.path().join("subdir/file.txt"), "content").unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_directory_empty_directories_are_equal() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_directory_is_deterministic() {
        let dir = TempDir::with_prefix("hash-test-").unwrap();

        fs::write(dir.path().join("a.txt"), "aaa").unwrap();
        fs::write(dir.path().join("b.txt"), "bbb").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/c.txt"), "ccc").unwrap();

        // Hash the same directory multiple times.
        let hash1 = hash_directory(dir.path()).unwrap();
        let hash2 = hash_directory(dir.path()).unwrap();
        let hash3 = hash_directory(dir.path()).unwrap();

        assert_eq!(hash1, hash2);
        assert_eq!(hash2, hash3);
    }

    #[test]
    fn hash_directory_symlinks_within_directory_allowed() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        // Create a real file in dir1.
        fs::write(dir1.path().join("target.txt"), "target content").unwrap();

        // Create a symlink in dir1 pointing to target.txt using a relative path.
        std::os::unix::fs::symlink("target.txt", dir1.path().join("link.txt")).unwrap();

        // Create the same structure in dir2.
        fs::write(dir2.path().join("target.txt"), "target content").unwrap();
        std::os::unix::fs::symlink("target.txt", dir2.path().join("link.txt")).unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        // Both should be equal since they have identical structures and symlink targets.
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_directory_symlinks_different_targets_produce_different_hash() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        // Create target files in both directories.
        fs::write(dir1.path().join("target_a.txt"), "content").unwrap();
        fs::write(dir1.path().join("target_b.txt"), "content").unwrap();
        fs::write(dir2.path().join("target_a.txt"), "content").unwrap();
        fs::write(dir2.path().join("target_b.txt"), "content").unwrap();

        // Create symlinks pointing to different targets.
        std::os::unix::fs::symlink("target_a.txt", dir1.path().join("link.txt")).unwrap();
        std::os::unix::fs::symlink("target_b.txt", dir2.path().join("link.txt")).unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        // Different symlink targets should produce different hashes.
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_directory_symlink_outside_directory_fails() {
        let dir = TempDir::with_prefix("hash-test-").unwrap();
        let outside_file = TempDir::with_prefix("hash-test-outside-").unwrap();
        let outside_path = outside_file.path().join("external.txt");
        fs::write(&outside_path, "external content").unwrap();

        // Create a symlink pointing outside the directory.
        std::os::unix::fs::symlink(&outside_path, dir.path().join("bad_link.txt")).unwrap();

        let result = hash_directory(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("points outside the directory"));
    }

    #[test]
    fn hash_directory_symlink_to_subdirectory_allowed() {
        let dir = TempDir::with_prefix("hash-test-").unwrap();

        // Create a subdirectory with a file.
        fs::create_dir(dir.path().join("subdir")).unwrap();
        fs::write(dir.path().join("subdir/file.txt"), "content").unwrap();

        // Create a symlink in root pointing to the file in subdirectory.
        std::os::unix::fs::symlink("subdir/file.txt", dir.path().join("link.txt")).unwrap();

        // This should succeed since the target is within the directory.
        let result = hash_directory(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn hash_directory_symlink_with_parent_refs_within_directory_allowed() {
        let dir = TempDir::with_prefix("hash-test-").unwrap();

        // Create a subdirectory with a symlink that uses .. to reference a file in the parent.
        fs::write(dir.path().join("target.txt"), "content").unwrap();
        fs::create_dir(dir.path().join("subdir")).unwrap();
        std::os::unix::fs::symlink("../target.txt", dir.path().join("subdir/link.txt")).unwrap();

        // This should succeed since the resolved target is within the directory.
        let result = hash_directory(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn hash_directory_symlink_escaping_via_parent_refs_fails() {
        let dir = TempDir::with_prefix("hash-test-").unwrap();
        let outside_dir = TempDir::with_prefix("hash-test-outside-").unwrap();
        let outside_file = outside_dir.path().join("external.txt");
        fs::write(&outside_file, "external").unwrap();

        // Create a symlink that uses .. to escape the directory.
        // The actual target depends on where temp dirs are created, so we use an absolute path
        // disguised with parent refs that ultimately escapes.
        std::os::unix::fs::symlink(
            format!(
                "../{}",
                outside_dir.path().file_name().unwrap().to_string_lossy()
            ),
            dir.path().join("escape_link"),
        )
        .unwrap();

        let result = hash_directory(dir.path());
        assert!(result.is_err());
    }

    #[test]
    fn hash_directory_file_vs_dir_produces_different_hash() {
        let dir1 = TempDir::with_prefix("hash-test-").unwrap();
        let dir2 = TempDir::with_prefix("hash-test-").unwrap();

        // In dir1, "entry" is a file.
        fs::write(dir1.path().join("entry"), "").unwrap();

        // In dir2, "entry" is a directory.
        fs::create_dir(dir2.path().join("entry")).unwrap();

        let hash1 = hash_directory(dir1.path()).unwrap();
        let hash2 = hash_directory(dir2.path()).unwrap();

        assert_ne!(hash1, hash2);
    }
}
