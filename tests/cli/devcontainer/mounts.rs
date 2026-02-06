//! Integration tests for devcontainer.json mounts configuration.
//!
//! Tests volume, tmpfs, and string-format mounts as described in
//! docs/devcontainer.md "Priority 5: Mounts and Volumes".

use indoc::formatdoc;
use sandbox::CommandExt;
use std::fs;

use crate::common::{sandbox_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};
use crate::ssh::{create_ssh_config, SshRemoteHost};

/// Extract a short unique ID from a TestRepo's temp directory name.
/// The TempDir suffix is random, so this is safe for concurrent use.
fn repo_id(repo: &TestRepo) -> String {
    repo.path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_string()
}

fn write_devcontainer_with_mounts(repo: &TestRepo, mounts_config: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1000 {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};
    fs::write(devcontainer_dir.join("Dockerfile"), dockerfile).expect("Failed to write Dockerfile");

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "mounts": {mounts_config},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"]
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

fn write_minimal_sandbox_toml(repo: &TestRepo) {
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");
}

/// Volume mount: the target directory should exist and be writable inside the container.
///
/// Docker named volumes are created implicitly when first referenced in a
/// container mount.  We derive the volume name from the repo's temp-dir so
/// that concurrent test runs never collide.
#[test]
fn mount_volume() {
    let repo = TestRepo::new();
    let vol = format!("vol-{}", repo_id(&repo));

    write_devcontainer_with_mounts(
        &repo,
        &format!(r#"[{{"type": "volume", "source": "{vol}", "target": "/data"}}]"#),
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Write a file to /data and read it back to confirm the mount is writable
    let stdout = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "mnt-vol",
            "--",
            "sh",
            "-c",
            "echo hello > /data/testfile && cat /data/testfile",
        ])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "hello");
}

/// tmpfs mount: the target should appear as a tmpfs filesystem.
#[test]
fn mount_tmpfs() {
    let repo = TestRepo::new();

    write_devcontainer_with_mounts(&repo, r#"[{"type": "tmpfs", "target": "/tmp/mytmp"}]"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Verify the mount point exists and is a tmpfs via `mount` output
    let stdout = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "mnt-tmpfs",
            "--",
            "sh",
            "-c",
            "mount | grep /tmp/mytmp",
        ])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("tmpfs"),
        "expected tmpfs mount at /tmp/mytmp, got: {stdout}"
    );
}

/// String-format mount: Docker --mount style comma-separated key=value pairs
/// should be parsed the same as the object format.
#[test]
fn mount_string_format() {
    let repo = TestRepo::new();
    let vol = format!("vol-{}", repo_id(&repo));

    write_devcontainer_with_mounts(
        &repo,
        &format!(r#"["type=volume,source={vol},target=/mnt"]"#),
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Write and read back to confirm the volume is mounted and writable
    let stdout = sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "mnt-strfmt",
            "--",
            "sh",
            "-c",
            "echo ok > /mnt/check && cat /mnt/check",
        ])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "ok");
}

/// Volume data should survive a container restart because Docker volumes
/// persist independently of the container lifecycle.
#[test]
fn mount_persists_across_restarts() {
    let repo = TestRepo::new();
    let vol = format!("vol-{}", repo_id(&repo));

    write_devcontainer_with_mounts(
        &repo,
        &format!(r#"[{{"type": "volume", "source": "{vol}", "target": "/data"}}]"#),
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // First run: write a sentinel file into the volume
    sandbox_command(&repo, &daemon)
        .args([
            "enter",
            "mnt-persist",
            "--",
            "sh",
            "-c",
            "echo persisted > /data/sentinel",
        ])
        .success()
        .expect("first sandbox enter failed");

    // Recreate the container (volume should survive)
    sandbox_command(&repo, &daemon)
        .args(["recreate", "mnt-persist"])
        .success()
        .expect("sandbox recreate failed");

    // Second run: the sentinel should still be there
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "mnt-persist", "--", "cat", "/data/sentinel"])
        .success()
        .expect("second sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "persisted");
}

/// Bind mounts should be rejected when using a remote Docker host because
/// the source path would reference the remote filesystem, not the developer's
/// machine — almost certainly not the intended behavior.
#[test]
fn mount_bind_blocked_remote() {
    let repo = TestRepo::new();

    write_devcontainer_with_mounts(
        &repo,
        r#"[{"type": "bind", "source": "/tmp/hostdir", "target": "/mnt/hostdir"}]"#,
    );

    // Point .sandbox.toml at a remote Docker host so the daemon tunnels
    // over SSH.  The devcontainer.json is still used for image build and
    // mounts config.
    let remote = SshRemoteHost::start();
    let ssh_config = create_ssh_config(&[&remote]);
    let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

    let config = formatdoc! {r#"
        host = "{remote_spec}"

        [agent]
        model = "claude-sonnet-4-5"
    "#, remote_spec = remote.ssh_spec()};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");

    // The command should fail with a clear error about bind mounts not
    // being supported on remote Docker.
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", "mnt-bind-remote", "--", "true"])
        .output()
        .expect("failed to execute sandbox enter");

    assert!(
        !output.status.success(),
        "sandbox enter should have rejected bind mount on remote Docker"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("bind") && stderr.to_lowercase().contains("remote"),
        "error should mention bind mounts and remote Docker, got: {stderr}"
    );
}
