// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for devcontainer.json mounts configuration:
//! volume, tmpfs, and string-format mounts.

use indoc::formatdoc;
use rumpelpod::CommandExt;
use std::fs;

use crate::common::{pod_command, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER};
use crate::executor::{ExecutorMode, ExecutorResources};
use crate::ssh::{write_ssh_config, SshRemoteHost};

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
        FROM cgr.dev/chainguard/wolfi-base
        RUN apk add --no-cache git shadow
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
            "containerUser": "{TEST_USER}"
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

fn alternate_id(id: u32) -> u32 {
    if id == 20_001 {
        20_002
    } else {
        20_001
    }
}

fn write_user_id_devcontainer(
    repo: &TestRepo,
    mounts_config: &str,
    update_remote_user_uid: Option<bool>,
) -> (u32, u32) {
    let host_uid = nix::unistd::getuid().as_raw();
    let host_gid = nix::unistd::getgid().as_raw();
    let image_uid = alternate_id(host_uid);
    let image_gid = alternate_id(host_gid);
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("create devcontainer directory");
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {r#"
            FROM cgr.dev/chainguard/wolfi-base
            RUN apk add --no-cache git shadow
            RUN groupadd -g {image_gid} {TEST_USER} \
                && useradd -m -u {image_uid} -g {image_gid} {TEST_USER} \
                && echo image-owned > /home/{TEST_USER}/image-owned \
                && chown {image_uid}:{image_gid} /home/{TEST_USER}/image-owned \
                && mkdir -p /workspaces/reference-project \
                && echo image-owned > /workspaces/reference-project/image-owned \
                && chown -R {image_uid}:{image_gid} /workspaces/reference-project
            USER {TEST_USER}
        "#},
    )
    .expect("write Dockerfile");

    let update_field = match update_remote_user_uid {
        Some(value) => format!(",\n    \"updateRemoteUserUID\": {value}"),
        None => String::new(),
    };
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "containerUser": "{TEST_USER}",
                "mounts": {mounts_config}{update_field}
            }}
        "#},
    )
    .expect("write devcontainer.json");

    (image_uid, image_gid)
}

fn require_local_linux_executor() -> bool {
    if !cfg!(target_os = "linux") {
        crate::executor::skip_test();
        return false;
    }
    match crate::executor::executor_mode() {
        ExecutorMode::Docker | ExecutorMode::Podman => true,
        ExecutorMode::Ssh | ExecutorMode::K8s => {
            crate::executor::skip_test();
            false
        }
    }
}

fn enter_user_ids(repo: &TestRepo, daemon: &TestDaemon, pod_name: &str) -> (u32, u32) {
    let output = pod_command(repo, daemon)
        .args([
            "enter",
            "--create",
            pod_name,
            "--",
            "sh",
            "-c",
            "id -u; id -g",
        ])
        .success()
        .expect("enter pod and read user IDs");
    let output = String::from_utf8(output).expect("id output is UTF-8");
    let mut lines = output.lines();
    let uid = lines
        .next()
        .expect("id output has UID")
        .parse()
        .expect("UID is numeric");
    let gid = lines
        .next()
        .expect("id output has GID")
        .parse()
        .expect("GID is numeric");
    assert_eq!(lines.next(), None, "id output has only UID and GID");
    (uid, gid)
}

#[test]
fn remote_user_uid_defaults_on_for_local_bind_mount() {
    if !require_local_linux_executor() {
        return;
    }
    let repo = TestRepo::new();
    let bind_source = repo.path().join("uid-bind");
    fs::create_dir(&bind_source).expect("create bind source");
    fs::write(bind_source.join("host-file"), "host\n").expect("write bind source file");
    write_user_id_devcontainer(
        &repo,
        r#"[{"type": "bind", "source": "${localWorkspaceFolder}/uid-bind", "target": "/mnt/uid-bind"}]"#,
        None,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let ids = enter_user_ids(&repo, &daemon, "uid-bind-default");
    assert_eq!(ids.0, nix::unistd::getuid().as_raw());
    assert_eq!(ids.1, nix::unistd::getgid().as_raw());

    let ownership = pod_command(&repo, &daemon)
        .args([
            "enter",
            "uid-bind-default",
            "--",
            "sh",
            "-c",
            r#"stat -c '%u:%g' "$HOME" "$HOME/image-owned" /workspaces/reference-project /workspaces/reference-project/image-owned && touch "$HOME/runtime-owned" /workspaces/reference-project/runtime-owned"#,
        ])
        .success()
        .expect("verify translated image ownership");
    let expected = format!("{0}:{1}\n{0}:{1}\n{0}:{1}\n{0}:{1}\n", ids.0, ids.1);
    assert_eq!(String::from_utf8_lossy(&ownership), expected);

    let contents = pod_command(&repo, &daemon)
        .args([
            "enter",
            "uid-bind-default",
            "--",
            "sh",
            "-c",
            "echo container >> /mnt/uid-bind/host-file && cat /mnt/uid-bind/host-file",
        ])
        .success()
        .expect("write through bind mount as container user");
    assert_eq!(String::from_utf8_lossy(&contents), "host\ncontainer\n");
}

#[test]
fn remote_user_uid_false_disables_local_bind_update() {
    if !require_local_linux_executor() {
        return;
    }
    let repo = TestRepo::new();
    fs::create_dir(repo.path().join("uid-bind")).expect("create bind source");
    let image_ids = write_user_id_devcontainer(
        &repo,
        r#"[{"type": "bind", "source": "${localWorkspaceFolder}/uid-bind", "target": "/mnt/uid-bind"}]"#,
        Some(false),
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    assert_eq!(
        enter_user_ids(&repo, &daemon, "uid-bind-disabled"),
        image_ids
    );
}

#[test]
fn remote_user_uid_true_forces_update_without_bind_mount() {
    if !require_local_linux_executor() {
        return;
    }
    let repo = TestRepo::new();
    write_user_id_devcontainer(&repo, "[]", Some(true));
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    assert_eq!(
        enter_user_ids(&repo, &daemon, "uid-forced"),
        (
            nix::unistd::getuid().as_raw(),
            nix::unistd::getgid().as_raw()
        )
    );
}

#[test]
fn remote_user_uid_stays_off_for_named_volume_by_default() {
    if !require_local_linux_executor() {
        return;
    }
    let repo = TestRepo::new();
    let volume = format!("uid-volume-{}", repo_id(&repo));
    let image_ids = write_user_id_devcontainer(
        &repo,
        &format!(r#"[{{"type": "volume", "source": "{volume}", "target": "/mnt/uid-volume"}}]"#),
        None,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    assert_eq!(
        enter_user_ids(&repo, &daemon, "uid-volume-default"),
        image_ids
    );
}

#[test]
fn remote_user_uid_collision_fails_image_preparation() {
    if !require_local_linux_executor() {
        return;
    }
    let repo = TestRepo::new();
    let host_uid = nix::unistd::getuid().as_raw();
    let host_gid = nix::unistd::getgid().as_raw();
    let image_uid = alternate_id(host_uid);
    let image_gid = alternate_id(host_gid);
    let collision_gid = alternate_id(image_gid);
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("create devcontainer directory");
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {r#"
            FROM cgr.dev/chainguard/wolfi-base
            RUN apk add --no-cache git shadow
            RUN groupadd -g {collision_gid} existing-user \
                && useradd -M -u {host_uid} -g {collision_gid} existing-user \
                && groupadd -g {image_gid} {TEST_USER} \
                && useradd -m -u {image_uid} -g {image_gid} {TEST_USER}
            USER {TEST_USER}
        "#},
    )
    .expect("write Dockerfile");
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
            {{
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "containerUser": "{TEST_USER}",
                "updateRemoteUserUID": true
            }}
        "#},
    )
    .expect("write devcontainer.json");
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "uid-collision", "--", "true"])
        .output()
        .expect("run rumpel enter");
    assert!(!output.status.success(), "UID collision should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("because it belongs to user 'existing-user'")
            && stderr.contains("set updateRemoteUserUID to false"),
        "unexpected error: {stderr}"
    );
}

#[test]
fn remote_user_uid_keeps_image_gid_when_host_gid_is_taken() {
    if !require_local_linux_executor() {
        return;
    }
    let repo = TestRepo::new();
    let host_uid = nix::unistd::getuid().as_raw();
    let host_gid = nix::unistd::getgid().as_raw();
    let image_uid = alternate_id(host_uid);
    let image_gid = alternate_id(host_gid);
    let cache_nonce = repo_id(&repo);
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("create devcontainer directory");
    fs::write(
        devcontainer_dir.join("Dockerfile"),
        formatdoc! {r#"
            FROM cgr.dev/chainguard/wolfi-base
            RUN apk add --no-cache git shadow
            RUN grep -Eq '^[^:]*:[^:]*:{host_gid}:' /etc/group \
                    || groupadd -g {host_gid} existing-group
            RUN groupadd -g {image_gid} {TEST_USER} \
                && useradd -m -u {image_uid} -g {image_gid} {TEST_USER}
            USER {TEST_USER}
        "#},
    )
    .expect("write Dockerfile");
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        formatdoc! {r#"
            {{
                "name": "gid-collision-{cache_nonce}",
                "build": {{
                    "dockerfile": "Dockerfile",
                    "context": ".."
                }},
                "workspaceFolder": "{TEST_REPO_PATH}",
                "containerUser": "{TEST_USER}",
                "updateRemoteUserUID": true
            }}
        "#},
    )
    .expect("write devcontainer.json");
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "gid-collision",
            "--",
            "sh",
            "-c",
            "id -u; id -g",
        ])
        .output()
        .expect("run rumpel enter");
    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{host_uid}\n{image_gid}\n")
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("keeping container user") && stderr.contains("requested GID"),
        "missing GID collision warning: {stderr}"
    );
}

#[test]
fn remote_user_uid_true_is_ignored_for_ssh_executor() {
    if !matches!(crate::executor::executor_mode(), ExecutorMode::Docker) {
        crate::executor::skip_test();
        return;
    }
    let repo = TestRepo::new();
    let image_ids = write_user_id_devcontainer(&repo, "[]", Some(true));
    let home = TestHome::new();
    let remote = SshRemoteHost::start();
    write_ssh_config(&home, &[&remote]);
    let daemon = TestDaemon::start(&home);
    let config = serde_json::to_string(&serde_json::json!({"host": remote.ssh_spec()})).unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), config).unwrap();

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "uid-ssh-unsupported",
            "--",
            "sh",
            "-c",
            "id -u; id -g",
        ])
        .output()
        .expect("run rumpel enter");
    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{}\n{}\n", image_ids.0, image_ids.1)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "updateRemoteUserUID has no effect unless rumpelpod uses a localhost container engine on Linux"
        ),
        "missing unsupported-host warning: {stderr}"
    );
}

#[test]
fn remote_user_uid_true_is_ignored_for_macos_localhost() {
    if !cfg!(target_os = "macos")
        || !matches!(
            crate::executor::executor_mode(),
            ExecutorMode::Docker | ExecutorMode::Podman
        )
    {
        crate::executor::skip_test();
        return;
    }
    let repo = TestRepo::new();
    let image_ids = write_user_id_devcontainer(&repo, "[]", Some(true));
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let output = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "uid-macos-unsupported",
            "--",
            "sh",
            "-c",
            "id -u; id -g",
        ])
        .output()
        .expect("run rumpel enter");
    assert!(
        output.status.success(),
        "rumpel enter failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{}\n{}\n", image_ids.0, image_ids.1)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "updateRemoteUserUID has no effect unless rumpelpod uses a localhost container engine on Linux"
        ),
        "missing unsupported-host warning: {stderr}"
    );
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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Write a file to /data and read it back to confirm the mount is writable
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "mnt-vol",
            "--",
            "sh",
            "-c",
            "echo hello > /data/testfile && cat /data/testfile",
        ])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "hello");
}

/// tmpfs mount: the target should appear as a tmpfs filesystem.
#[test]
fn mount_tmpfs() {
    let repo = TestRepo::new();

    write_devcontainer_with_mounts(&repo, r#"[{"type": "tmpfs", "target": "/tmp/mytmp"}]"#);
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Verify the mount point exists and is a tmpfs via /proc/mounts
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "mnt-tmpfs",
            "--",
            "sh",
            "-c",
            "grep /tmp/mytmp /proc/mounts",
        ])
        .success()
        .expect("rumpel enter failed");

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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Write and read back to confirm the volume is mounted and writable
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "mnt-strfmt",
            "--",
            "sh",
            "-c",
            "echo ok > /mnt/check && cat /mnt/check",
        ])
        .success()
        .expect("rumpel enter failed");

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
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // First run: write a sentinel file into the volume
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "mnt-persist",
            "--",
            "sh",
            "-c",
            "echo persisted > /data/sentinel",
        ])
        .success()
        .expect("first rumpel enter failed");

    // Recreate the container (volume should survive)
    pod_command(&repo, &daemon)
        .args(["recreate", "mnt-persist"])
        .success()
        .expect("pod recreate failed");

    // Second run: the sentinel should still be there
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "mnt-persist",
            "--",
            "cat",
            "/data/sentinel",
        ])
        .success()
        .expect("second rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "persisted");
}

/// Bind mounts on remote Docker hosts are converted to volumes and
/// populated via tar upload.  The source directory contents should
/// appear at the target path inside the container.
#[test]
fn mount_bind_remote_copies_content() {
    // Spins up its own SSH-over-Docker remote, which requires the
    // Docker executor.  The k8s mount path has its own coverage.
    if !matches!(
        crate::executor::executor_mode(),
        crate::executor::ExecutorMode::Docker
    ) {
        crate::executor::skip_test();
        return;
    }
    let repo = TestRepo::new();

    // Create a source directory with test content on the host.
    let bind_src = repo.path().join("bind-src");
    fs::create_dir_all(bind_src.join("sub")).unwrap();
    fs::write(bind_src.join("hello.txt"), "from-host\n").unwrap();
    fs::write(bind_src.join("sub/nested.txt"), "nested\n").unwrap();

    let bind_src_str = bind_src.to_string_lossy();
    write_devcontainer_with_mounts(
        &repo,
        &format!(r#"[{{"type": "bind", "source": "{bind_src_str}", "target": "/mnt/data"}}]"#,),
    );

    let home = TestHome::new();
    let remote = SshRemoteHost::start();
    write_ssh_config(&home, &[&remote]);
    let daemon = TestDaemon::start(&home);

    let config = serde_json::to_string(&serde_json::json!({"host": remote.ssh_spec()})).unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), config).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "mnt-bind-remote",
            "--",
            "sh",
            "-c",
            "cat /mnt/data/hello.txt && cat /mnt/data/sub/nested.txt",
        ])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "from-host\nnested");
}

/// Bind mount sources containing files not owned by the current user
/// should be rejected early, before the pod is created.
#[test]
fn mount_bind_remote_rejects_foreign_owned_files() {
    // Uses an SSH-over-Docker remote; Docker executor only.
    if !matches!(
        crate::executor::executor_mode(),
        crate::executor::ExecutorMode::Docker
    ) {
        crate::executor::skip_test();
        return;
    }
    let repo = TestRepo::new();

    // Use a system path that definitely has root-owned files.
    write_devcontainer_with_mounts(
        &repo,
        r#"[{"type": "bind", "source": "/etc", "target": "/mnt/etc"}]"#,
    );

    let home = TestHome::new();
    let remote = SshRemoteHost::start();
    write_ssh_config(&home, &[&remote]);
    let daemon = TestDaemon::start(&home);

    let config = serde_json::to_string(&serde_json::json!({"host": remote.ssh_spec()})).unwrap();
    fs::write(repo.path().join(".rumpelpod.json"), config).unwrap();

    let output = pod_command(&repo, &daemon)
        .args(["enter", "--create", "mnt-bind-foreign", "--", "true"])
        .output()
        .expect("failed to execute rumpel enter");

    assert!(
        !output.status.success(),
        "rumpel enter should reject bind mount with foreign-owned files"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("owned by uid"),
        "error should mention ownership, got: {stderr}"
    );
}

/// Prepared-image cache must invalidate when a `${localEnv:...}` inside
/// a mount target resolves to a different path: the image bakes in
/// `mkdir`+`chown` for the resolved targets, so reusing an image built
/// for a different resolution would leave docker to synthesize the new
/// target as root-owned and the non-root image USER could not write to
/// the fresh volume.
#[test]
fn mount_target_localenv_change_rebuilds_image() {
    let repo = TestRepo::new();
    let vol_prefix = format!("vol-{}", repo_id(&repo));

    write_devcontainer_with_mounts(
        &repo,
        r#"[{"type": "volume",
             "source": "RUMPELPOD_TEST_MNT_${localEnv:RUMPELPOD_TEST_MNT_NAME}",
             "target": "/mnt/${localEnv:RUMPELPOD_TEST_MNT_NAME}"}]"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let first_name = format!("{vol_prefix}-alpha");
    let first_stdout = pod_command(&repo, &daemon)
        .env("RUMPELPOD_TEST_MNT_NAME", &first_name)
        .args([
            "enter",
            "--create",
            "mnt-env-a",
            "--",
            "sh",
            "-c",
            &format!("echo one > /mnt/{first_name}/f && cat /mnt/{first_name}/f"),
        ])
        .success()
        .expect("first rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&first_stdout).trim(), "one");

    let second_name = format!("{vol_prefix}-beta");
    let second_stdout = pod_command(&repo, &daemon)
        .env("RUMPELPOD_TEST_MNT_NAME", &second_name)
        .args([
            "enter",
            "--create",
            "mnt-env-b",
            "--",
            "sh",
            "-c",
            &format!("echo two > /mnt/{second_name}/f && cat /mnt/{second_name}/f"),
        ])
        .success()
        .expect("second rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&second_stdout).trim(), "two");
}
