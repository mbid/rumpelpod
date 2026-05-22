// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use indoc::formatdoc;
use rumpelpod::CommandExt;
use std::fs;

use crate::common::{pod_command, TestDaemon, TestHome, TestRepo, TEST_REPO_PATH, TEST_USER};
use crate::executor::ExecutorResources;

fn write_devcontainer_json(repo: &TestRepo, config_body: &str) {
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
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            {config_body}
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

/// ${localEnv:MISSING:default_value} should fall back to the default when the
/// environment variable is not set.
#[test]
fn local_env_with_default() {
    let repo = TestRepo::new();

    write_devcontainer_json(
        &repo,
        r#""containerEnv": { "FALLBACK": "${localEnv:MISSING:default_value}" }"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "env-default",
            "--",
            "printenv",
            "FALLBACK",
        ])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        "default_value",
        "localEnv default substitution not implemented"
    );
}

/// ${localWorkspaceFolder} resolves to the absolute host path of the
/// workspace. We expose it via containerEnv so we can read it back.
#[test]
fn local_workspace_folder() {
    let repo = TestRepo::new();

    write_devcontainer_json(
        &repo,
        r#""containerEnv": { "HOST_PATH": "${localWorkspaceFolder}" }"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "lwf", "--", "printenv", "HOST_PATH"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    // On macOS, getcwd() resolves symlinks (e.g. /var -> /private/var),
    // so the daemon sees the canonical path. Compare canonicalized paths.
    let expected = std::fs::canonicalize(repo.path()).unwrap_or_else(|_| repo.path().to_path_buf());
    assert_eq!(
        stdout.trim(),
        expected.to_string_lossy().as_ref(),
        "localWorkspaceFolder substitution not implemented"
    );
}

/// ${localWorkspaceFolderBasename} resolves to just the directory name
/// (not the full path) of the host workspace folder.
#[test]
fn local_workspace_folder_basename() {
    let repo = TestRepo::new();

    write_devcontainer_json(
        &repo,
        r#""containerEnv": { "WS_NAME": "${localWorkspaceFolderBasename}" }"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "lwfb", "--", "printenv", "WS_NAME"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    let expected = repo
        .path()
        .file_name()
        .expect("repo path should have a basename")
        .to_string_lossy();
    assert_eq!(
        stdout.trim(),
        expected.as_ref(),
        "localWorkspaceFolderBasename substitution not implemented"
    );
}

/// ${containerWorkspaceFolder} resolves to the workspace path inside the
/// container, which should match the workspaceFolder setting.
#[test]
fn container_workspace_folder() {
    let repo = TestRepo::new();

    write_devcontainer_json(
        &repo,
        r#""containerEnv": { "CWF": "${containerWorkspaceFolder}" }"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "cwf", "--", "printenv", "CWF"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(
        stdout.trim(),
        TEST_REPO_PATH,
        "containerWorkspaceFolder substitution not implemented"
    );
}

/// ${containerWorkspaceFolderBasename} resolves to just the directory name
/// of the workspace folder inside the container.
#[test]
fn container_workspace_folder_basename() {
    let repo = TestRepo::new();

    write_devcontainer_json(
        &repo,
        r#""containerEnv": { "CWF_BASE": "${containerWorkspaceFolderBasename}" }"#,
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "cwfb", "--", "printenv", "CWF_BASE"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    let expected = std::path::Path::new(TEST_REPO_PATH)
        .file_name()
        .expect("TEST_REPO_PATH should have a basename")
        .to_string_lossy();
    assert_eq!(
        stdout.trim(),
        expected.as_ref(),
        "containerWorkspaceFolderBasename substitution not implemented"
    );
}

/// ${devcontainerId} must be stable across pod rebuilds -- destroying and
/// recreating a pod for the same repo+name should yield the same ID.
#[test]
fn devcontainer_id_stable() {
    let repo = TestRepo::new();

    write_devcontainer_json(&repo, r#""containerEnv": { "DC_ID": "${devcontainerId}" }"#);
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // First creation -- capture the ID.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "id-stable", "--", "printenv", "DC_ID"])
        .success()
        .expect("rumpel enter failed");
    let id_first = String::from_utf8_lossy(&stdout).trim().to_string();

    // A literal "${devcontainerId}" means substitution didn't happen.
    assert!(
        !id_first.contains("${"),
        "devcontainerId substitution not implemented"
    );

    // Recreate the pod (destroy + create).
    pod_command(&repo, &daemon)
        .args(["recreate", "id-stable"])
        .success()
        .expect("pod recreate failed");

    // Second creation -- ID should be identical.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "--create", "id-stable", "--", "printenv", "DC_ID"])
        .success()
        .expect("rumpel enter failed");
    let id_second = String::from_utf8_lossy(&stdout).trim().to_string();

    assert_eq!(
        id_first, id_second,
        "devcontainerId must be stable across rebuilds"
    );
}

/// Different pods (different names or repos) must receive distinct
/// ${devcontainerId} values.
#[test]
fn devcontainer_id_unique_per_pod() {
    let repo = TestRepo::new();

    write_devcontainer_json(&repo, r#""containerEnv": { "DC_ID": "${devcontainerId}" }"#);
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Pod A
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "id-unique-a",
            "--",
            "printenv",
            "DC_ID",
        ])
        .success()
        .expect("rumpel enter failed");
    let id_a = String::from_utf8_lossy(&stdout).trim().to_string();

    // Pod B (same repo, different name)
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "id-unique-b",
            "--",
            "printenv",
            "DC_ID",
        ])
        .success()
        .expect("rumpel enter failed");
    let id_b = String::from_utf8_lossy(&stdout).trim().to_string();

    assert_ne!(
        id_a, id_b,
        "devcontainerId per-pod uniqueness not implemented"
    );
}

/// Variable substitution should work inside runArgs -- here we use
/// ${localWorkspaceFolderBasename} in a --label flag and verify the
/// container actually received it.
#[test]
fn variables_in_run_args() {
    // Drives `docker ps`/`docker inspect` directly on the host, which
    // only works for the local Docker executor.
    if !matches!(
        crate::executor::executor_mode(),
        crate::executor::ExecutorMode::Docker
    ) {
        crate::executor::skip_test();
        return;
    }
    let repo = TestRepo::new();

    // Override runArgs to include a label with a variable substitution.
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
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": [
                "--label=workspace=${{localWorkspaceFolderBasename}}"
            ]
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Enter the pod so the container is created with the label.
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "run-args-var", "--", "true"])
        .success()
        .expect("rumpel enter failed");

    // Inspect the container to verify the label was set with the resolved value.
    let expected_basename = repo
        .path()
        .file_name()
        .expect("repo path should have a basename")
        .to_string_lossy()
        .to_string();

    // Find the container by the pod-name label rumpelpod sets at
    // creation time; robust against the container-naming scheme.
    let output = std::process::Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            "label=dev.rumpelpod.name=run-args-var",
            "--format",
            "{{.ID}}",
        ])
        .output()
        .expect("docker ps failed");
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        !container_id.is_empty(),
        "container not found for pod run-args-var"
    );

    let output = std::process::Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{index .Config.Labels \"workspace\"}}",
            &container_id,
        ])
        .output()
        .expect("docker inspect failed");
    let label_value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert_eq!(
        label_value, expected_basename,
        "runArgs variable substitution failed"
    );
}

/// ${containerWorkspaceFolder} in mount targets should be resolved.
/// Regression guard for a historical bug where `resolved_mounts()`
/// rejected daemon-side variables before the daemon had a chance to
/// substitute them.
#[test]
#[ignore = "chown-on-fresh-mount-targets runs as image USER (not root) since the executor \
            migration, so images whose USER is a non-root user cannot chown the root-owned \
            mount targets docker creates.  Proper fix: create the mount target dirs during \
            image preparation so docker does not synthesize a root-owned one."]
fn container_workspace_folder_in_mount_target() {
    let repo = TestRepo::new();

    // Mount target uses ${containerWorkspaceFolder} which is only known
    // daemon-side.  The basename of TEST_REPO_PATH ("workspace") lets us
    // construct the expected resolved path.
    let ws_basename = std::path::Path::new(TEST_REPO_PATH)
        .file_name()
        .unwrap()
        .to_string_lossy();
    let expected_mount = format!("/mnt/{ws_basename}");

    write_devcontainer_json(
        &repo,
        &formatdoc! {r#"
            "mounts": [
                {{
                    "target": "/mnt/${{containerWorkspaceFolderBasename}}",
                    "type": "tmpfs"
                }}
            ]
        "#},
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "cwf-mnt",
            "--",
            "stat",
            "-c",
            "%F",
            &expected_mount,
        ])
        .success()
        .expect("rumpel enter with containerWorkspaceFolderBasename mount target failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "directory");
}

/// ${localWorkspaceFolder} in bind mount sources should be resolved so
/// that mounts like "source=${localWorkspaceFolder}/subdir" work.
///
/// Skipped on macOS: Colima only shares $HOME with the Docker VM, but
/// test repos live under /var/folders (macOS TMPDIR), which is outside
/// the shared mount.
#[test]
fn local_workspace_folder_in_bind_mount() {
    if cfg!(target_os = "macos") {
        crate::executor::skip_test();
        return;
    }
    // A host bind mount cannot reach the test process's local path
    // from a remote cluster node.
    if !matches!(
        crate::executor::executor_mode(),
        crate::executor::ExecutorMode::Docker
    ) {
        crate::executor::skip_test();
        return;
    }
    let repo = TestRepo::new();

    // Create a directory with a marker file to mount into the container.
    let mount_src = repo.path().join("cloud");
    fs::create_dir_all(&mount_src).expect("Failed to create cloud directory");
    fs::write(mount_src.join("marker.txt"), "cloud-content").expect("Failed to write marker file");

    write_devcontainer_json(
        &repo,
        &formatdoc! {r#"
            "mounts": [
                {{
                    "source": "${{localWorkspaceFolder}}/cloud",
                    "target": "/cloud",
                    "type": "bind"
                }}
            ]
        "#},
    );
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            "lwf-mnt",
            "--",
            "cat",
            "/cloud/marker.txt",
        ])
        .success()
        .expect("rumpel enter with localWorkspaceFolder bind mount failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "cloud-content");
}

/// ${devcontainerId} in mount sources should be resolved, allowing
/// per-pod named volumes.
#[test]
#[ignore = "chown-on-fresh-mount-targets runs as image USER (not root) since the executor \
            migration, so images whose USER is a non-root user cannot chown the root-owned \
            mount targets docker creates.  Proper fix: create the mount target dirs during \
            image preparation so docker does not synthesize a root-owned one."]
fn variables_in_mounts() {
    let repo = TestRepo::new();

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
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "mounts": [
                {{
                    "source": "${{devcontainerId}}-data",
                    "target": "/data",
                    "type": "volume"
                }}
            ]
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // The mount should succeed now that ${devcontainerId} is resolved.
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "mnt-var", "--", "ls", "/data"])
        .success()
        .expect("rumpel enter with devcontainerId mount failed");
}
