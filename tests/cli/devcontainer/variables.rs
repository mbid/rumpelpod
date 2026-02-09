use indoc::formatdoc;
use sandbox::CommandExt;
use std::fs;

use crate::common::{sandbox_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

fn write_devcontainer_json(repo: &TestRepo, config_body: &str) {
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
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"],
            {config_body}
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

/// ${localEnv:MISSING:default_value} should fall back to the default when the
/// environment variable is not set.
#[test]
fn local_env_with_default() {
    let repo = TestRepo::new();

    write_devcontainer_json(
        &repo,
        r#""containerEnv": { "FALLBACK": "${localEnv:MISSING:default_value}" }"#,
    );
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "env-default", "--", "printenv", "FALLBACK"])
        .success()
        .expect("sandbox enter failed");

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
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "lwf", "--", "printenv", "HOST_PATH"])
        .success()
        .expect("sandbox enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    let expected = repo.path().to_string_lossy();
    assert_eq!(
        stdout.trim(),
        expected.as_ref(),
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
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "lwfb", "--", "printenv", "WS_NAME"])
        .success()
        .expect("sandbox enter failed");

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
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "cwf", "--", "printenv", "CWF"])
        .success()
        .expect("sandbox enter failed");

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
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "cwfb", "--", "printenv", "CWF_BASE"])
        .success()
        .expect("sandbox enter failed");

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

/// ${devcontainerId} must be stable across sandbox rebuilds -- destroying and
/// recreating a sandbox for the same repo+name should yield the same ID.
#[test]
fn devcontainer_id_stable() {
    let repo = TestRepo::new();

    write_devcontainer_json(&repo, r#""containerEnv": { "DC_ID": "${devcontainerId}" }"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // First creation — capture the ID.
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "id-stable", "--", "printenv", "DC_ID"])
        .success()
        .expect("sandbox enter failed");
    let id_first = String::from_utf8_lossy(&stdout).trim().to_string();

    // A literal "${devcontainerId}" means substitution didn't happen.
    assert!(
        !id_first.contains("${"),
        "devcontainerId substitution not implemented"
    );

    // Recreate the sandbox (destroy + create).
    sandbox_command(&repo, &daemon)
        .args(["recreate", "id-stable"])
        .success()
        .expect("sandbox recreate failed");

    // Second creation — ID should be identical.
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "id-stable", "--", "printenv", "DC_ID"])
        .success()
        .expect("sandbox enter failed");
    let id_second = String::from_utf8_lossy(&stdout).trim().to_string();

    assert_eq!(
        id_first, id_second,
        "devcontainerId must be stable across rebuilds"
    );
}

/// Different sandboxes (different names or repos) must receive distinct
/// ${devcontainerId} values.
#[test]
fn devcontainer_id_unique_per_sandbox() {
    let repo = TestRepo::new();

    write_devcontainer_json(&repo, r#""containerEnv": { "DC_ID": "${devcontainerId}" }"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Sandbox A
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "id-unique-a", "--", "printenv", "DC_ID"])
        .success()
        .expect("sandbox enter failed");
    let id_a = String::from_utf8_lossy(&stdout).trim().to_string();

    // Sandbox B (same repo, different name)
    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "id-unique-b", "--", "printenv", "DC_ID"])
        .success()
        .expect("sandbox enter failed");
    let id_b = String::from_utf8_lossy(&stdout).trim().to_string();

    assert_ne!(
        id_a, id_b,
        "devcontainerId per-sandbox uniqueness not implemented"
    );
}

/// Variable substitution should work inside runArgs -- here we use
/// ${localWorkspaceFolderBasename} in a --label flag and verify the
/// container actually received it.
#[test]
fn variables_in_run_args() {
    let repo = TestRepo::new();

    // Override runArgs to include a label with a variable substitution.
    // We still need --runtime=runc, so we include both.
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
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": [
                "--runtime=runc",
                "--label=workspace=${{localWorkspaceFolderBasename}}"
            ]
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Enter the sandbox so the container is created with the label.
    sandbox_command(&repo, &daemon)
        .args(["enter", "run-args-var", "--", "true"])
        .success()
        .expect("sandbox enter failed");

    // Inspect the container to verify the label was set with the resolved value.
    let expected_basename = repo
        .path()
        .file_name()
        .expect("repo path should have a basename")
        .to_string_lossy()
        .to_string();

    // Find the container ID by name prefix since the full container name
    // includes a hash suffix that we do not want to recompute in the test.
    let name_prefix = format!(
        "{}-run-args-var",
        repo.path().file_name().unwrap().to_string_lossy()
    );
    let output = std::process::Command::new("docker")
        .args([
            "ps",
            "-a",
            "--filter",
            &format!("name={}", name_prefix),
            "--format",
            "{{.ID}}",
        ])
        .output()
        .expect("docker ps failed");
    let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        !container_id.is_empty(),
        "container not found with name prefix '{}'",
        name_prefix
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

/// ${devcontainerId} in mount sources should be resolved, allowing
/// per-sandbox named volumes.
#[test]
fn variables_in_mounts() {
    let repo = TestRepo::new();

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
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"],
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
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // The mount should succeed now that ${devcontainerId} is resolved.
    sandbox_command(&repo, &daemon)
        .args(["enter", "mnt-var", "--", "ls", "/data"])
        .success()
        .expect("sandbox enter with devcontainerId mount failed");
}
