use indoc::{formatdoc, indoc};
use rumpelpod::CommandExt;
use std::fs;

use crate::common::{pod_command, TestRepo, TEST_REPO_PATH, TEST_USER};
use crate::executor::TestExecutor;

fn write_devcontainer_with_env(repo: &TestRepo, env_config: &str) {
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
            "containerEnv": {env_config},
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

#[test]
fn container_env_simple() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(&repo, r#"{ "MY_VAR": "simple_value" }"#);
    let exec = TestExecutor::start("env-simple");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let stdout = pod_command(&repo, &exec.daemon)
        .args(["enter", "env-simple", "--", "printenv", "MY_VAR"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "simple_value");
}

#[test]
fn container_env_local_substitution() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(&repo, r#"{ "HOST_VAR": "${localEnv:TEST_HOST_VAR}" }"#);
    let exec = TestExecutor::start("env-subst");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // Set the environment variable in the command process
    let stdout = pod_command(&repo, &exec.daemon)
        .env("TEST_HOST_VAR", "secret_value")
        .args(["enter", "env-subst", "--", "printenv", "HOST_VAR"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "secret_value");
}

#[test]
fn container_env_local_substitution_missing() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(
        &repo,
        r#"{ "MISSING_VAR": "${localEnv:NON_EXISTENT_VAR}" }"#,
    );
    let exec = TestExecutor::start("env-missing");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let stdout = pod_command(&repo, &exec.daemon)
        .args(["enter", "env-missing", "--", "printenv", "MISSING_VAR"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "");
}

#[test]
fn container_env_mixed() {
    let repo = TestRepo::new();

    write_devcontainer_with_env(
        &repo,
        r#"{
        "STATIC": "static",
        "DYNAMIC": "${localEnv:TEST_DYNAMIC}"
    }"#,
    );
    let exec = TestExecutor::start("env-mixed");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let stdout = pod_command(&repo, &exec.daemon)
        .env("TEST_DYNAMIC", "dynamic")
        .args([
            "enter",
            "env-mixed",
            "--",
            "sh",
            "-c",
            "echo $STATIC $DYNAMIC",
        ])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "static dynamic");
}

#[test]
fn container_env_recreate() {
    let repo = TestRepo::new();

    // Initial config
    write_devcontainer_with_env(&repo, r#"{ "MY_VAR": "value1" }"#);
    let exec = TestExecutor::start("recreate-env");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    // First enter
    let stdout = pod_command(&repo, &exec.daemon)
        .args(["enter", "recreate-env", "--", "printenv", "MY_VAR"])
        .success()
        .expect("rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "value1");

    // Update config
    write_devcontainer_with_env(&repo, r#"{ "MY_VAR": "value2" }"#);

    // Recreate
    pod_command(&repo, &exec.daemon)
        .args(["recreate", "recreate-env"])
        .success()
        .expect("pod recreate failed");

    // Verify new env var
    let stdout = pod_command(&repo, &exec.daemon)
        .args(["enter", "recreate-env", "--", "printenv", "MY_VAR"])
        .success()
        .expect("rumpel enter failed");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "value2");
}

// ---------------------------------------------------------------------------
// --env-file in runArgs
// ---------------------------------------------------------------------------

fn write_devcontainer_with_env_file(repo: &TestRepo, env_file_run_arg: &str) {
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
            "runArgs": ["--runtime=runc", {env_file_run_arg}]
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");
}

/// An .env file referenced via `--env-file` in runArgs should be read on the
/// client side and its variables injected into the container.
#[test]
fn env_file_basic() {
    let repo = TestRepo::new();

    fs::write(
        repo.path().join(".env"),
        indoc! {"
            MY_SECRET=hunter2
            OTHER_VAR=hello world
        "},
    )
    .expect("Failed to write .env");

    write_devcontainer_with_env_file(&repo, r#""--env-file", ".env""#);
    let exec = TestExecutor::start("env-file-basic");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let stdout = pod_command(&repo, &exec.daemon)
        .args([
            "enter",
            "env-file-basic",
            "--",
            "sh",
            "-c",
            "echo $MY_SECRET $OTHER_VAR",
        ])
        .success()
        .expect("rumpel enter failed");

    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "hunter2 hello world"
    );
}

/// Comments and blank lines in .env files should be ignored.
#[test]
fn env_file_comments_and_blanks() {
    let repo = TestRepo::new();

    fs::write(
        repo.path().join(".env"),
        indoc! {"
            # This is a comment
            KEEP=yes

            # Another comment
            ALSO_KEEP=also yes
        "},
    )
    .expect("Failed to write .env");

    write_devcontainer_with_env_file(&repo, r#""--env-file", ".env""#);
    let exec = TestExecutor::start("env-file-comments");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let stdout = pod_command(&repo, &exec.daemon)
        .args([
            "enter",
            "env-file-comments",
            "--",
            "sh",
            "-c",
            "echo $KEEP $ALSO_KEEP",
        ])
        .success()
        .expect("rumpel enter failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "yes also yes");
}

/// --env-file=path (equals form) should work the same as --env-file path.
#[test]
fn env_file_equals_form() {
    let repo = TestRepo::new();

    fs::write(repo.path().join(".env"), "EQ_VAR=from_equals\n").expect("Failed to write .env");

    write_devcontainer_with_env_file(&repo, r#""--env-file=.env""#);
    let exec = TestExecutor::start("env-file-eq");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let stdout = pod_command(&repo, &exec.daemon)
        .args(["enter", "env-file-eq", "--", "printenv", "EQ_VAR"])
        .success()
        .expect("rumpel enter failed");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "from_equals");
}

/// Variables from --env-file should be merged with containerEnv.
/// containerEnv values should take precedence over --env-file values
/// since containerEnv is more explicit.
#[test]
fn env_file_merged_with_container_env() {
    let repo = TestRepo::new();

    fs::write(
        repo.path().join(".env"),
        indoc! {"
            FROM_FILE=file_value
            SHARED=from_file
        "},
    )
    .expect("Failed to write .env");

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
            "containerEnv": {{
                "FROM_JSON": "json_value",
                "SHARED": "from_json"
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc", "--env-file", ".env"]
        }}
    "#};

    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    let exec = TestExecutor::start("env-file-merge");
    fs::write(repo.path().join(".rumpelpod.toml"), &exec.toml).unwrap();

    let stdout = pod_command(&repo, &exec.daemon)
        .args([
            "enter",
            "env-file-merge",
            "--",
            "sh",
            "-c",
            "echo $FROM_FILE $FROM_JSON $SHARED",
        ])
        .success()
        .expect("rumpel enter failed");

    assert_eq!(
        String::from_utf8_lossy(&stdout).trim(),
        "file_value json_value from_json"
    );
}
