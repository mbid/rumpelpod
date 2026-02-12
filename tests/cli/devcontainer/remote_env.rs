use indoc::formatdoc;
use rumpelpod::CommandExt;
use std::fs;

use crate::common::{pod_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

fn write_devcontainer_with_remote_env(repo: &TestRepo, remote_env_config: &str) {
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
            "remoteEnv": {remote_env_config},
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

fn write_minimal_pod_toml(repo: &TestRepo) {
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

/// remoteEnv with a simple static value should be visible in `rumpel enter` commands.
#[test]
fn remote_env_simple() {
    let repo = TestRepo::new();

    write_devcontainer_with_remote_env(&repo, r#"{ "MY_VAR": "value" }"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // printenv exits non-zero when the variable is not set, so .success() will
    // fail until remoteEnv injection is implemented.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "renv-simple", "--", "printenv", "MY_VAR"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "value");
}

/// remoteEnv supports ${localEnv:VAR} substitution to forward host variables into the container.
#[test]
fn remote_env_local_env_substitution() {
    let repo = TestRepo::new();

    write_devcontainer_with_remote_env(&repo, r#"{ "VAR": "${localEnv:HOST_VAR}" }"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // printenv exits non-zero when the variable is not set, so .success() will
    // fail until remoteEnv with ${localEnv} substitution is implemented.
    let stdout = pod_command(&repo, &daemon)
        .env("HOST_VAR", "from_host")
        .args(["enter", "renv-local", "--", "printenv", "VAR"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "from_host");
}

/// remoteEnv supports ${containerEnv:VAR} to reference variables already set inside the container.
/// This is the only property where ${containerEnv} is available, since the container must be
/// running to resolve it.
#[test]
fn remote_env_container_env_substitution() {
    let repo = TestRepo::new();

    write_devcontainer_with_remote_env(&repo, r#"{ "PATH": "${containerEnv:PATH}:/extra" }"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // PATH always exists, so printenv will succeed — but without remoteEnv the
    // value won't contain :/extra, so the assertion below will fire.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "renv-cenv", "--", "printenv", "PATH"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.trim().ends_with(":/extra"),
        "Expected PATH to end with ':/extra', got: {stdout}",
    );
    // The container's original PATH should still be present (not empty before :/extra)
    assert!(
        stdout.trim().len() > ":/extra".len(),
        "Expected PATH to contain original container PATH plus :/extra, got: {stdout}",
    );
}

/// remoteEnv should also be applied when running `rumpel agent`. The agent executes
/// commands inside the pod via the same exec mechanism as `rumpel enter`, so
/// remoteEnv must be injected on every exec — not just the first one.
///
/// We verify this by running multiple `rumpel enter` execs against the same pod
/// and confirming the variable is present each time. This is the same code path that
/// the agent's bash tool uses.
#[test]
fn remote_env_available_in_agent() {
    let repo = TestRepo::new();

    write_devcontainer_with_remote_env(&repo, r#"{ "AGENT_TEST_VAR": "agent_value" }"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // First exec — creates the pod and runs a command
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "renv-agent", "--", "printenv", "AGENT_TEST_VAR"])
        .success()
        .expect("rumpel enter failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "agent_value");

    // Second exec into the same pod — simulates what the agent's bash tool does
    // on subsequent tool calls. remoteEnv must be injected every time, not just once.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "renv-agent", "--", "printenv", "AGENT_TEST_VAR"])
        .success()
        .expect("rumpel enter (second exec) failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "agent_value");
}

/// remoteEnv should NOT affect the container's own process environment — only processes
/// started via `rumpel enter` or `rumpel agent`. A background process started by the
/// container (not via rumpel enter) should not have remoteEnv variables.
///
/// We verify this with a two-phase approach using containerEnv as a control:
/// set a variable via containerEnv (which should be in all processes) and a different
/// one via remoteEnv (which should only be in exec sessions). Then check that
/// PID 1's environment has the containerEnv var but not the remoteEnv var.
#[test]
fn remote_env_not_in_container_processes() {
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

    // Use both containerEnv (visible to all processes) and remoteEnv (exec-only)
    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "containerEnv": {{ "CONTAINER_MARKER": "present" }},
            "remoteEnv": {{ "REMOTE_ONLY": "secret" }},
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

    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Verify remoteEnv IS visible in rumpel enter (this panics until implemented)
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "renv-bg", "--", "printenv", "REMOTE_ONLY"])
        .success()
        .expect("rumpel enter failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "secret");

    // Verify containerEnv is visible in rumpel enter (control)
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "renv-bg", "--", "printenv", "CONTAINER_MARKER"])
        .success()
        .expect("rumpel enter (container marker) failed");
    let stdout = String::from_utf8_lossy(&stdout);
    assert_eq!(stdout.trim(), "present");

    // Read PID 1's environment — it should have CONTAINER_MARKER but NOT REMOTE_ONLY.
    // We use xargs with /proc/1/environ (null-delimited) to get a readable format.
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "renv-bg",
            "--",
            "sh",
            "-c",
            "tr '\\0' '\\n' < /proc/1/environ",
        ])
        .success()
        .expect("rumpel enter (read pid 1 env) failed");
    let stdout = String::from_utf8_lossy(&stdout);

    assert!(
        stdout.contains("CONTAINER_MARKER=present"),
        "PID 1 should have containerEnv variables as a control, got: {stdout}",
    );
    assert!(
        !stdout.contains("REMOTE_ONLY"),
        "PID 1 should NOT have remoteEnv variables, but found REMOTE_ONLY in: {stdout}",
    );
}

fn write_devcontainer_with_user_env_probe(repo: &TestRepo, probe_value: Option<&str>) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    // Add a PATH entry via .profile so loginShell probing can discover it
    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git
        RUN useradd -m -u 1000 {TEST_USER}
        RUN echo 'export PATH=$PATH:/custom/probe/bin' >> /home/{TEST_USER}/.profile
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};
    fs::write(devcontainer_dir.join("Dockerfile"), dockerfile).expect("Failed to write Dockerfile");

    let probe_line = match probe_value {
        Some(v) => format!(r#""userEnvProbe": "{v}","#),
        None => String::new(),
    };

    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            {probe_line}
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

/// userEnvProbe "loginShell" sources .profile, making PATH additions visible.
#[test]
fn user_env_probe_login_shell() {
    let repo = TestRepo::new();

    write_devcontainer_with_user_env_probe(&repo, Some("loginShell"));
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "probe-login", "--", "printenv", "PATH"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        stdout.contains("/custom/probe/bin"),
        "Expected PATH to contain /custom/probe/bin from .profile, got: {stdout}",
    );
}

/// userEnvProbe "none" skips shell init files, so .profile additions are invisible.
#[test]
fn user_env_probe_none() {
    let repo = TestRepo::new();

    write_devcontainer_with_user_env_probe(&repo, Some("none"));
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "probe-none", "--", "printenv", "PATH"])
        .success()
        .expect("rumpel enter failed");

    let stdout = String::from_utf8_lossy(&stdout);
    assert!(
        !stdout.contains("/custom/probe/bin"),
        "Expected PATH to NOT contain /custom/probe/bin with probe=none, got: {stdout}",
    );
}
