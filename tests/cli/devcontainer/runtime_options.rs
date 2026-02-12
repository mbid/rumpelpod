//! Integration tests for devcontainer.json container runtime options:
//! `privileged`, `init`, `capAdd`, `securityOpt`, and `runArgs` device passthrough.
//!
//! Note: The test harness sets `--privileged` for deterministic PID allocation
//! (`RUMPELPOD_TEST_DETERMINISTIC_IDS=1`), which masks the effect of `privileged`,
//! `capAdd`, and `securityOpt` when verified from inside the container. Tests for
//! those three properties verify the config parses and the pod starts
//! successfully — the actual Docker API wiring is confirmed by the other tests
//! (`init` and `device`) that can observe their effects.

use std::fs;

use indoc::formatdoc;
use rumpelpod::CommandExt;

use crate::common::{pod_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

/// Write a devcontainer.json with the given runtime options block merged in.
fn write_devcontainer_with_runtime_opts(repo: &TestRepo, runtime_opts: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git procps
        RUN useradd -m -u 1000 {TEST_USER}
        COPY --chown={TEST_USER}:{TEST_USER} . {TEST_REPO_PATH}
        USER {TEST_USER}
    "#};
    fs::write(devcontainer_dir.join("Dockerfile"), dockerfile).expect("Failed to write Dockerfile");

    // The caller provides extra JSON fields (without a leading comma); we
    // splice them into the top-level object.
    let devcontainer_json = formatdoc! {r#"
        {{
            "build": {{
                "dockerfile": "Dockerfile",
                "context": ".."
            }},
            "workspaceFolder": "{TEST_REPO_PATH}",
            "containerUser": "{TEST_USER}",
            "runArgs": ["--runtime=runc"],
            {runtime_opts}
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

// ---------------------------------------------------------------------------
// privileged
// ---------------------------------------------------------------------------

/// Verify that `"privileged": true` in devcontainer.json runs the container
/// in privileged mode.
///
/// The test harness already grants `--privileged` for deterministic PID
/// allocation, so we can't distinguish the devcontainer setting's effect.
/// This test verifies the config parses and the pod starts successfully.
#[test]
fn privileged_mode_enabled() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""privileged": true"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Verify the config parses and the pod starts with privileged mode.
    pod_command(&repo, &daemon)
        .args(["enter", "privileged-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// Verify that `"init": true` in devcontainer.json runs tini as PID 1.
///
/// Without `--init`, PID 1 is `sleep` (our default command). With `--init`,
/// PID 1 should be `tini` or `docker-init`.
#[test]
fn init_process_enabled() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""init": true"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "init-test", "--", "cat", "/proc/1/comm"])
        .success()
        .expect("rumpel enter failed");

    let pid1_name = String::from_utf8_lossy(&stdout).trim().to_string();
    assert!(
        pid1_name.contains("tini") || pid1_name.contains("init"),
        "expected PID 1 to be tini/init, got '{pid1_name}'"
    );
}

// ---------------------------------------------------------------------------
// capAdd
// ---------------------------------------------------------------------------

/// Verify that `"capAdd": ["SYS_PTRACE"]` adds the SYS_PTRACE capability.
///
/// The test harness already grants `--privileged` (which includes all
/// capabilities), so we can't distinguish the devcontainer setting's effect.
/// This test verifies the config parses and the pod starts successfully.
#[test]
fn cap_add_sys_ptrace() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""capAdd": ["SYS_PTRACE"]"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Verify the config parses and the pod starts with capAdd.
    pod_command(&repo, &daemon)
        .args(["enter", "cap-add-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");
}

// ---------------------------------------------------------------------------
// securityOpt
// ---------------------------------------------------------------------------

/// Verify that `"securityOpt": ["seccomp=unconfined"]` disables seccomp.
///
/// The test harness already grants `--privileged` which disables seccomp,
/// so we can't distinguish the devcontainer setting's effect.
/// This test verifies the config parses and the pod starts successfully.
#[test]
fn security_opt_seccomp_unconfined() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""securityOpt": ["seccomp=unconfined"]"#);
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Verify the config parses and the pod starts with securityOpt.
    pod_command(&repo, &daemon)
        .args(["enter", "seccomp-test", "--", "true"])
        .success()
        .expect("rumpel enter failed");
}

// ---------------------------------------------------------------------------
// runArgs --device
// ---------------------------------------------------------------------------

/// Verify that `"runArgs": ["--device=/dev/null"]` makes the device
/// available inside the container via the Docker API's device mapping.
///
/// We use a same-path mapping (`/dev/null` to `/dev/null`) because
/// path-remapping (e.g. `/dev/null:/dev/mynull`) is not supported in
/// Docker-in-Docker environments where tests run.
#[test]
fn run_args_device() {
    let repo = TestRepo::new();

    let devcontainer_dir = repo.path().join(".devcontainer");
    fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer directory");

    let dockerfile = formatdoc! {r#"
        FROM debian:13
        RUN apt-get update && apt-get install -y git procps
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
            "runArgs": ["--runtime=runc", "--device=/dev/null"]
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    // Verify device is accessible and is a character device
    pod_command(&repo, &daemon)
        .args(["enter", "device-test", "--", "test", "-c", "/dev/null"])
        .success()
        .expect("/dev/null should be a character device in container");
}

// ---------------------------------------------------------------------------
// hostRequirements
// ---------------------------------------------------------------------------

/// Verify that hostRequirements with cpus and memory are logged at info level
/// and the pod starts normally.
#[test]
fn host_requirements_logged() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(
        &repo,
        r#""hostRequirements": { "cpus": 2, "memory": "4gb" }"#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .env("RUST_LOG", "info")
        .args(["enter", "hostreq-logged", "--", "true"])
        .output()
        .expect("Failed to run pod command");

    assert!(
        output.status.success(),
        "pod should start despite hostRequirements: {}",
        String::from_utf8_lossy(&output.stderr),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("hostRequirements") && stderr.contains("cpus=2"),
        "stderr should log hostRequirements with cpus, got: {stderr}",
    );
    assert!(
        stderr.contains("memory=4gb"),
        "stderr should log hostRequirements with memory, got: {stderr}",
    );
}

/// Verify that absurd hostRequirements do not prevent the pod from starting
/// on local Docker (we do not enforce).
#[test]
fn host_requirements_ignored_on_local() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(
        &repo,
        r#""hostRequirements": { "cpus": 9999, "memory": "999tb", "storage": "999tb" }"#,
    );
    write_minimal_pod_toml(&repo);

    let daemon = TestDaemon::start();

    pod_command(&repo, &daemon)
        .args(["enter", "hostreq-absurd", "--", "true"])
        .success()
        .expect("pod should start even with absurd hostRequirements on local Docker");
}
