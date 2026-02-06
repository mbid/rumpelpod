//! Integration tests for devcontainer.json container runtime options:
//! `privileged`, `init`, `capAdd`, `securityOpt`, and `runArgs` device passthrough.
//!
//! All tests are marked `#[should_panic]` because these features are not yet implemented.
//! Each specifies an `expected` message so we know the test fails at the right place
//! rather than in unrelated setup code.
//!
//! Note: The test harness sets `--privileged` for deterministic PID allocation
//! (`SANDBOX_TEST_DETERMINISTIC_IDS=1`), which masks the effect of `privileged`,
//! `capAdd`, and `securityOpt` when verified from inside the container. Tests for
//! those three properties create the config and enter the sandbox (proving it parses),
//! then explicitly panic because the devcontainer.json field is not wired through to
//! Docker. When implementing these features, replace the `panic!()` with real
//! assertions — the surrounding verification scaffolding is provided as a guide.

use std::fs;

use indoc::formatdoc;
use sandbox::CommandExt;

use crate::common::{sandbox_command, TestDaemon, TestRepo, TEST_REPO_PATH, TEST_USER};

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

fn write_minimal_sandbox_toml(repo: &TestRepo) {
    let config = formatdoc! {r#"
        [agent]
        model = "claude-sonnet-4-5"
    "#};
    fs::write(repo.path().join(".sandbox.toml"), config).expect("Failed to write .sandbox.toml");
}

// ---------------------------------------------------------------------------
// privileged
// ---------------------------------------------------------------------------

/// Verify that `"privileged": true` in devcontainer.json runs the container
/// in privileged mode.
///
/// The test harness already grants `--privileged` for deterministic PID
/// allocation, so the container capabilities check would pass regardless.
/// We enter the sandbox to prove the config parses, then explicitly panic
/// until the devcontainer.json field is wired to the Docker API.
///
/// Once implemented, replace the panic with:
///   grep CapEff /proc/self/status → verify all capability bits are set.
#[test]
#[should_panic(expected = "privileged from devcontainer.json not yet wired to Docker")]
fn privileged_mode_enabled() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""privileged": true"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Prove the config is valid and the sandbox starts.
    sandbox_command(&repo, &daemon)
        .args(["enter", "privileged-test", "--", "true"])
        .success()
        .expect("sandbox enter failed");

    // TODO: once implemented, verify via CapEff in /proc/self/status
    // that all capability bits are set (e.g. starts_with("0000003f")).
    panic!("privileged from devcontainer.json not yet wired to Docker");
}

// ---------------------------------------------------------------------------
// init
// ---------------------------------------------------------------------------

/// Verify that `"init": true` in devcontainer.json runs tini as PID 1.
///
/// Without `--init`, PID 1 is `sleep` (our default command). When the
/// feature is implemented PID 1 should be `tini` or `docker-init`.
#[test]
#[should_panic(expected = "expected PID 1 to be tini/init")]
fn init_process_enabled() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""init": true"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    let stdout = sandbox_command(&repo, &daemon)
        .args(["enter", "init-test", "--", "cat", "/proc/1/comm"])
        .success()
        .expect("sandbox enter failed");

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
/// capabilities), so checking CapEff would pass regardless. We enter the
/// sandbox to prove the config parses, then explicitly panic until the
/// devcontainer.json field is wired to Docker.
///
/// Once implemented, replace the panic with:
///   check bit 19 (SYS_PTRACE) in CapEff from /proc/self/status.
#[test]
#[should_panic(expected = "capAdd from devcontainer.json not yet wired to Docker")]
fn cap_add_sys_ptrace() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""capAdd": ["SYS_PTRACE"]"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Prove the config is valid and the sandbox starts.
    sandbox_command(&repo, &daemon)
        .args(["enter", "cap-add-test", "--", "true"])
        .success()
        .expect("sandbox enter failed");

    // TODO: once implemented, verify bit 19 (SYS_PTRACE) is set in CapEff.
    panic!("capAdd from devcontainer.json not yet wired to Docker");
}

// ---------------------------------------------------------------------------
// securityOpt
// ---------------------------------------------------------------------------

/// Verify that `"securityOpt": ["seccomp=unconfined"]` disables seccomp.
///
/// The test harness already grants `--privileged` which disables seccomp,
/// so checking /proc/self/status Seccomp field would pass regardless. We
/// enter the sandbox to prove the config parses, then explicitly panic
/// until the devcontainer.json field is wired to Docker.
///
/// Once implemented, replace the panic with:
///   check Seccomp field in /proc/self/status equals 0 (disabled).
#[test]
#[should_panic(expected = "securityOpt from devcontainer.json not yet wired to Docker")]
fn security_opt_seccomp_unconfined() {
    let repo = TestRepo::new();

    write_devcontainer_with_runtime_opts(&repo, r#""securityOpt": ["seccomp=unconfined"]"#);
    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // Prove the config is valid and the sandbox starts.
    sandbox_command(&repo, &daemon)
        .args(["enter", "seccomp-test", "--", "true"])
        .success()
        .expect("sandbox enter failed");

    // TODO: once implemented, verify Seccomp == 0 in /proc/self/status.
    panic!("securityOpt from devcontainer.json not yet wired to Docker");
}

// ---------------------------------------------------------------------------
// runArgs --device
// ---------------------------------------------------------------------------

/// Verify that `"runArgs": ["--device=/dev/null:/dev/mynull"]` makes the
/// device available inside the container.
///
/// Currently `runArgs` only extracts `--runtime` and `--network`; the
/// `--device` flag is silently dropped. The `test -e /dev/mynull` command
/// will exit non-zero, causing `.success()` to return an error.
#[test]
#[should_panic(expected = "/dev/mynull not found")]
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
            "runArgs": ["--runtime=runc", "--device=/dev/null:/dev/mynull"]
        }}
    "#};
    fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    write_minimal_sandbox_toml(&repo);

    let daemon = TestDaemon::start();

    // `test -e` exits non-zero when the path doesn't exist, so .success()
    // returns Err and .expect() panics with our message.
    sandbox_command(&repo, &daemon)
        .args(["enter", "device-test", "--", "test", "-e", "/dev/mynull"])
        .success()
        .expect("/dev/mynull not found in container");
}
