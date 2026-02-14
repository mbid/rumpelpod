//! Integration test for system-install/uninstall on Linux (systemd).
//!
//! This test creates a real user on the host, installs the rumpelpod daemon
//! as a systemd user service for that user, exercises enter/delete, then
//! uninstalls and cleans up.  Because it mutates the host (useradd, userdel,
//! loginctl enable-linger), it only runs when RUMPELPOD_TEST_SYSTEMD=1.

use std::process::Command;

use rumpelpod::CommandExt;

const ENV_VAR: &str = "RUMPELPOD_TEST_SYSTEMD";

/// Fail fast with a clear message when the env var is not set.
fn require_systemd_env() {
    if std::env::var(ENV_VAR).as_deref() != Ok("1") {
        panic!(
            "Refusing to run: {ENV_VAR} is not set to 1.\n\
             This test creates/deletes users and systemd services on the host.\n\
             Set {ENV_VAR}=1 to opt in (e.g. inside the devcontainer)."
        );
    }
}

/// A host user that is deleted on drop.
struct TestUser {
    name: String,
    home: String,
}

impl TestUser {
    fn create() -> Self {
        let suffix: u32 = rand::random::<u32>() % 100_000;
        let name = format!("rp_test_{suffix}");
        let home = format!("/home/{name}");

        // Create user with a home directory, bash shell, and docker access.
        Command::new("sudo")
            .args(["useradd", "-m", "-s", "/bin/bash", "-G", "docker", &name])
            .success()
            .unwrap_or_else(|e| panic!("useradd {name} failed: {e}"));

        // systemd user services require linger so that a user manager
        // instance is started even without a login session.
        Command::new("sudo")
            .args(["loginctl", "enable-linger", &name])
            .success()
            .unwrap_or_else(|e| panic!("enable-linger {name} failed: {e}"));

        // Wait for the user manager to start so that the systemd user bus
        // is available for `systemctl --user`.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        loop {
            let ok = Command::new("sudo")
                .args([
                    "-u",
                    &name,
                    "env",
                    &format!("XDG_RUNTIME_DIR=/run/user/{}", uid_of(&name)),
                    "systemctl",
                    "--user",
                    "--version",
                ])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if ok {
                break;
            }
            if std::time::Instant::now() > deadline {
                panic!("systemd user manager for {name} did not start in time");
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }

        TestUser { name, home }
    }

    fn uid(&self) -> u32 {
        uid_of(&self.name)
    }

    /// Run a command as this user with the correct environment.
    fn cmd(&self, program: &str) -> Command {
        let mut cmd = Command::new("sudo");
        cmd.args([
            "-u",
            &self.name,
            "env",
            &format!("XDG_RUNTIME_DIR=/run/user/{}", self.uid()),
            &format!("HOME={}", self.home),
            program,
        ]);
        cmd
    }

    /// Run a shell command string as this user inside the given directory.
    /// Needed because the test runner process cannot chdir into the test
    /// user's home (which has mode 700).
    fn shell_in(&self, dir: &str, shell_cmd: &str) -> Command {
        let mut cmd = Command::new("sudo");
        cmd.args([
            "-u",
            &self.name,
            "env",
            &format!("XDG_RUNTIME_DIR=/run/user/{}", self.uid()),
            &format!("HOME={}", self.home),
            "sh",
            "-c",
            &format!("cd {dir} && {shell_cmd}"),
        ]);
        cmd
    }
}

impl Drop for TestUser {
    fn drop(&mut self) {
        // Stop any systemd services the test user might have left running.
        let _ = Command::new("sudo")
            .args([
                "-u",
                &self.name,
                "env",
                &format!("XDG_RUNTIME_DIR=/run/user/{}", uid_of(&self.name)),
                "systemctl",
                "--user",
                "stop",
                "rumpelpod.socket",
            ])
            .output();
        let _ = Command::new("sudo")
            .args([
                "-u",
                &self.name,
                "env",
                &format!("XDG_RUNTIME_DIR=/run/user/{}", uid_of(&self.name)),
                "systemctl",
                "--user",
                "stop",
                "rumpelpod.service",
            ])
            .output();

        // Disable linger first so the user manager shuts down.
        let _ = Command::new("sudo")
            .args(["loginctl", "disable-linger", &self.name])
            .output();
        // Give the user manager a moment to exit.
        std::thread::sleep(std::time::Duration::from_millis(500));
        // Remove user and home directory.
        let _ = Command::new("sudo")
            .args(["userdel", "-r", &self.name])
            .output();
    }
}

/// Look up a user's numeric UID.
fn uid_of(user: &str) -> u32 {
    let out = Command::new("id")
        .args(["-u", user])
        .output()
        .expect("id -u failed");
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .expect("uid is not a number")
}

#[test]
fn systemd_install_enter_delete_uninstall() {
    require_systemd_env();

    let user = TestUser::create();

    // Build our debug binary path.
    let rumpel_bin = assert_cmd::cargo::cargo_bin!("rumpel");
    let rumpel_bin = rumpel_bin.to_string_lossy();

    // ---- install the binary into the test user's PATH ----
    let cargo_bin_dir = format!("{}/.cargo/bin", user.home);
    Command::new("sudo")
        .args(["-u", &user.name, "mkdir", "-p", &cargo_bin_dir])
        .success()
        .expect("mkdir .cargo/bin failed");
    Command::new("sudo")
        .args(["cp", &rumpel_bin, &format!("{cargo_bin_dir}/rumpel")])
        .success()
        .expect("cp rumpel binary failed");
    Command::new("sudo")
        .args([
            "chown",
            &format!("{}:{}", user.name, user.name),
            &format!("{cargo_bin_dir}/rumpel"),
        ])
        .success()
        .expect("chown rumpel binary failed");

    // ---- create a test repo as the test user ----
    let repo_dir = format!("{}/test-repo", user.home);
    user.cmd("mkdir")
        .arg(&repo_dir)
        .success()
        .expect("mkdir test-repo failed");
    user.cmd("git")
        .args(["init", &repo_dir])
        .success()
        .expect("git init failed");
    user.cmd("git")
        .args(["-C", &repo_dir, "config", "user.email", "test@example.com"])
        .success()
        .expect("git config email failed");
    user.cmd("git")
        .args(["-C", &repo_dir, "config", "user.name", "Test User"])
        .success()
        .expect("git config name failed");
    user.cmd("git")
        .args(["-C", &repo_dir, "commit", "--allow-empty", "-m", "init"])
        .success()
        .expect("git commit failed");

    // Write a devcontainer.json + .rumpelpod.toml for a minimal pod.
    let dc_dir = format!("{repo_dir}/.devcontainer");
    user.cmd("mkdir")
        .args(["-p", &dc_dir])
        .success()
        .expect("mkdir .devcontainer failed");

    // Build a minimal test image (docker is shared across all users).
    let image_id = build_minimal_test_image();

    let devcontainer_json = format!(
        r#"{{
    "image": "{image_id}",
    "workspaceFolder": "/workspace",
    "runArgs": ["--runtime=runc"]
}}"#
    );
    write_as_user(
        &user,
        &format!("{dc_dir}/devcontainer.json"),
        &devcontainer_json,
    );
    write_as_user(&user, &format!("{repo_dir}/.rumpelpod.toml"), "\n");

    let rumpel = format!("{cargo_bin_dir}/rumpel");

    // ---- system-install ----
    user.cmd(&rumpel)
        .arg("system-install")
        .success()
        .expect("system-install failed");

    // Verify the systemd socket is active.
    let status_out = user
        .cmd("systemctl")
        .args(["--user", "is-active", "rumpelpod.socket"])
        .output()
        .expect("systemctl is-active failed");
    let status = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        status.trim() == "active",
        "rumpelpod.socket should be active, got: {status}"
    );

    // ---- enter a pod ----
    let enter_out = user
        .shell_in(
            &repo_dir,
            &format!("{rumpel} enter systemd-test -- echo hello-from-pod"),
        )
        .output()
        .expect("rumpel enter failed to spawn");
    assert!(
        enter_out.status.success(),
        "rumpel enter failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&enter_out.stdout),
        String::from_utf8_lossy(&enter_out.stderr),
    );
    let enter_stdout = String::from_utf8_lossy(&enter_out.stdout);
    assert!(
        enter_stdout.contains("hello-from-pod"),
        "expected 'hello-from-pod' in output, got: {enter_stdout}"
    );

    // ---- delete the pod ----
    user.shell_in(&repo_dir, &format!("{rumpel} delete --wait systemd-test"))
        .success()
        .expect("rumpel delete failed");

    // ---- system-uninstall ----
    user.cmd(&rumpel)
        .arg("system-uninstall")
        .success()
        .expect("system-uninstall failed");

    // Verify the socket unit is gone.
    let status_out = user
        .cmd("systemctl")
        .args(["--user", "is-active", "rumpelpod.socket"])
        .output()
        .expect("systemctl is-active failed");
    let status = String::from_utf8_lossy(&status_out.stdout);
    assert!(
        status.trim() != "active",
        "rumpelpod.socket should NOT be active after uninstall, got: {status}"
    );
}

/// Build a minimal Docker image that has git + a non-root user.
fn build_minimal_test_image() -> String {
    let tmp = tempfile::TempDir::with_prefix("rp-systemd-img-").expect("tmpdir");
    let dockerfile = tmp.path().join("Dockerfile");
    std::fs::write(
        &dockerfile,
        "FROM debian:13\n\
         RUN apt-get update && apt-get install -y git\n\
         RUN useradd -m -s /bin/bash poduser\n\
         RUN mkdir -p /workspace && chown poduser:poduser /workspace\n\
         USER poduser\n",
    )
    .expect("write Dockerfile");

    let output = Command::new("docker")
        .args(["build", "-q", "-f"])
        .arg(&dockerfile)
        .arg(tmp.path())
        .output()
        .expect("docker build failed");

    assert!(
        output.status.success(),
        "docker build failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Write a file as the test user via sudo tee.
fn write_as_user(user: &TestUser, path: &str, content: &str) {
    use std::io::Write;
    let mut child = Command::new("sudo")
        .args(["-u", &user.name, "tee", path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .unwrap_or_else(|e| panic!("tee {path} failed to spawn: {e}"));
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(content.as_bytes())
        .unwrap();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    assert!(status.success(), "tee {path} failed");
}
