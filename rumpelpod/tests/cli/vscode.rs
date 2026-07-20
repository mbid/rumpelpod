// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser integration coverage for the VS Code extension.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::os::unix::process::CommandExt as ProcessCommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use indoc::{formatdoc, indoc};
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;
use rumpelpod::CommandExt as RumpelCommandExt;

use crate::common::{
    create_commit, pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo,
};
use crate::executor::ExecutorResources;

const POD_NAME: &str = "vscode-review";
const CHANGED_FILE: &str = "browser-diff.txt";
const ORIGINAL_CONTENT: &str = "content from the host";
const POD_CONTENT: &str = "content from the pod";

struct ProcessGroup {
    child: Child,
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                eprintln!("checking code-server before cleanup failed: {error}");
            }
        }

        let pid = Pid::from_raw(self.child.id() as i32);
        if let Err(error) = killpg(pid, Signal::SIGTERM) {
            eprintln!("stopping code-server process group failed: {error}");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    if let Err(error) = killpg(pid, Signal::SIGKILL) {
                        eprintln!("killing code-server process group failed: {error}");
                    }
                    if let Err(error) = self.child.wait() {
                        eprintln!("waiting for killed code-server failed: {error}");
                    }
                    return;
                }
                Err(error) => {
                    eprintln!("checking code-server cleanup status failed: {error}");
                    return;
                }
            }
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root above rumpelpod crate")
        .to_path_buf()
}

fn executable_on_path(name: &str) -> PathBuf {
    let path = std::env::var_os("PATH").expect("PATH is not set");
    std::env::split_paths(&path)
        .map(|directory| directory.join(name))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("{name} is not installed on PATH"))
}

fn find_vsix(root: &Path) -> PathBuf {
    if let Some(path) = std::env::var_os("RUMPELPOD_VSCODE_VSIX") {
        let path = PathBuf::from(path);
        assert!(
            path.is_file(),
            "RUMPELPOD_VSCODE_VSIX does not name a file: {}",
            path.display()
        );
        return path;
    }

    let mut candidates = Vec::new();
    for directory in [root.join("vscode"), root.join("vscode/dist")] {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("reading {}: {error}", directory.display()),
        };
        for entry in entries {
            let entry = entry.unwrap_or_else(|error| {
                panic!("reading an entry in {}: {error}", directory.display())
            });
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) == Some("vsix") {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    assert_eq!(
        candidates.len(),
        1,
        "expected exactly one packaged extension under vscode/ or vscode/dist/, found: {candidates:?}"
    );
    candidates.remove(0)
}

fn reserve_loopback_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("reserve code-server port");
    listener.local_addr().expect("read reserved port").port()
}

fn wait_for_pod_ref(repo: &TestRepo, expected_commit: &str) {
    let pod_ref = format!("refs/rumpelpod/{POD_NAME}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let output = Command::new("git")
            .args(["rev-parse", "--verify", &pod_ref])
            .current_dir(repo.path())
            .output()
            .expect("read pod ref");
        let actual = String::from_utf8_lossy(&output.stdout);
        if output.status.success() && actual.trim() == expected_commit {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{pod_ref} did not reach commit {expected_commit} within 30 seconds"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn wait_for_server(child: &mut Child, port: u16) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return;
        }
        if let Some(status) = child.try_wait().expect("check code-server status") {
            panic!("code-server exited before accepting connections: {status}");
        }
        assert!(
            Instant::now() < deadline,
            "code-server did not accept connections on port {port} within 30 seconds"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn install_extension(code_server: &Path, vsix: &Path, user_data_dir: &Path, extensions_dir: &Path) {
    let output = Command::new(code_server)
        .arg("--user-data-dir")
        .arg(user_data_dir)
        .arg("--extensions-dir")
        .arg(extensions_dir)
        .arg("--install-extension")
        .arg(vsix)
        .arg("--force")
        .output()
        .expect("run code-server extension installer");
    assert!(
        output.status.success(),
        "code-server failed to install {}:\nstdout:\n{}\nstderr:\n{}",
        vsix.display(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn start_code_server(
    code_server: &Path,
    repo: &TestRepo,
    daemon: &TestDaemon,
    user_data_dir: &Path,
    extensions_dir: &Path,
    port: u16,
) -> ProcessGroup {
    let address = format!("127.0.0.1:{port}");
    let ambient_path = std::env::var("PATH").expect("PATH is not set");
    let daemon_bin = daemon.bin_dir.display();
    let extension_path = format!("{daemon_bin}:{ambient_path}");

    let mut command = Command::new(code_server);
    command
        .arg("--auth")
        .arg("none")
        .arg("--bind-addr")
        .arg(&address)
        .arg("--disable-telemetry")
        .arg("--disable-update-check")
        .arg("--disable-getting-started-override")
        .arg("--user-data-dir")
        .arg(user_data_dir)
        .arg("--extensions-dir")
        .arg(extensions_dir)
        .arg(repo.path())
        .env("HOME", &daemon.home_path)
        .env("PATH", extension_path)
        .env("RUMPELPOD_DAEMON_SOCKET", &daemon.socket_path)
        .stdin(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            libc::setpgid(0, 0);
            Ok(())
        });
    }
    let child = command
        .spawn_with_logging("CODE-SERVER")
        .expect("start code-server");
    let mut group = ProcessGroup { child };
    wait_for_server(&mut group.child, port);
    group
}

fn write_code_server_settings(user_data_dir: &Path) {
    let settings_dir = user_data_dir.join("User");
    fs::create_dir_all(&settings_dir).expect("create code-server settings directory");
    fs::write(
        settings_dir.join("settings.json"),
        indoc! {r#"
            {
                "security.workspace.trust.enabled": false,
                "telemetry.telemetryLevel": "off",
                "workbench.startupEditor": "none",
                "diffEditor.renderSideBySide": true
            }
        "#},
    )
    .expect("write code-server settings");
}

fn run_browser_assertions(root: &Path, port: u16, chromium: &Path, artifacts: &Path) {
    fs::create_dir_all(artifacts).expect("create browser artifact directory");
    let script = root.join("integration/vscode/browser.cjs");
    let base_url = format!("http://127.0.0.1:{port}");
    let status = Command::new("node")
        .arg(&script)
        .current_dir(root.join("vscode"))
        .env("RUMPELPOD_VSCODE_URL", base_url)
        .env("RUMPELPOD_VSCODE_POD", POD_NAME)
        .env("RUMPELPOD_VSCODE_CHANGED_FILE", CHANGED_FILE)
        .env("RUMPELPOD_VSCODE_ORIGINAL_CONTENT", ORIGINAL_CONTENT)
        .env("RUMPELPOD_VSCODE_POD_CONTENT", POD_CONTENT)
        .env("RUMPELPOD_CHROMIUM", chromium)
        .env("RUMPELPOD_VSCODE_ARTIFACTS", artifacts)
        .status()
        .expect("run Playwright browser assertions");
    assert!(status.success(), "Playwright browser assertions failed");
}

#[test]
fn vscode_browser_opens_pod_change_as_diff() {
    println!("xtest:timeout=300");

    let root = workspace_root();
    let code_server = executable_on_path("code-server");
    let chromium = executable_on_path("chromium");
    let vsix = find_vsix(&root);

    let repo = TestRepo::new();
    fs::write(
        repo.path().join(CHANGED_FILE),
        format!("{ORIGINAL_CONTENT}\n"),
    )
    .expect("write initial file");
    Command::new("git")
        .args(["add", CHANGED_FILE])
        .current_dir(repo.path())
        .success()
        .expect("stage initial file");
    create_commit(repo.path(), "Add browser diff fixture");

    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).expect("write rumpelpod config");

    pod_command(&repo, &daemon)
        .args(["enter", "--create", POD_NAME, "--", "echo", "setup"])
        .success()
        .expect("launch test pod");
    let change_command = formatdoc! {"
        printf '%s\\n' '{POD_CONTENT}' > {CHANGED_FILE} && \\
        git add {CHANGED_FILE} && \\
        git commit --no-verify -m 'Change browser diff fixture'
    "};
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            POD_NAME,
            "--",
            "sh",
            "-c",
            &change_command,
        ])
        .success()
        .expect("commit changed file in pod");
    let pod_head = pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            POD_NAME,
            "--",
            "git",
            "rev-parse",
            "HEAD",
        ])
        .success()
        .expect("read pod commit");
    let pod_head = String::from_utf8(pod_head)
        .expect("pod commit is utf8")
        .trim()
        .to_string();
    wait_for_pod_ref(&repo, &pod_head);

    let browser_home = tempfile::tempdir().expect("create code-server home");
    let user_data_dir = browser_home.path().join("user-data");
    let extensions_dir = browser_home.path().join("extensions");
    fs::create_dir_all(&extensions_dir).expect("create code-server extension directory");
    write_code_server_settings(&user_data_dir);
    install_extension(&code_server, &vsix, &user_data_dir, &extensions_dir);

    let port = reserve_loopback_port();
    let _code_server = start_code_server(
        &code_server,
        &repo,
        &daemon,
        &user_data_dir,
        &extensions_dir,
        port,
    );
    let artifacts = root
        .join("target/vscode-integration")
        .join(std::process::id().to_string());
    run_browser_assertions(&root, port, &chromium, &artifacts);
}
