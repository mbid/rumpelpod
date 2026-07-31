// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Browser integration coverage for the VS Code extension.

use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use indoc::{formatdoc, indoc};
use nix::sys::signal::{kill, Signal};
use nix::unistd::{Pid, Uid};
use rumpelpod::CommandExt as RumpelCommandExt;

use crate::common::{
    create_commit, pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo,
};
use crate::executor::ExecutorResources;

const POD_NAME: &str = "vscode-review";
const CREATED_POD_NAME: &str = "vscode-created";
const CHANGED_FILE: &str = "browser-diff.txt";
const ORIGINAL_CONTENT: &str = "content from the host";
const POD_CONTENT: &str = "content from the pod";
struct CodeServer {
    child: Child,
}

impl Drop for CodeServer {
    fn drop(&mut self) {
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => {}
            Err(error) => {
                eprintln!("checking code-server before cleanup failed: {error}");
            }
        }

        let pid = Pid::from_raw(self.child.id() as i32);
        if let Err(error) = kill(pid, Signal::SIGTERM) {
            eprintln!("stopping code-server failed: {error}");
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Ok(None) => {
                    if let Err(error) = kill(pid, Signal::SIGKILL) {
                        eprintln!("killing code-server failed: {error}");
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

fn code_server_is_ready(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .is_err()
    {
        return false;
    }
    if stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .is_err()
    {
        return false;
    }
    let mut response = String::new();
    if stream.read_to_string(&mut response).is_err() {
        return false;
    }
    let compact: String = response
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    response.starts_with("HTTP/1.1 200")
        && (compact.contains("\"status\":\"alive\"") || compact.contains("\"status\":\"expired\""))
}

fn wait_for_server(child: &mut Child, port: u16) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().expect("check code-server status") {
            return Err(format!(
                "code-server exited before accepting connections: {status}"
            ));
        }
        if code_server_is_ready(port) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "code-server did not become healthy on port {port} within 30 seconds"
            ));
        }
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
    sync_violation: &Path,
) -> (CodeServer, u16) {
    let ambient_path = std::env::var("PATH").expect("PATH is not set");
    let daemon_bin = daemon.bin_dir.display();
    let extension_path = format!("{daemon_bin}:{ambient_path}");

    let mut failures = Vec::new();
    for _attempt in 0..3 {
        let port = reserve_loopback_port();
        let address = format!("127.0.0.1:{port}");
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
            .env("PATH", &extension_path)
            .env("RUMPELPOD_DAEMON_SOCKET", &daemon.socket_path)
            .env(
                "RUMPELPOD_VSCODE_REAL_RUMPEL",
                daemon.bin_dir.join("rumpel"),
            )
            .env("RUMPELPOD_VSCODE_SYNC_VIOLATION", sync_violation)
            .stdin(Stdio::null());
        let child = command
            .spawn_with_logging("CODE-SERVER")
            .expect("start code-server");
        let mut server = CodeServer { child };
        match wait_for_server(&mut server.child, port) {
            Ok(()) => return (server, port),
            Err(error) => failures.push(error),
        }
    }
    panic!("code-server failed to start after three attempts: {failures:?}")
}

fn write_code_server_settings(user_data_dir: &Path, executable: &Path) {
    let settings_dir = user_data_dir.join("User");
    fs::create_dir_all(&settings_dir).expect("create code-server settings directory");
    let settings = serde_json::json!({
        "editor.accessibilitySupport": "on",
        "security.workspace.trust.enabled": false,
        "telemetry.telemetryLevel": "off",
        "workbench.startupEditor": "none",
        "workbench.secondarySideBar.defaultVisibility": "hidden",
        "rumpelpod.executable": executable,
    });
    fs::write(
        settings_dir.join("settings.json"),
        serde_json::to_string_pretty(&settings).expect("serialize code-server settings"),
    )
    .expect("write code-server settings");
}

fn write_extension_rumpel_wrapper(directory: &Path) -> PathBuf {
    let executable = directory.join("rumpel-vscode-test");
    fs::write(
        &executable,
        indoc! {r#"
            #!/bin/sh
            if [ "$1" = "list" ]; then
                for argument in "$@"; do
                    if [ "$argument" = "--sync" ]; then
                        : > "$RUMPELPOD_VSCODE_SYNC_VIOLATION"
                        echo "VS Code invoked list --sync during an ordinary UI operation" >&2
                        exit 97
                    fi
                done
            fi
            exec "$RUMPELPOD_VSCODE_REAL_RUMPEL" "$@"
        "#},
    )
    .expect("write VS Code rumpel wrapper");
    let mut permissions = fs::metadata(&executable)
        .expect("read VS Code rumpel wrapper metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&executable, permissions).expect("make VS Code rumpel wrapper executable");
    executable
}

fn run_browser_assertions(
    root: &Path,
    port: u16,
    chromium: &Path,
    artifacts: &Path,
    repo: &TestRepo,
    daemon: &TestDaemon,
) {
    fs::create_dir_all(artifacts).expect("create browser artifact directory");
    let script = root.join("integration/vscode/browser.cjs");
    let base_url = format!("http://127.0.0.1:{port}");
    let status = Command::new("node")
        .arg(&script)
        .current_dir(root.join("vscode"))
        .env("RUMPELPOD_VSCODE_URL", base_url)
        .env("RUMPELPOD_VSCODE_POD", POD_NAME)
        .env("RUMPELPOD_VSCODE_CREATED_POD", CREATED_POD_NAME)
        .env("RUMPELPOD_VSCODE_CHANGED_FILE", CHANGED_FILE)
        .env("RUMPELPOD_VSCODE_ORIGINAL_CONTENT", ORIGINAL_CONTENT)
        .env("RUMPELPOD_VSCODE_POD_CONTENT", POD_CONTENT)
        .env("RUMPELPOD_VSCODE_REPO_ROOT", repo.path())
        .env("RUMPELPOD_VSCODE_RUMPEL", daemon.bin_dir.join("rumpel"))
        .env("RUMPELPOD_DAEMON_SOCKET", &daemon.socket_path)
        .env("RUMPELPOD_VSCODE_HOME", &daemon.home_path)
        .env("RUMPELPOD_CHROMIUM", chromium)
        .env("RUMPELPOD_VSCODE_ARTIFACTS", artifacts)
        .status()
        .expect("run Playwright browser assertions");
    assert!(status.success(), "Playwright browser assertions failed");
}

#[test]
fn vscode_agent_environment_is_systemd_safe() {
    let root = workspace_root();
    let temporary = tempfile::tempdir().expect("create agent environment test directory");
    let source = temporary.path().join("process-environment");
    let destination = temporary.path().join("rumpelpod/agent-environment");
    fs::write(
        &source,
        b"UNRELATED=discard\0OPENAI_API_KEY=sentinel\"with\\chars\0",
    )
    .expect("write NUL-delimited process environment");
    let user = std::env::var("USER").expect("USER is not set");

    let destination_argument =
        format!("RUMPELPOD_AGENT_ENVIRONMENT_FILE={}", destination.display());
    Command::new("sudo")
        .args(["--non-interactive", "env", &destination_argument, "bash"])
        .arg(root.join(".devcontainer/write-agent-environment.sh"))
        .arg(&user)
        .arg(&source)
        .success()
        .expect("write protected agent environment");

    let content = fs::read_to_string(&destination).expect("read agent environment");
    assert_eq!(
        content, "OPENAI_API_KEY=\"sentinel\\\"with\\\\chars\"\n",
        "agent environment was not escaped for systemd"
    );
    assert!(
        !content.contains("UNRELATED"),
        "unapproved variable was written"
    );
    let mode = fs::metadata(&destination)
        .expect("read agent environment metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "agent environment was not private");
    let directory_owner = fs::metadata(destination.parent().expect("agent environment parent"))
        .expect("read agent environment directory metadata")
        .uid();
    assert_eq!(
        directory_owner,
        Uid::current().as_raw(),
        "root entrypoint setup left the user service directory under another owner"
    );
}

#[test]
fn vscode_server_is_unauthenticated_and_loopback_only() {
    let root = workspace_root();
    let temporary = tempfile::tempdir().expect("create VS Code service test directory");
    let home = temporary.path().join("home");
    let bin_dir = home.join(".local/bin");
    let capture = temporary.path().join("code-server-arguments");
    let code_server = bin_dir.join("code-server");
    fs::create_dir_all(&bin_dir).expect("create fake code-server directory");
    fs::write(
        &code_server,
        indoc! {r#"
            #!/bin/sh
            set -eu
            if [ "${PASSWORD+x}" = x ] || [ "${HASHED_PASSWORD+x}" = x ]; then
                exit 91
            fi
            printf '%s\n' "$@" > "$CAPTURE"
        "#},
    )
    .expect("write fake code-server");
    fs::set_permissions(&code_server, fs::Permissions::from_mode(0o755))
        .expect("make fake code-server executable");

    Command::new("sh")
        .arg(root.join(".devcontainer/start-vscode.sh"))
        .env("HOME", &home)
        .env("CAPTURE", &capture)
        .env("PASSWORD", "must-not-reach-code-server")
        .env("HASHED_PASSWORD", "must-not-reach-code-server")
        .env("RUMPELPOD_VSCODE_BIND_ADDR", "0.0.0.0:9999")
        .success()
        .expect("start loopback-only code-server service");

    let arguments = fs::read_to_string(&capture).expect("read code-server arguments");
    let workspace = Path::new("/workspaces/anyhow-demo");
    let workspace = workspace.display();
    assert_eq!(
        arguments,
        formatdoc! {"
            --auth
            none
            --bind-addr
            127.0.0.1:3000
            --disable-telemetry
            --disable-update-check
            --disable-workspace-trust
            {workspace}
        "},
        "the browser service accepted authentication or network overrides"
    );
    assert!(
        !home.join(".config/rumpelpod/vscode-password").exists(),
        "the browser service created a password credential"
    );
    let service = fs::read_to_string(root.join(".devcontainer/rumpelpod-vscode.service"))
        .expect("read VS Code service");
    assert!(
        service.contains("ConditionPathIsDirectory=/workspaces/anyhow-demo/.git")
            && service.contains("WorkingDirectory=/workspaces/anyhow-demo"),
        "the browser service did not use the demo repository in /workspaces"
    );
}

#[test]
fn vscode_demo_workspace_uses_standard_runtime() {
    let root = workspace_root();
    let temporary = tempfile::tempdir().expect("create VS Code demo test directory");
    let home = temporary.path().join("home");
    let source = temporary.path().join("cached-anyhow");
    let workspace = temporary.path().join("workspaces/anyhow-demo");
    fs::create_dir_all(source.join("src")).expect("create cached anyhow source");
    fs::write(
        source.join("Cargo.toml"),
        indoc! {r#"
            [package]
            name = "anyhow"
            version = "1.0.102"
            edition = "2021"
        "#},
    )
    .expect("write cached anyhow manifest");
    fs::write(source.join("src/lib.rs"), "pub struct Error;\n")
        .expect("write cached anyhow source");
    fs::write(source.join(".cargo-ok"), "").expect("write registry marker");
    fs::write(source.join(".cargo_vcs_info.json"), "{}").expect("write registry metadata");

    let prepare = root.join(".devcontainer/prepare-vscode-demo.sh");
    Command::new("sh")
        .arg(&prepare)
        .env("HOME", &home)
        .env("RUMPELPOD_VSCODE_DEMO_SOURCE", &source)
        .env("RUMPELPOD_VSCODE_WORKSPACE", &workspace)
        .success()
        .expect("seed VS Code demo workspace");

    let config: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(workspace.join(".devcontainer/devcontainer.json"))
            .expect("read demo devcontainer"),
    )
    .expect("parse demo devcontainer");
    assert_eq!(config["workspaceFolder"], "/workspace/anyhow");
    assert_eq!(config["containerUser"], "root");
    assert!(
        config.get("runArgs").is_none(),
        "demo devcontainer requested an outer-container runtime"
    );
    assert_eq!(config["userEnvProbe"], "none");
    let dockerfile = fs::read_to_string(workspace.join(".devcontainer/Dockerfile"))
        .expect("read demo Dockerfile");
    assert!(
        dockerfile.contains(
            "rust:1.96.1-slim-bookworm@sha256:e18a79fc84dfcfc3ab5ba72290398a644c135c97eaa881447fddc354ee4701a3"
        ),
        "demo Rust image was not pinned"
    );
    assert!(
        !dockerfile.contains("sysbox"),
        "demo Dockerfile requested Sysbox"
    );
    assert!(!workspace.join(".cargo-ok").exists());
    assert!(!workspace.join(".cargo_vcs_info.json").exists());
    let status = Command::new("git")
        .args(["status", "--porcelain"])
        .current_dir(&workspace)
        .success()
        .expect("read demo repository status");
    assert!(status.is_empty(), "seeded demo repository was dirty");
    let user_name = Command::new("git")
        .args(["config", "--local", "user.name"])
        .current_dir(&workspace)
        .success()
        .expect("read demo repository Git user name");
    assert_eq!(user_name, b"Rumpelpod VS Code\n");
    let user_email = Command::new("git")
        .args(["config", "--local", "user.email"])
        .current_dir(&workspace)
        .success()
        .expect("read demo repository Git email");
    assert_eq!(user_email, b"rumpelpod-vscode@localhost\n");

    let marker = workspace.join("developer-work");
    fs::write(&marker, "preserve me\n").expect("write demo developer work");
    Command::new("sh")
        .arg(&prepare)
        .env("HOME", &home)
        .env("RUMPELPOD_VSCODE_DEMO_SOURCE", &source)
        .env("RUMPELPOD_VSCODE_WORKSPACE", &workspace)
        .success()
        .expect("re-run VS Code demo preparation");
    assert_eq!(
        fs::read_to_string(marker).expect("read preserved demo work"),
        "preserve me\n",
        "live extension rebuild replaced the demo working tree"
    );
}

#[test]
fn vscode_browser_lists_creates_and_reviews_pods() {
    println!("xtest:timeout=360");

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
    crate::codex::common::setup_controlled_home(&home);
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start_with_local_llm_clis(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).expect("write rumpelpod config");

    pod_command(&repo, &daemon)
        .args(["enter", "--create", POD_NAME, "--", "echo", "setup"])
        .success()
        .expect("launch test pod");

    let browser_home = tempfile::tempdir().expect("create code-server home");
    let user_data_dir = browser_home.path().join("user-data");
    let extensions_dir = browser_home.path().join("extensions");
    fs::create_dir_all(&extensions_dir).expect("create code-server extension directory");
    let extension_rumpel = write_extension_rumpel_wrapper(browser_home.path());
    let sync_violation = browser_home.path().join("unexpected-list-sync");
    write_code_server_settings(&user_data_dir, &extension_rumpel);
    install_extension(&code_server, &vsix, &user_data_dir, &extensions_dir);

    let (_code_server, port) = start_code_server(
        &code_server,
        &repo,
        &daemon,
        &user_data_dir,
        &extensions_dir,
        &sync_violation,
    );
    let artifacts = root
        .join("target/vscode-integration")
        .join(std::process::id().to_string());
    run_browser_assertions(&root, port, &chromium, &artifacts, &repo, &daemon);
    assert!(
        !sync_violation.exists(),
        "an ordinary VS Code UI operation invoked rumpel list --sync"
    );
}
