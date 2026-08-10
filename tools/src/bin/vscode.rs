// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build and refresh the browser VS Code development environment.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use rumpelpod::daemon::protocol::{DaemonEvent, PodInfo};
use rumpelpod::review::ReviewPlan;
use ts_rs::{Config, TS};

const LINUX_RUMPEL_TARGETS: [(&str, &str); 2] = [
    ("x86_64-unknown-linux-musl", "rumpel-linux-amd64"),
    ("aarch64-unknown-linux-musl", "rumpel-linux-arm64"),
];

#[derive(Parser)]
struct Args {
    /// Verify generated bindings and compile/package the extension without updating services.
    #[arg(long)]
    check: bool,

    /// Generate TypeScript bindings without building the extension or updating services.
    #[arg(long)]
    types_only: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args = Args::parse();
    let repo_root = tools::repo_root()?;
    let generated = repo_root.join("vscode/src/generated");
    let vscode_dir = repo_root.join("vscode");
    check_extension_version(&vscode_dir)?;

    if args.check {
        check_types(&generated)?;
        package_extension(&vscode_dir)?;
        return Ok(());
    }

    generate_types(&generated)?;
    if args.types_only {
        return Ok(());
    }

    package_extension(&vscode_dir)?;

    for (target, _) in LINUX_RUMPEL_TARGETS {
        run_command(
            tools::cargo_cmd().args([
                "build",
                "-p",
                "rumpelpod",
                "--bin",
                "rumpel",
                "--target",
                target,
            ]),
            &format!("building rumpel for {target}"),
        )?;
    }
    let native_target = match std::env::consts::ARCH {
        "x86_64" => "x86_64-unknown-linux-musl",
        "aarch64" => "aarch64-unknown-linux-musl",
        architecture => {
            return Err(anyhow::anyhow!(
                "unsupported VS Code development architecture: {architecture}"
            ));
        }
    };
    let rumpel = repo_root
        .join("target")
        .join(native_target)
        .join("debug/rumpel");
    if !rumpel.exists() {
        let rumpel = rumpel.display();
        return Err(anyhow::anyhow!("built rumpel binary not found at {rumpel}"));
    }
    let rumpel = install_rumpel(&rumpel, &repo_root)?;

    let home = dirs::home_dir().context("locating the home directory")?;
    let prepare_demo = home.join(".local/lib/rumpelpod/prepare-vscode-demo.sh");
    install_runtime_file(
        &repo_root.join(".devcontainer/prepare-vscode-demo.sh"),
        &prepare_demo,
        0o755,
    )?;
    let mut prepare_demo_command = Command::new(&prepare_demo);
    run_command(
        &mut prepare_demo_command,
        "preparing the anyhow VS Code demo workspace",
    )?;
    install_runtime_file(
        &repo_root.join(".devcontainer/start-vscode.sh"),
        &home.join(".local/lib/rumpelpod/start-vscode.sh"),
        0o755,
    )?;
    install_runtime_file(
        &repo_root.join(".devcontainer/rumpelpod-vscode.service"),
        &home.join(".config/systemd/user/rumpelpod-vscode.service"),
        0o644,
    )?;

    let mut daemon_reload = Command::new("systemctl");
    configure_user_bus(&mut daemon_reload);
    run_command(
        daemon_reload.args(["--user", "daemon-reload"]),
        "reloading development user services",
    )?;

    let mut install = Command::new(&rumpel);
    configure_user_bus(&mut install);
    run_command(
        install.arg("system-install"),
        "updating the rumpelpod daemon",
    )?;

    let code_server = Path::new("/usr/local/bin/code-server");
    if !code_server.exists() {
        return Err(anyhow::anyhow!(
            "code-server is not installed; rebuild the rumpelpod devcontainer"
        ));
    }
    let vsix = vscode_dir.join("dist/rumpelpod-vscode.vsix");
    let mut install_extension = Command::new(code_server);
    configure_user_bus(&mut install_extension);
    run_command(
        install_extension
            .args(["--force", "--install-extension"])
            .arg(&vsix),
        "installing the VS Code extension",
    )?;

    let mut enable = Command::new("systemctl");
    configure_user_bus(&mut enable);
    run_command(
        enable.args(["--user", "enable", "rumpelpod-vscode.service"]),
        "enabling browser VS Code",
    )?;

    let mut restart = Command::new("systemctl");
    configure_user_bus(&mut restart);
    run_command(
        restart.args(["--user", "restart", "rumpelpod-vscode.service"]),
        "restarting browser VS Code",
    )?;
    wait_for_vscode()?;

    let workspace = Path::new("/workspaces/anyhow-demo");
    let workspace = workspace.display();
    println!("rumpelpod VS Code is serving {workspace} on port 3000");
    Ok(())
}

fn install_runtime_file(source: &Path, destination: &Path, mode: u32) -> Result<()> {
    let parent = destination.parent().with_context(|| {
        let destination = destination.display();
        format!("runtime file has no parent directory: {destination}")
    })?;
    std::fs::create_dir_all(parent).with_context(|| {
        let parent = parent.display();
        format!("creating runtime file directory {parent}")
    })?;

    let staged = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        let parent = parent.display();
        format!("creating staged runtime file in {parent}")
    })?;
    std::fs::copy(source, staged.path()).with_context(|| {
        let source = source.display();
        format!("staging runtime file {source}")
    })?;
    std::fs::set_permissions(staged.path(), std::fs::Permissions::from_mode(mode))
        .context("setting runtime file permissions")?;
    staged
        .persist(destination)
        .map_err(|error| error.error)
        .with_context(|| {
            let destination = destination.display();
            format!("installing runtime file at {destination}")
        })?;
    Ok(())
}

fn vscode_is_ready() -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], 3000));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(1)) else {
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

fn wait_for_vscode() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if vscode_is_ready() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let mut status = Command::new("systemctl");
    configure_user_bus(&mut status);
    let output = status
        .args([
            "--user",
            "--no-pager",
            "--full",
            "status",
            "rumpelpod-vscode.service",
        ])
        .output()
        .context("reading browser VS Code service status")?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(anyhow::anyhow!(
        "browser VS Code did not become healthy on port 3000 within 60 seconds\n{stdout}{stderr}"
    ))
}

fn install_rumpel(source: &Path, repo_root: &Path) -> Result<PathBuf> {
    let home = dirs::home_dir().context("locating the home directory")?;
    let bin_dir = home.join(".local/bin");
    std::fs::create_dir_all(&bin_dir).with_context(|| {
        let bin_dir = bin_dir.display();
        format!("creating development binary directory {bin_dir}")
    })?;

    let destination = bin_dir.join("rumpel");
    tools::install_binary(source, &destination)?;
    for (target, name) in LINUX_RUMPEL_TARGETS {
        let payload = repo_root.join("target").join(target).join("debug/rumpel");
        tools::install_binary(&payload, &bin_dir.join(name))?;
    }
    Ok(destination)
}

fn install_npm_dependencies(vscode_dir: &Path) -> Result<()> {
    run_command(
        Command::new("npm").arg("ci").current_dir(vscode_dir),
        "installing VS Code extension dependencies",
    )
}

fn check_extension_version(vscode_dir: &Path) -> Result<()> {
    let expected = rumpelpod::PACKAGE_VERSION;
    let package_path = vscode_dir.join("package.json");
    let package = read_json(&package_path)?;
    check_json_version(&package_path, &package, "/version", expected)?;

    let lock_path = vscode_dir.join("package-lock.json");
    let lock = read_json(&lock_path)?;
    check_json_version(&lock_path, &lock, "/version", expected)?;
    check_json_version(&lock_path, &lock, "/packages//version", expected)?;
    Ok(())
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    let source = std::fs::read_to_string(path).with_context(|| {
        let path = path.display();
        format!("reading {path}")
    })?;
    serde_json::from_str(&source).with_context(|| {
        let path = path.display();
        format!("parsing {path}")
    })
}

fn check_json_version(
    path: &Path,
    value: &serde_json::Value,
    pointer: &str,
    expected: &str,
) -> Result<()> {
    let Some(actual) = value.pointer(pointer).and_then(serde_json::Value::as_str) else {
        let path = path.display();
        return Err(anyhow::anyhow!(
            "{path} has no string at JSON pointer {pointer}"
        ));
    };
    if actual != expected {
        let path = path.display();
        return Err(anyhow::anyhow!(
            "VS Code extension version {actual} in {path} does not match Cargo version {expected}"
        ));
    }
    Ok(())
}

fn package_extension(vscode_dir: &Path) -> Result<()> {
    install_npm_dependencies(vscode_dir)?;
    run_command(
        Command::new("npm")
            .args(["run", "package"])
            .current_dir(vscode_dir),
        "packaging the VS Code extension",
    )
}

fn configure_user_bus(command: &mut Command) {
    let uid = unsafe { libc::getuid() };
    let runtime_dir = format!("/run/user/{uid}");
    command.env("XDG_RUNTIME_DIR", &runtime_dir).env(
        "DBUS_SESSION_BUS_ADDRESS",
        format!("unix:path={runtime_dir}/bus"),
    );
}

fn run_command(command: &mut Command, description: &str) -> Result<()> {
    let status = command
        .status()
        .with_context(|| format!("failed while {description}"))?;
    if !status.success() {
        return Err(anyhow::anyhow!("{description} exited with {status}"));
    }
    Ok(())
}

fn generate_types(output: &Path) -> Result<()> {
    if output.exists() {
        std::fs::remove_dir_all(output).with_context(|| {
            let output = output.display();
            format!("removing generated bindings at {output}")
        })?;
    }
    std::fs::create_dir_all(output).with_context(|| {
        let output = output.display();
        format!("creating generated bindings directory {output}")
    })?;

    let config = Config::new().with_out_dir(output).with_large_int("number");
    PodInfo::export_all(&config).context("generating PodInfo TypeScript bindings")?;
    DaemonEvent::export_all(&config).context("generating DaemonEvent TypeScript bindings")?;
    ReviewPlan::export_all(&config).context("generating ReviewPlan TypeScript bindings")?;
    normalize_generated_types(output)?;

    std::fs::write(
        output.join("protocol.ts"),
        concat!(
            "// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.\n",
            "// SPDX-License-Identifier: Apache-2.0\n",
            "\n",
            "// Rust is the source of truth for these API types.\n",
            "export type { DaemonEvent } from \"./DaemonEvent\";\n",
            "export type { PodInfo } from \"./PodInfo\";\n",
            "export type { ReviewFile } from \"./ReviewFile\";\n",
            "export type { ReviewPlan } from \"./ReviewPlan\";\n",
        ),
    )
    .context("writing generated TypeScript protocol barrel")?;
    Ok(())
}

fn normalize_generated_types(root: &Path) -> Result<()> {
    let entries = std::fs::read_dir(root).with_context(|| {
        let root = root.display();
        format!("reading generated bindings directory {root}")
    })?;
    for entry in entries {
        let entry = entry.context("reading generated bindings entry")?;
        let path = entry.path();
        let file_type = entry.file_type().context("reading generated file type")?;
        if file_type.is_dir() {
            normalize_generated_types(&path)?;
            continue;
        }
        if !file_type.is_file() || path.extension() != Some(OsStr::new("ts")) {
            continue;
        }

        let source = std::fs::read_to_string(&path).with_context(|| {
            let path = path.display();
            format!("reading generated TypeScript file {path}")
        })?;
        let had_final_newline = source.ends_with('\n');
        let mut normalized = source
            .lines()
            .map(str::trim_end)
            .collect::<Vec<_>>()
            .join("\n");
        if had_final_newline {
            normalized.push('\n');
        }
        std::fs::write(&path, normalized).with_context(|| {
            let path = path.display();
            format!("normalizing generated TypeScript file {path}")
        })?;
    }
    Ok(())
}

fn check_types(expected: &Path) -> Result<()> {
    let temp = tempfile::TempDir::with_prefix("rumpelpod-vscode-types-")?;
    generate_types(temp.path())?;
    let actual_files = read_tree(temp.path())?;
    let expected_files = read_tree(expected)?;
    if actual_files != expected_files {
        return Err(anyhow::anyhow!(
            "generated VS Code API types are stale; run `cargo vscode --types-only`"
        ));
    }
    Ok(())
}

fn read_tree(root: &Path) -> Result<BTreeMap<PathBuf, Vec<u8>>> {
    let mut files = BTreeMap::new();
    read_tree_into(root, root, &mut files)?;
    Ok(files)
}

fn read_tree_into(root: &Path, dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) -> Result<()> {
    let entries = std::fs::read_dir(dir).with_context(|| {
        let dir = dir.display();
        format!("reading generated bindings directory {dir}")
    })?;
    for entry in entries {
        let entry = entry.context("reading generated bindings entry")?;
        let path = entry.path();
        let file_type = entry.file_type().context("reading generated file type")?;
        if file_type.is_dir() {
            read_tree_into(root, &path, files)?;
        } else if file_type.is_file() && path.extension() == Some(OsStr::new("ts")) {
            let relative = path
                .strip_prefix(root)
                .context("generated file escaped its output directory")?
                .to_path_buf();
            files.insert(relative, std::fs::read(&path)?);
        }
    }
    Ok(())
}
