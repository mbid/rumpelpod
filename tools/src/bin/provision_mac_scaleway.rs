// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Provision an Apple Silicon Mac mini on Scaleway for macOS builds.
//!
//! Creates a 24-hour server, installs Rust/Homebrew/Docker/musl toolchain,
//! and writes SSH credentials to `.env`.
//!
//! Usage: cargo run --bin provision-mac-scaleway

use std::process::{Command, ExitCode};

use anyhow::{Context, Result};

const ZONE: &str = "fr-par-1";
// Cheapest available: 8-core M2, 16GB, 256GB SSD, EUR0.17/hr
const SERVER_TYPE: &str = "M2-M";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let repo_root = tools::repo_root()?;
    let resource_dir = repo_root.join("cloud/macos");
    let state_file = resource_dir.join("scaleway-server.json");

    let home = std::env::var("HOME").context("HOME not set")?;
    let scw = format!("{home}/.local/bin/scw");
    let ssh_key = std::env::var("SSH_KEY")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| resource_dir.join("id_ed25519"));
    let ssh_config_dir = format!("{home}/.ssh/config.d");
    let ssh_config_file = format!("{ssh_config_dir}/macos");

    if state_file.exists() {
        let path = state_file.display();
        anyhow::bail!(
            "a server state file already exists at {path}\n\
             Remove the file if the server is already gone."
        );
    }

    std::fs::create_dir_all(&resource_dir)
        .with_context(|| format!("creating {}", resource_dir.display()))?;

    if !ssh_key.exists() {
        let key_path = ssh_key.display();
        eprintln!("==> Generating SSH keypair at {key_path}...");
        tools::run(Command::new("ssh-keygen").args([
            "-t",
            "ed25519",
            "-f",
            ssh_key.to_str().unwrap(),
            "-N",
            "",
            "-C",
            "rumpelpod-cloud",
        ]))?;
    }

    eprintln!("==> Creating Apple Silicon server (type={SERVER_TYPE}, zone={ZONE})...");
    let server_json = tools::output(Command::new(&scw).args([
        "apple-silicon",
        "server",
        "create",
        &format!("type={SERVER_TYPE}"),
        &format!("zone={ZONE}"),
        "commitment-type=duration_24h",
        "-o",
        "json",
        "-w",
    ]))?;

    let parsed: serde_json::Value =
        serde_json::from_str(&server_json).context("parsing scw JSON output")?;
    let server_id = parsed["id"]
        .as_str()
        .context("missing 'id' in server JSON")?;
    let server_ip = parsed["ip"]
        .as_str()
        .context("missing 'ip' in server JSON")?;
    let vnc_url = parsed["vnc_url"].as_str().unwrap_or("");

    std::fs::write(&state_file, &server_json)
        .with_context(|| format!("writing {}", state_file.display()))?;

    eprintln!("==> Server created: {server_id}");
    eprintln!("    IP: {server_ip}");

    // Schedule auto-deletion after the 24h minimum lease.
    eprintln!("==> Scheduling auto-deletion (server will be deleted once 24h lease expires)...");
    tools::run_quiet(Command::new(&scw).args([
        "apple-silicon",
        "server",
        "update",
        server_id,
        "schedule-deletion=true",
        &format!("zone={ZONE}"),
    ]))?;

    // -- Wait for SSH and add to known_hosts ----------------------------------

    eprintln!("==> Adding server to SSH known_hosts...");
    let known_hosts_path = format!("{home}/.ssh/known_hosts");
    for i in 1..=30 {
        let scan = Command::new("ssh-keyscan")
            .args(["-T", "5", server_ip])
            .output();
        if let Ok(out) = scan {
            let keys = String::from_utf8_lossy(&out.stdout);
            if !keys.trim().is_empty() {
                // Append and deduplicate.
                let mut existing = std::fs::read_to_string(&known_hosts_path).unwrap_or_default();
                existing.push_str(&keys);
                let mut lines: Vec<&str> = existing.lines().collect();
                lines.sort();
                lines.dedup();
                let deduped = lines.join("\n") + "\n";
                std::fs::write(&known_hosts_path, deduped)?;
                eprintln!("    Known host added.");
                break;
            }
        }
        eprintln!("    Waiting for SSH to become available (attempt {i}/30)...");
        std::thread::sleep(std::time::Duration::from_secs(10));
    }

    // Extract password from VNC URL for sudo (format: vnc://user:pass@host:port).
    let vnc_pass = vnc_url
        .strip_prefix("vnc://")
        .and_then(|s| s.split_once(':'))
        .and_then(|(_, rest)| rest.split_once('@'))
        .map(|(pass, _)| pass)
        .unwrap_or("");

    let ssh_target = format!("m1@{server_ip}");

    // Enable passwordless sudo.
    eprintln!("==> Enabling passwordless sudo...");
    ssh_cmd(
        &ssh_target,
        &format!(
            "echo '{vnc_pass}' | sudo -S bash -c 'echo \"m1 ALL=(ALL) NOPASSWD: ALL\" > /etc/sudoers.d/m1'"
        ),
    )?;

    // Add our public key to authorized_keys.
    eprintln!("==> Adding public key to server...");
    let pub_key = std::fs::read_to_string(format!("{}.pub", ssh_key.display()))
        .context("reading SSH public key")?;
    ssh_cmd(
        &ssh_target,
        &format!("echo '{pub_key}' >> ~/.ssh/scw_authorized_keys"),
    )?;

    // Install Rust via rustup.
    eprintln!("==> Installing Rust via rustup...");
    ssh_cmd(
        &ssh_target,
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y",
    )?;

    // Install Homebrew.
    eprintln!("==> Installing Homebrew...");
    ssh_cmd(
        &ssh_target,
        "NONINTERACTIVE=1 /bin/bash -c \"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"",
    )?;

    // .zprofile is only sourced by login shells; non-interactive SSH commands
    // run as non-login shells that only source .zshenv.
    eprintln!("==> Adding Homebrew to PATH in .zshenv...");
    ssh_cmd(
        &ssh_target,
        "echo 'eval \"$(/opt/homebrew/bin/brew shellenv)\"' >> ~/.zshenv",
    )?;

    eprintln!("==> Installing Docker via Colima...");
    ssh_cmd(
        &ssh_target,
        "brew install colima docker docker-buildx docker-compose && colima start --cpu 4 --memory 8",
    )?;

    // docker-buildx is installed via homebrew, so Docker needs to know
    // where to find CLI plugins.
    eprintln!("==> Configuring Docker CLI plugins path...");
    ssh_cmd(
        &ssh_target,
        r#"mkdir -p ~/.docker && python3 -c "
import json, os
p = os.path.expanduser('~/.docker/config.json')
cfg = json.load(open(p)) if os.path.exists(p) else {}
cfg['cliPluginsExtraDirs'] = ['/opt/homebrew/lib/docker/cli-plugins']
json.dump(cfg, open(p, 'w'), indent=2)
""#,
    )?;

    eprintln!("==> Installing git-lfs...");
    ssh_cmd(&ssh_target, "brew install git-lfs")?;

    eprintln!("==> Installing musl cross-compilation toolchain...");
    ssh_cmd(
        &ssh_target,
        "brew install FiloSottile/musl-cross/musl-cross",
    )?;

    eprintln!("==> Adding Rust musl targets...");
    ssh_cmd(
        &ssh_target,
        "source \"$HOME/.cargo/env\" && rustup target add x86_64-unknown-linux-musl aarch64-unknown-linux-musl",
    )?;

    // Tests that exercise `rumpel claude` and `rumpel codex` need the
    // host CLIs so detect_local_claude / local_has_codex find them and
    // bake them into the prepared container image.
    eprintln!("==> Installing Node.js (needed for Claude Code and Codex CLIs)...");
    ssh_cmd(&ssh_target, "brew install node")?;

    eprintln!("==> Installing Claude Code and Codex CLIs...");
    ssh_cmd(
        &ssh_target,
        "npm install -g @anthropic-ai/claude-code @openai/codex",
    )?;

    // Tests create git repos and expect "master" as the default branch.
    eprintln!("==> Setting default git branch to master...");
    ssh_cmd(&ssh_target, "git config --global init.defaultBranch master")?;

    // -- Set up local SSH config so `ssh macos` works -------------------------

    let ssh_key_display = ssh_key.display();
    let ssh_host_block =
        format!("Host macos\n  HostName {server_ip}\n  User m1\n  IdentityFile {ssh_key_display}");

    let mut write_config = true;
    if std::path::Path::new(&ssh_config_file).exists() {
        eprintln!();
        eprintln!("==> SSH config already exists at {ssh_config_file}:");
        let existing = std::fs::read_to_string(&ssh_config_file)?;
        eprintln!("{existing}");
        write_config = tools::confirm("Overwrite?")?;
    }

    if write_config {
        std::fs::create_dir_all(&ssh_config_dir)?;
        std::fs::write(&ssh_config_file, &ssh_host_block)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&ssh_config_file, std::fs::Permissions::from_mode(0o600))?;
        }
        eprintln!("    Wrote {ssh_config_file}");
    }

    // Check whether ~/.ssh/config already includes config.d.
    let ssh_config_main = format!("{home}/.ssh/config");
    let includes_config_d = std::fs::read_to_string(&ssh_config_main)
        .map(|c| c.contains("Include config.d/*"))
        .unwrap_or(false);
    if !includes_config_d {
        eprintln!();
        eprintln!(" NOTE: Add this line to the TOP of ~/.ssh/config:");
        eprintln!();
        eprintln!("   Include config.d/*");
    }

    let state_display = state_file.display();
    eprintln!();
    eprintln!("============================================");
    eprintln!(" Mac mini ready!");
    eprintln!("============================================");
    eprintln!(" Server ID : {server_id}");
    eprintln!(" IP        : {server_ip}");
    eprintln!(" Zone      : {ZONE}");
    eprintln!(" Type      : {SERVER_TYPE}");
    eprintln!(" Commitment: 24h (auto-delete scheduled)");
    eprintln!();
    eprintln!(" SSH:");
    eprintln!("   ssh macos");
    eprintln!();
    eprintln!(" VNC (Remmina):");
    if !vnc_url.is_empty() {
        eprintln!("   {vnc_url}");
    } else {
        eprintln!("   Get VNC details with:");
        eprintln!("     {scw} apple-silicon server get {server_id} zone={ZONE} -o json | jq '{{vnc_url, ip}}'");
        eprintln!("   Then in Remmina: create VNC connection to the IP:port shown.");
        eprintln!("   The VNC password is shown in the Scaleway console overview page.");
    }
    eprintln!(" State saved to: {state_display}");
    eprintln!();

    // Write SSH config and known_hosts as raw files in the resource dir.
    // The entrypoint.sh copies these to ~/.ssh/ when the devcontainer starts.
    let container_ssh_config =
        format!("Host macos\n  HostName {server_ip}\n  User m1\n  IdentityFile ~/.ssh/macos_id\n");
    std::fs::write(resource_dir.join("ssh_config"), &container_ssh_config)
        .context("writing ssh_config")?;

    let known_hosts_line =
        tools::output(Command::new("ssh-keyscan").args(["-T", "5", server_ip])).unwrap_or_default();
    std::fs::write(resource_dir.join("known_hosts"), &known_hosts_line)
        .context("writing known_hosts")?;

    let resource_dir_display = resource_dir.display();
    eprintln!(" macOS credentials written to {resource_dir_display}");

    Ok(ExitCode::SUCCESS)
}

fn ssh_cmd(target: &str, cmd: &str) -> Result<()> {
    tools::run(Command::new("ssh").args([target, cmd]))
}
