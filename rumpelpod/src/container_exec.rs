// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Execute a command inside a container with the pod server's resolved
//! environment.
//!
//! `rumpel container-exec -- <command>` is the internal mechanism used by
//! `rumpel enter` and similar commands run from the local machine.
//! Instead of passing environment variables on the `docker exec` /
//! `kubectl exec` command line, the command fetches the resolved
//! environment from the local pod server and applies it before exec-ing
//! the target command.  This keeps the pod server as the single source
//! of truth for the environment.

use std::collections::HashMap;
use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};

use crate::devcontainer::UserEnvProbe;
use crate::pod::server::TOKEN_FILE;

const DEVCONTAINER_CONFIG_PATH: &str = "/opt/rumpelpod/devcontainer.json";

pub fn container_exec(command: Vec<String>, workdir: Option<PathBuf>) -> Result<()> {
    crate::switch_user::switch_user().context("switching to container user")?;

    let token =
        std::fs::read_to_string(TOKEN_FILE).context("reading pod server token from disk")?;

    let port_path = std::path::Path::new(crate::port_file::SERVER_PORT_FILE);
    let port =
        crate::port_file::read_required(port_path).context("reading pod server port from disk")?;

    let url = format!("http://127.0.0.1:{port}/env");
    let env: HashMap<String, String> = reqwest::blocking::Client::new()
        .get(&url)
        .bearer_auth(&token)
        .send()
        .context("fetching resolved env from pod server")?
        .json()
        .context("parsing env response")?;

    for (key, value) in &env {
        std::env::set_var(key, value);
    }

    if std::io::stdin().is_terminal() {
        crate::ensure_tui_terminal_env();
    }

    if let Some(ref dir) = workdir {
        std::env::set_current_dir(dir).with_context(|| format!("chdir to {}", dir.display()))?;
    }

    // When no command is given, default to the current user's login
    // shell with flags derived from the devcontainer's userEnvProbe.
    let command = if command.is_empty() {
        let uid = nix::unistd::getuid();
        let user = nix::unistd::User::from_uid(uid)
            .with_context(|| format!("looking up uid {uid}"))?
            .with_context(|| format!("uid {uid} not found in passwd"))?;
        let shell = user.shell.to_string_lossy().to_string();
        let mut cmd = vec![shell];
        if let Some(flags) = interactive_shell_flags() {
            cmd.push(flags);
        }
        cmd
    } else {
        command
    };

    let err = Command::new(&command[0]).args(&command[1..]).exec();
    Err(err).context(format!("exec {:?}", command[0]))
}

/// Read userEnvProbe from the baked devcontainer.json and return the
/// corresponding interactive shell flags (e.g. "-li").
fn interactive_shell_flags() -> Option<String> {
    let json = std::fs::read_to_string(DEVCONTAINER_CONFIG_PATH).ok()?;
    let doc: serde_json::Value = serde_json::from_str(&json).ok()?;
    let probe_str = doc.get("userEnvProbe")?.as_str()?;
    let probe: UserEnvProbe =
        serde_json::from_value(serde_json::Value::String(probe_str.to_string())).ok()?;
    probe.shell_flags_interactive().map(String::from)
}
