// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Handler for `rumpel ssh-add <pod> <args>...`.
//!
//! The daemon owns the per-pod ssh-agent; we ask it to make sure the
//! agent is up and to hand us the socket path, then exec `ssh-add`
//! locally with `SSH_AUTH_SOCK` pointing at that socket.  All args
//! after the pod name are forwarded verbatim so any ssh-add flag
//! (`-l`, `-d`, `-D`, `-t`, ...) works without rumpel having to know
//! about it.

use std::os::unix::process::CommandExt;
use std::process::Command;

use anyhow::{Context, Result};

use crate::cli::SshAddCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, PodName};
use crate::git::get_repo_root;

pub fn ssh_add(cmd: &SshAddCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = daemon::protocol::DaemonClient::new_unix(&socket_path);
    let pod_name = PodName::new(cmd.name.clone()).map_err(|e| anyhow::anyhow!(e))?;

    let agent_sock = client.ensure_ssh_agent(pod_name, repo_root)?;

    // Use exec so ssh-add inherits the terminal directly (passphrase
    // prompts, signal handling) and its exit status becomes ours.
    let err = Command::new("ssh-add")
        .args(&cmd.args)
        .env("SSH_AUTH_SOCK", &agent_sock)
        .exec();
    Err(err).context("failed to exec ssh-add")
}
