// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::cli::ReconnectCommand;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, ReconnectPodConnectionRequest};
use crate::git::get_repo_root;

pub fn reconnect(cmd: &ReconnectCommand) -> Result<()> {
    let repo_path = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    client.reconnect_pod_connection(ReconnectPodConnectionRequest {
        pod_name: cmd.name.clone(),
        repo_path,
        reconnect_host: cmd.host,
    })
}
