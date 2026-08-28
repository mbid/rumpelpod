// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::cli::ConnectCommand;
use crate::daemon;
use crate::daemon::protocol::{ClientContext, ConnectPodRequest, Daemon, DaemonClient};
use crate::git::get_repo_root;

pub fn connect(cmd: &ConnectCommand) -> Result<()> {
    let repo_path = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    client.connect_pod(ConnectPodRequest {
        pod_name: cmd.name.clone(),
        repo_path,
        client_context: ClientContext::current(),
    })
}
