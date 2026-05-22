// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use crate::cli::{ForwardPortCommand, PortsCommand};
use crate::daemon;
use crate::daemon::protocol::{AddForwardedPortRequest, Daemon, DaemonClient, PodName};
use crate::git::get_repo_root;

pub fn ports(cmd: &PortsCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let pod_name = PodName::new(cmd.name.clone()).map_err(|e| anyhow::anyhow!(e))?;
    let ports = client.list_ports(pod_name, repo_root)?;

    println!("{:<12} {:<8} LABEL", "CONTAINER", "LOCAL");
    for p in &ports {
        let container_port = p.container_port;
        let local_port = p.local_port;
        let label = &p.label;
        println!("{container_port:<12} {local_port:<8} {label}");
    }

    Ok(())
}

pub fn forward_port(cmd: &ForwardPortCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let pod_name = PodName::new(cmd.target.pod_name.clone()).map_err(|e| anyhow::anyhow!(e))?;
    let request = AddForwardedPortRequest {
        pod_name,
        repo_path: repo_root,
        container_port: cmd.target.container_port,
        local_port: cmd.local_port,
        label: cmd.label.clone().unwrap_or_default(),
    };
    let info = client.add_forwarded_port(request)?;

    let container_port = info.container_port;
    let local_port = info.local_port;
    println!("forwarded container port {container_port} to local port {local_port}");

    Ok(())
}
