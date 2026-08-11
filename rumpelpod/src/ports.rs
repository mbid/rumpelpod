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

    println!("{:<24} {:<8} LABEL", "TARGET", "LOCAL");
    for p in &ports {
        let container_port = p.container_port;
        let local_port = p.local_port;
        let label = &p.label;
        let target = if p.service.is_empty() {
            container_port.to_string()
        } else {
            format!("{}:{container_port}", p.service)
        };
        println!("{target:<24} {local_port:<8} {label}");
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
        service: cmd.service.clone(),
        container_port: cmd.target.container_port,
        local_port: cmd.local_port,
        label: cmd.label.clone().unwrap_or_default(),
    };
    let info = client.add_forwarded_port(request)?;

    let container_port = info.container_port;
    let local_port = info.local_port;
    let target = if info.service.is_empty() {
        container_port.to_string()
    } else {
        format!("{}:{container_port}", info.service)
    };
    println!("forwarded container port {target} to local port {local_port}");

    Ok(())
}
