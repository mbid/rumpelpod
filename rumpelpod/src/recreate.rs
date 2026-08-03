// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;

use anyhow::Result;

use crate::cli::RecreateCommand;
use crate::config::load_json_config;
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, LaunchProgress, PodLaunchParams, PodName};
use crate::enter::{
    collect_local_env, determine_host, find_local_claude_cli, find_local_codex_cli,
    find_local_grok_cli, find_local_pi_cli,
};
use crate::git::{get_current_branch, get_git_user_config, get_repo_root};
use crate::image::OutputLine;

pub fn recreate(cmd: &RecreateCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let pod_name = PodName::new(cmd.name.clone()).map_err(|e| anyhow::anyhow!(e))?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);
    let pods = client.list_pods(repo_root.clone(), true, false)?;
    if !pods.iter().any(|p| p.name == cmd.name) {
        let name = &cmd.name;
        return Err(anyhow::anyhow!("pod '{name}' does not exist"));
    }

    let docker_host = determine_host(&repo_root, cmd.host_args.resolve()?)?;
    let mut local_env_vars = collect_local_env(&repo_root)?;
    let resolved_host = client.resolve_host(docker_host)?;
    let create_reservation = crate::initialize::CreateReservation::acquire(
        &client,
        &socket_path,
        pod_name.clone(),
        repo_root.clone(),
    )?;
    crate::initialize::run(
        &repo_root,
        &cmd.name,
        &resolved_host.host,
        resolved_host.docker_socket.as_deref(),
        &mut local_env_vars,
        &create_reservation,
    )?;
    let docker_host = resolved_host.host;

    let host_branch = get_current_branch(&repo_root);
    let git_identity = get_git_user_config(&repo_root);
    let claude_cli_path = find_local_claude_cli();
    let codex_cli_path = find_local_codex_cli();
    let pi_cli_path = find_local_pi_cli();
    let grok_cli_path = find_local_grok_cli();
    let json_config = load_json_config(&repo_root)?;

    let description_file = json_config
        .merge
        .description_file_path()
        .map(str::to_string);
    let ssh_auth_sock = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from);
    let mut create_reservation = create_reservation;
    let create_token = Some(create_reservation.token_for_handoff()?);
    let progress = client.recreate_pod(PodLaunchParams {
        pod_name,
        repo_path: repo_root,
        host_branch,
        host: docker_host,
        create_token,
        git_identity: Some(git_identity),
        claude_cli_path,
        codex_cli_path,
        pi_cli_path,
        inject_system_prompt: json_config.inject_system_prompt,
        grok_cli_path,
        description_file,
        local_env_vars,
        ssh_auth_sock,
    });
    let mut progress = match progress {
        Ok(progress) => {
            create_reservation.disarm();
            progress
        }
        Err(error) => return Err(error),
    };
    for line in &mut progress {
        match line {
            OutputLine::Stdout(s) => println!("{s}"),
            OutputLine::Stderr(s) => eprintln!("{s}"),
        }
    }
    progress.finish()?;

    let name = &cmd.name;
    println!("recreated pod '{name}'");

    Ok(())
}
