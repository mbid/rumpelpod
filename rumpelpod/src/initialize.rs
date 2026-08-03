// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side execution of devcontainer initializeCommand.

use std::collections::HashMap;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::config::{ContainerEngine, Host};
use crate::devcontainer::{
    resolve_devcontainer_vars, DevContainer, LifecycleCommand, StringOrArray,
};

/// Run initializeCommand when configured and return the concrete backend host.
///
/// The caller supplies the local environment snapshot that will later be sent
/// to the daemon. Backend overrides are added to that same map before variable
/// substitution so `${localEnv:DOCKER_HOST}` matches the child process.
pub(crate) fn run(
    repo_path: &Path,
    pod_name: &str,
    host: Host,
    local_env: &mut HashMap<String, String>,
) -> Result<Host> {
    let devcontainer = DevContainer::find_and_load(repo_path)?
        .map(|(devcontainer, _)| devcontainer)
        .unwrap_or_default();
    let Some(command) = devcontainer.initialize_command.as_ref() else {
        return Ok(host);
    };
    if command_is_empty(command) {
        return Ok(host);
    }

    let host = host.resolve_container_tools()?;
    let env_overrides = backend_environment(&host);
    local_env.extend(env_overrides.clone());

    let devcontainer = resolve_devcontainer_vars(devcontainer, repo_path, pod_name, local_env);
    let Some(command) = devcontainer.initialize_command.as_ref() else {
        return Err(anyhow::anyhow!(
            "initializeCommand disappeared during variable substitution"
        ));
    };

    eprintln!("running initializeCommand...");
    run_command(command, repo_path, &env_overrides)
        .context("initializeCommand in devcontainer.json failed")?;
    Ok(host)
}

fn command_is_empty(command: &LifecycleCommand) -> bool {
    match command {
        LifecycleCommand::String(command) => command.trim().is_empty(),
        LifecycleCommand::Array(command) => command.is_empty(),
        LifecycleCommand::Object(command) => command.is_empty(),
    }
}

fn backend_environment(host: &Host) -> HashMap<String, String> {
    let mut env = HashMap::new();
    match host {
        Host::Localhost {
            engine: ContainerEngine::Docker,
        } => {
            let socket = crate::daemon::default_docker_socket();
            let socket = socket.display();
            env.insert("DOCKER_HOST".to_string(), format!("unix://{socket}"));
            env.insert("DOCKER_CONTEXT".to_string(), "default".to_string());
        }
        Host::Ssh {
            ssh_destination,
            engine: ContainerEngine::Docker,
        } => {
            env.insert(
                "DOCKER_HOST".to_string(),
                format!("ssh://{ssh_destination}"),
            );
            env.insert("DOCKER_CONTEXT".to_string(), "default".to_string());
        }
        Host::Ssh {
            ssh_destination,
            engine: ContainerEngine::Podman,
        } => {
            let host = format!("ssh://{ssh_destination}");
            env.insert("DOCKER_HOST".to_string(), host.clone());
            env.insert("CONTAINER_HOST".to_string(), host);
        }
        Host::Localhost {
            engine: ContainerEngine::Podman,
        }
        | Host::Kubernetes { .. } => {}
        Host::Localhost {
            engine: ContainerEngine::Auto,
        }
        | Host::Ssh {
            engine: ContainerEngine::Auto,
            ..
        } => {
            panic!("container engine auto remained after resolve")
        }
    }
    env
}

fn run_command(
    command: &LifecycleCommand,
    workdir: &Path,
    env: &HashMap<String, String>,
) -> Result<()> {
    match command {
        LifecycleCommand::String(command) => {
            let args = ["/bin/sh".to_string(), "-c".to_string(), command.clone()];
            run_one("initializeCommand", &args, workdir, env)
        }
        LifecycleCommand::Array(args) => run_one("initializeCommand", args, workdir, env),
        LifecycleCommand::Object(commands) => run_parallel(commands, workdir, env),
    }
}

fn run_parallel(
    commands: &HashMap<String, StringOrArray>,
    workdir: &Path,
    env: &HashMap<String, String>,
) -> Result<()> {
    let handles: Vec<_> = commands
        .iter()
        .map(|(name, command)| {
            let name = name.clone();
            let args = match command {
                StringOrArray::String(command) => {
                    vec!["/bin/sh".to_string(), "-c".to_string(), command.clone()]
                }
                StringOrArray::Array(args) => args.clone(),
            };
            let workdir = workdir.to_path_buf();
            let env = env.clone();
            std::thread::spawn(move || {
                let label = format!("initializeCommand/{name}");
                run_one(&label, &args, &workdir, &env)
            })
        })
        .collect();

    let mut first_error = None;
    for handle in handles {
        let result = match handle.join() {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("initializeCommand thread panicked")),
        };
        if let Err(error) = result {
            if first_error.is_none() {
                first_error = Some(error);
            }
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn run_one(
    name: &str,
    args: &[String],
    workdir: &Path,
    env: &HashMap<String, String>,
) -> Result<()> {
    let Some((program, args)) = args.split_first() else {
        return Ok(());
    };

    let status = Command::new(program)
        .args(args)
        .current_dir(workdir)
        .envs(env)
        .status()
        .with_context(|| format!("spawning {name}"))?;
    if !status.success() {
        return Err(anyhow::anyhow!("{name} exited with {status}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::backend_environment;
    use crate::config::{ContainerEngine, Host};

    #[test]
    fn initialize_command_ssh_environment_targets_remote_engine() {
        let host = Host::Ssh {
            ssh_destination: "developer@example.test".to_string(),
            engine: ContainerEngine::Docker,
        };

        let environment = backend_environment(&host);
        assert_eq!(
            environment.get("DOCKER_HOST").map(String::as_str),
            Some("ssh://developer@example.test")
        );
        assert_eq!(
            environment.get("DOCKER_CONTEXT").map(String::as_str),
            Some("default")
        );
    }

    #[test]
    fn initialize_command_kubernetes_environment_does_not_invent_docker_target() {
        let host = Host::Kubernetes {
            context: "test-context".to_string(),
            namespace: "test-namespace".to_string(),
            registry: "registry.example.test".to_string(),
            node_selector: None,
            tolerations: None,
            builder: None,
            image_builder: ContainerEngine::Docker,
        };

        assert!(backend_environment(&host).is_empty());
    }
}
