// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Host-side execution of devcontainer initializeCommand.

use std::collections::HashMap;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::sys::signal::{killpg, Signal};
use nix::unistd::Pid;

use crate::config::{ContainerEngine, Host};
use crate::daemon::protocol::{CreateReservationRejected, Daemon, DaemonClient, PodName};
use crate::devcontainer::{
    resolve_devcontainer_vars, DevContainer, LifecycleCommand, StringOrArray,
};

const CREATE_RESERVATION_RENEW_INTERVAL: Duration = Duration::from_secs(20);
const CREATE_RESERVATION_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const CREATE_RESERVATION_LOSS_DEADLINE: Duration = Duration::from_secs(50);
const CREATE_RESERVATION_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const COMMAND_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Keeps exclusive creation permission alive while host initialization runs.
pub(crate) struct CreateReservation {
    client: DaemonClient,
    pod_name: PodName,
    repo_path: PathBuf,
    token: Option<String>,
    stop_tx: Option<Sender<()>>,
    heartbeat: Option<JoinHandle<Result<()>>>,
    lease_lost: Arc<AtomicBool>,
}

impl CreateReservation {
    pub(crate) fn acquire(
        client: &DaemonClient,
        socket_path: &Path,
        pod_name: PodName,
        repo_path: PathBuf,
    ) -> Result<Self> {
        let token = client.reserve_create(pod_name.clone(), repo_path.clone())?;
        let heartbeat_client = DaemonClient::new_unix_with_timeout(
            socket_path,
            Some(CREATE_RESERVATION_REQUEST_TIMEOUT),
        );
        let cleanup_client = DaemonClient::new_unix_with_timeout(
            socket_path,
            Some(CREATE_RESERVATION_REQUEST_TIMEOUT),
        );
        let (stop_tx, stop_rx) = mpsc::channel();
        let heartbeat_pod_name = pod_name.clone();
        let heartbeat_repo_path = repo_path.clone();
        let heartbeat_token = token.clone();
        let lease_lost = Arc::new(AtomicBool::new(false));
        let heartbeat_lease_lost = lease_lost.clone();
        let heartbeat = std::thread::spawn(move || {
            reservation_heartbeat(
                &heartbeat_client,
                heartbeat_pod_name,
                heartbeat_repo_path,
                heartbeat_token,
                stop_rx,
                &heartbeat_lease_lost,
            )
        });

        Ok(Self {
            client: cleanup_client,
            pod_name,
            repo_path,
            token: Some(token),
            stop_tx: Some(stop_tx),
            heartbeat: Some(heartbeat),
            lease_lost,
        })
    }

    pub(crate) fn token_for_handoff(&mut self) -> Result<String> {
        self.stop_heartbeat()?;
        self.token
            .clone()
            .context("create reservation token was already consumed")
    }

    pub(crate) fn disarm(&mut self) {
        self.token = None;
    }

    fn lease_lost(&self) -> Arc<AtomicBool> {
        self.lease_lost.clone()
    }

    fn stop_heartbeat(&mut self) -> Result<()> {
        let send_failed = self
            .stop_tx
            .take()
            .is_some_and(|stop_tx| stop_tx.send(()).is_err());
        let result = match self.heartbeat.take() {
            Some(heartbeat) => match heartbeat.join() {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("create reservation heartbeat panicked")),
            },
            None => Ok(()),
        };
        result?;
        if send_failed {
            return Err(anyhow::anyhow!(
                "create reservation heartbeat stopped unexpectedly"
            ));
        }
        Ok(())
    }
}

impl Drop for CreateReservation {
    fn drop(&mut self) {
        if let Err(error) = self.stop_heartbeat() {
            eprintln!("warning: failed to stop create reservation heartbeat: {error:#}");
        }
        let Some(token) = self.token.take() else {
            return;
        };
        if let Err(error) = self.client.release_create_reservation(
            self.pod_name.clone(),
            self.repo_path.clone(),
            token,
        ) {
            eprintln!("warning: failed to release create reservation: {error:#}");
        }
    }
}

fn reservation_heartbeat(
    client: &DaemonClient,
    pod_name: PodName,
    repo_path: PathBuf,
    token: String,
    stop_rx: Receiver<()>,
    lease_lost: &AtomicBool,
) -> Result<()> {
    reservation_heartbeat_loop(
        stop_rx,
        lease_lost,
        CREATE_RESERVATION_RENEW_INTERVAL,
        CREATE_RESERVATION_RETRY_INTERVAL,
        CREATE_RESERVATION_LOSS_DEADLINE,
        || client.renew_create_reservation(pod_name.clone(), repo_path.clone(), token.clone()),
    )
}

fn reservation_heartbeat_loop<F>(
    stop_rx: Receiver<()>,
    lease_lost: &AtomicBool,
    renew_interval: Duration,
    retry_interval: Duration,
    loss_deadline: Duration,
    mut renew: F,
) -> Result<()>
where
    F: FnMut() -> Result<()>,
{
    let mut last_success = Instant::now();
    let mut interval = renew_interval;
    loop {
        match stop_rx.recv_timeout(interval) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => return Ok(()),
            Err(RecvTimeoutError::Timeout) => match renew() {
                Ok(()) => {
                    last_success = Instant::now();
                    interval = renew_interval;
                }
                Err(error) => {
                    let rejected = error
                        .chain()
                        .any(|cause| cause.is::<CreateReservationRejected>());
                    if rejected || last_success.elapsed() >= loss_deadline {
                        lease_lost.store(true, Ordering::Release);
                        return Err(error.context("create reservation lease was lost"));
                    }
                    interval = retry_interval;
                }
            },
        }
    }
}

/// Run initializeCommand when configured.
///
/// The caller supplies the local environment snapshot that will later be sent
/// to the daemon. Backend overrides are added to that same map before variable
/// substitution so `${localEnv:DOCKER_HOST}` matches the child process.
pub(crate) fn run(
    repo_path: &Path,
    pod_name: &str,
    host: &Host,
    docker_socket: Option<&Path>,
    local_env: &mut HashMap<String, String>,
    reservation: &CreateReservation,
) -> Result<()> {
    let devcontainer = DevContainer::find_and_load(repo_path)?
        .map(|(devcontainer, _)| devcontainer)
        .unwrap_or_default();
    let Some(command) = devcontainer.initialize_command.as_ref() else {
        return Ok(());
    };
    if command_is_empty(command) {
        return Ok(());
    }

    let env_overrides = backend_environment(host, docker_socket)?;
    local_env.extend(env_overrides.clone());

    let devcontainer = resolve_devcontainer_vars(devcontainer, repo_path, pod_name, local_env);
    let Some(command) = devcontainer.initialize_command.as_ref() else {
        return Err(anyhow::anyhow!(
            "initializeCommand disappeared during variable substitution"
        ));
    };

    eprintln!("running initializeCommand...");
    let lease_lost = reservation.lease_lost();
    run_command(command, repo_path, &env_overrides, &lease_lost)
        .context("initializeCommand in devcontainer.json failed")?;
    Ok(())
}

fn command_is_empty(command: &LifecycleCommand) -> bool {
    match command {
        LifecycleCommand::String(command) => command.trim().is_empty(),
        LifecycleCommand::Array(command) => command.is_empty(),
        LifecycleCommand::Object(command) => command.is_empty(),
    }
}

fn backend_environment(
    host: &Host,
    docker_socket: Option<&Path>,
) -> Result<HashMap<String, String>> {
    let mut env = HashMap::new();
    match host {
        Host::Localhost {
            engine: ContainerEngine::Docker,
        } => {
            let socket = docker_socket.context("daemon did not return its local Docker socket")?;
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
    Ok(env)
}

fn run_command(
    command: &LifecycleCommand,
    workdir: &Path,
    env: &HashMap<String, String>,
    lease_lost: &Arc<AtomicBool>,
) -> Result<()> {
    match command {
        LifecycleCommand::String(command) => {
            let args = ["/bin/sh".to_string(), "-c".to_string(), command.clone()];
            run_one("initializeCommand", &args, workdir, env, lease_lost)
        }
        LifecycleCommand::Array(args) => {
            run_one("initializeCommand", args, workdir, env, lease_lost)
        }
        LifecycleCommand::Object(commands) => run_parallel(commands, workdir, env, lease_lost),
    }
}

fn run_parallel(
    commands: &HashMap<String, StringOrArray>,
    workdir: &Path,
    env: &HashMap<String, String>,
    lease_lost: &Arc<AtomicBool>,
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
            let lease_lost = lease_lost.clone();
            std::thread::spawn(move || {
                let label = format!("initializeCommand/{name}");
                run_one(&label, &args, &workdir, &env, &lease_lost)
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
    lease_lost: &AtomicBool,
) -> Result<()> {
    let Some((program, args)) = args.split_first() else {
        return Ok(());
    };

    let mut command = Command::new(program);
    command
        .args(args)
        .current_dir(workdir)
        .envs(env)
        .process_group(0);
    let mut child = command
        .spawn()
        .with_context(|| format!("spawning {name}"))?;
    loop {
        if lease_lost.load(Ordering::Acquire) {
            if child.try_wait()?.is_none() {
                let pid = i32::try_from(child.id()).context("initializer process ID overflowed")?;
                match killpg(Pid::from_raw(pid), Signal::SIGKILL) {
                    Ok(()) | Err(Errno::ESRCH) => {}
                    Err(error) => {
                        return Err(error)
                            .with_context(|| format!("terminating {name} after reservation loss"));
                    }
                }
                child
                    .wait()
                    .with_context(|| format!("waiting for terminated {name}"))?;
            }
            return Err(anyhow::anyhow!(
                "{name} stopped because its create reservation was lost"
            ));
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                return Err(anyhow::anyhow!("{name} exited with {status}"));
            }
            return Ok(());
        }
        std::thread::sleep(COMMAND_STATUS_POLL_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::time::Duration;

    use super::{backend_environment, reservation_heartbeat_loop, run_one};
    use crate::config::{ContainerEngine, Host};
    use crate::daemon::protocol::CreateReservationRejected;

    #[test]
    fn initialize_command_ssh_environment_targets_remote_engine() {
        let host = Host::Ssh {
            ssh_destination: "developer@example.test".to_string(),
            engine: ContainerEngine::Docker,
        };

        let environment = backend_environment(&host, None).expect("resolve SSH environment");
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

        assert!(backend_environment(&host, None)
            .expect("resolve Kubernetes environment")
            .is_empty());
    }

    #[test]
    fn initialize_command_local_docker_environment_uses_daemon_socket() {
        let host = Host::Localhost {
            engine: ContainerEngine::Docker,
        };

        let environment = backend_environment(&host, Some(Path::new("/tmp/daemon-docker.sock")))
            .expect("resolve Docker environment");
        assert_eq!(
            environment.get("DOCKER_HOST").map(String::as_str),
            Some("unix:///tmp/daemon-docker.sock")
        );
    }

    #[test]
    fn initialize_command_stops_after_create_reservation_loss() {
        let tempdir = tempfile::tempdir().expect("create temporary directory");
        let ready = tempdir.path().join("ready");
        let survivor = tempdir.path().join("survivor");
        let ready_arg = ready.display();
        let survivor_arg = survivor.display();
        let args = [
            "/bin/sh".to_string(),
            "-c".to_string(),
            format!("touch '{ready_arg}'; sleep 1; touch '{survivor_arg}'"),
        ];
        let lease_lost = Arc::new(AtomicBool::new(false));
        let command_lease_lost = lease_lost.clone();
        let handle = std::thread::spawn(move || {
            run_one(
                "initializeCommand",
                &args,
                Path::new("/"),
                &HashMap::new(),
                &command_lease_lost,
            )
        });
        for _ in 0..200 {
            if ready.exists() || handle.is_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "initializer did not start its subprocess");
        lease_lost.store(true, Ordering::Release);
        let error = handle
            .join()
            .expect("initializer thread should not panic")
            .expect_err("lost reservation should stop command");
        let error = format!("{error:#}");
        assert!(
            error.contains("create reservation was lost"),
            "unexpected error: {error}"
        );
        std::thread::sleep(Duration::from_millis(1100));
        assert!(
            !survivor.exists(),
            "initializer subprocess survived reservation loss"
        );
    }

    #[test]
    fn create_reservation_rejection_stops_heartbeat_immediately() {
        let (_stop_tx, stop_rx) = mpsc::channel();
        let lease_lost = AtomicBool::new(false);
        let result = reservation_heartbeat_loop(
            stop_rx,
            &lease_lost,
            Duration::from_millis(1),
            Duration::from_secs(30),
            Duration::from_secs(50),
            || {
                Err(
                    CreateReservationRejected::new(409, "reservation was replaced".to_string())
                        .into(),
                )
            },
        );

        result.expect_err("daemon rejection should stop the heartbeat");
        assert!(lease_lost.load(Ordering::Acquire));
    }
}
