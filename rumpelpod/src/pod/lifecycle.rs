// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Lifecycle command execution inside the container.
//!
//! Reads the lifecycle config from PodServerState (originally parsed from
//! the workspace's devcontainer.json on server startup) and runs commands
//! in order, using flag files for once-per-creation state and an in-memory
//! bool for per-start state.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::{Context, Result};

use super::types::{base64_encode, LifecycleCommandResult, LifecycleResponse};
use crate::devcontainer::{LifecycleCommand, LifecycleConfig, StringOrArray, WaitFor};

/// Flag files recording which once-per-creation commands have run.
const FLAGS_DIR: &str = "/opt/rumpelpod/lifecycle";

pub fn run(
    config: &LifecycleConfig,
    env: &HashMap<String, String>,
    post_start_ran: &Arc<AtomicBool>,
    workdir: &Path,
) -> Result<LifecycleResponse> {
    std::fs::create_dir_all(FLAGS_DIR)
        .with_context(|| format!("creating lifecycle flags directory {FLAGS_DIR}"))?;

    let on_create_ran = flag_exists("on-create-ran");
    let post_create_ran = flag_exists("post-create-ran");

    // Collect the full ordered sequence of (name, command, should_run).
    let mut sequence: Vec<(&str, &LifecycleCommand, bool)> = Vec::new();

    if let Some(ref cmd) = config.on_create_command {
        sequence.push(("onCreateCommand", cmd, !on_create_ran));
    }
    if let Some(ref cmd) = config.update_content_command {
        sequence.push(("updateContentCommand", cmd, true));
    }
    if let Some(ref cmd) = config.post_create_command {
        sequence.push(("postCreateCommand", cmd, !post_create_ran));
    }
    if let Some(ref cmd) = config.post_start_command {
        let ran = post_start_ran.load(std::sync::atomic::Ordering::Relaxed);
        sequence.push(("postStartCommand", cmd, !ran));
    }
    let wait_for = &config.wait_for;

    let mut results = Vec::new();
    let mut background = Vec::new();

    for (name, cmd, should_run) in &sequence {
        if !should_run {
            continue;
        }

        let is_foreground = match *name {
            "onCreateCommand" => *wait_for >= WaitFor::OnCreateCommand,
            "updateContentCommand" => *wait_for >= WaitFor::UpdateContentCommand,
            "postCreateCommand" => *wait_for >= WaitFor::PostCreateCommand,
            "postStartCommand" => *wait_for >= WaitFor::PostStartCommand,
            _ => true,
        };

        if is_foreground {
            let result = run_lifecycle_command(name, cmd, env, workdir);
            mark_ran(name, post_start_ran);

            match result {
                Ok(r) => {
                    if r.exit_code != 0 {
                        // On failure, mark subsequent once-per-creation
                        // commands as done to prevent retries.
                        mark_ran_on_failure(name, post_start_ran);
                        results.push(r);
                        return Ok(LifecycleResponse {
                            results,
                            background,
                        });
                    }
                    results.push(r);
                }
                Err(e) => return Err(e),
            }
        } else {
            background.push(name.to_string());
        }
    }

    // Spawn background commands in a single thread.
    if !background.is_empty() {
        let bg_cmds: Vec<(String, LifecycleCommand)> = background
            .iter()
            .filter_map(|name| {
                sequence
                    .iter()
                    .find(|(n, _, should)| *n == name.as_str() && *should)
                    .map(|(n, cmd, _)| (n.to_string(), (*cmd).clone()))
            })
            .collect();
        let workdir = workdir.to_path_buf();
        let post_start_ran = post_start_ran.clone();
        let env = env.clone();
        std::thread::spawn(move || {
            for (name, cmd) in &bg_cmds {
                if let Err(e) = run_lifecycle_command(name, cmd, &env, &workdir) {
                    eprintln!("background {name} failed: {e:#}");
                    break;
                }
                mark_ran(name, &post_start_ran);
            }
        });
    }

    Ok(LifecycleResponse {
        results,
        background,
    })
}

/// Run a single lifecycle command (string, array, or parallel object).
fn run_lifecycle_command(
    name: &str,
    cmd: &LifecycleCommand,
    env: &HashMap<String, String>,
    workdir: &Path,
) -> Result<LifecycleCommandResult> {
    match cmd {
        LifecycleCommand::String(s) => run_one_command(name, &["sh", "-c", s], env, workdir),
        LifecycleCommand::Array(args) => {
            let args_ref: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            run_one_command(name, &args_ref, env, workdir)
        }
        LifecycleCommand::Object(map) => {
            // Run all named commands in parallel, wait for all.
            let handles: Vec<_> = map
                .iter()
                .map(|(task_name, cmd_value)| {
                    let cmd_args: Vec<String> = match cmd_value {
                        StringOrArray::String(s) => {
                            vec!["sh".into(), "-c".into(), s.clone()]
                        }
                        StringOrArray::Array(a) => a.clone(),
                    };
                    let wd = workdir.to_path_buf();
                    let label = format!("{name}/{task_name}");
                    let env = env.clone();
                    std::thread::spawn(move || {
                        let args_ref: Vec<&str> = cmd_args.iter().map(|s| s.as_str()).collect();
                        run_one_command(&label, &args_ref, &env, &wd)
                    })
                })
                .collect();

            let mut first_failure = None;
            for handle in handles {
                let r = handle
                    .join()
                    .map_err(|_| anyhow::anyhow!("lifecycle command thread panicked"))??;
                if r.exit_code != 0 && first_failure.is_none() {
                    first_failure = Some(r);
                }
            }

            match first_failure {
                Some(f) => Ok(f),
                None => Ok(LifecycleCommandResult {
                    name: name.to_string(),
                    exit_code: 0,
                    stderr: String::new(),
                }),
            }
        }
    }
}

/// Execute a single command with the fully resolved pod environment.
fn run_one_command(
    name: &str,
    args: &[&str],
    env: &HashMap<String, String>,
    workdir: &Path,
) -> Result<LifecycleCommandResult> {
    let mut cmd = Command::new(args[0]);
    cmd.args(&args[1..]);
    cmd.current_dir(workdir);
    cmd.env_clear();
    cmd.envs(env);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::piped());

    let child = cmd
        .spawn()
        .with_context(|| format!("spawning lifecycle command {name}"))?;
    let output = child
        .wait_with_output()
        .with_context(|| format!("waiting for lifecycle command {name}"))?;

    let stderr = if output.status.success() {
        String::new()
    } else {
        base64_encode(&output.stderr)
    };

    Ok(LifecycleCommandResult {
        name: name.to_string(),
        exit_code: output.status.code().unwrap_or(-1),
        stderr,
    })
}

fn flag_exists(name: &str) -> bool {
    Path::new(FLAGS_DIR).join(name).exists()
}

fn set_flag(name: &str) {
    let path = Path::new(FLAGS_DIR).join(name);
    if let Err(e) = std::fs::File::create(&path) {
        let path = path.display();
        eprintln!("warning: failed to create lifecycle flag {path}: {e}");
    }
}

/// Record that a lifecycle command has run.
fn mark_ran(name: &str, post_start_ran: &AtomicBool) {
    match name {
        "onCreateCommand" => set_flag("on-create-ran"),
        "postCreateCommand" => set_flag("post-create-ran"),
        "postStartCommand" => {
            post_start_ran.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        _ => {}
    }
}

/// On failure, mark downstream once-per-creation commands as done to
/// prevent retries (matches the daemon's existing behavior).
fn mark_ran_on_failure(failed_name: &str, post_start_ran: &AtomicBool) {
    match failed_name {
        "onCreateCommand" => {
            set_flag("on-create-ran");
            set_flag("post-create-ran");
        }
        "updateContentCommand" => {
            set_flag("post-create-ran");
        }
        "postCreateCommand" => {
            set_flag("post-create-ran");
        }
        "postStartCommand" => {
            post_start_ran.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        _ => {}
    }
}
