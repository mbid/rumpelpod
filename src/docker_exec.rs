//! Docker exec utilities using the bollard library.
//!
//! This module provides synchronous wrappers around bollard's async exec API,
//! supporting both simple command execution and commands that need stdin input.

use anyhow::{Context, Result};
use bollard::container::LogOutput;
use bollard::exec::StartExecResults;
use bollard::secret::ExecConfig;
use bollard::Docker;
use tokio::io::AsyncWriteExt;
use tokio_stream::StreamExt;

use crate::async_runtime::block_on;

/// Execute a command inside a container and return the output.
///
/// Returns the combined stdout/stderr output. Returns an error if the command
/// fails (non-zero exit code) or if there's a Docker API error.
pub fn exec_command(
    docker: &Docker,
    container_id: &str,
    user: Option<&str>,
    workdir: Option<&str>,
    env: Option<Vec<&str>>,
    cmd: Vec<&str>,
) -> Result<Vec<u8>> {
    exec_with_stdin(docker, container_id, user, workdir, env, cmd, None)
}

/// Execute a command inside a container with optional stdin input.
///
/// If `stdin_data` is provided, it will be written to the command's stdin.
/// Returns the combined stdout/stderr output.
pub fn exec_with_stdin(
    docker: &Docker,
    container_id: &str,
    user: Option<&str>,
    workdir: Option<&str>,
    env: Option<Vec<&str>>,
    cmd: Vec<&str>,
    stdin_data: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let config = ExecConfig {
        attach_stdin: Some(stdin_data.is_some()),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(cmd.into_iter().map(String::from).collect()),
        user: user.map(String::from),
        working_dir: workdir.map(String::from),
        env: env.map(|e| e.into_iter().map(String::from).collect()),
        ..Default::default()
    };

    let exec = block_on(docker.create_exec(container_id, config)).context("creating exec")?;

    let output = block_on(async {
        let start_result = docker.start_exec(&exec.id, None).await?;

        match start_result {
            StartExecResults::Attached { mut output, input } => {
                // If we have stdin data, write it and close the stream
                if let Some(data) = stdin_data {
                    let mut input = input;
                    input.write_all(data).await?;
                    input.shutdown().await?;
                }

                // Collect output
                let mut result = Vec::new();
                while let Some(chunk) = output.next().await {
                    match chunk? {
                        LogOutput::StdOut { message } | LogOutput::StdErr { message } => {
                            result.extend_from_slice(&message);
                        }
                        _ => {}
                    }
                }
                Ok::<_, bollard::errors::Error>(result)
            }
            StartExecResults::Detached => Ok(Vec::new()),
        }
    })
    .context("executing command")?;

    // Check exit code
    let inspect = block_on(docker.inspect_exec(&exec.id)).context("inspecting exec")?;
    let exit_code = inspect.exit_code.unwrap_or(0);

    if exit_code != 0 {
        let stderr = String::from_utf8_lossy(&output);
        anyhow::bail!("command exited with code {}: {}", exit_code, stderr.trim());
    }

    Ok(output)
}

/// Execute a command and return success status without requiring exit code 0.
///
/// Useful for commands like `test -e` where non-zero exit is expected.
pub fn exec_check(
    docker: &Docker,
    container_id: &str,
    user: Option<&str>,
    workdir: Option<&str>,
    cmd: Vec<&str>,
) -> Result<bool> {
    let config = ExecConfig {
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(cmd.into_iter().map(String::from).collect()),
        user: user.map(String::from),
        working_dir: workdir.map(String::from),
        ..Default::default()
    };

    let exec = block_on(docker.create_exec(container_id, config)).context("creating exec")?;

    block_on(async {
        let start_result = docker.start_exec(&exec.id, None).await?;

        // Consume output stream to let the command complete
        if let StartExecResults::Attached { mut output, .. } = start_result {
            while output.next().await.is_some() {}
        }
        Ok::<_, bollard::errors::Error>(())
    })
    .context("executing command")?;

    let inspect = block_on(docker.inspect_exec(&exec.id)).context("inspecting exec")?;
    Ok(inspect.exit_code.unwrap_or(1) == 0)
}

/// Result of executing a command, including exit code.
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i64,
}

/// Result of executing a command with timeout support
pub enum ExecResult {
    Completed(ExecOutput),
    TimedOut { stdout: Vec<u8>, stderr: Vec<u8> },
}

/// Execute a command and capture output with a timeout.
///
/// If the command completes within the timeout, returns `ExecResult::Completed`.
/// If the command times out, returns `ExecResult::TimedOut` containing the partial output.
pub fn exec_capture_with_timeout(
    docker: &Docker,
    container_id: &str,
    user: Option<&str>,
    workdir: Option<&str>,
    env: Option<Vec<&str>>,
    cmd: Vec<&str>,
    timeout_duration: std::time::Duration,
) -> Result<ExecResult> {
    let config = ExecConfig {
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(cmd.into_iter().map(String::from).collect()),
        user: user.map(String::from),
        working_dir: workdir.map(String::from),
        env: env.map(|e| e.into_iter().map(String::from).collect()),
        ..Default::default()
    };

    let exec = block_on(docker.create_exec(container_id, config)).context("creating exec")?;

    let result = block_on(async {
        let start_result = docker.start_exec(&exec.id, None).await?;

        match start_result {
            StartExecResults::Attached { mut output, .. } => {
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();

                let res = tokio::time::timeout(timeout_duration, async {
                    while let Some(chunk) = output.next().await {
                        match chunk? {
                            LogOutput::StdOut { message } => stdout.extend_from_slice(&message),
                            LogOutput::StdErr { message } => stderr.extend_from_slice(&message),
                            _ => {}
                        }
                    }
                    Ok::<_, bollard::errors::Error>(())
                })
                .await;

                match res {
                    Ok(Ok(())) => Ok(Ok((stdout, stderr))),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Ok(Err((stdout, stderr))), // Timeout
                }
            }
            StartExecResults::Detached => Ok(Ok((Vec::new(), Vec::new()))),
        }
    })
    .context("executing command")?;

    match result {
        Ok((stdout, stderr)) => {
            let inspect = block_on(docker.inspect_exec(&exec.id)).context("inspecting exec")?;
            let exit_code = inspect.exit_code.unwrap_or(0);
            Ok(ExecResult::Completed(ExecOutput {
                stdout,
                stderr,
                exit_code,
            }))
        }
        Err((stdout, stderr)) => Ok(ExecResult::TimedOut { stdout, stderr }),
    }
}
