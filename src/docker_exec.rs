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
