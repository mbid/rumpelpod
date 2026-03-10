//! Host-side exec proxy for reaching container-serve via docker exec.
//!
//! Instead of routing through bridge IPs or SSH port forwards, we exec
//! `rumpel tcp-proxy --port <port>` into the container for each TCP
//! connection.  The proxy bridges the connection's bytes over the exec's
//! stdin/stdout.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use bollard::Docker;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use crate::tunnel::BollardStdoutReader;

/// Handle for an active exec proxy listener.  Dropping cancels the
/// accept loop.
pub struct ExecProxyHandle {
    /// Local port the proxy listener is bound to.
    pub port: u16,
    alive: Arc<AtomicBool>,
    _cancel_tx: tokio::sync::watch::Sender<bool>,
}

impl ExecProxyHandle {
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }
}

/// Start a local TCP listener that proxies each accepted connection
/// through a `docker exec` of `rumpel tcp-proxy`.
pub async fn start_exec_proxy(
    docker: &Docker,
    container_id: &str,
    container_port: u16,
) -> Result<ExecProxyHandle> {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("binding exec proxy listener")?;
    let port = listener.local_addr()?.port();

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let alive = Arc::new(AtomicBool::new(true));

    let docker = docker.clone();
    let container_id = container_id.to_string();
    let alive2 = alive.clone();

    tokio::spawn(async move {
        accept_loop(
            listener,
            docker,
            container_id,
            container_port,
            cancel_rx,
            alive2,
        )
        .await;
    });

    Ok(ExecProxyHandle {
        port,
        alive,
        _cancel_tx: cancel_tx,
    })
}

async fn accept_loop(
    listener: TcpListener,
    docker: Docker,
    container_id: String,
    container_port: u16,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    alive: Arc<AtomicBool>,
) {
    loop {
        let stream = tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => stream,
                    Err(e) => {
                        log::error!("exec proxy accept error: {e}");
                        break;
                    }
                }
            }
            _ = cancel_rx.changed() => break,
        };

        let docker = docker.clone();
        let container_id = container_id.clone();

        tokio::spawn(async move {
            if let Err(e) = bridge_connection(stream, &docker, &container_id, container_port).await
            {
                log::debug!("exec proxy bridge ended: {e:#}");
            }
        });
    }

    alive.store(false, Ordering::Relaxed);
}

async fn bridge_connection(
    tcp_stream: tokio::net::TcpStream,
    docker: &Docker,
    container_id: &str,
    container_port: u16,
) -> Result<()> {
    use bollard::exec::StartExecResults;
    use bollard::secret::ExecConfig;

    let config = ExecConfig {
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(vec![
            crate::daemon::RUMPEL_CONTAINER_BIN.to_string(),
            "tcp-proxy".to_string(),
            "--port".to_string(),
            container_port.to_string(),
        ]),
        ..Default::default()
    };

    let exec = docker
        .create_exec(container_id, config)
        .await
        .context("creating tcp-proxy exec")?;

    let (output, mut input) = match docker
        .start_exec(&exec.id, None)
        .await
        .context("starting tcp-proxy exec")?
    {
        StartExecResults::Attached { output, input } => (output, input),
        StartExecResults::Detached => {
            return Err(anyhow::anyhow!("tcp-proxy exec started in detached mode"));
        }
    };

    let (stderr_tx, mut stderr_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let mut reader = BollardStdoutReader {
        stream: Box::pin(output),
        pending: Vec::new(),
        pending_offset: 0,
        stderr_tx,
    };

    // Log stderr in background
    tokio::spawn(async move {
        while let Some(data) = stderr_rx.recv().await {
            if let Ok(s) = std::str::from_utf8(&data) {
                for line in s.lines() {
                    log::debug!("tcp-proxy stderr: {line}");
                }
            }
        }
    });

    let (mut tcp_read, mut tcp_write) = tcp_stream.into_split();

    // exec stdout -> tcp write
    let h1 = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tcp_write.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = tcp_write.shutdown().await;
    });

    // tcp read -> exec stdin
    let h2 = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            match tcp_read.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if input.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = input.shutdown().await;
    });

    let _ = h1.await;
    let _ = h2.await;

    Ok(())
}
