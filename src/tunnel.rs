/// Multiplexed TCP tunnel over exec stdin/stdout.
///
/// Containers (both K8s and Docker) cannot always reach the host's git
/// HTTP server directly.  This module implements a framing protocol that
/// carries multiple TCP streams over a single stdin/stdout pipe
/// established by exec-ing into the container.
///
/// Framing:
///   [stream_id: u32 LE] [frame_type: u8] [payload_len: u32 LE] [payload]
///
/// Frame types:
///   OPEN  (0x01) -- pod -> host, empty payload.  Host opens TCP to target.
///   DATA  (0x02) -- bidirectional.  Max payload 64 KiB.
///   CLOSE (0x03) -- bidirectional, empty payload.  Graceful stream close.
///
/// Pod side (`run_tunnel_server`): binds a loopback TCP listener, assigns
/// stream IDs, and multiplexes accepted connections over stdout.
///
/// Host side (`start_tunnel` / `start_docker_tunnel`): runs
/// `rumpel tunnel-server` inside the container via exec, demultiplexes
/// frames from stdout, and opens local TCP connections to the target
/// address for each stream.
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;
use std::task::Poll;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

/// Default port for the tunnel listener CLI flag.  In practice,
/// `start_tunnel` always passes 0 (ephemeral) so each tunnel gets a
/// fresh port with no conflicts.
pub const DEFAULT_TUNNEL_PORT: u16 = 7891;

const FRAME_OPEN: u8 = 0x01;
const FRAME_DATA: u8 = 0x02;
const FRAME_CLOSE: u8 = 0x03;

/// Hard cap on a single DATA payload.
const MAX_PAYLOAD: usize = 64 * 1024;

/// Header is stream_id(4) + frame_type(1) + payload_len(4) = 9 bytes.
const HEADER_LEN: usize = 9;

// ── Framing helpers ────────────────────────────────────────────────────

struct Frame {
    stream_id: u32,
    frame_type: u8,
    payload: Vec<u8>,
}

async fn read_frame<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Frame> {
    let mut hdr = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut hdr)
        .await
        .context("reading frame header")?;
    let stream_id = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let frame_type = hdr[4];
    let payload_len = u32::from_le_bytes([hdr[5], hdr[6], hdr[7], hdr[8]]) as usize;
    if payload_len > MAX_PAYLOAD {
        return Err(anyhow::anyhow!(
            "frame payload too large: {payload_len} > {MAX_PAYLOAD} (stream {stream_id})"
        ));
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        reader
            .read_exact(&mut payload)
            .await
            .context("reading frame payload")?;
    }
    Ok(Frame {
        stream_id,
        frame_type,
        payload,
    })
}

async fn write_frame<W: AsyncWriteExt + Unpin>(writer: &mut W, frame: &Frame) -> Result<()> {
    let mut hdr = [0u8; HEADER_LEN];
    hdr[0..4].copy_from_slice(&frame.stream_id.to_le_bytes());
    hdr[4] = frame.frame_type;
    hdr[5..9].copy_from_slice(&(frame.payload.len() as u32).to_le_bytes());
    writer
        .write_all(&hdr)
        .await
        .context("writing frame header")?;
    if !frame.payload.is_empty() {
        writer
            .write_all(&frame.payload)
            .await
            .context("writing frame payload")?;
    }
    writer.flush().await.context("flushing frame")?;
    Ok(())
}

// ── Pod side ───────────────────────────────────────────────────────────

/// Run the in-pod tunnel server.  Binds a TCP listener on loopback,
/// multiplexes accepted connections over stdout, and demultiplexes
/// host replies from stdin.  Never returns under normal operation.
pub fn run_tunnel_server(port: u16) -> ! {
    let rt = tokio::runtime::Runtime::new().expect("creating tokio runtime");
    rt.block_on(async { run_tunnel_server_async(port).await });
    std::process::exit(0);
}

async fn run_tunnel_server_async(port: u16) {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}"))
        .await
        .expect("binding tunnel listener");

    // Report the actual bound port so the host side can parse it from stderr.
    // When port=0 (ephemeral), the OS assigns a fresh port with no conflicts.
    let actual_port = listener
        .local_addr()
        .expect("getting listener address")
        .port();
    eprintln!("tunnel listening on port {actual_port}");

    let stdout = Arc::new(Mutex::new(tokio::io::stdout()));

    // Map of stream_id -> sender that feeds data to the TCP write task.
    let streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let next_id = Arc::new(AtomicU32::new(1));

    // Stdin reader task: dispatch incoming frames to the right stream.
    let streams_for_stdin = streams.clone();
    tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        loop {
            let frame = match read_frame(&mut stdin).await {
                Ok(f) => f,
                Err(_) => break,
            };
            match frame.frame_type {
                FRAME_DATA => {
                    let map = streams_for_stdin.lock().await;
                    if let Some(tx) = map.get(&frame.stream_id) {
                        // If the receiver is gone the stream was already torn down.
                        let _ = tx.send(frame.payload).await;
                    }
                }
                FRAME_CLOSE => {
                    // Drop the sender so the TCP write task sees channel close.
                    streams_for_stdin.lock().await.remove(&frame.stream_id);
                }
                _ => {}
            }
        }
    });

    // Accept loop
    loop {
        let (tcp_stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };

        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(64);
        streams.lock().await.insert(id, data_tx);

        let stdout_clone = stdout.clone();
        let streams_clone = streams.clone();

        // Send OPEN
        {
            let mut out = stdout_clone.lock().await;
            if write_frame(
                &mut *out,
                &Frame {
                    stream_id: id,
                    frame_type: FRAME_OPEN,
                    payload: Vec::new(),
                },
            )
            .await
            .is_err()
            {
                break;
            }
        }

        let (read_half, write_half) = tokio::io::split(tcp_stream);

        // TCP read -> DATA frames to stdout; CLOSE on EOF
        let stdout_for_read = stdout_clone.clone();
        let streams_for_read = streams_clone.clone();
        tokio::spawn(async move {
            let mut reader = read_half;
            let mut buf = vec![0u8; MAX_PAYLOAD];
            loop {
                let n = match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut out = stdout_for_read.lock().await;
                if write_frame(
                    &mut *out,
                    &Frame {
                        stream_id: id,
                        frame_type: FRAME_DATA,
                        payload: buf[..n].to_vec(),
                    },
                )
                .await
                .is_err()
                {
                    break;
                }
            }
            // Send CLOSE
            let mut out = stdout_for_read.lock().await;
            let _ = write_frame(
                &mut *out,
                &Frame {
                    stream_id: id,
                    frame_type: FRAME_CLOSE,
                    payload: Vec::new(),
                },
            )
            .await;
            streams_for_read.lock().await.remove(&id);
        });

        // mpsc receiver -> TCP write; shutdown on channel close
        tokio::spawn(async move {
            let mut writer = write_half;
            let mut rx = data_rx;
            while let Some(data) = rx.recv().await {
                if writer.write_all(&data).await.is_err() {
                    break;
                }
            }
            let _ = writer.shutdown().await;
        });
    }
}

// ── Host side ──────────────────────────────────────────────────────────

/// Handle for an active tunnel.  Dropping this cancels the tunnel.
pub struct TunnelHandle {
    /// The actual port the tunnel listener bound to inside the pod.
    pub port: u16,
    alive: Arc<AtomicBool>,
    _cancel_tx: tokio::sync::watch::Sender<bool>,
}

impl TunnelHandle {
    /// Whether the mux task is still running.  Returns false once the
    /// WebSocket/pipe to the pod breaks or the task is cancelled.
    pub fn is_alive(&self) -> bool {
        self.alive.load(Ordering::Relaxed)
    }
}

/// Shared mux loop for the host side of the tunnel.  Reads frames from
/// the container's stdout, dispatches them to local TCP connections to
/// `target_addr`, and writes response frames back via the container's
/// stdin.
///
/// `_keepalive` is held for the lifetime of the task (e.g. to prevent
/// the kube `AttachedProcess` from being dropped, which would close the
/// WebSocket).
fn spawn_host_mux(
    mut pod_stdout: impl AsyncRead + Unpin + Send + 'static,
    pod_stdin: impl AsyncWriteExt + Unpin + Send + 'static,
    target_addr: String,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
    alive: Arc<AtomicBool>,
    _keepalive: impl Send + 'static,
) {
    let pod_stdin_mu = Arc::new(Mutex::new(pod_stdin));

    type WriteMap = Arc<Mutex<HashMap<u32, tokio::io::WriteHalf<TcpStream>>>>;
    let writes: WriteMap = Arc::new(Mutex::new(HashMap::new()));

    let stdin_mu = pod_stdin_mu.clone();
    let writes_clone = writes.clone();

    tokio::spawn(async move {
        let _keepalive = _keepalive;

        loop {
            tokio::select! {
                frame_res = read_frame(&mut pod_stdout) => {
                    let frame = match frame_res {
                        Ok(f) => f,
                        Err(e) => {
                            log::debug!("tunnel mux: read error: {e}");
                            break;
                        }
                    };
                    match frame.frame_type {
                        FRAME_OPEN => {
                            let sid = frame.stream_id;
                            // Connect synchronously so the write half is in the
                            // map before we read the next frame (which is likely
                            // a DATA for this same stream).
                            let tcp = match TcpStream::connect(&target_addr).await {
                                Ok(s) => s,
                                Err(e) => {
                                    log::debug!(
                                        "tunnel: failed to connect to {target_addr}: {e}"
                                    );
                                    let mut w = stdin_mu.lock().await;
                                    let _ = write_frame(
                                        &mut *w,
                                        &Frame {
                                            stream_id: sid,
                                            frame_type: FRAME_CLOSE,
                                            payload: Vec::new(),
                                        },
                                    )
                                    .await;
                                    continue;
                                }
                            };
                            let (read_half, write_half) = tokio::io::split(tcp);
                            writes_clone.lock().await.insert(sid, write_half);

                            // Spawn reader: local TCP read -> DATA frames back
                            // to pod, CLOSE on EOF.
                            let stdin_for_reader = stdin_mu.clone();
                            let writes_for_reader = writes_clone.clone();
                            tokio::spawn(async move {
                                let mut reader = read_half;
                                let mut buf = vec![0u8; MAX_PAYLOAD];
                                loop {
                                    let n = match reader.read(&mut buf).await {
                                        Ok(0) | Err(_) => break,
                                        Ok(n) => n,
                                    };
                                    let mut w = stdin_for_reader.lock().await;
                                    if write_frame(
                                        &mut *w,
                                        &Frame {
                                            stream_id: sid,
                                            frame_type: FRAME_DATA,
                                            payload: buf[..n].to_vec(),
                                        },
                                    )
                                    .await
                                    .is_err()
                                    {
                                        break;
                                    }
                                }
                                let mut w = stdin_for_reader.lock().await;
                                let _ = write_frame(
                                    &mut *w,
                                    &Frame {
                                        stream_id: sid,
                                        frame_type: FRAME_CLOSE,
                                        payload: Vec::new(),
                                    },
                                )
                                .await;
                                writes_for_reader.lock().await.remove(&sid);
                            });
                        }
                        FRAME_DATA => {
                            let mut map = writes_clone.lock().await;
                            if let Some(writer) = map.get_mut(&frame.stream_id) {
                                if writer.write_all(&frame.payload).await.is_err() {
                                    map.remove(&frame.stream_id);
                                }
                            }
                        }
                        FRAME_CLOSE => {
                            // Drop the write half so the local TCP connection
                            // sees EOF on its read side.
                            writes_clone.lock().await.remove(&frame.stream_id);
                        }
                        _ => {
                            let frame_type = frame.frame_type;
                            log::debug!(
                                "tunnel mux: unknown frame type {frame_type}"
                            );
                        }
                    }
                }
                _ = cancel_rx.changed() => {
                    break;
                }
            }
        }
        alive.store(false, Ordering::Relaxed);
    });
}

/// Start a tunnel into a K8s pod.
///
/// Launches `rumpel tunnel-server` inside the pod via kubectl exec,
/// waits for the readiness message on stderr, then spawns a mux task
/// that bridges frames from the pod to local TCP connections to
/// `target_addr`.
pub async fn start_tunnel(
    pods: kube::api::Api<k8s_openapi::api::core::v1::Pod>,
    name: &str,
    target_addr: &str,
) -> Result<TunnelHandle> {
    use kube::api::AttachParams;

    let target_addr = target_addr.to_string();

    // Kill any leftover tunnel-server from a previous run and wait for it
    // to release the listener port.
    if let Ok(proc) = pods
        .exec(
            name,
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "pkill -f 'rumpel tunnel-server' 2>/dev/null; sleep 0.1; true".to_string(),
            ],
            &AttachParams::default()
                .stdout(true)
                .stderr(false)
                .stdin(false),
        )
        .await
    {
        // Wait for the exec to finish so the old process has time to exit.
        let _ = proc.join().await;
    }

    let mut attached = pods
        .exec(
            name,
            vec![
                "/opt/rumpelpod/bin/rumpel".to_string(),
                "tunnel-server".to_string(),
                "--port".to_string(),
                "0".to_string(),
            ],
            &AttachParams::default()
                .stdout(true)
                .stderr(true)
                .stdin(true),
        )
        .await
        .context("exec tunnel-server in pod")?;

    // Wait for readiness on stderr.
    let mut stderr = attached.stderr().context("taking tunnel stderr")?;
    let mut stderr_buf = Vec::new();
    let mut tunnel_port: u16 = 0;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow::anyhow!(
                "timeout waiting for tunnel-server readiness"
            ));
        }
        let mut tmp = [0u8; 256];
        let n = tokio::time::timeout(remaining, stderr.read(&mut tmp))
            .await
            .context("timeout reading tunnel stderr")?
            .context("reading tunnel stderr")?;
        if n == 0 {
            return Err(anyhow::anyhow!(
                "tunnel-server stderr closed before readiness signal"
            ));
        }
        stderr_buf.extend_from_slice(&tmp[..n]);
        if let Ok(s) = std::str::from_utf8(&stderr_buf) {
            for line in s.lines() {
                if let Some(rest) = line.strip_prefix("tunnel listening on port ") {
                    tunnel_port = rest
                        .trim()
                        .parse()
                        .context("parsing tunnel port from readiness message")?;
                    break;
                }
            }
            if tunnel_port != 0 {
                break;
            }
        }
    }

    // Drain remaining stderr to debug log in background.
    tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if let Ok(s) = std::str::from_utf8(&buf[..n]) {
                        for line in s.lines() {
                            log::debug!("tunnel-server stderr: {line}");
                        }
                    }
                }
            }
        }
    });

    let pod_stdout = attached.stdout().context("taking tunnel stdout")?;
    let pod_stdin = attached.stdin().context("taking tunnel stdin")?;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let alive = Arc::new(AtomicBool::new(true));

    spawn_host_mux(
        pod_stdout,
        pod_stdin,
        target_addr,
        cancel_rx,
        alive.clone(),
        attached,
    );

    Ok(TunnelHandle {
        port: tunnel_port,
        alive,
        _cancel_tx: cancel_tx,
    })
}

// ── Docker exec tunnel ────────────────────────────────────────────────

/// Adapter that wraps bollard's multiplexed exec output stream into an
/// `AsyncRead` that only yields stdout bytes.  Stderr chunks are
/// forwarded to a channel for readiness detection and debug logging.
pub(crate) struct BollardStdoutReader {
    pub(crate) stream: Pin<
        Box<
            dyn futures_core::Stream<
                    Item = std::result::Result<
                        bollard::container::LogOutput,
                        bollard::errors::Error,
                    >,
                > + Send,
        >,
    >,
    /// Leftover bytes from a previous StdOut chunk that did not fit
    /// into the caller's buffer.
    pub(crate) pending: Vec<u8>,
    pub(crate) pending_offset: usize,
    /// Channel for stderr chunks (readiness + debug).
    pub(crate) stderr_tx: mpsc::UnboundedSender<Vec<u8>>,
}

impl AsyncRead for BollardStdoutReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Drain any leftover bytes from a previous chunk first.
        if self.pending_offset < self.pending.len() {
            let remaining = &self.pending[self.pending_offset..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            self.pending_offset += n;
            if self.pending_offset == self.pending.len() {
                self.pending.clear();
                self.pending_offset = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Poll the underlying stream for the next chunk.
        match self.stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(chunk))) => {
                let (bytes, is_stdout) = match chunk {
                    bollard::container::LogOutput::StdOut { message } => (message.to_vec(), true),
                    bollard::container::LogOutput::StdErr { message } => (message.to_vec(), false),
                    bollard::container::LogOutput::Console { message } => (message.to_vec(), true),
                    bollard::container::LogOutput::StdIn { .. } => {
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                };
                if !is_stdout {
                    let _ = self.stderr_tx.send(bytes);
                    // Re-poll to get actual stdout data.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                let n = bytes.len().min(buf.remaining());
                buf.put_slice(&bytes[..n]);
                if n < bytes.len() {
                    self.pending = bytes;
                    self.pending_offset = n;
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Start a tunnel into a Docker container.
///
/// Launches `rumpel tunnel-server` inside the container via
/// `docker exec`, waits for the readiness message on stderr, then
/// spawns a mux task that bridges frames to local TCP connections to
/// `target_addr`.
pub async fn start_docker_tunnel(
    docker: &bollard::Docker,
    container_id: &str,
    target_addr: &str,
    port: u16,
) -> Result<TunnelHandle> {
    use bollard::exec::StartExecResults;
    use bollard::secret::ExecConfig;
    use tokio_stream::StreamExt;

    let target_addr = target_addr.to_string();

    // Kill any leftover tunnel-server from a previous run.
    let kill_config = ExecConfig {
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(vec![
            "sh".to_string(),
            "-c".to_string(),
            "pkill -f 'rumpel tunnel-server' 2>/dev/null; sleep 0.1; true".to_string(),
        ]),
        ..Default::default()
    };
    let kill_exec = docker
        .create_exec(container_id, kill_config)
        .await
        .context("creating kill exec")?;
    if let StartExecResults::Attached { mut output, .. } = docker
        .start_exec(&kill_exec.id, None)
        .await
        .context("starting kill exec")?
    {
        while output.next().await.is_some() {}
    }

    // Launch the tunnel server.
    let config = ExecConfig {
        attach_stdin: Some(true),
        attach_stdout: Some(true),
        attach_stderr: Some(true),
        cmd: Some(vec![
            "/opt/rumpelpod/bin/rumpel".to_string(),
            "tunnel-server".to_string(),
            "--port".to_string(),
            port.to_string(),
        ]),
        ..Default::default()
    };
    let exec = docker
        .create_exec(container_id, config)
        .await
        .context("creating tunnel exec")?;
    let (output, input) = match docker
        .start_exec(&exec.id, None)
        .await
        .context("starting tunnel exec")?
    {
        StartExecResults::Attached { output, input } => (output, input),
        StartExecResults::Detached => {
            return Err(anyhow::anyhow!("tunnel exec started in detached mode"));
        }
    };

    // Consume the bollard stream until we see the readiness message on
    // stderr, buffering any stdout data that arrives alongside it.
    let mut stdout_buf = Vec::new();
    let mut stderr_buf = Vec::new();
    let mut tunnel_port: u16 = 0;
    let mut remaining_stream = output;
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(anyhow::anyhow!(
                "timeout waiting for docker tunnel-server readiness"
            ));
        }
        let chunk = tokio::time::timeout(remaining, remaining_stream.next())
            .await
            .context("timeout reading docker tunnel output")?;
        match chunk {
            Some(Ok(bollard::container::LogOutput::StdErr { message })) => {
                stderr_buf.extend_from_slice(&message);
                if let Ok(s) = std::str::from_utf8(&stderr_buf) {
                    // Only consider newline-terminated lines to avoid
                    // parsing partial output that Docker may split across
                    // chunks.
                    for line in s.lines() {
                        if let Some(rest) = line.strip_prefix("tunnel listening on port ") {
                            if let Ok(port) = rest.trim().parse::<u16>() {
                                tunnel_port = port;
                                break;
                            }
                        }
                    }
                    if tunnel_port != 0 {
                        break;
                    }
                }
            }
            Some(Ok(bollard::container::LogOutput::StdOut { message })) => {
                stdout_buf.extend_from_slice(&message);
            }
            Some(Ok(bollard::container::LogOutput::Console { message })) => {
                stdout_buf.extend_from_slice(&message);
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                return Err(anyhow::anyhow!("docker exec stream error: {e}"));
            }
            None => {
                return Err(anyhow::anyhow!(
                    "docker exec stream closed before readiness signal"
                ));
            }
        }
    }

    // Wrap the remaining bollard stream into an AsyncRead, pre-filling
    // with any stdout bytes we buffered during the readiness wait.
    let (stderr_tx, stderr_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let reader = BollardStdoutReader {
        stream: Box::pin(remaining_stream),
        pending: stdout_buf,
        pending_offset: 0,
        stderr_tx,
    };

    // Drain stderr from the channel to debug log in background.
    tokio::spawn(async move {
        let mut rx = stderr_rx;
        while let Some(data) = rx.recv().await {
            if let Ok(s) = std::str::from_utf8(&data) {
                for line in s.lines() {
                    log::debug!("docker tunnel-server stderr: {line}");
                }
            }
        }
    });

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
    let alive = Arc::new(AtomicBool::new(true));

    spawn_host_mux(reader, input, target_addr, cancel_rx, alive.clone(), ());

    Ok(TunnelHandle {
        port: tunnel_port,
        alive,
        _cancel_tx: cancel_tx,
    })
}
