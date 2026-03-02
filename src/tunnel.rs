/// Multiplexed TCP tunnel over kubectl exec stdin/stdout.
///
/// K8s pods cannot reach the host's git HTTP server directly because the
/// host IP is typically not routable from inside a pod.  This module
/// implements a framing protocol that carries multiple TCP streams over a
/// single stdin/stdout pipe established by `kubectl exec`.
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
/// Host side (`start_tunnel`): runs `rumpel tunnel-server` inside the pod
/// via `kubectl exec`, demultiplexes frames from stdout, and opens local
/// TCP connections to the target address for each stream.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

/// Port the tunnel listener binds inside the pod.
pub const TUNNEL_PORT: u16 = 7891;

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
        bail!(
            "frame payload too large: {} > {} (stream {})",
            payload_len,
            MAX_PAYLOAD,
            stream_id
        );
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
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("binding tunnel listener");

    // Readiness signal -- the host side reads stderr looking for this line.
    eprintln!("tunnel listening on port {}", port);

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
    _cancel_tx: tokio::sync::watch::Sender<bool>,
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

    // Kill any leftover tunnel-server from a previous run.
    let _ = pods
        .exec(
            name,
            vec![
                "sh".to_string(),
                "-c".to_string(),
                "pkill -f 'rumpel tunnel-server' 2>/dev/null || true".to_string(),
            ],
            &AttachParams::default()
                .stdout(true)
                .stderr(false)
                .stdin(false),
        )
        .await;

    let mut attached = pods
        .exec(
            name,
            vec![
                "/opt/rumpelpod/bin/rumpel".to_string(),
                "tunnel-server".to_string(),
                "--port".to_string(),
                TUNNEL_PORT.to_string(),
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
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("timeout waiting for tunnel-server readiness");
        }
        let mut tmp = [0u8; 256];
        let n = tokio::time::timeout(remaining, stderr.read(&mut tmp))
            .await
            .context("timeout reading tunnel stderr")?
            .context("reading tunnel stderr")?;
        if n == 0 {
            bail!("tunnel-server stderr closed before readiness signal");
        }
        stderr_buf.extend_from_slice(&tmp[..n]);
        if let Ok(s) = std::str::from_utf8(&stderr_buf) {
            if s.contains("tunnel listening") {
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
                            log::debug!("tunnel-server stderr: {}", line);
                        }
                    }
                }
            }
        }
    });

    let mut pod_stdout = attached.stdout().context("taking tunnel stdout")?;
    let pod_stdin = attached.stdin().context("taking tunnel stdin")?;

    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    // Shared write half (stdin to pod) for sending frames back.
    let pod_stdin_mu = Arc::new(Mutex::new(pod_stdin));

    // Map of stream_id -> write half of the local TCP connection.
    type WriteMap = Arc<Mutex<HashMap<u32, tokio::io::WriteHalf<TcpStream>>>>;
    let writes: WriteMap = Arc::new(Mutex::new(HashMap::new()));

    let stdin_mu = pod_stdin_mu.clone();
    let writes_clone = writes.clone();
    let mut cancel = cancel_rx.clone();

    // Mux task: reads frames from pod stdout, dispatches to local TCP.
    tokio::spawn(async move {
        // Keep the AttachedProcess alive so the WebSocket stays open.
        let _attached = attached;

        loop {
            tokio::select! {
                frame_res = read_frame(&mut pod_stdout) => {
                    let frame = match frame_res {
                        Ok(f) => f,
                        Err(e) => {
                            log::debug!("tunnel mux: read error: {}", e);
                            break;
                        }
                    };
                    match frame.frame_type {
                        FRAME_OPEN => {
                            let addr = target_addr.clone();
                            let stdin_for_stream = stdin_mu.clone();
                            let writes_for_stream = writes_clone.clone();
                            let sid = frame.stream_id;
                            tokio::spawn(async move {
                                let tcp = match TcpStream::connect(&addr).await {
                                    Ok(s) => s,
                                    Err(e) => {
                                        log::debug!(
                                            "tunnel: failed to connect to {}: {}",
                                            addr, e
                                        );
                                        // Send CLOSE back so the pod side tears
                                        // down the stream.
                                        let mut w = stdin_for_stream.lock().await;
                                        let _ = write_frame(&mut *w, &Frame {
                                            stream_id: sid,
                                            frame_type: FRAME_CLOSE,
                                            payload: Vec::new(),
                                        }).await;
                                        return;
                                    }
                                };
                                let (read_half, write_half) = tokio::io::split(tcp);
                                writes_for_stream
                                    .lock()
                                    .await
                                    .insert(sid, write_half);

                                // Spawn reader: local TCP read -> DATA frames
                                // back to pod, CLOSE on EOF.
                                let stdin_for_reader = stdin_for_stream.clone();
                                let writes_for_reader = writes_for_stream.clone();
                                tokio::spawn(async move {
                                    let mut reader = read_half;
                                    let mut buf = vec![0u8; MAX_PAYLOAD];
                                    loop {
                                        let n = match reader.read(&mut buf).await {
                                            Ok(0) | Err(_) => break,
                                            Ok(n) => n,
                                        };
                                        let mut w = stdin_for_reader.lock().await;
                                        if write_frame(&mut *w, &Frame {
                                            stream_id: sid,
                                            frame_type: FRAME_DATA,
                                            payload: buf[..n].to_vec(),
                                        }).await.is_err() {
                                            break;
                                        }
                                    }
                                    // Send CLOSE
                                    let mut w = stdin_for_reader.lock().await;
                                    let _ = write_frame(&mut *w, &Frame {
                                        stream_id: sid,
                                        frame_type: FRAME_CLOSE,
                                        payload: Vec::new(),
                                    }).await;
                                    writes_for_reader.lock().await.remove(&sid);
                                });
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
                            log::debug!(
                                "tunnel mux: unknown frame type {}",
                                frame.frame_type
                            );
                        }
                    }
                }
                _ = cancel.changed() => {
                    break;
                }
            }
        }
    });

    Ok(TunnelHandle {
        _cancel_tx: cancel_tx,
    })
}
