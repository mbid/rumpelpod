//! Client-side terminal bridge for attaching to a remote PTY session
//! over WebSocket.
//!
//! Replaces `docker exec -it ... screen ...` with a direct WebSocket
//! connection to the in-container PTY server.  Automatically reconnects
//! when the connection is lost (e.g. after laptop suspend).

use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::signal::unix::{signal, SignalKind};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;

use crate::config::Host;
use crate::daemon::protocol::DaemonClient;
use crate::daemon::reconnect::ReconnectEvent;
use crate::pod::pty::PtyControl;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsWriter = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

/// How often the write loop sends a WebSocket ping.  The connection
/// goes through docker exec or kubectl port-forward tunnels, so TCP
/// keepalive on the loopback socket is useless.  Periodic pings force
/// data through the tunnel and cause it to detect a dead underlying
/// connection (e.g. after laptop suspend).
const PING_INTERVAL: Duration = Duration::from_secs(30);

/// Ctrl-a (0x01) is the first byte of the detach sequence (same as
/// GNU screen).
const DETACH_PREFIX: u8 = 0x01;
/// 'd' (0x64) or Ctrl-d (0x04) completes the detach sequence after
/// Ctrl-a, so it works whether the user releases Ctrl or not.
const DETACH_SUFFIX: u8 = b'd';
const DETACH_SUFFIX_CTRL: u8 = 0x04;

pub enum AttachOutcome {
    /// User pressed the detach sequence; session still running.
    Detached,
    /// The remote session ended (child exited).
    SessionEnded,
}

/// RAII guard that restores the original terminal settings on drop,
/// ensuring cleanup even on panic or early return.
struct TerminalGuard {
    original: nix::sys::termios::Termios,
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        if let Err(e) = nix::sys::termios::tcsetattr(
            io::stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            &self.original,
        ) {
            eprintln!("warning: failed to restore terminal: {e}");
        }
    }
}

fn apply_termios(termios: &nix::sys::termios::Termios) {
    if let Err(e) =
        nix::sys::termios::tcsetattr(io::stdin(), nix::sys::termios::SetArg::TCSANOW, termios)
    {
        eprintln!("warning: failed to set terminal attributes: {e}");
    }
}

nix::ioctl_read_bad!(tiocgwinsz, libc::TIOCGWINSZ, libc::winsize);

/// Get the current terminal dimensions via ioctl.
pub fn get_terminal_size() -> Result<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    unsafe {
        tiocgwinsz(io::stdout().as_raw_fd(), &mut ws).context("TIOCGWINSZ ioctl failed")?;
    }
    Ok((ws.ws_col, ws.ws_row))
}

/// Session parameters sent as the first WebSocket message.
/// The server spawns the session if it doesn't exist, otherwise
/// reuses the existing one and replays the screen state.
pub struct SessionParams {
    pub name: String,
    pub cmd: Vec<String>,
    pub workdir: Option<String>,
    pub env: Vec<String>,
}

/// How to coordinate reconnection with the daemon for remote hosts.
///
/// When provided, the attach loop waits for the daemon's SSE endpoint
/// instead of polling blindly.  This lets the daemon manage SSH tunnel
/// retries with exponential backoff and notify all waiting clients.
pub struct ReconnectConfig {
    pub daemon_socket: PathBuf,
    pub host: Host,
}

/// Connect to or launch a Claude session over WebSocket.
///
/// Connects to `ws://HOST:PORT/claude`, sends the session parameters as
/// the first message, and bridges local stdin/stdout until the user
/// detaches (Ctrl-a d) or the session ends.  Raw mode is deferred until
/// the first output arrives from the remote so ctrl-c works during
/// startup.  Automatically reconnects if the WebSocket connection drops.
pub fn attach(
    url: &str,
    token: &str,
    params: SessionParams,
    reconnect: Option<ReconnectConfig>,
) -> Result<AttachOutcome> {
    eprintln!("[Ctrl-a d to detach]");

    // -- Terminal setup -------------------------------------------------

    let original_termios =
        nix::sys::termios::tcgetattr(io::stdin()).context("reading terminal attributes")?;
    let _guard = TerminalGuard {
        original: original_termios.clone(),
    };

    let mut raw = original_termios.clone();
    nix::sys::termios::cfmakeraw(&mut raw);

    // -- Run async bridge -----------------------------------------------

    let url = url.to_string();
    let token = token.to_string();
    let outcome = crate::async_runtime::block_on(attach_async(
        &url,
        &token,
        params,
        &original_termios,
        &raw,
        reconnect,
    ))?;

    // Reset terminal emulator state that escape sequences from the remote
    // may have changed (termios is restored by TerminalGuard, but modes
    // like alternate screen or hidden cursor need explicit cleanup).
    // Scroll the TUI content into scrollback so the shell prompt appears
    // on a clean visible area while the output remains accessible.
    let (_, rows) = get_terminal_size().unwrap_or((80, 24));
    io::stdout()
        .write_all(
            format!(
                "\x1b[?1049l\
                 \x1b[?1006l\
                 \x1b[?1003l\
                 \x1b[?1002l\
                 \x1b[?1000l\
                 \x1b[?2004l\
                 \x1b[0m\
                 \x1b[?25h\
                 \x1b[r\
                 \x1b[{rows}S\
                 \x1b[H"
            )
            .as_bytes(),
        )
        .and_then(|()| io::stdout().flush())
        .context("resetting terminal emulator state")?;

    Ok(outcome)
}

// ---------------------------------------------------------------------------
// Internal bridge outcome (distinguishes connection loss from session end)
// ---------------------------------------------------------------------------

enum BridgeOutcome {
    Detached,
    SessionEnded,
    ConnectionLost,
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

/// Build the WebSocket URL and handshake request from the container URL.
fn build_ws_request(
    url: &str,
    token: &str,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>> {
    let mut ws_url = Url::parse(url).context("parsing container URL")?;
    let scheme = match ws_url.scheme() {
        "http" => "ws",
        "https" => "wss",
        other => return Err(anyhow::anyhow!("unexpected scheme: {other}")),
    };
    ws_url
        .set_scheme(scheme)
        .expect("ws/wss are always valid schemes");
    ws_url.set_path("/claude");

    let host = match ws_url.port() {
        Some(port) => format!("{}:{port}", ws_url.host_str().unwrap_or("localhost")),
        None => ws_url.host_str().unwrap_or("localhost").to_string(),
    };
    tokio_tungstenite::tungstenite::http::Request::builder()
        .uri(ws_url.as_str())
        .header("Host", &host)
        .header("Authorization", format!("Bearer {token}"))
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Version", "13")
        .header(
            "Sec-WebSocket-Key",
            tokio_tungstenite::tungstenite::handshake::client::generate_key(),
        )
        .body(())
        .context("building WebSocket request")
}

/// Connect a WebSocket, configure TCP keepalive for fast dead-connection
/// detection (important after laptop suspend/resume), and send the
/// session parameters.
async fn connect_ws(
    url: &str,
    token: &str,
    params: &SessionParams,
    create: bool,
) -> Result<WsStream> {
    let request = build_ws_request(url, token)?;

    let (mut ws, _response) = tokio_tungstenite::connect_async(request)
        .await
        .context("WebSocket handshake failed")?;

    let (cols, rows) = get_terminal_size().unwrap_or((80, 24));
    let session_msg = PtyControl::Session {
        name: params.name.clone(),
        cmd: params.cmd.clone(),
        workdir: params.workdir.clone().map(Into::into),
        env: params.env.clone(),
        cols,
        rows,
        create,
    };
    let json = serde_json::to_string(&session_msg).context("serializing session params")?;
    ws.send(Message::Text(json.into()))
        .await
        .context("sending session parameters")?;

    Ok(ws)
}

// ---------------------------------------------------------------------------
// Async entry point with reconnection
// ---------------------------------------------------------------------------

async fn attach_async(
    url: &str,
    token: &str,
    params: SessionParams,
    original_termios: &nix::sys::termios::Termios,
    raw_termios: &nix::sys::termios::Termios,
    reconnect: Option<ReconnectConfig>,
) -> Result<AttachOutcome> {
    // First connection: propagate errors (invalid URL, unreachable pod).
    let ws = connect_ws(url, token, &params, true).await?;

    // Defer raw mode until the remote sends its first output, so ctrl-c
    // works while waiting for the session to start.
    match bridge(ws, Some(raw_termios)).await {
        BridgeOutcome::Detached => return Ok(AttachOutcome::Detached),
        BridgeOutcome::SessionEnded => return Ok(AttachOutcome::SessionEnded),
        BridgeOutcome::ConnectionLost => {}
    }

    // Reconnection loop.  Uses create=false so the server does not
    // spawn a fresh session if the original child already exited.
    loop {
        // Leave raw mode while disconnected so ctrl-c delivers SIGINT
        // and the user can kill the process normally.
        apply_termios(original_termios);
        eprintln!("[connection lost]");

        if let Some(ref rc) = reconnect {
            // Let the daemon coordinate the SSH tunnel retry with
            // exponential backoff.  Each subscription triggers an
            // immediate attempt and resets the backoff interval.
            wait_for_host_reconnect(rc).await?;
        } else {
            eprintln!("[reconnecting...]");
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        let ws = match connect_ws(url, token, &params, false).await {
            Ok(ws) => ws,
            Err(_) => continue,
        };

        // Reconnection replays screen state immediately, so enter raw
        // mode before the bridge starts.
        apply_termios(raw_termios);
        write_status("[reconnected]\r\n").await;

        match bridge(ws, None).await {
            BridgeOutcome::Detached => return Ok(AttachOutcome::Detached),
            BridgeOutcome::SessionEnded => return Ok(AttachOutcome::SessionEnded),
            BridgeOutcome::ConnectionLost => continue,
        }
    }
}

/// Wait for the daemon to re-establish the SSH tunnel to a remote host.
///
/// Subscribes to the daemon's SSE endpoint and prints status messages
/// as the daemon retries.  Returns Ok(()) when the tunnel is back up.
async fn wait_for_host_reconnect(config: &ReconnectConfig) -> Result<()> {
    let daemon_socket = config.daemon_socket.clone();
    let host = config.host.clone();

    let (tx, mut rx) = tokio::sync::mpsc::channel::<ReconnectEvent>(16);

    tokio::task::spawn_blocking(move || -> Result<()> {
        let client = DaemonClient::new_unix(&daemon_socket);
        for event in client.reconnect_events(&host)? {
            let event = event?;
            let is_connected = matches!(event, ReconnectEvent::Connected);
            if tx.blocking_send(event).is_err() {
                break;
            }
            if is_connected {
                break;
            }
        }
        Ok(())
    });

    while let Some(event) = rx.recv().await {
        match event {
            ReconnectEvent::Attempting => {
                eprintln!("[reconnecting to host...]");
            }
            ReconnectEvent::Connected => {
                return Ok(());
            }
            ReconnectEvent::Failed { error } => {
                eprintln!("[reconnect failed: {error}, retrying...]");
            }
        }
    }

    Err(anyhow::anyhow!(
        "reconnect stream ended without connected event"
    ))
}

/// Write a status message to stdout.  Uses \r\n because the terminal
/// is in raw mode.
async fn write_status(msg: &str) {
    let mut stdout = tokio::io::stdout();
    let _ = stdout.write_all(msg.as_bytes()).await;
    let _ = stdout.flush().await;
}

// ---------------------------------------------------------------------------
// WebSocket <-> terminal bridge
// ---------------------------------------------------------------------------

/// When `raw_termios` is `Some`, the terminal is still in cooked mode
/// and raw mode is deferred until the first output arrives from the
/// remote.  When `None`, the caller already set raw mode.
async fn bridge(ws: WsStream, raw_termios: Option<&nix::sys::termios::Termios>) -> BridgeOutcome {
    let (ws_write, ws_read) = ws.split();

    // Shared flag: set by read_loop on every received message, cleared
    // by write_loop after each ping.  If write_loop sees the flag
    // still clear after READ_TIMEOUT, the connection is dead.
    let received = Arc::new(AtomicBool::new(true));

    // Whether raw mode is active.  write_loop gates stdin forwarding
    // on this so keystrokes aren't forwarded in cooked mode.
    let raw_active = Arc::new(AtomicBool::new(raw_termios.is_none()));
    // Wakes write_loop when read_loop activates raw mode, so the
    // select! re-evaluates the stdin branch condition immediately
    // instead of waiting for the next ping or signal.
    let raw_notify = Arc::new(tokio::sync::Notify::new());

    tokio::select! {
        result = write_loop(ws_write, Arc::clone(&received), Arc::clone(&raw_active), Arc::clone(&raw_notify)) => {
            match result {
                Ok(BridgeOutcome::Detached) => BridgeOutcome::Detached,
                Ok(BridgeOutcome::SessionEnded) => BridgeOutcome::SessionEnded,
                // WebSocket send error = connection lost
                Ok(BridgeOutcome::ConnectionLost) | Err(_) => BridgeOutcome::ConnectionLost,
            }
        }
        outcome = read_loop(ws_read, Arc::clone(&received), raw_termios, raw_active, raw_notify) => outcome,
    }
}

/// Forward stdin, window-resize signals, and periodic keepalive pings
/// to the WebSocket.
async fn write_loop(
    mut ws_write: WsWriter,
    received: Arc<AtomicBool>,
    raw_active: Arc<AtomicBool>,
    raw_notify: Arc<tokio::sync::Notify>,
) -> Result<BridgeOutcome> {
    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = [0u8; 4096];
    let mut saw_ctrl_a = false;
    let mut sigwinch =
        signal(SignalKind::window_change()).context("registering SIGWINCH handler")?;
    let mut ping_interval = tokio::time::interval(PING_INTERVAL);
    // First tick fires immediately; skip it.
    ping_interval.tick().await;

    loop {
        let is_raw = raw_active.load(Ordering::Relaxed);
        tokio::select! {
            // Only forward stdin once raw mode is active, otherwise
            // the cooked-mode line discipline would echo AND we'd
            // forward -- and ctrl-c should stay a signal, not data.
            n = stdin.read(&mut stdin_buf), if is_raw => {
                let n = match n {
                    Ok(0) | Err(_) => return Ok(BridgeOutcome::SessionEnded),
                    Ok(n) => n,
                };

                match process_stdin(&stdin_buf[..n], &mut saw_ctrl_a) {
                    StdinAction::Detach => return Ok(BridgeOutcome::Detached),
                    StdinAction::Send(data) => {
                        ws_write.send(Message::Binary(data.into())).await
                            .context("sending to WebSocket")?;
                    }
                    StdinAction::Nothing => {}
                }
            }
            _ = sigwinch.recv() => {
                if let Ok((cols, rows)) = get_terminal_size() {
                    let msg = PtyControl::Resize { cols, rows };
                    let json = serde_json::to_string(&msg)
                        .expect("Resize is always serializable");
                    ws_write
                        .send(Message::Text(json.into()))
                        .await
                        .context("sending resize")?;
                }
            }
            _ = ping_interval.tick() => {
                // If nothing was received since the last ping,
                // the tunnel is likely dead.
                if !received.swap(false, Ordering::Relaxed) {
                    return Ok(BridgeOutcome::ConnectionLost);
                }
                ws_write.send(Message::Ping(vec![].into())).await
                    .context("sending keepalive ping")?;
            }
            // Restart the loop so the stdin branch condition is
            // re-evaluated now that raw mode is active.
            _ = raw_notify.notified(), if !is_raw => {}
        }
    }
}

/// Forward WebSocket output to stdout.  Returns `SessionEnded` if the
/// server sends a `SessionEnded` control message, `ConnectionLost` if
/// the WebSocket closes or errors without one.
async fn read_loop(
    mut ws_read: WsReader,
    received: Arc<AtomicBool>,
    raw_termios: Option<&nix::sys::termios::Termios>,
    raw_active: Arc<AtomicBool>,
    raw_notify: Arc<tokio::sync::Notify>,
) -> BridgeOutcome {
    let mut stdout = tokio::io::stdout();
    let mut entered_raw = raw_termios.is_none();
    while let Some(Ok(msg)) = ws_read.next().await {
        received.store(true, Ordering::Relaxed);
        match msg {
            Message::Binary(data) => {
                if !entered_raw {
                    if let Some(termios) = raw_termios {
                        apply_termios(termios);
                    }
                    entered_raw = true;
                    raw_active.store(true, Ordering::Relaxed);
                    raw_notify.notify_one();
                }
                if stdout.write_all(&data).await.is_err() || stdout.flush().await.is_err() {
                    break;
                }
            }
            Message::Text(text) => {
                if let Ok(PtyControl::SessionEnded) = serde_json::from_str(&text) {
                    return BridgeOutcome::SessionEnded;
                }
            }
            Message::Close(_) => break,
            // tungstenite handles Ping internally (auto-pongs before
            // returning a message to the caller).
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
    // WebSocket closed or errored without a SessionEnded message.
    BridgeOutcome::ConnectionLost
}

// ---------------------------------------------------------------------------
// Stdin processing
// ---------------------------------------------------------------------------

enum StdinAction {
    Detach,
    Send(Vec<u8>),
    Nothing,
}

fn process_stdin(data: &[u8], saw_ctrl_a: &mut bool) -> StdinAction {
    let mut to_send = Vec::with_capacity(data.len() + 1);
    for &byte in data {
        if *saw_ctrl_a {
            *saw_ctrl_a = false;
            if byte == DETACH_SUFFIX || byte == DETACH_SUFFIX_CTRL {
                return StdinAction::Detach;
            } else if byte == DETACH_PREFIX {
                // Ctrl-a Ctrl-a -> send one literal Ctrl-a, stay alert
                to_send.push(DETACH_PREFIX);
                *saw_ctrl_a = true;
            } else {
                // Not a detach sequence -- flush the buffered Ctrl-a
                to_send.push(DETACH_PREFIX);
                to_send.push(byte);
            }
        } else if byte == DETACH_PREFIX {
            *saw_ctrl_a = true;
        } else {
            to_send.push(byte);
        }
    }
    if to_send.is_empty() {
        StdinAction::Nothing
    } else {
        StdinAction::Send(to_send)
    }
}
