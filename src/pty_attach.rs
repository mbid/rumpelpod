//! Client-side terminal bridge for attaching to a remote PTY session
//! over WebSocket.
//!
//! Replaces `docker exec -it ... screen ...` with a direct WebSocket
//! connection to the in-container PTY server.

use std::io;
use std::os::fd::AsRawFd;

use anyhow::{Context, Result};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::signal::unix::{signal, SignalKind};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};
use url::Url;

use crate::pod::pty::PtyControl;

type WsStream = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsWriter = SplitSink<WsStream, Message>;
type WsReader = SplitStream<WsStream>;

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
    pub user: Option<String>,
    pub workdir: Option<String>,
    pub env: Vec<String>,
}

/// Connect to or launch a Claude session over WebSocket.
///
/// Puts the terminal into raw mode, connects to `ws://HOST:PORT/claude`,
/// sends the session parameters as the first message, and bridges local
/// stdin/stdout until the user detaches (Ctrl-a d) or the session ends.
pub fn attach(url: &str, token: &str, params: SessionParams) -> Result<AttachOutcome> {
    eprintln!("[Ctrl-a d to detach]");

    // -- Terminal setup -------------------------------------------------

    let original_termios =
        nix::sys::termios::tcgetattr(io::stdin()).context("reading terminal attributes")?;
    let _guard = TerminalGuard {
        original: original_termios.clone(),
    };

    let mut raw = original_termios;
    nix::sys::termios::cfmakeraw(&mut raw);
    nix::sys::termios::tcsetattr(io::stdin(), nix::sys::termios::SetArg::TCSANOW, &raw)
        .context("setting terminal to raw mode")?;

    // -- Run async bridge -----------------------------------------------

    let url = url.to_string();
    let token = token.to_string();
    crate::async_runtime::block_on(attach_async(&url, &token, params))
}

async fn attach_async(url: &str, token: &str, params: SessionParams) -> Result<AttachOutcome> {
    // -- WebSocket connection -------------------------------------------

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
    let request = tokio_tungstenite::tungstenite::http::Request::builder()
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
        .context("building WebSocket request")?;

    let (mut ws, _response) = tokio_tungstenite::connect_async(request)
        .await
        .context("WebSocket handshake failed")?;

    // -- Send session parameters ----------------------------------------

    let (cols, rows) = get_terminal_size().unwrap_or((80, 24));
    let session_msg = PtyControl::Session {
        name: params.name,
        cmd: params.cmd,
        user: params.user,
        workdir: params.workdir.map(Into::into),
        env: params.env,
        cols,
        rows,
    };
    let json = serde_json::to_string(&session_msg).context("serializing session params")?;
    ws.send(Message::Text(json.into()))
        .await
        .context("sending session parameters")?;

    // -- Bridge ---------------------------------------------------------
    // Two independent directions: the writer task owns ws_write and
    // forwards stdin + SIGWINCH; the reader task pipes ws_read to stdout.
    // tungstenite handles WebSocket pings internally (auto-pongs before
    // returning a message), so the reader never needs write access.

    let (ws_write, ws_read) = ws.split();

    tokio::select! {
        outcome = write_loop(ws_write) => outcome,
        _ = read_loop(ws_read) => Ok(AttachOutcome::SessionEnded),
    }
}

/// Forward stdin and window-resize signals to the WebSocket.
async fn write_loop(mut ws_write: WsWriter) -> Result<AttachOutcome> {
    let mut stdin = tokio::io::stdin();
    let mut stdin_buf = [0u8; 4096];
    let mut saw_ctrl_a = false;
    let mut sigwinch =
        signal(SignalKind::window_change()).context("registering SIGWINCH handler")?;

    loop {
        tokio::select! {
            n = stdin.read(&mut stdin_buf) => {
                let n = match n {
                    Ok(0) | Err(_) => return Ok(AttachOutcome::SessionEnded),
                    Ok(n) => n,
                };

                match process_stdin(&stdin_buf[..n], &mut saw_ctrl_a) {
                    StdinAction::Detach => return Ok(AttachOutcome::Detached),
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
        }
    }
}

/// Forward WebSocket output to stdout.
async fn read_loop(mut ws_read: WsReader) {
    let mut stdout = tokio::io::stdout();
    while let Some(Ok(msg)) = ws_read.next().await {
        match msg {
            Message::Binary(data) => {
                if stdout.write_all(&data).await.is_err() || stdout.flush().await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            // tungstenite handles Ping internally (auto-pongs before
            // returning a message to the caller).
            // Text/Pong/Frame are not expected from the server.
            Message::Text(_) | Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
    }
}

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
