//! PTY session manager for persistent terminal sessions.
//!
//! Replaces GNU screen: the in-container server holds PTY sessions
//! open across client disconnections, allowing detach/reattach.
//! A virtual terminal buffer (vt100) tracks the screen state so the
//! full TUI can be replayed instantly when a new client attaches.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::routing::{any, post};
use axum::{Json, Router};
use nix::pty::{forkpty, ForkptyResult, Winsize};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{Pid, User};
use serde::{Deserialize, Serialize};
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

fn err_json(e: anyhow::Error) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: format!("{e:#}"),
        }),
    )
}

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

struct PtySession {
    #[allow(dead_code)]
    name: String,
    master_fd: OwnedFd,
    child_pid: Pid,
    #[allow(dead_code)]
    created_at: std::time::Instant,
    /// Virtual terminal buffer tracking the screen state for replay
    /// on reattach, like screen/tmux.
    screen: Arc<Mutex<vt100::Parser>>,
    /// Broadcast channel carrying raw PTY output bytes.  Connected
    /// clients subscribe; the persistent reader task is the sole sender.
    output_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
}

#[derive(Clone)]
pub struct PtySessions {
    inner: Arc<Mutex<HashMap<String, PtySession>>>,
}

impl Default for PtySessions {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl PtySessions {
    pub fn new() -> Self {
        Self::default()
    }

    #[allow(clippy::too_many_arguments)]
    async fn spawn(
        &self,
        name: String,
        cmd: Vec<String>,
        user: Option<String>,
        workdir: Option<PathBuf>,
        env: Vec<String>,
        cols: u16,
        rows: u16,
    ) -> Result<bool> {
        let mut sessions = self.inner.lock().await;

        // Check for existing live session first
        if sessions.contains_key(&name) {
            if child_is_alive(sessions[&name].child_pid) {
                return Ok(false);
            }
            // Child exited, remove stale session
            sessions.remove(&name);
        }

        let winsize = Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let user_info = match &user {
            Some(u) => {
                let info = User::from_name(u)?.with_context(|| format!("user '{u}' not found"))?;
                Some(info)
            }
            None => None,
        };

        // Safety: we only call async-signal-safe functions (setuid, setgid,
        // chdir, execvp) in the child before exec. The mutex is held in the
        // parent, so the child (which has its own address space after fork)
        // never touches it.
        let result = unsafe { forkpty(&winsize, None) }.context("forkpty")?;

        match result {
            ForkptyResult::Child => {
                // -- child process --
                // These calls do not return on success (exec replaces the process).

                if let Some(ref info) = user_info {
                    // Set gid before uid to avoid permission errors
                    let _ = nix::unistd::setgid(info.gid);
                    let _ = nix::unistd::setuid(info.uid);

                    // HOME must match the target user for shell init scripts
                    let home = info.dir.to_string_lossy();
                    std::env::set_var("HOME", &*home);
                    std::env::set_var("USER", &info.name);
                    std::env::set_var("LOGNAME", &info.name);
                }

                if let Some(ref dir) = workdir {
                    let _ = std::env::set_current_dir(dir);
                }

                for entry in &env {
                    if let Some((key, value)) = entry.split_once('=') {
                        std::env::set_var(key, value);
                    }
                }

                // Defaults so programs emit color/cursor codes.
                // The caller's env list can override these.
                if std::env::var_os("TERM").is_none() {
                    std::env::set_var("TERM", "xterm-256color");
                }
                if std::env::var_os("COLORTERM").is_none() {
                    std::env::set_var("COLORTERM", "truecolor");
                }

                if cmd.is_empty() {
                    eprintln!("pty: empty command");
                    std::process::exit(1);
                }

                let err = std::process::Command::new(&cmd[0]).args(&cmd[1..]).exec();
                eprintln!("pty: exec failed: {err}");
                std::process::exit(1);
            }
            ForkptyResult::Parent { child, master } => {
                // Set master fd to non-blocking for async I/O
                let flags = nix::fcntl::fcntl(&master, nix::fcntl::FcntlArg::F_GETFL)
                    .context("fcntl F_GETFL")?;
                let mut oflags = nix::fcntl::OFlag::from_bits_truncate(flags);
                oflags.insert(nix::fcntl::OFlag::O_NONBLOCK);
                nix::fcntl::fcntl(&master, nix::fcntl::FcntlArg::F_SETFL(oflags))
                    .context("fcntl F_SETFL O_NONBLOCK")?;

                let screen = Arc::new(Mutex::new(vt100::Parser::new(rows, cols, 0)));
                let (output_tx, _) = tokio::sync::broadcast::channel(256);

                // Spawn persistent reader: continuously drains PTY output,
                // updates the screen buffer, and broadcasts to clients.
                // Runs even when no client is attached so the child never
                // blocks on write() and the screen buffer stays current.
                let reader_fd = nix::unistd::dup(&master).context("dup master for reader")?;
                spawn_persistent_reader(
                    reader_fd,
                    Arc::clone(&screen),
                    output_tx.clone(),
                    self.clone(),
                    name.clone(),
                );

                let session = PtySession {
                    name: name.clone(),
                    master_fd: master,
                    child_pid: child,
                    created_at: std::time::Instant::now(),
                    screen,
                    output_tx,
                };
                sessions.insert(name, session);
                Ok(true)
            }
        }
    }

    /// Return a dup'd fd for writing input to the PTY, plus the screen
    /// buffer for replay and a broadcast receiver for live output.
    /// The original fd stays in the session so the PTY survives detach.
    async fn attach(
        &self,
        name: &str,
    ) -> Result<(
        OwnedFd,
        Arc<Mutex<vt100::Parser>>,
        tokio::sync::broadcast::Receiver<Vec<u8>>,
    )> {
        let sessions = self.inner.lock().await;
        let session = sessions
            .get(name)
            .with_context(|| format!("no such pty session: {name}"))?;

        let duped = nix::unistd::dup(&session.master_fd).context("dup master fd")?;
        let rx = session.output_tx.subscribe();
        Ok((duped, Arc::clone(&session.screen), rx))
    }

    async fn resize(&self, name: &str, cols: u16, rows: u16) -> Result<()> {
        let sessions = self.inner.lock().await;
        let session = sessions
            .get(name)
            .with_context(|| format!("no such pty session: {name}"))?;
        set_winsize(session.master_fd.as_raw_fd(), cols, rows)?;
        session
            .screen
            .lock()
            .await
            .screen_mut()
            .set_size(rows, cols);
        Ok(())
    }

    /// Remove a dead session from the registry.
    async fn remove_if_dead(&self, name: &str) {
        let mut sessions = self.inner.lock().await;
        if let Some(s) = sessions.get(name) {
            if !child_is_alive(s.child_pid) {
                sessions.remove(name);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Persistent PTY reader
// ---------------------------------------------------------------------------

/// Background task that continuously reads PTY output, updates the
/// screen buffer, and broadcasts to any connected WebSocket clients.
fn spawn_persistent_reader(
    fd: OwnedFd,
    screen: Arc<Mutex<vt100::Parser>>,
    tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    sessions: PtySessions,
    name: String,
) {
    tokio::spawn(async move {
        let async_fd = match AsyncFd::new(fd) {
            Ok(fd) => fd,
            Err(e) => {
                eprintln!("pty: persistent reader AsyncFd::new failed: {e}");
                return;
            }
        };

        let mut buf = vec![0u8; 4096];
        loop {
            let mut ready = match async_fd.readable().await {
                Ok(r) => r,
                Err(_) => break,
            };

            match ready.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
                if n > 0 {
                    Ok(n as usize)
                } else if n == 0 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "pty eof",
                    ))
                } else {
                    Err(std::io::Error::last_os_error())
                }
            }) {
                Ok(Ok(n)) => {
                    let data = &buf[..n];
                    screen.lock().await.process(data);
                    // Send returns Err only when there are no receivers,
                    // which is normal when no client is attached.
                    let _ = tx.send(data.to_vec());
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    sessions.remove_if_dead(&name).await;
                    break;
                }
                Ok(Err(_)) => break,
                // WouldBlock -- AsyncFd will re-poll
                Err(_) => continue,
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn child_is_alive(pid: Pid) -> bool {
    match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
        Ok(WaitStatus::StillAlive) => true,
        // Any terminal status means the child is gone
        Ok(_) => false,
        // ECHILD means the child was already reaped
        Err(nix::errno::Errno::ECHILD) => false,
        // Other errors are unexpected; treat as dead to avoid leaking
        Err(_) => false,
    }
}

/// Build the escape sequence stream that reconstructs the full terminal
/// state for a new client: alternate screen mode, screen contents with
/// formatting, input modes, cursor position, and cursor visibility.
fn build_screen_replay(screen: &vt100::Screen) -> Vec<u8> {
    let mut out = Vec::new();

    // Switch to alternate screen first so the content lands in the
    // right buffer (TUI apps like ink use alternate screen).
    if screen.alternate_screen() {
        out.extend_from_slice(b"\x1b[?1049h");
    }

    // state_formatted() = contents (clear + cells with colors) + input
    // modes (application keypad/cursor, bracketed paste, mouse protocol).
    out.extend_from_slice(&screen.state_formatted());

    // cursor_state_formatted() = cursor visibility + cursor position.
    out.extend_from_slice(&screen.cursor_state_formatted());

    out
}

fn set_winsize(fd: RawFd, cols: u16, rows: u16) -> Result<()> {
    let ws = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCSWINSZ is a well-defined ioctl for setting terminal
    // window size, and ws is a valid Winsize struct on the stack.
    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws as *const Winsize) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("ioctl TIOCSWINSZ");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PtySpawnRequest {
    pub name: String,
    pub cmd: Vec<String>,
    pub user: Option<String>,
    pub workdir: Option<PathBuf>,
    #[serde(default)]
    pub env: Vec<String>,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Serialize)]
struct PtySpawnResponse {
    created: bool,
}

#[derive(Debug, Deserialize)]
pub struct PtyAttachQuery {
    pub name: String,
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

async fn pty_spawn_handler(
    State(sessions): State<PtySessions>,
    Json(req): Json<PtySpawnRequest>,
) -> Result<Json<PtySpawnResponse>, (StatusCode, Json<ErrorResponse>)> {
    let created = sessions
        .spawn(
            req.name,
            req.cmd,
            req.user,
            req.workdir,
            req.env,
            req.cols,
            req.rows,
        )
        .await
        .map_err(err_json)?;
    Ok(Json(PtySpawnResponse { created }))
}

async fn pty_attach_handler(
    ws: WebSocketUpgrade,
    State(sessions): State<PtySessions>,
    Query(query): Query<PtyAttachQuery>,
) -> Response {
    ws.on_upgrade(move |socket| handle_pty_socket(socket, sessions, query.name))
}

// ---------------------------------------------------------------------------
// WebSocket <-> PTY bridge
// ---------------------------------------------------------------------------

/// Wire protocol over WebSocket binary messages:
///   0x00 + data        -- terminal I/O (bidirectional)
///   0x01 + u16le cols + u16le rows -- resize (client -> server only)
const MSG_DATA: u8 = 0x00;
const MSG_RESIZE: u8 = 0x01;

async fn handle_pty_socket(mut socket: WebSocket, sessions: PtySessions, name: String) {
    let (write_fd, screen, mut output_rx) = match sessions.attach(&name).await {
        Ok(tuple) => tuple,
        Err(e) => {
            eprintln!("pty attach failed for '{name}': {e:#}");
            return;
        }
    };

    // Replay the current screen state so the client sees the full TUI
    // immediately, like screen/tmux do on reattach.
    {
        let parser = screen.lock().await;
        let replay = build_screen_replay(parser.screen());
        if !replay.is_empty() {
            let mut msg = Vec::with_capacity(1 + replay.len());
            msg.push(MSG_DATA);
            msg.extend_from_slice(&replay);
            if socket.send(Message::Binary(msg.into())).await.is_err() {
                return;
            }
        }
    }

    let raw_fd = write_fd.as_raw_fd();

    // Main loop: multiplex between broadcast output and WebSocket input.
    let ws_sessions = sessions.clone();
    let ws_name = name.clone();
    loop {
        tokio::select! {
            // Persistent reader produced output -> forward to WebSocket
            output = output_rx.recv() => {
                match output {
                    Ok(data) => {
                        let mut msg = Vec::with_capacity(1 + data.len());
                        msg.push(MSG_DATA);
                        msg.extend_from_slice(&data);
                        if socket.send(Message::Binary(msg.into())).await.is_err() {
                            break;
                        }
                    }
                    // Lagged: we missed some output, not fatal for a terminal
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    // Sender dropped: child exited
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }

            // WebSocket received a message -> handle it
            ws_msg = socket.recv() => {
                match ws_msg {
                    Some(Ok(Message::Binary(data))) => {
                        if data.is_empty() {
                            continue;
                        }
                        match data[0] {
                            MSG_DATA => {
                                let payload = &data[1..];
                                if !payload.is_empty() {
                                    // Blocking write is acceptable for small terminal
                                    // input chunks; the kernel PTY buffer is large
                                    // enough that this won't block in practice.
                                    let written = unsafe {
                                        libc::write(
                                            raw_fd,
                                            payload.as_ptr() as *const libc::c_void,
                                            payload.len(),
                                        )
                                    };
                                    if written < 0 {
                                        break;
                                    }
                                }
                            }
                            MSG_RESIZE => {
                                if data.len() >= 5 {
                                    let cols = u16::from_le_bytes([data[1], data[2]]);
                                    let rows = u16::from_le_bytes([data[3], data[4]]);
                                    let _ = ws_sessions.resize(&ws_name, cols, rows).await;
                                }
                            }
                            _ => {
                                // Unknown message type -- ignore rather than crash,
                                // since future protocol extensions may add new types.
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    // Ignore text, ping, pong
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                    // WebSocket closed
                    None => break,
                }
            }
        }
    }

    // The dup'd write_fd is dropped here; the session's master_fd and
    // the persistent reader's fd keep the PTY alive for future reattach.
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn pty_routes(sessions: PtySessions) -> Router {
    Router::new()
        .route("/pty/spawn", post(pty_spawn_handler))
        .route("/pty/attach", any(pty_attach_handler))
        .with_state(sessions)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_roundtrip_through_vt100() {
        let mut parser = vt100::Parser::new(24, 80, 0);

        parser.process(b"\x1b[?1049h");
        parser.process(b"\x1b[H\x1b[2J");
        parser.process(b"~/workspace $ ");
        parser.process(b"\x1b[2;1H");
        parser.process(b"\x1b[1;32mgreen text\x1b[0m");
        parser.process(b"\x1b[24;1H");
        parser.process(b"status bar");

        let screen = parser.screen();
        assert!(screen.alternate_screen());

        let replay = build_screen_replay(screen);

        // Feed replay into a fresh parser (simulating a new client).
        let mut replayed = vt100::Parser::new(24, 80, 0);
        replayed.process(&replay);

        let contents = replayed.screen().contents();
        assert!(contents.contains("~/workspace"));
        assert!(contents.contains("green text"));
        assert!(contents.contains("status bar"));

        // Old content on a dirty screen must be cleared by the replay.
        let mut dirty = vt100::Parser::new(24, 80, 0);
        dirty.process(b"THIS SHOULD BE OVERWRITTEN BY REPLAY");
        dirty.process(&replay);
        assert!(!dirty.screen().contents().contains("OVERWRITTEN"));
    }

    #[test]
    fn resize_preserves_screen_content() {
        let mut parser = vt100::Parser::new(24, 80, 0);
        parser.process(b"\x1b[?1049h");
        parser.process(b"\x1b[H\x1b[2J");
        parser.process(b"~/workspace $ ");
        assert!(parser.screen().contents().contains("~/workspace"));

        // Same-size resize must not erase the buffer.
        parser.screen_mut().set_size(24, 80);
        assert!(parser.screen().contents().contains("~/workspace"));

        // Different-size resize must preserve content too.
        parser.screen_mut().set_size(30, 100);
        assert!(parser.screen().contents().contains("~/workspace"));
    }
}
