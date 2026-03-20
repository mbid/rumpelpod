//! PTY session manager for persistent terminal sessions.
//!
//! Replaces GNU screen: the in-container server holds PTY sessions
//! open across client disconnections, allowing detach/reattach.
//! A virtual terminal buffer (vt100) tracks the screen state so the
//! full TUI can be replayed instantly when a new client attaches.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::Response;
use nix::pty::{forkpty, ForkptyResult, Winsize};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// Session types
// ---------------------------------------------------------------------------

struct PtySession {
    master_fd: OwnedFd,
    child_pid: Pid,
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

    /// Spawn a new session or reuse an existing one.  Returns a dup'd
    /// write fd, the screen buffer for replay, and a broadcast receiver.
    /// Returns `Ok(None)` when `create` is false and the session does
    /// not exist (used by reconnecting clients to avoid spawning a
    /// fresh session after the original child exited).
    #[allow(clippy::too_many_arguments)]
    async fn spawn_or_attach(
        &self,
        name: String,
        cmd: Vec<String>,
        workdir: Option<PathBuf>,
        env: Vec<String>,
        cols: u16,
        rows: u16,
        create: bool,
    ) -> Result<
        Option<(
            OwnedFd,
            Arc<Mutex<vt100::Parser>>,
            tokio::sync::broadcast::Receiver<Vec<u8>>,
        )>,
    > {
        let mut sessions = self.inner.lock().await;

        // Reap dead sessions so we start fresh if the child exited.
        if let Some(s) = sessions.get(&name) {
            if !child_is_alive(s.child_pid) {
                sessions.remove(&name);
            }
        }

        if !sessions.contains_key(&name) {
            if !create {
                return Ok(None);
            }
            let session = spawn_session(&name, &cmd, workdir, &env, cols, rows, self)?;
            sessions.insert(name.clone(), session);
        }

        let session = sessions.get(&name).unwrap();

        // Resize to match the attaching client's terminal, so
        // reattaching after a window resize (or reconnection) shows
        // the right dimensions.
        set_winsize(session.master_fd.as_raw_fd(), cols, rows)?;
        session
            .screen
            .lock()
            .await
            .screen_mut()
            .set_size(rows, cols);

        let duped = nix::unistd::dup(&session.master_fd).context("dup master fd")?;
        let rx = session.output_tx.subscribe();
        Ok(Some((duped, Arc::clone(&session.screen), rx)))
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
// Session spawning
// ---------------------------------------------------------------------------

fn spawn_session(
    name: &str,
    cmd: &[String],
    workdir: Option<PathBuf>,
    env: &[String],
    cols: u16,
    rows: u16,
    sessions: &PtySessions,
) -> Result<PtySession> {
    let winsize = Winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    if cmd.is_empty() {
        return Err(anyhow::anyhow!("empty command"));
    }

    // Safety: we only call async-signal-safe functions (chdir, execvp)
    // in the child before exec. The mutex is held in the parent, so
    // the child (which has its own address space after fork) never
    // touches it.
    let result = unsafe { forkpty(&winsize, None) }.context("forkpty")?;

    match result {
        ForkptyResult::Child => {
            // -- child process --
            // These calls do not return on success (exec replaces the process).

            if let Some(ref dir) = workdir {
                if let Err(e) = std::env::set_current_dir(dir) {
                    let dir = dir.display();
                    eprintln!("pty: chdir to {dir} failed: {e}");
                    std::process::exit(1);
                }
            }

            for entry in env {
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
                sessions.clone(),
                name.to_string(),
            );

            Ok(PtySession {
                master_fd: master,
                child_pid: child,
                screen,
                output_tx,
            })
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
                nix::unistd::read(inner, &mut buf)
                    .map_err(std::io::Error::from)
                    .and_then(|n| {
                        if n == 0 {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::UnexpectedEof,
                                "pty eof",
                            ))
                        } else {
                            Ok(n)
                        }
                    })
            }) {
                Ok(Ok(n)) => {
                    let data = &buf[..n];
                    screen.lock().await.process(data);
                    // Send returns Err only when there are no receivers,
                    // which is normal when no client is attached.
                    let _ = tx.send(data.to_vec());
                }
                // EOF (read returned 0) or EIO (PTY slave closed on
                // Linux) -- the child exited.
                Ok(Err(_)) => {
                    sessions.remove_if_dead(&name).await;
                    break;
                }
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
// Claude CLI resolution
// ---------------------------------------------------------------------------

/// Return the path to the Claude CLI binary, which must be pre-installed
/// in the container image (baked in by the prepared image build).
fn find_claude_cli() -> Result<PathBuf> {
    let bin_path = Path::new(crate::daemon::CLAUDE_CONTAINER_BIN);
    if bin_path.exists() {
        return Ok(bin_path.to_path_buf());
    }

    // The user's image ships its own claude binary.
    if let Ok(found) = which("claude") {
        return Ok(found);
    }

    Err(anyhow::anyhow!(
        "Claude CLI not found at {} or in PATH",
        crate::daemon::CLAUDE_CONTAINER_BIN
    ))
}

/// Resolve a binary name via PATH, like `which(1)`.
fn which(name: &str) -> Result<PathBuf> {
    let path_var = std::env::var("PATH").unwrap_or_default();
    for dir in path_var.split(':') {
        let candidate = Path::new(dir).join(name);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(anyhow::anyhow!("'{name}' not found in PATH"))
}

// ---------------------------------------------------------------------------
// Wire protocol
// ---------------------------------------------------------------------------

/// Text messages carry JSON control messages. Binary messages carry
/// raw PTY data (no prefix, no framing beyond WebSocket itself).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PtyControl {
    /// Sent as the first message to identify/create a session.
    Session {
        name: String,
        cmd: Vec<String>,
        workdir: Option<PathBuf>,
        env: Vec<String>,
        cols: u16,
        rows: u16,
        /// When false, the server will not spawn a new session if the
        /// named one does not exist (used for reconnection).
        #[serde(default = "default_true")]
        create: bool,
    },
    /// Terminal resize (client -> server).
    Resize { cols: u16, rows: u16 },
    /// Sent by the server when the PTY child process has exited.
    SessionEnded,
}

fn default_true() -> bool {
    true
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn claude_session_handler(
    ws: WebSocketUpgrade,
    State(state): State<super::server::PodServerState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_pty_socket(socket, state.pty_sessions))
}

// ---------------------------------------------------------------------------
// WebSocket <-> PTY bridge
// ---------------------------------------------------------------------------

async fn handle_pty_socket(mut socket: WebSocket, sessions: PtySessions) {
    // First message must be a Session control message.
    let (name, mut cmd, workdir, env, cols, rows, create) = match socket.recv().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str::<PtyControl>(&text) {
            Ok(PtyControl::Session {
                name,
                cmd,
                workdir,
                env,
                cols,
                rows,
                create,
            }) => (name, cmd, workdir, env, cols, rows, create),
            Ok(other) => {
                eprintln!("pty: expected session message, got {other:?}");
                return;
            }
            Err(e) => {
                eprintln!("pty: invalid session request: {e}");
                return;
            }
        },
        Some(Ok(_)) => {
            eprintln!("pty: expected text message with session params, got binary");
            return;
        }
        Some(Err(e)) => {
            eprintln!("pty: WebSocket error reading session request: {e}");
            return;
        }
        None => return,
    };

    // Resolve the Claude CLI binary before first spawn.
    if create {
        match tokio::task::spawn_blocking(find_claude_cli)
            .await
            .expect("find_claude_cli panicked")
        {
            Ok(claude_bin) => {
                cmd[0] = claude_bin.to_string_lossy().into_owned();
            }
            Err(e) => {
                eprintln!("pty: failed to find Claude CLI: {e:#}");
                return;
            }
        }
    }

    let (write_fd, screen, mut output_rx) = match sessions
        .spawn_or_attach(name.clone(), cmd, workdir, env, cols, rows, create)
        .await
    {
        Ok(Some(tuple)) => tuple,
        Ok(None) => {
            // Session does not exist and create=false (reconnection
            // to a session that already exited).
            let msg = serde_json::to_string(&PtyControl::SessionEnded)
                .expect("SessionEnded is always serializable");
            let _ = socket.send(Message::Text(msg.into())).await;
            return;
        }
        Err(e) => {
            eprintln!("pty session failed for '{name}': {e:#}");
            return;
        }
    };

    // Replay the current screen state so the client sees the full TUI
    // immediately, like screen/tmux do on reattach.
    {
        let parser = screen.lock().await;
        let replay = build_screen_replay(parser.screen());
        if !replay.is_empty() && socket.send(Message::Binary(replay.into())).await.is_err() {
            return;
        }
    }

    // Main loop: multiplex between broadcast output and WebSocket input.
    loop {
        tokio::select! {
            // Persistent reader produced output -> forward as binary
            output = output_rx.recv() => {
                match output {
                    Ok(data) => {
                        if socket.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    // Lagged: we missed some output, not fatal for a terminal
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                    // Sender dropped: child exited.  Tell the client
                    // so it can distinguish this from a network error.
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        let msg = serde_json::to_string(&PtyControl::SessionEnded)
                            .expect("SessionEnded is always serializable");
                        let _ = socket.send(Message::Text(msg.into())).await;
                        break;
                    }
                }
            }

            // WebSocket received a message -> handle it
            ws_msg = socket.recv() => {
                match ws_msg {
                    // Binary = raw PTY input from client
                    Some(Ok(Message::Binary(data))) => {
                        if !data.is_empty()
                            && nix::unistd::write(&write_fd, &data).is_err()
                        {
                            break;
                        }
                    }
                    // Text = JSON control message
                    Some(Ok(Message::Text(text))) => {
                        match serde_json::from_str::<PtyControl>(&text) {
                            Ok(PtyControl::Resize { cols, rows }) => {
                                let _ = sessions.resize(&name, cols, rows).await;
                            }
                            Ok(PtyControl::Session { .. }) => {
                                // Session message after handshake is nonsensical
                            }
                            Ok(PtyControl::SessionEnded) => {
                                // Server-to-client only, ignore if received
                            }
                            Err(e) => {
                                eprintln!("pty: invalid control message: {e}");
                            }
                        }
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => continue,
                    Some(Err(_)) => break,
                    None => break,
                }
            }
        }
    }

    // The dup'd write_fd is dropped here; the session's master_fd and
    // the persistent reader's fd keep the PTY alive for future reattach.
}
