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
use axum::extract::State;
use axum::response::Response;
use nix::pty::{forkpty, ForkptyResult, Winsize};
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{Pid, User};
use serde::Deserialize;
use tokio::io::unix::AsyncFd;
use tokio::sync::Mutex;

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

    /// Spawn a new session or reuse an existing one.  Returns a dup'd
    /// write fd, the screen buffer for replay, and a broadcast receiver.
    #[allow(clippy::too_many_arguments)]
    async fn spawn_or_attach(
        &self,
        name: String,
        cmd: Vec<String>,
        user: Option<String>,
        workdir: Option<PathBuf>,
        env: Vec<String>,
        cols: u16,
        rows: u16,
    ) -> Result<(
        OwnedFd,
        Arc<Mutex<vt100::Parser>>,
        tokio::sync::broadcast::Receiver<Vec<u8>>,
    )> {
        let mut sessions = self.inner.lock().await;

        // Reap dead sessions so we start fresh if the child exited.
        if let Some(s) = sessions.get(&name) {
            if !child_is_alive(s.child_pid) {
                sessions.remove(&name);
            }
        }

        if !sessions.contains_key(&name) {
            let session = spawn_session(&name, &cmd, user, workdir, &env, cols, rows, self)?;
            sessions.insert(name.clone(), session);
        }

        let session = sessions.get(&name).unwrap();
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
// Session spawning
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_session(
    name: &str,
    cmd: &[String],
    user: Option<String>,
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

    let user_info = match &user {
        Some(u) => {
            let info = User::from_name(u)?.with_context(|| format!("user '{u}' not found"))?;
            Some(info)
        }
        None => None,
    };

    if cmd.is_empty() {
        return Err(anyhow::anyhow!("empty command"));
    }

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
                name: name.to_string(),
                master_fd: master,
                child_pid: child,
                created_at: std::time::Instant::now(),
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
// Request types
// ---------------------------------------------------------------------------

/// Sent by the client as the first WebSocket text message to identify
/// the session and provide spawn parameters (used only if the session
/// does not already exist).
#[derive(Debug, Deserialize)]
pub struct PtySessionRequest {
    pub name: String,
    pub cmd: Vec<String>,
    pub user: Option<String>,
    pub workdir: Option<PathBuf>,
    #[serde(default)]
    pub env: Vec<String>,
    pub cols: u16,
    pub rows: u16,
}

// ---------------------------------------------------------------------------
// HTTP handler
// ---------------------------------------------------------------------------

pub async fn claude_session_handler(
    ws: WebSocketUpgrade,
    State(sessions): State<PtySessions>,
) -> Response {
    ws.on_upgrade(move |socket| handle_pty_socket(socket, sessions))
}

// ---------------------------------------------------------------------------
// WebSocket <-> PTY bridge
// ---------------------------------------------------------------------------

/// Wire protocol over WebSocket binary messages:
///   0x00 + data        -- terminal I/O (bidirectional)
///   0x01 + u16le cols + u16le rows -- resize (client -> server only)
const MSG_DATA: u8 = 0x00;
const MSG_RESIZE: u8 = 0x01;

async fn handle_pty_socket(mut socket: WebSocket, sessions: PtySessions) {
    // First message must be a text message with the session request JSON.
    let req: PtySessionRequest = match socket.recv().await {
        Some(Ok(Message::Text(text))) => match serde_json::from_str(&text) {
            Ok(req) => req,
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

    let name = req.name.clone();

    let (write_fd, screen, mut output_rx) = match sessions
        .spawn_or_attach(
            req.name,
            req.cmd,
            req.user,
            req.workdir,
            req.env,
            req.cols,
            req.rows,
        )
        .await
    {
        Ok(tuple) => tuple,
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
                                    let _ = sessions.resize(&name, cols, rows).await;
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
