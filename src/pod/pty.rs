//! PTY session manager for persistent terminal sessions.
//!
//! Replaces GNU screen: the in-container server holds PTY sessions
//! open across client disconnections, allowing detach/reattach.

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

                let session = PtySession {
                    name: name.clone(),
                    master_fd: master,
                    child_pid: child,
                    created_at: std::time::Instant::now(),
                };
                sessions.insert(name, session);
                Ok(true)
            }
        }
    }

    /// Check whether a session exists and its child is still alive.
    /// Cleans up dead sessions as a side effect.
    async fn exists(&self, name: &str) -> bool {
        let mut sessions = self.inner.lock().await;
        match sessions.get(name) {
            Some(s) => {
                if child_is_alive(s.child_pid) {
                    true
                } else {
                    sessions.remove(name);
                    false
                }
            }
            None => false,
        }
    }

    /// Return a dup'd fd for the master side, suitable for async I/O.
    /// The original fd stays in the session so the PTY survives detach.
    async fn attach(&self, name: &str) -> Result<OwnedFd> {
        let sessions = self.inner.lock().await;
        let session = sessions
            .get(name)
            .with_context(|| format!("no such pty session: {name}"))?;

        let duped = nix::unistd::dup(&session.master_fd).context("dup master fd")?;
        Ok(duped)
    }

    async fn resize(&self, name: &str, cols: u16, rows: u16) -> Result<()> {
        let sessions = self.inner.lock().await;
        let session = sessions
            .get(name)
            .with_context(|| format!("no such pty session: {name}"))?;
        set_winsize(session.master_fd.as_raw_fd(), cols, rows)
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
pub struct PtyStatusRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
struct PtyStatusResponse {
    exists: bool,
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

async fn pty_status_handler(
    State(sessions): State<PtySessions>,
    Json(req): Json<PtyStatusRequest>,
) -> Result<Json<PtyStatusResponse>, (StatusCode, Json<ErrorResponse>)> {
    let exists = sessions.exists(&req.name).await;
    Ok(Json(PtyStatusResponse { exists }))
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
    let master_fd = match sessions.attach(&name).await {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("pty attach failed for '{name}': {e:#}");
            return;
        }
    };

    let raw_fd = master_fd.as_raw_fd();
    let async_fd = match AsyncFd::new(master_fd) {
        Ok(fd) => Arc::new(fd),
        Err(e) => {
            eprintln!("pty: AsyncFd::new failed: {e}");
            return;
        }
    };

    // Channel for PTY output that needs to be sent over the WebSocket.
    // Bounded to provide backpressure if the WebSocket consumer is slow.
    let (pty_tx, mut pty_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);

    // Task: read from PTY master fd and forward to channel
    let read_fd = Arc::clone(&async_fd);
    let read_name = name.clone();
    let read_sessions = sessions.clone();
    let pty_reader = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let mut ready = match read_fd.readable().await {
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
                    let mut msg = Vec::with_capacity(1 + n);
                    msg.push(MSG_DATA);
                    msg.extend_from_slice(&buf[..n]);
                    if pty_tx.send(msg).await.is_err() {
                        // WebSocket side dropped the receiver
                        break;
                    }
                }
                Ok(Err(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    // Child exited
                    read_sessions.remove_if_dead(&read_name).await;
                    break;
                }
                Ok(Err(_)) => break,
                // WouldBlock -- AsyncFd will re-poll
                Err(_) => continue,
            }
        }
    });

    // Main loop: multiplex between PTY output (via channel) and WebSocket input.
    // Owning the WebSocket in a single task avoids needing futures_util::StreamExt::split.
    let ws_sessions = sessions.clone();
    let ws_name = name.clone();
    loop {
        tokio::select! {
            // PTY produced output -> send to WebSocket
            pty_msg = pty_rx.recv() => {
                match pty_msg {
                    Some(data) => {
                        if socket.send(Message::Binary(data.into())).await.is_err() {
                            break;
                        }
                    }
                    // PTY reader task exited (child died or error)
                    None => break,
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

    // Stop the PTY reader; we do NOT close the session's master fd --
    // only the dup'd fd (inside async_fd) is dropped when this function
    // returns, preserving the session for future reattach.
    pty_reader.abort();
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn pty_routes(sessions: PtySessions) -> Router {
    Router::new()
        .route("/pty/spawn", post(pty_spawn_handler))
        .route("/pty/status", post(pty_status_handler))
        .route("/pty/attach", any(pty_attach_handler))
        .with_state(sessions)
}
