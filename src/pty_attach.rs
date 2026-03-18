//! Client-side terminal bridge for attaching to a remote PTY session
//! over WebSocket.
//!
//! Replaces `docker exec -it ... screen ...` with a direct WebSocket
//! connection to the in-container PTY server.

use std::io::{self, Write};
use std::os::fd::{AsRawFd, BorrowedFd};

use anyhow::{Context, Result};
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{ClientRequestBuilder, Message};

use crate::pod::pty::PtyControl;

/// Ctrl-a (0x01) is the first byte of the detach sequence (same as
/// GNU screen). Ctrl+letter works on all keyboard layouts, unlike
/// Ctrl+punctuation which breaks on non-US layouts in gnome-terminal.
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

    // -- WebSocket connection -------------------------------------------

    let ws_url = format!(
        "{}/claude",
        url.replacen("http://", "ws://", 1)
            .replacen("https://", "wss://", 1),
    );
    let uri: tungstenite::http::Uri = ws_url.parse().context("parsing WebSocket URI")?;
    let request =
        ClientRequestBuilder::new(uri).with_header("Authorization", format!("Bearer {token}"));

    let (mut ws, _response) =
        tungstenite::connect(request).context("WebSocket handshake failed")?;

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
        .context("sending session parameters")?;

    // -- Set up non-blocking I/O ----------------------------------------

    let tcp_raw_fd = match ws.get_ref() {
        MaybeTlsStream::Plain(tcp) => tcp.as_raw_fd(),
        _ => return Err(anyhow::anyhow!("unexpected TLS stream for local WebSocket")),
    };

    // SAFETY: the TCP stream is owned by the WebSocket and stays open
    // for the duration of this function.
    let tcp_fd = unsafe { BorrowedFd::borrow_raw(tcp_raw_fd) };

    // Set the TCP stream to non-blocking so ws.read() returns WouldBlock
    // instead of blocking when no data is available.
    let flags =
        nix::fcntl::fcntl(tcp_fd, nix::fcntl::FcntlArg::F_GETFL).context("fcntl F_GETFL")?;
    let mut oflags = nix::fcntl::OFlag::from_bits_truncate(flags);
    oflags.insert(nix::fcntl::OFlag::O_NONBLOCK);
    nix::fcntl::fcntl(tcp_fd, nix::fcntl::FcntlArg::F_SETFL(oflags))
        .context("fcntl F_SETFL O_NONBLOCK")?;

    // -- Single-threaded poll loop --------------------------------------

    let stdin_raw_fd = io::stdin().as_raw_fd();
    // SAFETY: stdin is open for the duration of this function.
    let stdin_fd = unsafe { BorrowedFd::borrow_raw(stdin_raw_fd) };
    let mut stdout = io::stdout().lock();
    let mut stdin_buf = [0u8; 4096];
    let mut saw_ctrl_a = false;
    let mut last_size = get_terminal_size().ok();
    let mut detached = false;

    loop {
        // SAFETY: BorrowedFd requires the fd to be valid for the
        // lifetime of the borrow. Both stdin and the TCP socket are
        // open for the duration of this loop.
        let poll_fds = &mut [
            PollFd::new(stdin_fd, PollFlags::POLLIN),
            PollFd::new(tcp_fd, PollFlags::POLLIN),
        ];

        match poll(poll_fds, PollTimeout::from(100u16)) {
            Ok(_) => {}
            Err(nix::errno::Errno::EINTR) => continue,
            Err(e) => return Err(e).context("poll"),
        }

        // Check for terminal resize each iteration.
        let current_size = get_terminal_size().ok();
        if current_size != last_size {
            if let Some((cols, rows)) = current_size {
                let msg = PtyControl::Resize { cols, rows };
                let json = serde_json::to_string(&msg).expect("Resize is always serializable");
                if ws.send(Message::Text(json.into())).is_err() {
                    break;
                }
            }
            last_size = current_size;
        }

        // stdin ready -> read, process detach keys, send to WebSocket
        if poll_fds[0]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
        {
            let n = nix::unistd::read(stdin_fd, &mut stdin_buf);
            match n {
                Ok(0) => break,
                Ok(n) => {
                    let mut to_send = Vec::with_capacity(n + 1);
                    for &byte in &stdin_buf[..n] {
                        if saw_ctrl_a {
                            saw_ctrl_a = false;
                            if byte == DETACH_SUFFIX || byte == DETACH_SUFFIX_CTRL {
                                detached = true;
                                break;
                            } else if byte == DETACH_PREFIX {
                                // Ctrl-a Ctrl-a -> send one literal Ctrl-a, stay alert
                                to_send.push(DETACH_PREFIX);
                                saw_ctrl_a = true;
                            } else {
                                // Not a detach sequence -- flush the buffered Ctrl-a
                                to_send.push(DETACH_PREFIX);
                                to_send.push(byte);
                            }
                        } else if byte == DETACH_PREFIX {
                            saw_ctrl_a = true;
                        } else {
                            to_send.push(byte);
                        }
                    }

                    if detached {
                        break;
                    }

                    if !to_send.is_empty() && ws.send(Message::Binary(to_send.into())).is_err() {
                        break;
                    }
                }
                Err(nix::errno::Errno::EINTR) => continue,
                Err(_) => break,
            }
        }

        // WebSocket ready -> read messages, write to stdout
        if poll_fds[1]
            .revents()
            .is_some_and(|r| r.contains(PollFlags::POLLIN))
        {
            // Drain all available messages before going back to poll,
            // since tungstenite may buffer multiple frames from one read.
            loop {
                match ws.read() {
                    Ok(Message::Binary(data)) => {
                        let _ = stdout.write_all(&data);
                        let _ = stdout.flush();
                    }
                    Ok(Message::Close(_)) => {
                        return Ok(AttachOutcome::SessionEnded);
                    }
                    Ok(_) => {}
                    Err(tungstenite::Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(tungstenite::Error::ConnectionClosed)
                    | Err(tungstenite::Error::AlreadyClosed) => {
                        return Ok(AttachOutcome::SessionEnded);
                    }
                    Err(_) => return Ok(AttachOutcome::SessionEnded),
                }
            }
        }

        // stdin hangup or error
        if poll_fds[0]
            .revents()
            .is_some_and(|r| r.intersects(PollFlags::POLLHUP | PollFlags::POLLERR))
        {
            break;
        }

        // WebSocket hangup or error
        if poll_fds[1]
            .revents()
            .is_some_and(|r| r.intersects(PollFlags::POLLHUP | PollFlags::POLLERR))
        {
            break;
        }
    }

    // Best-effort close handshake.
    let _ = ws.close(None);

    // Terminal is restored by _guard's Drop.

    if detached {
        Ok(AttachOutcome::Detached)
    } else {
        Ok(AttachOutcome::SessionEnded)
    }
}
