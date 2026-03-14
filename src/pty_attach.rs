//! Client-side terminal bridge for attaching to a remote PTY session
//! over WebSocket.
//!
//! Replaces `docker exec -it ... screen ...` with a direct WebSocket
//! connection to the in-container PTY server.

use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use log::trace;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{ClientRequestBuilder, Message, WebSocket};

/// Message type prefix for terminal I/O data.
const MSG_DATA: u8 = 0x00;
/// Message type prefix for resize notifications.
const MSG_RESIZE: u8 = 0x01;

/// Ctrl-a (0x01) is the first byte of the detach sequence (same as
/// GNU screen). Ctrl+letter works on all keyboard layouts, unlike
/// Ctrl+punctuation which breaks on non-US layouts in gnome-terminal.
const DETACH_PREFIX: u8 = 0x01;
/// 'd' (0x64) completes the detach sequence after Ctrl-a.
const DETACH_SUFFIX: u8 = b'd';

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

/// Build a resize message: 0x01 prefix + cols (u16 LE) + rows (u16 LE).
fn resize_message(cols: u16, rows: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(5);
    buf.push(MSG_RESIZE);
    buf.extend_from_slice(&cols.to_le_bytes());
    buf.extend_from_slice(&rows.to_le_bytes());
    buf
}

/// Outbound messages queued by the stdin reader thread for the
/// WebSocket writer loop to send.
enum Outbound {
    Data(Vec<u8>),
    Resize(u16, u16),
}

/// Attach to a remote PTY session over WebSocket.
///
/// Puts the terminal into raw mode, connects to
/// `ws://HOST:PORT/pty/attach?name=SESSION`, and bridges local
/// stdin/stdout to the WebSocket until the user detaches (Ctrl-a d)
/// or the remote session ends.
pub fn attach(url: &str, token: &str, session_name: &str) -> Result<AttachOutcome> {
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
        "{}/pty/attach?name={session_name}",
        url.replacen("http://", "ws://", 1)
            .replacen("https://", "wss://", 1),
    );
    let uri: tungstenite::http::Uri = ws_url.parse().context("parsing WebSocket URI")?;
    let request =
        ClientRequestBuilder::new(uri).with_header("Authorization", format!("Bearer {token}"));

    let (mut ws, _response) =
        tungstenite::connect(request).context("WebSocket handshake failed")?;

    // Set a short read timeout so the WebSocket loop can periodically
    // drain outbound messages and check shutdown flags without blocking
    // indefinitely on read().
    set_read_timeout(&ws, Some(Duration::from_millis(50)))?;

    // -- Initial resize -------------------------------------------------

    if let Ok((cols, rows)) = get_terminal_size() {
        let msg = resize_message(cols, rows);
        ws.send(Message::Binary(msg.into()))
            .context("sending initial resize")?;
    }

    // -- Shared state ---------------------------------------------------

    let done = Arc::new(AtomicBool::new(false));
    let detached = Arc::new(AtomicBool::new(false));

    // Channel for the stdin thread to send data to the WS loop.
    let (outbound_tx, outbound_rx) = std::sync::mpsc::channel::<Outbound>();

    // -- Stdin reader thread --------------------------------------------
    //
    // Reads from stdin and forwards data through the channel.
    // Detects terminal resizes by polling get_terminal_size() each
    // iteration rather than using signalfd, which breaks when other
    // threads (e.g. reqwest workers) have SIGWINCH unblocked.

    let done_stdin = Arc::clone(&done);
    let detached_flag = Arc::clone(&detached);

    let stdin_handle = std::thread::spawn(move || {
        let stdin_fd = io::stdin().as_raw_fd();
        let mut buf = [0u8; 4096];

        // Detach-key state machine: tracks whether we just saw Ctrl-a.
        let mut saw_ctrl_a = false;

        // Track last known terminal size to detect resizes.
        let mut last_size = get_terminal_size().ok();

        loop {
            if done_stdin.load(Ordering::Relaxed) {
                break;
            }

            // Detect terminal resize by comparing current size to last known.
            let current_size = get_terminal_size().ok();
            if current_size != last_size {
                if let Some((cols, rows)) = current_size {
                    if outbound_tx.send(Outbound::Resize(cols, rows)).is_err() {
                        break;
                    }
                }
                last_size = current_size;
            }

            // Use poll(2) to wait for stdin with a short timeout so we
            // can re-check for resizes and the done flag periodically.
            let mut poll_fd = libc::pollfd {
                fd: stdin_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_ret = unsafe { libc::poll(&mut poll_fd, 1, 100) };
            if poll_ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            if poll_ret == 0 {
                continue;
            }

            let n = match unsafe {
                libc::read(stdin_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
            } {
                n if n > 0 => n as usize,
                0 => break,
                _ if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted => continue,
                _ => break,
            };

            let data = &buf[..n];
            trace!("stdin: read {n} bytes: {data:02x?}");

            // Process input through the detach-key state machine.
            let mut to_send = Vec::with_capacity(n + 1);
            for &byte in data {
                if saw_ctrl_a {
                    saw_ctrl_a = false;
                    if byte == DETACH_SUFFIX {
                        trace!("detach sequence complete");
                        detached_flag.store(true, Ordering::Relaxed);
                        done_stdin.store(true, Ordering::Relaxed);
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
                    trace!("detach prefix byte received");
                    saw_ctrl_a = true;
                } else {
                    to_send.push(byte);
                }
            }

            if detached_flag.load(Ordering::Relaxed) {
                break;
            }

            if !to_send.is_empty() && outbound_tx.send(Outbound::Data(to_send)).is_err() {
                break;
            }
        }
    });

    // -- WebSocket loop (main thread) -----------------------------------
    //
    // Owns the WebSocket. Alternates between:
    //  1. Trying to read a message (with a short timeout so we don't block)
    //  2. Draining outbound messages from the channel

    let mut stdout = io::stdout().lock();

    loop {
        if done.load(Ordering::Relaxed) {
            break;
        }

        // Try to read from the WebSocket. With the read timeout set,
        // this returns WouldBlock after ~50ms if no data arrives.
        match ws.read() {
            Ok(Message::Binary(data)) => {
                if !data.is_empty() && data[0] == MSG_DATA {
                    // Ignore write errors to stdout -- terminal may be gone.
                    let _ = stdout.write_all(&data[1..]);
                    let _ = stdout.flush();
                }
            }
            Ok(Message::Close(_)) => {
                break;
            }
            Ok(Message::Ping(_) | Message::Pong(_)) => {
                // Pings are auto-replied by tungstenite.
            }
            Ok(Message::Text(_) | Message::Frame(_)) => {}
            Err(tungstenite::Error::Io(ref e)) if e.kind() == io::ErrorKind::WouldBlock => {
                // Read timeout expired, fall through to drain outbound.
            }
            Err(tungstenite::Error::ConnectionClosed) | Err(tungstenite::Error::AlreadyClosed) => {
                break;
            }
            Err(_) => {
                break;
            }
        }

        // Drain all pending outbound messages.
        loop {
            match outbound_rx.try_recv() {
                Ok(Outbound::Data(data)) => {
                    let mut msg_buf = Vec::with_capacity(1 + data.len());
                    msg_buf.push(MSG_DATA);
                    msg_buf.extend_from_slice(&data);
                    if ws.send(Message::Binary(msg_buf.into())).is_err() {
                        done.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Ok(Outbound::Resize(cols, rows)) => {
                    let msg = resize_message(cols, rows);
                    if ws.send(Message::Binary(msg.into())).is_err() {
                        done.store(true, Ordering::Relaxed);
                        break;
                    }
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    done.store(true, Ordering::Relaxed);
                    break;
                }
            }
        }
    }

    done.store(true, Ordering::Relaxed);
    let _ = stdin_handle.join();

    // Best-effort close handshake.
    let _ = ws.close(None);

    // Terminal is restored by _guard's Drop.

    if detached.load(Ordering::Relaxed) {
        Ok(AttachOutcome::Detached)
    } else {
        Ok(AttachOutcome::SessionEnded)
    }
}

/// Set the read timeout on the TCP stream underlying the WebSocket.
fn set_read_timeout(
    ws: &WebSocket<MaybeTlsStream<std::net::TcpStream>>,
    timeout: Option<Duration>,
) -> Result<()> {
    match ws.get_ref() {
        MaybeTlsStream::Plain(tcp) => {
            tcp.set_read_timeout(timeout)
                .context("setting TCP read timeout")?;
        }
        _ => {
            return Err(anyhow::anyhow!("unexpected TLS stream for local WebSocket"));
        }
    }
    Ok(())
}
