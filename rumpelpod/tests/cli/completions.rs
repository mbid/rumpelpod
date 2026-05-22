// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use rumpelpod::CommandExt;

use crate::common::{
    pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo, SOCKET_PATH_ENV,
};
use crate::executor::ExecutorResources;

const PTY_ROWS: u16 = 24;
const PTY_COLS: u16 = 120;

/// How often to dump the screen while waiting, so hangs are debuggable.
const SCREEN_DUMP_INTERVAL: Duration = Duration::from_secs(5);

/// Overall deadline for any single `wait_for` call.  Without this a
/// silent completion failure (e.g. completer returns zero candidates)
/// hangs the test runner forever; the per-test xtest timeout would
/// eventually fire, but a focused panic with the rendered screen is
/// far more useful for diagnosis.
const WAIT_FOR_TIMEOUT: Duration = Duration::from_secs(30);

const PROMPT: &str = "RTEST$ ";

/// An interactive bash session running inside a PTY.
///
/// Uses a vt100 terminal emulator to parse escape sequences and provide
/// rendered screen contents rather than raw byte matching.
struct BashSession {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    rx: mpsc::Receiver<Vec<u8>>,
    parser: vt100::Parser,
    writer: Box<dyn Write + Send>,
    /// Raw bytes received from the PTY, kept for diagnostics on failure.
    raw_log: Vec<u8>,
}

impl BashSession {
    /// Spawn an interactive bash with completions pre-loaded.
    ///
    /// Sources `rumpel completions bash` and waits for the prompt
    /// before returning, so the caller can immediately start typing
    /// commands that use tab completion.
    ///
    /// `bin_dir` is the entire `$PATH` the bash process sees.
    fn spawn(cwd: &Path, home: &Path, bin_dir: &Path, daemon: Option<&TestDaemon>) -> Self {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: PTY_ROWS,
                cols: PTY_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("create PTY");

        let mut cmd = CommandBuilder::new("bash");
        cmd.args(["--norc", "--noprofile"]);
        cmd.cwd(cwd);
        cmd.env_clear();
        cmd.env("PATH", bin_dir);
        cmd.env("HOME", home);
        cmd.env("TERM", "xterm");
        if let Some(d) = daemon {
            cmd.env(SOCKET_PATH_ENV, d.socket_path.to_str().unwrap());
            // The production timeout is too tight for parallel test
            // load on a busy CI box; raise it just for the test.
            cmd.env("RUMPELPOD_COMPLETIONS_TIMEOUT_MS", "10000");
        }

        let child = pair.slave.spawn_command(cmd).expect("spawn bash");

        let mut reader = pair.master.try_clone_reader().expect("clone PTY reader");
        let writer = pair.master.take_writer().expect("take PTY writer");

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });

        let mut session = BashSession {
            child,
            rx,
            parser: vt100::Parser::new(PTY_ROWS, PTY_COLS, 0),
            writer,
            raw_log: Vec::new(),
        };

        // Bash may source /etc/bash.bashrc which sets its own PS1.
        // Override it to a known value we can reliably wait for.
        session.send(&format!("PS1='{PROMPT}'"));
        session.wait_for(PROMPT);

        // Source the completion registration script.
        session.send("eval \"$(rumpel completions bash)\"");
        session.wait_for(PROMPT);

        session
    }

    /// Block until `needle` appears in the rendered terminal screen.
    ///
    /// Panics if the PTY closes or [`WAIT_FOR_TIMEOUT`] elapses before
    /// the needle appears.  Periodically dumps the screen so hangs are
    /// debuggable.
    fn wait_for(&mut self, needle: &str) -> String {
        let deadline = Instant::now() + WAIT_FOR_TIMEOUT;
        let mut last_dump = Instant::now();

        loop {
            let now = Instant::now();
            if now >= deadline {
                let contents = self.parser.screen().contents();
                let raw = String::from_utf8_lossy(&self.raw_log);
                panic!(
                    "{:?} did not appear on screen within {:?}.\n\
                     Screen contents:\n{}\n\
                     Raw PTY bytes:\n{}",
                    needle, WAIT_FOR_TIMEOUT, contents, raw
                );
            }
            let recv_timeout = std::cmp::min(SCREEN_DUMP_INTERVAL, deadline - now);
            match self.rx.recv_timeout(recv_timeout) {
                Ok(bytes) => {
                    self.raw_log.extend_from_slice(&bytes);
                    self.parser.process(&bytes);
                    // Drain any additional buffered chunks before checking.
                    while let Ok(more) = self.rx.try_recv() {
                        self.raw_log.extend_from_slice(&more);
                        self.parser.process(&more);
                    }
                    let contents = self.parser.screen().contents();
                    if contents.contains(needle) {
                        return contents;
                    }
                    if last_dump.elapsed() >= SCREEN_DUMP_INTERVAL {
                        self.dump_screen(needle);
                        last_dump = Instant::now();
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.dump_screen(needle);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    let contents = self.parser.screen().contents();
                    let raw = String::from_utf8_lossy(&self.raw_log);
                    panic!(
                        "PTY closed before {:?} appeared on screen.\n\
                         Screen contents:\n{}\n\
                         Raw PTY bytes:\n{}",
                        needle, contents, raw
                    );
                }
            }
        }
    }

    fn dump_screen(&self, waiting_for: &str) {
        let screen = self.parser.screen();
        let contents = screen.contents();
        let trimmed = contents.trim();
        let (cur_row, cur_col) = screen.cursor_position();
        eprintln!(
            "[wait_for {:?}] cursor=({},{}) screen:\n{}",
            waiting_for, cur_row, cur_col, trimmed
        );
    }

    /// Type text and press Enter.
    fn send(&mut self, text: &str) {
        self.writer
            .write_all(text.as_bytes())
            .expect("write to PTY");
        self.writer.write_all(b"\r").expect("write Enter to PTY");
        self.writer.flush().expect("flush PTY writer");
    }

    /// Write raw bytes to the PTY (e.g. a Tab character for completion).
    fn write_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("write raw to PTY");
        self.writer.flush().expect("flush PTY writer");
    }
}

impl Drop for BashSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

/// Tab-completing a partial subcommand fills in the full name.
#[test]
fn bash_completes_subcommands() {
    let repo = TestRepo::new();
    let home = TestHome::new();

    let mut session = BashSession::spawn(repo.path(), home.path(), &home.bin_dir(), None);

    // "ent" uniquely matches "enter", so Tab should auto-complete it.
    session.write_raw(b"rumpel ent\t");
    session.wait_for("rumpel enter");
}

/// Tab-completing a pod name position offers names from the daemon.
#[test]
fn bash_completes_pod_names() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Create a pod so there is something to complete.
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "my-pod", "--", "true"])
        .success()
        .expect("failed to create pod");

    let mut session = BashSession::spawn(repo.path(), home.path(), &daemon.bin_dir, Some(&daemon));

    // "m" uniquely matches "my-pod" (flags start with "--"),
    // so Tab should auto-complete to "my-pod".
    session.write_raw(b"rumpel stop m\t");
    session.wait_for("my-pod");
}

/// Tab-completing cp's source argument offers local paths.
#[test]
fn bash_completes_cp_source_local_paths() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    fs::write(repo.path().join("local-source.txt"), "source").unwrap();

    let mut session = BashSession::spawn(repo.path(), home.path(), &home.bin_dir(), None);

    session.write_raw(b"rumpel cp local-s\t");
    session.wait_for("local-source.txt");
}

/// Tab-completing cp's destination argument offers local paths.
#[test]
fn bash_completes_cp_dest_local_paths() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    fs::create_dir(repo.path().join("local-dest")).unwrap();

    let mut session = BashSession::spawn(repo.path(), home.path(), &home.bin_dir(), None);

    session.write_raw(b"rumpel cp pod:/tmp/file local-d\t");
    session.wait_for("local-dest/");
}
