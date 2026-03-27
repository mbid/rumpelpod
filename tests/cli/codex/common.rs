//! Common utilities for codex integration tests.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::common::{TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

/// Write controlled codex credentials into the test home directory.
///
/// Reads the OpenAI API key from the OPENAI_API_KEY env var and writes
/// a ~/.codex/auth.json, emulating a user who ran `codex login`.
fn setup_controlled_home(home: &TestHome) {
    let api_key = std::env::var("OPENAI_API_KEY")
        .expect("OPENAI_API_KEY must be set to run codex integration tests");

    let codex_dir = home.path().join(".codex");
    std::fs::create_dir_all(&codex_dir).expect("create .codex dir");
    std::fs::write(
        codex_dir.join("auth.json"),
        format!(r#"{{"auth_mode":"apikey","OPENAI_API_KEY":"{api_key}"}}"#),
    )
    .expect("write auth.json");
}

/// Set up everything needed before running a codex command.
///
/// Uses `start_with_host_llm_clis` so the daemon can detect the host
/// codex binary and install it via prepare-image.
pub fn setup_codex_test_repo(
    test_name: &str,
) -> (TestHome, TestRepo, ExecutorResources, TestDaemon) {
    let repo = TestRepo::new();
    // No extra devcontainer setup -- the codex binary is installed
    // by prepare-image when the daemon detects it on the host.
    crate::common::write_test_devcontainer(&repo, "", "");

    let home = TestHome::new();
    setup_controlled_home(&home);
    let executor = ExecutorResources::setup(&home, test_name);
    let daemon = TestDaemon::start_with_host_llm_clis(&home);
    std::fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml)
        .expect("write .rumpelpod.toml");
    (home, repo, executor, daemon)
}

const PTY_ROWS: u16 = 500;
const PTY_COLS: u16 = 80;
const SCREEN_DUMP_INTERVAL: Duration = Duration::from_secs(5);

/// An interactive Codex session running via `rumpel codex`.
pub struct CodexSession {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    rx: mpsc::Receiver<Vec<u8>>,
    parser: vt100::Parser,
    writer: Box<dyn Write + Send>,
    raw_log: Vec<u8>,
}

impl CodexSession {
    /// Spawn `rumpel codex test` inside a PTY.
    pub fn spawn(repo: &TestRepo, daemon: &TestDaemon, home: &Path, codex_args: &[&str]) -> Self {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: PTY_ROWS,
                cols: PTY_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("create PTY");

        let mut cmd = CommandBuilder::new("rumpel");
        cmd.env_clear();
        cmd.cwd(repo.path());
        cmd.env("PATH", std::env::var("PATH").expect("PATH must be set"));
        cmd.env("HOME", home.to_str().unwrap());
        cmd.env(
            "RUMPELPOD_DAEMON_SOCKET",
            daemon.socket_path.to_str().unwrap(),
        );

        cmd.args(["codex", "test"]);
        if !codex_args.is_empty() {
            cmd.arg("--");
            for arg in codex_args {
                cmd.arg(arg);
            }
        }

        let child = pair.slave.spawn_command(cmd).expect("spawn rumpel codex");

        let mut reader = pair.master.try_clone_reader().expect("clone PTY reader");
        let writer = pair.master.take_writer().expect("take PTY writer");

        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(n) = reader.read(&mut buffer) {
                if n == 0 {
                    break;
                }
                if tx.send(buffer[..n].to_vec()).is_err() {
                    break;
                }
            }
        });

        let parser = vt100::Parser::new(PTY_ROWS, PTY_COLS, 0);

        CodexSession {
            child,
            rx,
            parser,
            writer,
            raw_log: Vec::new(),
        }
    }

    /// Block until `needle` appears in the rendered terminal screen.
    pub fn wait_for(&mut self, needle: &str) -> String {
        let mut last_dump = Instant::now();

        loop {
            match self.rx.recv_timeout(SCREEN_DUMP_INTERVAL) {
                Ok(bytes) => {
                    self.raw_log.extend_from_slice(&bytes);
                    self.parser.process(&bytes);
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
                    last_dump = Instant::now();
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

    /// Dismiss startup dialogs by pressing Enter until we reach the
    /// main input prompt (not on the alternate screen).
    pub fn dismiss_dialogs(&mut self) {
        loop {
            self.wait_for("\u{203a}");

            while let Ok(bytes) = self.rx.try_recv() {
                self.raw_log.extend_from_slice(&bytes);
                self.parser.process(&bytes);
            }

            if !self.parser.screen().alternate_screen() {
                break;
            }

            self.writer.write_all(b"\r").expect("write Enter");
            self.writer.flush().expect("flush");
        }
    }

    fn dump_screen(&self, waiting_for: &str) {
        let screen = self.parser.screen();
        let contents = screen.contents();
        let trimmed = contents.trim();
        let alt = screen.alternate_screen();
        let (cur_row, cur_col) = screen.cursor_position();
        eprintln!(
            "[wait_for {:?}] alt_screen={} cursor=({},{}) screen:\n{}",
            waiting_for, alt, cur_row, cur_col, trimmed
        );
    }

    /// Type text into the prompt and press Enter.
    pub fn send(&mut self, text: &str) {
        self.writer
            .write_all(text.as_bytes())
            .expect("write to PTY");
        self.writer.flush().expect("flush PTY writer");

        let needle_len = text.len().min(40);
        let needle = &text[text.len() - needle_len..];
        self.wait_for(needle);

        self.writer.write_all(b"\r").expect("write Enter to PTY");
        self.writer.flush().expect("flush PTY writer");
    }
}

impl Drop for CodexSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
