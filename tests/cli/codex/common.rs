//! Common utilities for codex integration tests.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use indoc::formatdoc;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::common::{write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

/// Write a devcontainer that has the codex CLI installed.
fn write_codex_test_devcontainer(repo: &TestRepo) {
    // Download a pre-built codex binary from the GitHub release.
    // The exact URL and version will need to be updated as new
    // releases are published.
    let extra_dockerfile = formatdoc! {r#"
        RUN apt-get update && apt-get install -y curl
        RUN ARCH=$(dpkg --print-architecture) && \
            case "$ARCH" in \
                amd64) CODEX_ARCH="x86_64-unknown-linux-gnu" ;; \
                arm64) CODEX_ARCH="aarch64-unknown-linux-gnu" ;; \
                *) echo "unsupported arch: $ARCH" && exit 1 ;; \
            esac && \
            curl -fsSL "https://github.com/openai/codex/releases/latest/download/codex-$CODEX_ARCH.tar.gz" \
            | tar xz -C /usr/local/bin
    "#};

    write_test_devcontainer(repo, &extra_dockerfile, "");
}

/// Write controlled codex credentials into the test home directory.
///
/// Reads the OpenAI API key from the OPENAI_API_KEY env var.
fn setup_controlled_home(home: &TestHome) {
    let api_key = std::env::var("OPENAI_API_KEY")
        .expect("OPENAI_API_KEY must be set to run codex integration tests");

    let codex_dir = home.path().join(".codex");
    std::fs::create_dir_all(&codex_dir).expect("create .codex dir");
    std::fs::write(
        codex_dir.join("auth.json"),
        format!(r#"{{"auth_mode":"api_key","OPENAI_API_KEY":"{api_key}"}}"#),
    )
    .expect("write auth.json");
}

/// Set up everything needed before running a codex command.
///
/// Returns in the correct drop order: home must outlive executor and daemon.
pub fn setup_codex_test_repo(
    test_name: &str,
) -> (TestHome, TestRepo, ExecutorResources, TestDaemon) {
    let repo = TestRepo::new();
    write_codex_test_devcontainer(&repo);

    let home = TestHome::new();
    setup_controlled_home(&home);
    let executor = ExecutorResources::setup(&home, test_name);
    let daemon = TestDaemon::start(&home);
    std::fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml)
        .expect("write .rumpelpod.toml");
    (home, repo, executor, daemon)
}

// Tall enough to hold long responses without scrolling off, normal width.
const PTY_ROWS: u16 = 500;
const PTY_COLS: u16 = 80;

/// How often to dump the screen contents while waiting.
const SCREEN_DUMP_INTERVAL: Duration = Duration::from_secs(5);

/// An interactive Codex session running via `rumpel codex`.
///
/// Uses a vt100 terminal emulator to parse raw escape sequences and
/// provide rendered screen contents rather than raw byte matching.
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
        // The codex command reads OPENAI_API_KEY to write credentials
        // into the container.
        cmd.env(
            "OPENAI_API_KEY",
            std::env::var("OPENAI_API_KEY").expect("OPENAI_API_KEY must be set"),
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
