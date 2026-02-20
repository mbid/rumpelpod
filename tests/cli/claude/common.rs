//! Common utilities for claude integration tests.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use indoc::formatdoc;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::common::{build_test_image, ImageId, TestDaemon, TestRepo, TEST_REPO_PATH};

use super::proxy::ClaudeTestProxy;

/// Resolve the host's claude CLI binary to its real path (following symlinks).
pub fn find_claude_binary() -> PathBuf {
    let output = Command::new("which")
        .arg("claude")
        .output()
        .expect("run `which claude`");

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    assert!(
        !path.is_empty(),
        "claude binary not found on host -- install Claude CLI first"
    );

    std::fs::canonicalize(&path).expect("resolve claude binary symlinks")
}

/// Build the test image with claude CLI and screen.
///
/// Copies the host's claude binary into the build context rather than
/// downloading it (Docker builds in this environment lack DNS).
pub fn build_claude_test_image(repo: &TestRepo) -> ImageId {
    let claude_binary = find_claude_binary();
    let claude_dest = repo.path().join("claude-cli-binary");
    std::fs::copy(&claude_binary, &claude_dest).expect("copy claude binary into build context");

    // Extra lines run after `USER testuser` from build_test_image.
    // Switch to root for package install + binary placement, then back.
    let extra = "\
USER root
RUN apt-get update && apt-get install -y screen
RUN mv /home/testuser/workspace/claude-cli-binary /usr/local/bin/claude \
    && chmod +x /usr/local/bin/claude
USER testuser";

    build_test_image(repo.path(), extra).expect("build claude test image")
}

/// Write devcontainer config that points at the given image and injects
/// the proxy's base URL into the container environment.
pub fn write_claude_test_config(repo: &TestRepo, image_id: &ImageId) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("create .devcontainer dir");

    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_id}",
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"],
            "remoteEnv": {{
                "ANTHROPIC_BASE_URL": "${{localEnv:ANTHROPIC_BASE_URL}}"
            }}
        }}
    "#};

    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("write devcontainer.json");

    std::fs::write(repo.path().join(".rumpelpod.toml"), "").expect("write .rumpelpod.toml");
}

/// Build the image, write config, and start a daemon -- everything needed
/// before running a claude command.
pub fn setup_claude_test_repo(proxy: &ClaudeTestProxy) -> (TestRepo, TestDaemon) {
    let _ = proxy; // used only to ensure the proxy is started first
    let repo = TestRepo::new();
    let image_id = build_claude_test_image(&repo);
    write_claude_test_config(&repo, &image_id);
    let daemon = TestDaemon::start();
    (repo, daemon)
}

// Tall enough to hold long responses without scrolling off, normal width.
const PTY_ROWS: u16 = 500;
const PTY_COLS: u16 = 80;

/// How often to dump the screen contents while waiting.
const SCREEN_DUMP_INTERVAL: Duration = Duration::from_secs(5);

/// An interactive Claude CLI session running inside a container PTY.
///
/// Uses a vt100 terminal emulator to parse raw escape sequences and
/// provide rendered screen contents rather than raw byte matching.
pub struct ClaudeSession {
    child: Box<dyn portable_pty::Child + Send + Sync>,
    rx: mpsc::Receiver<Vec<u8>>,
    parser: vt100::Parser,
    writer: Box<dyn Write + Send>,
    /// Raw bytes received from the PTY, kept for diagnostics on failure.
    raw_log: Vec<u8>,
}

impl ClaudeSession {
    /// Spawn `rumpel claude test` inside a PTY.
    ///
    /// Omitting `--dangerously-skip-permissions-hook` causes rumpel to
    /// pass `--dangerously-skip-permissions` directly to the claude CLI,
    /// which also suppresses the workspace trust dialog.
    ///
    /// `claude_args` are appended after `--` and forwarded to the
    /// claude CLI inside the container.
    pub fn spawn(
        repo: &TestRepo,
        daemon: &TestDaemon,
        proxy: &ClaudeTestProxy,
        model: &str,
        claude_args: &[&str],
    ) -> Self {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: PTY_ROWS,
                cols: PTY_COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("create PTY");

        // Note: we intentionally do NOT set the PTY to raw mode here.
        // Docker exec -it sets raw mode on its stdin (our PTY slave) when
        // it starts, so our settings would be overwritten anyway.

        let mut cmd = CommandBuilder::new("rumpel");
        cmd.cwd(repo.path());
        cmd.env(
            "RUMPELPOD_DAEMON_SOCKET",
            daemon.socket_path.to_str().unwrap(),
        );
        cmd.env(
            "ANTHROPIC_BASE_URL",
            format!("http://{}:{}", proxy.addr, proxy.port),
        );

        if std::env::var("RUMPELPOD_TEST_LLM_OFFLINE").is_err() {
            cmd.env("RUMPELPOD_TEST_LLM_OFFLINE", "1");
        }

        cmd.args(["claude", "test", "--", "--model", model]);
        for arg in claude_args {
            cmd.arg(arg);
        }

        let child = pair.slave.spawn_command(cmd).expect("spawn rumpel claude");

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

        ClaudeSession {
            child,
            rx,
            parser,
            writer,
            raw_log: Vec::new(),
        }
    }

    /// Block until `needle` appears in the rendered terminal screen.
    ///
    /// Returns the full screen contents at the moment the needle was found.
    /// Panics if the PTY closes before the needle appears.  Does not
    /// enforce its own timeout -- the caller or test harness is
    /// responsible for aborting hung tests.
    ///
    /// Periodically dumps the screen contents so failures are debuggable.
    pub fn wait_for(&mut self, needle: &str) -> String {
        let mut last_dump = Instant::now();

        loop {
            match self.rx.recv_timeout(SCREEN_DUMP_INTERVAL) {
                Ok(bytes) => {
                    self.raw_log.extend_from_slice(&bytes);
                    self.parser.process(&bytes);
                    // Drain any additional buffered chunks before checking,
                    // so we don't miss text split across sends.
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

    pub fn dump_screen(&self, waiting_for: &str) {
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
    ///
    /// Waits for the TUI to echo the text on screen before submitting,
    /// so callers do not need arbitrary sleeps between send and wait_for.
    pub fn send(&mut self, text: &str) {
        self.writer
            .write_all(text.as_bytes())
            .expect("write to PTY");
        self.writer.flush().expect("flush PTY writer");

        // Wait until the TUI has rendered the typed text.  Use a short
        // suffix to handle terminal line-wrapping (which inserts newlines
        // into screen contents).
        let needle_len = text.len().min(40);
        let needle = &text[text.len() - needle_len..];
        self.wait_for(needle);

        self.writer.write_all(b"\r").expect("write Enter to PTY");
        self.writer.flush().expect("flush PTY writer");
    }
}

impl Drop for ClaudeSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}
