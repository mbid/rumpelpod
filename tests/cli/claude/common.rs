//! Common utilities for claude integration tests.

use std::io::{Read, Write};
use std::path::Path;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use indoc::formatdoc;
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use tempfile::TempDir;

use crate::common::{build_test_image, ImageId, TestDaemon, TestRepo, TEST_REPO_PATH};
use crate::executor::{executor_mode, ExecutorMode, TestPod};

use super::proxy::ClaudeTestProxy;

/// Pinned Claude Code version for deterministic tests.
const CLAUDE_CODE_VERSION: &str = "2.1.63";

/// Fixed date injected via a Node.js Date override (see build_claude_test_image).
/// Ensures prompts that include the current date produce stable cache keys.
const FAKE_DATE: &str = "2026-02-01 00:00:00";

/// JS module that shifts Date.now() so `new Date()` returns FAKE_DATE.
///
/// Only overrides JavaScript's Date object, not system clocks, so
/// Node.js timers and I/O work normally (unlike libfaketime's
/// LD_PRELOAD approach which breaks libuv's event loop).
/// Time still advances -- only the epoch is shifted.
const FAKETIME_JS: &str = indoc::indoc! {r#"
    const _Date = globalThis.Date;
    const _off = new _Date('FAKE_DATE_PLACEHOLDER').getTime() - _Date.now();
    function F(...a) {
      if (!new.target) return new _Date(_Date.now()+_off).toString();
      return a.length ? new _Date(...a) : new _Date(_Date.now()+_off);
    }
    F.prototype = _Date.prototype;
    F.now = () => _Date.now() + _off;
    F.parse = _Date.parse;
    F.UTC = _Date.UTC;
    Object.defineProperty(F,Symbol.hasInstance,{value:o=>o instanceof _Date});
    globalThis.Date = F;
"#};

/// npm registry URL for the pinned Claude Code version.
fn claude_code_tarball_url() -> String {
    format!("https://registry.npmjs.org/@anthropic-ai/claude-code/-/claude-code-{CLAUDE_CODE_VERSION}.tgz")
}

/// Build the test image with a pinned Claude CLI version and fake date.
///
/// Downloads the pinned npm package directly inside the Docker build
/// (which has network access for apt-get anyway) and extracts it
/// without npm -- only the node runtime is needed.  Omitting npm also
/// prevents Claude CLI's background `npm view` update check.
/// Overrides JavaScript's Date via NODE_OPTIONS so the CLI always
/// reports a fixed date in prompts (libfaketime breaks Node.js's
/// event loop).
pub fn build_claude_test_image(repo: &TestRepo) -> ImageId {
    let tarball_url = claude_code_tarball_url();
    let faketime_js = FAKETIME_JS.replace("FAKE_DATE_PLACEHOLDER", FAKE_DATE);

    // nodejs without npm: the CLI only needs the node runtime, and
    // omitting npm prevents claude's background `npm view` update
    // check from running inside the container.
    let extra = formatdoc! {r#"
        USER root
        RUN apt-get update && apt-get install -y nodejs curl
        RUN curl -fsSL "{tarball_url}" \
            | tar xz -C /usr/local/lib --transform='s,^package,claude-code,' \
            && ln -s /usr/local/lib/claude-code/cli.js /usr/local/bin/claude \
            && chmod +x /usr/local/lib/claude-code/cli.js
        COPY faketime.js /opt/faketime.js
        ENV NODE_OPTIONS="--require /opt/faketime.js"
        USER testuser
    "#};

    // Write the JS into the build context so the COPY picks it up.
    std::fs::write(repo.path().join("faketime.js"), &faketime_js)
        .expect("write faketime.js to build context");

    build_test_image(repo.path(), &extra).expect("build claude test image")
}

/// Write devcontainer config that points at the given image and injects
/// the proxy's base URL into the container environment.
///
/// Only writes devcontainer.json; .rumpelpod.toml is handled by TestPod.
fn write_claude_test_config(repo: &TestRepo, image_ref: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("create .devcontainer dir");

    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_ref}",
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
}

/// Create a temp directory that acts as HOME for the test process.
///
/// Contains only the minimal config files needed for `copy_claude_config`
/// in the daemon, so tests don't depend on the real user's Claude config.
/// Includes fake OAuth credentials so the CLI considers the user "logged
/// in" without needing the host's real tokens.
fn create_controlled_home() -> TempDir {
    let home =
        TempDir::with_prefix("rumpelpod-claude-home-").expect("create controlled HOME temp dir");

    // Minimal .claude.json: skip onboarding and accept bypass mode.
    // strip_claude_json in the daemon will add per-project trust entries.
    std::fs::write(
        home.path().join(".claude.json"),
        r#"{"hasCompletedOnboarding":true,"lastOnboardingVersion":"999.0.0","bypassPermissionsModeAccepted":true}"#,
    )
    .expect("write controlled .claude.json");

    let claude_dir = home.path().join(".claude");
    std::fs::create_dir(&claude_dir).expect("create controlled .claude dir");
    std::fs::write(claude_dir.join("settings.json"), "{}").expect("write controlled settings.json");

    // The Claude CLI refuses to make API calls unless it sees OAuth
    // credentials (it shows "Not logged in" otherwise).  Provide fake
    // tokens with a far-future expiry so the CLI skips token refresh.
    // The proxy replaces the auth header before forwarding to the real
    // API, so these dummy values never reach Anthropic.
    std::fs::write(
        claude_dir.join(".credentials.json"),
        r#"{"claudeAiOauth":{"accessToken":"sk-ant-oat01-fake-test-token-AAAAAAAAAAAAAAAAAA-BBBBBBBBBBBBBBBBBBB-CCCCCCCCCCCCCCCCCCCCCCCC","refreshToken":"sk-ant-ort01-fake-test-token-AAAAAAAAAAAAAAAAAA-BBBBBBBBBBBBBBBBBBB-CCCCCCCCCCCCCCCCCCCCCCCC","expiresAt":4102444800000,"scopes":["user:inference"],"subscriptionType":"max","rateLimitTier":"default_claude_max_5x"}}"#,
    )
    .expect("write controlled .credentials.json");

    // On k8s, the daemon needs kubeconfig to talk to the cluster.
    // Copy it from the real HOME into the fake one.
    let real_kube = std::path::PathBuf::from(std::env::var("HOME").expect("HOME must be set"))
        .join(".kube/config");
    if let Ok(kubeconfig) = std::fs::read(&real_kube) {
        let kube_dir = home.path().join(".kube");
        std::fs::create_dir_all(&kube_dir).expect("create .kube dir");
        std::fs::write(kube_dir.join("config"), kubeconfig).expect("write kubeconfig");
    }

    home
}

/// Build the image, write config, and start a daemon -- everything needed
/// before running a claude command.
///
/// Returns the controlled HOME temp dir alongside the repo and pod so
/// it is not dropped (and cleaned up) before the test finishes.
pub fn setup_claude_test_repo(
    proxy: &ClaudeTestProxy,
    test_name: &str,
) -> (TestRepo, TestPod, TempDir) {
    let _ = proxy; // used only to ensure the proxy is started first
    let repo = TestRepo::new();
    let image_id = build_claude_test_image(&repo);

    // On k8s the local Docker image must be pushed to the in-cluster
    // registry; write devcontainer.json with the registry reference.
    let image_ref = match executor_mode() {
        ExecutorMode::K8s => {
            let cluster = crate::k8s::k8s_cluster_config();
            crate::k8s::push_image(&cluster, &image_id, test_name)
        }
        ExecutorMode::Docker | ExecutorMode::Ssh => image_id.to_string(),
    };
    write_claude_test_config(&repo, &image_ref);

    // Create the controlled home before starting the pod so
    // copy_claude_config (which runs in the daemon) reads our files.
    let fake_home = create_controlled_home();
    let pod = TestPod::start_build_with_home(&repo, test_name, fake_home.path());
    (repo, pod, fake_home)
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
        home: &Path,
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
        cmd.env_clear();
        cmd.cwd(repo.path());
        // PATH is needed so rumpel can find git, docker, etc.
        cmd.env("PATH", std::env::var("PATH").expect("PATH must be set"));
        cmd.env("HOME", home.to_str().unwrap());
        cmd.env(
            "RUMPELPOD_DAEMON_SOCKET",
            daemon.socket_path.to_str().unwrap(),
        );
        // Forwarded into the container via ${localEnv:ANTHROPIC_BASE_URL}
        // in devcontainer.json.
        cmd.env(
            "ANTHROPIC_BASE_URL",
            format!("http://{}:{}", proxy.addr, proxy.port),
        );

        cmd.env(
            "RUMPELPOD_TEST_LLM_OFFLINE",
            std::env::var("RUMPELPOD_TEST_LLM_OFFLINE").unwrap_or_else(|_| "1".to_string()),
        );

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

    /// Write raw bytes to the PTY without waiting for echo or pressing Enter.
    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).expect("write raw to PTY");
        self.writer.flush().expect("flush PTY writer");
    }

    /// Wait for the child process to exit.  Returns once the PTY reader
    /// disconnects (child exited) and the process has been reaped.
    pub fn wait_for_exit(&mut self) {
        // Drain the PTY reader until it disconnects.
        loop {
            match self.rx.recv_timeout(Duration::from_secs(10)) {
                Ok(bytes) => {
                    self.raw_log.extend_from_slice(&bytes);
                    self.parser.process(&bytes);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    panic!("timed out waiting for child to exit");
                }
            }
        }
        // Reap the child so the exit status is collected.
        if let Err(e) = self.child.wait() {
            eprintln!("warning: failed to wait for child: {e}");
        }
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
