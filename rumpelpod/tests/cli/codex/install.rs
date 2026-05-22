// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that `rumpel codex` installs the Codex CLI into the prepared
//! image based on the binary the client resolves on the local machine,
//! not the one the daemon happens to find on its own PATH.

use std::fs;
use std::io::Read;
use std::process::Command;
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{native_pty_system, CommandBuilder, PtySize};

use crate::common::{write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

/// The client resolves the codex binary path and sends it to the
/// daemon, so the prepared image includes Codex CLI even though the
/// daemon itself cannot find the binary on its own PATH.
///
/// Mirrors `image_includes_claude_from_client_path` but actually
/// launches codex inside the container and waits for the welcome
/// banner: that proves the binary not only got installed but also
/// runs end-to-end.
#[test]
fn image_includes_codex_from_client_path() {
    println!("xtest:timeout=145");
    assert!(
        Command::new("codex")
            .arg("--version")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success()),
        "codex must be in PATH to run this test",
    );

    let repo = TestRepo::new();
    write_test_devcontainer(&repo, "", "");
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    // Daemon's bin dir does not contain codex: verifies the daemon
    // cannot detect the local machine's CLI on its own.
    let daemon = TestDaemon::start(&home);
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    // Give only the client a view of the local machine's `codex` so
    // find_local_codex_cli picks it up but the daemon does not.
    let client_only = home.client_only_bin_dir(&["codex"]);
    let client_path = format!("{}:{}", client_only.display(), daemon.bin_dir.display());

    let pty = native_pty_system()
        .openpty(PtySize {
            rows: 50,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("openpty");

    let mut cmd = CommandBuilder::new("rumpel");
    cmd.env_clear();
    cmd.cwd(repo.path());
    cmd.env("PATH", &client_path);
    cmd.env("HOME", home.path().to_str().unwrap());
    cmd.env(
        "RUMPELPOD_DAEMON_SOCKET",
        daemon.socket_path.to_str().unwrap(),
    );
    cmd.args([
        "enter",
        "--create",
        "codex-install-test",
        "--",
        "/opt/rumpelpod/bin/codex",
    ]);
    let mut child = pty.slave.spawn_command(cmd).expect("spawn rumpel enter");

    let mut reader = pty.master.try_clone_reader().expect("clone PTY reader");
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

    // The TUI lays text out via cursor-positioning escapes, so the
    // rendered screen contents are the only reliable place to look
    // for the welcome banner -- the words never appear contiguously
    // in the raw byte stream.  "Press enter to continue" is the
    // last line rendered, so seeing it means the welcome screen
    // has fully painted.
    let mut parser = vt100::Parser::new(50, 120, 0);
    let needle = "Press enter to continue";
    let deadline = Instant::now() + Duration::from_secs(140);
    let found = loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break false;
        }
        match rx.recv_timeout(remaining.min(Duration::from_secs(2))) {
            Ok(bytes) => {
                parser.process(&bytes);
                if parser.screen().contents().contains(needle) {
                    break true;
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break false,
        }
    };

    let _ = child.kill();
    let _ = child.wait();

    assert!(
        found,
        "codex did not display {needle:?} within the timeout. Rendered screen:\n{}",
        parser.screen().contents(),
    );
}
