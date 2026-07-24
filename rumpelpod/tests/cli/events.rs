// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::process::{Child, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rumpelpod::daemon::protocol::DaemonEvent;
use rumpelpod::CommandExt as RumpelCommandExt;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

struct EventProcess {
    child: Child,
}

impl Drop for EventProcess {
    fn drop(&mut self) {
        if let Err(error) = self.child.kill() {
            eprintln!("stopping rumpel events failed: {error}");
        }
        if let Err(error) = self.child.wait() {
            eprintln!("waiting for rumpel events failed: {error}");
        }
    }
}

#[test]
fn events_reports_pod_commit_after_user_post_receive_hook() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    std::fs::write(repo.path().join(".rumpelpod.json"), &executor.json)
        .expect("write rumpelpod config");

    let hook_path = repo.path().join(".git/hooks/post-receive");
    std::fs::write(
        &hook_path,
        "#!/bin/sh\nprintf 'ran\\n' > \"$GIT_DIR/user-post-receive-ran\"\nexit 0\n",
    )
    .expect("write user post-receive hook");
    let mut permissions = std::fs::metadata(&hook_path)
        .expect("read user hook metadata")
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(&hook_path, permissions).expect("make user hook executable");

    let pod_name = "event-commit";
    pod_command(&repo, &daemon)
        .args(["enter", "--create", pod_name, "--", "echo", "setup"])
        .success()
        .expect("launch test pod");

    let mut child = pod_command(&repo, &daemon);
    let mut child = child
        .args(["events", "--json"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("start rumpel events");
    let stdout = child.stdout.take().expect("rumpel events stdout");
    let _events = EventProcess { child };
    let (line_tx, line_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if line_tx.send(line).is_err() {
                return;
            }
        }
    });

    let initial = line_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("receive initial daemon event")
        .expect("read initial daemon event");
    assert_eq!(
        serde_json::from_str::<DaemonEvent>(&initial).expect("parse initial daemon event"),
        DaemonEvent::Resync
    );

    pod_command(&repo, &daemon)
        .args([
            "enter",
            "--create",
            pod_name,
            "--",
            "git",
            "commit",
            "--no-verify",
            "--allow-empty",
            "-m",
            "Event commit",
        ])
        .success()
        .expect("commit in pod");

    let expected = DaemonEvent::PodReviewChanged {
        repository: repo.path().to_string_lossy().into_owned(),
        pod: pod_name.to_string(),
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = line_rx
            .recv_timeout(remaining)
            .expect("receive pod review event")
            .expect("read pod review event");
        let event: DaemonEvent = serde_json::from_str(&line).expect("parse pod review event");
        if event == expected {
            break;
        }
    }

    assert!(
        repo.path().join(".git/user-post-receive-ran").exists(),
        "rumpelpod post-receive hook prevented the user hook"
    );
}
