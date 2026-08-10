// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use rumpelpod::daemon::protocol::{DaemonClient, DaemonEvent};
use rumpelpod::CommandExt as RumpelCommandExt;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

#[test]
fn events_report_pod_status_and_commit_after_user_post_receive_hook() {
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

    let client = DaemonClient::new_unix(&daemon.socket_path);
    let mut events = client.daemon_events().expect("subscribe to daemon events");
    assert_eq!(
        events
            .next()
            .expect("receive initial event")
            .expect("read initial event"),
        DaemonEvent::Resync
    );
    let (event_tx, event_rx) = mpsc::channel();
    std::thread::spawn(move || {
        for event in events {
            if event_tx.send(event).is_err() {
                return;
            }
        }
    });
    let wait_for_event = |expected: DaemonEvent| {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            assert!(
                Instant::now() < deadline,
                "timed out waiting for daemon event: {expected:?}"
            );
            let remaining = deadline.saturating_duration_since(Instant::now());
            let event = event_rx
                .recv_timeout(remaining)
                .expect("receive daemon event")
                .expect("read daemon event");
            if event == expected {
                return;
            }
        }
    };

    let pod_name = "event-commit";
    pod_command(&repo, &daemon)
        .args(["enter", "--create", pod_name, "--", "echo", "setup"])
        .success()
        .expect("launch test pod");
    wait_for_event(DaemonEvent::PodStatusChanged {
        repository: repo.path().to_string_lossy().into_owned(),
        pod: pod_name.to_string(),
    });

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

    wait_for_event(DaemonEvent::PodReviewChanged {
        repository: repo.path().to_string_lossy().into_owned(),
        pod: pod_name.to_string(),
    });

    assert!(
        repo.path().join(".git/user-post-receive-ran").exists(),
        "rumpelpod post-receive hook prevented the user hook"
    );
}
