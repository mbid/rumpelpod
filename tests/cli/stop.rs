//! Integration tests for the `rumpel stop` subcommand (multi-pod support).

use std::fs;
use std::time::Duration;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::{executor_supports_stop, ExecutorResources};

#[test]
fn stop_multiple_pods() {
    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "stop-multi");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Create three pods
    for name in ["sm-a", "sm-b", "sm-c"] {
        let output = pod_command(&repo, &daemon)
            .args(["enter", name, "--", "true"])
            .output()
            .expect("Failed to run rumpel enter");
        assert!(
            output.status.success(),
            "creating pod '{name}' failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Stop all three in one command
    let output = pod_command(&repo, &daemon)
        .args(["stop", "--wait", "sm-a", "sm-b", "sm-c"])
        .output()
        .expect("Failed to run rumpel stop");
    assert!(
        output.status.success(),
        "multi-stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify all are stopped
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["sm-a", "sm-b", "sm-c"] {
        let line = stdout
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("pod '{name}' should still be listed: {stdout}"));
        assert!(
            line.contains("stopped"),
            "pod '{name}' should be stopped: {line}"
        );
    }
}

#[test]
fn stop_multiple_continues_past_unknown() {
    // When one pod in a multi-stop does not exist, the others should
    // still be stopped and the command should report the failure.
    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "stop-unknown");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Create two pods
    for name in ["su-a", "su-c"] {
        let output = pod_command(&repo, &daemon)
            .args(["enter", name, "--", "true"])
            .output()
            .expect("Failed to run rumpel enter");
        assert!(output.status.success());
    }

    // Stop with a nonexistent pod in the middle
    let output = pod_command(&repo, &daemon)
        .args(["stop", "--wait", "su-a", "no-such-pod", "su-c"])
        .output()
        .expect("Failed to run rumpel stop");

    // Command should fail overall because one pod was unknown
    assert!(
        !output.status.success(),
        "should fail when a pod is unknown"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("1 pod(s) could not be stopped"),
        "should report failure count: {stderr}"
    );

    // The other two should still have been stopped
    let output = pod_command(&repo, &daemon)
        .arg("list")
        .output()
        .expect("Failed to list");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in ["su-a", "su-c"] {
        let line = stdout
            .lines()
            .find(|l| l.contains(name))
            .unwrap_or_else(|| panic!("pod '{name}' should still be listed: {stdout}"));
        assert!(
            line.contains("stopped"),
            "pod '{name}' should be stopped despite the unknown one: {line}"
        );
    }
}

/// A client subscribed to pod reconnect events must receive a Stopped
/// event when the pod is intentionally stopped, rather than retrying
/// forever.
#[test]
fn stop_sends_reconnect_stopped_event() {
    use rumpelpod::daemon::protocol::DaemonClient;
    use rumpelpod::daemon::reconnect::ReconnectEvent;

    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "stop-reconnect");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let pod_name = "stop-ev";
    let output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "true"])
        .output()
        .expect("Failed to run rumpel enter");
    assert!(
        output.status.success(),
        "creating pod failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Subscribe to reconnect events before stopping.  The daemon's pod
    // event listener is running, so subscribe() returns a receiver.
    let socket_path = daemon.socket_path.clone();
    let repo_path = repo.path().to_path_buf();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let client = DaemonClient::new_unix(&socket_path);
        let stream = client
            .pod_reconnect_events(&repo_path, pod_name)
            .expect("pod_reconnect_events failed");
        for event in stream {
            let event = event.expect("error reading reconnect event");
            let done = matches!(event, ReconnectEvent::Stopped | ReconnectEvent::Connected);
            let _ = tx.send(event);
            if done {
                break;
            }
        }
    });

    // Stop the pod -- the subscriber should get a Stopped event.
    let output = pod_command(&repo, &daemon)
        .args(["stop", "--wait", pod_name])
        .output()
        .expect("Failed to run rumpel stop");
    assert!(
        output.status.success(),
        "stop failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let event = rx
        .recv_timeout(Duration::from_secs(30))
        .expect("no event from reconnect stream after stop");
    assert!(
        matches!(event, ReconnectEvent::Stopped),
        "expected Stopped event, got {event:?}"
    );
}

/// When a pod has already been stopped, subscribing to its reconnect
/// events must immediately return a Stopped event (no active listener).
#[test]
fn stop_reconnect_after_stop() {
    use rumpelpod::daemon::protocol::DaemonClient;
    use rumpelpod::daemon::reconnect::ReconnectEvent;

    if !executor_supports_stop() {
        return;
    }
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "stop-reconnect-after");
    let daemon = TestDaemon::start(&home);
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    let pod_name = "stop-after";
    let output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "true"])
        .output()
        .expect("Failed to run rumpel enter");
    assert!(output.status.success());

    // Stop the pod first.
    let output = pod_command(&repo, &daemon)
        .args(["stop", "--wait", pod_name])
        .output()
        .expect("Failed to run rumpel stop");
    assert!(output.status.success());

    // Now subscribe -- the listener is already gone, so the endpoint
    // should return a Stopped event immediately.
    let client = DaemonClient::new_unix(&daemon.socket_path);
    let stream = client
        .pod_reconnect_events(repo.path(), pod_name)
        .expect("pod_reconnect_events failed");

    let event = stream
        .into_iter()
        .next()
        .expect("stream should have at least one event")
        .expect("error reading reconnect event");
    assert!(
        matches!(event, ReconnectEvent::Stopped),
        "expected Stopped event, got {event:?}"
    );
}
