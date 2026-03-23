//! Integration tests for SSH agent forwarding in pods.

use std::fs;

use rumpelpod::CommandExt;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

/// Add a key to a pod's ssh-agent and verify it is usable from inside the
/// container via the relayed socket.
#[test]
fn ssh_add_and_list() {
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home, "ssh-agent");
    let daemon = TestDaemon::start(&home);
    let repo = TestRepo::new();

    // The base test image installs git, which pulls in openssh-client as a
    // dependency on Debian.  That gives us ssh-add inside the container.
    write_test_devcontainer(&repo, "", "");
    fs::write(repo.path().join(".rumpelpod.toml"), &executor.toml).unwrap();

    // Create the pod.
    pod_command(&repo, &daemon)
        .args(["enter", "ssh-test", "--", "true"])
        .success()
        .expect("failed to create pod");

    // Generate a throwaway ed25519 key on the host.
    let key_path = home.path().join("test_ed25519");
    std::process::Command::new("ssh-keygen")
        .args(["-t", "ed25519", "-f"])
        .arg(&key_path)
        .args(["-N", "", "-q"])
        .success()
        .expect("ssh-keygen failed");

    // Add the key via rumpel ssh.
    let stdout = pod_command(&repo, &daemon)
        .args(["ssh", "ssh-test", "add"])
        .arg(&key_path)
        .success()
        .expect("rumpel ssh add failed");
    let output = String::from_utf8_lossy(&stdout);
    assert!(
        output.contains("Identity added") || output.contains("identity added"),
        "unexpected ssh add output: {output}"
    );

    // List keys from the host side.
    let stdout = pod_command(&repo, &daemon)
        .args(["ssh", "ssh-test", "list"])
        .success()
        .expect("rumpel ssh list failed");
    let list_output = String::from_utf8_lossy(&stdout);
    assert!(
        list_output.contains("ssh-ed25519") || list_output.contains("ED25519"),
        "expected key in host-side list: {list_output}"
    );

    // Verify the key is reachable from inside the container through the
    // relayed agent socket.
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "ssh-test", "--", "ssh-add", "-l"])
        .success()
        .expect("ssh-add -l inside container failed");
    let container_output = String::from_utf8_lossy(&stdout);
    assert!(
        container_output.contains("ssh-ed25519") || container_output.contains("ED25519"),
        "expected key visible inside container: {container_output}"
    );
}
