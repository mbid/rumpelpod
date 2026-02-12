//! Integration tests for the `rumpel cp` subcommand.

use std::fs;

use rumpelpod::CommandExt;

use crate::common::{build_test_image, pod_command, write_test_pod_config, TestDaemon, TestRepo};

#[test]
fn cp_from_pod_to_host() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a file inside the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "cp-test",
            "--",
            "sh",
            "-c",
            "echo hello-from-pod > /tmp/testfile.txt",
        ])
        .success()
        .expect("failed to create file in pod");

    // Copy it out
    let host_dest = daemon.temp_dir().join("copied.txt");
    pod_command(&repo, &daemon)
        .args([
            "cp",
            "cp-test:/tmp/testfile.txt",
            host_dest.to_str().unwrap(),
        ])
        .success()
        .expect("rumpel cp from pod failed");

    let content = fs::read_to_string(&host_dest).expect("failed to read copied file");
    assert_eq!(content.trim(), "hello-from-pod");
}

#[test]
fn cp_from_host_to_pod() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Ensure pod exists
    pod_command(&repo, &daemon)
        .args(["enter", "cp-in-test", "--", "true"])
        .success()
        .expect("failed to start pod");

    // Write a local file
    let local_file = daemon.temp_dir().join("upload.txt");
    fs::write(&local_file, "hello-from-host\n").expect("failed to write local file");

    // Copy it into the pod
    pod_command(&repo, &daemon)
        .args([
            "cp",
            local_file.to_str().unwrap(),
            "cp-in-test:/tmp/upload.txt",
        ])
        .success()
        .expect("rumpel cp to pod failed");

    // Verify inside the pod
    let stdout = pod_command(&repo, &daemon)
        .args(["enter", "cp-in-test", "--", "cat", "/tmp/upload.txt"])
        .success()
        .expect("failed to read file in pod");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello-from-host");
}

#[test]
fn cp_no_pod_syntax_fails() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["cp", "/local/a", "/local/b"])
        .output()
        .expect("failed to run rumpel cp");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("POD:PATH"),
        "Error should mention POD:PATH syntax: {}",
        stderr
    );
}

#[test]
fn cp_both_pod_syntax_fails() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    let output = pod_command(&repo, &daemon)
        .args(["cp", "pod1:/a", "pod2:/b"])
        .output()
        .expect("failed to run rumpel cp");

    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Both"),
        "Error should mention both sides: {}",
        stderr
    );
}

#[test]
fn cp_directory_from_pod() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a directory with files inside the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "cp-dir-test",
            "--",
            "sh",
            "-c",
            "mkdir -p /tmp/testdir && echo aaa > /tmp/testdir/a.txt && echo bbb > /tmp/testdir/b.txt",
        ])
        .success()
        .expect("failed to create directory in pod");

    // Copy directory out
    let host_dest = daemon.temp_dir().join("testdir");
    pod_command(&repo, &daemon)
        .args([
            "cp",
            "cp-dir-test:/tmp/testdir",
            host_dest.to_str().unwrap(),
        ])
        .success()
        .expect("rumpel cp directory from pod failed");

    assert!(host_dest.join("a.txt").exists(), "a.txt should exist");
    assert!(host_dest.join("b.txt").exists(), "b.txt should exist");

    let a = fs::read_to_string(host_dest.join("a.txt")).unwrap();
    assert_eq!(a.trim(), "aaa");
}

#[test]
fn cp_with_flags() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Create a file inside the pod
    pod_command(&repo, &daemon)
        .args([
            "enter",
            "cp-flags-test",
            "--",
            "sh",
            "-c",
            "echo flagtest > /tmp/flagfile.txt",
        ])
        .success()
        .expect("failed to create file in pod");

    // Copy with -a -L -q flags
    let host_dest = daemon.temp_dir().join("flagcopy.txt");
    pod_command(&repo, &daemon)
        .args([
            "cp",
            "-a",
            "-L",
            "-q",
            "cp-flags-test:/tmp/flagfile.txt",
            host_dest.to_str().unwrap(),
        ])
        .success()
        .expect("rumpel cp with flags failed");

    let content = fs::read_to_string(&host_dest).expect("failed to read copied file");
    assert_eq!(content.trim(), "flagtest");
}
