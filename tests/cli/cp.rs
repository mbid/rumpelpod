//! Integration tests for the `rumpel cp` subcommand.

use std::fs;

use rumpelpod::CommandExt;

use crate::common::{build_test_image, pod_command, TestRepo};
use crate::executor::TestPod;

#[test]
fn cp_from_pod_to_host() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "cp-from-pod");

    // Create a file inside the pod
    pod_command(&repo, &pod.daemon)
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
    let host_dest = pod.daemon.temp_dir().join("copied.txt");
    pod_command(&repo, &pod.daemon)
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
    let pod = TestPod::start(&repo, &image_id, "cp-to-pod");

    // Ensure pod exists
    pod_command(&repo, &pod.daemon)
        .args(["enter", "cp-in-test", "--", "true"])
        .success()
        .expect("failed to start pod");

    // Write a local file
    let local_file = pod.daemon.temp_dir().join("upload.txt");
    fs::write(&local_file, "hello-from-host\n").expect("failed to write local file");

    // Copy it into the pod
    pod_command(&repo, &pod.daemon)
        .args([
            "cp",
            local_file.to_str().unwrap(),
            "cp-in-test:/tmp/upload.txt",
        ])
        .success()
        .expect("rumpel cp to pod failed");

    // Verify inside the pod
    let stdout = pod_command(&repo, &pod.daemon)
        .args(["enter", "cp-in-test", "--", "cat", "/tmp/upload.txt"])
        .success()
        .expect("failed to read file in pod");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "hello-from-host");
}

#[test]
fn cp_no_pod_syntax_fails() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "cp-no-syntax");

    let output = pod_command(&repo, &pod.daemon)
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
    let pod = TestPod::start(&repo, &image_id, "cp-both-syntax");

    let output = pod_command(&repo, &pod.daemon)
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
    let pod = TestPod::start(&repo, &image_id, "cp-dir-from");

    // Create a directory with files inside the pod
    pod_command(&repo, &pod.daemon)
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
    let host_dest = pod.daemon.temp_dir().join("testdir");
    pod_command(&repo, &pod.daemon)
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
fn cp_directory_to_pod() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    write_test_pod_config(&repo, &image_id);

    let daemon = TestDaemon::start();

    // Ensure pod exists
    pod_command(&repo, &daemon)
        .args(["enter", "cp-dir-in-test", "--", "true"])
        .success()
        .expect("failed to start pod");

    // Create a local directory with files
    let local_dir = daemon.temp_dir().join("upload-dir");
    fs::create_dir(&local_dir).unwrap();
    fs::write(local_dir.join("x.txt"), "xxx\n").unwrap();
    fs::write(local_dir.join("y.txt"), "yyy\n").unwrap();

    // Copy directory into the pod
    pod_command(&repo, &daemon)
        .args([
            "cp",
            local_dir.to_str().unwrap(),
            "cp-dir-in-test:/tmp/upload-dir",
        ])
        .success()
        .expect("rumpel cp directory to pod failed");

    // Verify files inside the pod
    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "cp-dir-in-test",
            "--",
            "cat",
            "/tmp/upload-dir/x.txt",
        ])
        .success()
        .expect("failed to read x.txt in pod");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "xxx");

    let stdout = pod_command(&repo, &daemon)
        .args([
            "enter",
            "cp-dir-in-test",
            "--",
            "cat",
            "/tmp/upload-dir/y.txt",
        ])
        .success()
        .expect("failed to read y.txt in pod");
    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "yyy");
}

#[test]
fn cp_with_flags() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "cp-flags");

    // Create a file inside the pod
    pod_command(&repo, &pod.daemon)
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

    // Copy with -a -L flags
    let host_dest = daemon.temp_dir().join("flagcopy.txt");
    pod_command(&repo, &daemon)
        .args([
            "cp",
            "-a",
            "-L",
            "cp-flags-test:/tmp/flagfile.txt",
            host_dest.to_str().unwrap(),
        ])
        .success()
        .expect("rumpel cp with flags failed");

    let content = fs::read_to_string(&host_dest).expect("failed to read copied file");
    assert_eq!(content.trim(), "flagtest");
}

#[test]
fn cp_relative_path_from_pod() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "cp-rel-from");

    // Create a file at a path relative to the repo root inside the pod.
    pod_command(&repo, &pod.daemon)
        .args([
            "enter",
            "cp-rel-test",
            "--",
            "sh",
            "-c",
            "echo relative-content > relative-file.txt",
        ])
        .success()
        .expect("failed to create file in pod");

    // Copy it out using a relative container path (no leading /).
    let host_dest = pod.daemon.temp_dir().join("rel-copied.txt");
    pod_command(&repo, &pod.daemon)
        .args([
            "cp",
            "cp-rel-test:relative-file.txt",
            host_dest.to_str().unwrap(),
        ])
        .success()
        .expect("rumpel cp with relative path failed");

    let content = fs::read_to_string(&host_dest).expect("failed to read copied file");
    assert_eq!(content.trim(), "relative-content");
}

#[test]
fn cp_relative_path_to_pod() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "cp-rel-to");

    // Ensure pod exists
    pod_command(&repo, &pod.daemon)
        .args(["enter", "cp-rel-in-test", "--", "true"])
        .success()
        .expect("failed to start pod");

    // Write a local file
    let local_file = pod.daemon.temp_dir().join("rel-upload.txt");
    fs::write(&local_file, "relative-upload\n").expect("failed to write local file");

    // Copy it into the pod using a relative container path
    pod_command(&repo, &pod.daemon)
        .args([
            "cp",
            local_file.to_str().unwrap(),
            "cp-rel-in-test:rel-upload.txt",
        ])
        .success()
        .expect("rumpel cp to pod with relative path failed");

    // Verify by reading the file at the expected absolute location
    let stdout = pod_command(&repo, &pod.daemon)
        .args(["enter", "cp-rel-in-test", "--", "cat", "rel-upload.txt"])
        .success()
        .expect("failed to read file in pod");

    assert_eq!(String::from_utf8_lossy(&stdout).trim(), "relative-upload");
}

#[test]
fn cp_to_pod_owns_files_as_container_user() {
    let repo = TestRepo::new();
    let image_id = build_test_image(repo.path(), "").expect("Failed to build test image");
    let pod = TestPod::start(&repo, &image_id, "cp-owns");

    // Ensure pod exists
    pod_command(&repo, &pod.daemon)
        .args(["enter", "cp-own-test", "--", "true"])
        .success()
        .expect("failed to start pod");

    // Write a local file
    let local_file = pod.daemon.temp_dir().join("owned.txt");
    fs::write(&local_file, "check-owner\n").expect("failed to write local file");

    // Copy into the pod (without -a, so chown should kick in)
    pod_command(&repo, &pod.daemon)
        .args([
            "cp",
            local_file.to_str().unwrap(),
            "cp-own-test:/tmp/owned.txt",
        ])
        .success()
        .expect("rumpel cp to pod failed");

    // Check the file owner matches the container user
    let stdout = pod_command(&repo, &pod.daemon)
        .args([
            "enter",
            "cp-own-test",
            "--",
            "stat",
            "-c",
            "%U",
            "/tmp/owned.txt",
        ])
        .success()
        .expect("failed to stat file in pod");

    let owner = String::from_utf8_lossy(&stdout).trim().to_string();
    // The default test image runs as a non-root user; the file should not be root.
    assert_ne!(
        owner, "root",
        "File should be owned by the container user, not root"
    );
}
