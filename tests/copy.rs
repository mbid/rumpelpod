//! Integration tests for the `copy` feature (copying directories into sandbox image).

mod common;

use std::fs;

use indoc::formatdoc;

use common::{run_git, SandboxFixture};

#[test]
fn test_copy_simple_path() {
    let fixture = SandboxFixture::new("test-copy-simple");

    // Create a directory on the host to copy
    let host_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let host_path = host_dir.path();
    fs::write(host_path.join("test_file.txt"), "hello from host").unwrap();
    fs::create_dir_all(host_path.join("subdir")).unwrap();
    fs::write(host_path.join("subdir/nested.txt"), "nested content").unwrap();

    // Configure .sandbox.toml to copy the directory
    let host_display = host_path.display();
    let config = formatdoc! {r#"
        [[copy]]
        host-path = "{host_display}"
        guest-path = "/copied-dir"
    "#};
    fs::write(fixture.repo.dir.join(".sandbox.toml"), config).expect("Failed to write config");

    run_git(&fixture.repo.dir, &["add", ".sandbox.toml"]);
    run_git(&fixture.repo.dir, &["commit", "--amend", "--no-edit"]);

    // Verify the file was copied
    let output = fixture.run(&["cat", "/copied-dir/test_file.txt"]);
    assert!(
        output.status.success(),
        "Failed to read copied file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "hello from host"
    );

    // Verify nested file was copied
    let output = fixture.run(&["cat", "/copied-dir/subdir/nested.txt"]);
    assert!(
        output.status.success(),
        "Failed to read nested file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "nested content"
    );
}

#[test]
fn test_copy_home_expansion() {
    let fixture = SandboxFixture::new("test-copy-home");

    // Create a test file in a temp location
    let host_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let host_path = host_dir.path();
    fs::write(host_path.join("config.txt"), "config content").unwrap();

    // Configure .sandbox.toml to copy to home directory
    // Using the temp dir as host path, and ~ expansion for guest path
    let host_display = host_path.display();
    let config = formatdoc! {r#"
        [[copy]]
        host-path = "{host_display}"
        guest-path = "~/.myconfig"
    "#};
    fs::write(fixture.repo.dir.join(".sandbox.toml"), config).expect("Failed to write config");

    run_git(&fixture.repo.dir, &["add", ".sandbox.toml"]);
    run_git(&fixture.repo.dir, &["commit", "--amend", "--no-edit"]);

    // The username in tests may be the host username or "userNNN" fallback
    // depending on whether $USER is set. Get the actual username to find the file.
    let uid = nix::unistd::getuid().as_raw();
    let username = std::env::var("USER").unwrap_or_else(|_| format!("user{uid}"));
    let expected_path = format!("/home/{username}/.myconfig/config.txt");

    // Verify the file was copied to home directory
    let output = fixture.run(&["cat", &expected_path]);
    assert!(
        output.status.success(),
        "Failed to read copied file at {}: {}",
        expected_path,
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "config content"
    );
}

#[test]
fn test_copy_multiple_entries() {
    let fixture = SandboxFixture::new("test-copy-multiple");

    // Create two directories on the host
    let dir1 = tempfile::tempdir().expect("Failed to create temp dir 1");
    let dir2 = tempfile::tempdir().expect("Failed to create temp dir 2");

    fs::write(dir1.path().join("file1.txt"), "content1").unwrap();
    fs::write(dir2.path().join("file2.txt"), "content2").unwrap();

    // Configure .sandbox.toml with multiple copy entries
    let dir1_display = dir1.path().display();
    let dir2_display = dir2.path().display();
    let config = formatdoc! {r#"
        [[copy]]
        host-path = "{dir1_display}"
        guest-path = "/dir1"

        [[copy]]
        host-path = "{dir2_display}"
        guest-path = "/dir2"
    "#};
    fs::write(fixture.repo.dir.join(".sandbox.toml"), config).expect("Failed to write config");

    run_git(&fixture.repo.dir, &["add", ".sandbox.toml"]);
    run_git(&fixture.repo.dir, &["commit", "--amend", "--no-edit"]);

    // Verify both files were copied
    let output = fixture.run(&["cat", "/dir1/file1.txt"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "content1");

    let output = fixture.run(&["cat", "/dir2/file2.txt"]);
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "content2");
}

#[test]
fn test_copy_single_file() {
    let fixture = SandboxFixture::new("test-copy-file");

    // Create a single file on the host to copy (not a directory)
    let host_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let host_file = host_dir.path().join("myconfig.txt");
    fs::write(&host_file, "single file content").unwrap();

    // Configure .sandbox.toml to copy the single file
    let host_display = host_file.display();
    let config = formatdoc! {r#"
        [[copy]]
        host-path = "{host_display}"
        guest-path = "/etc/myconfig.txt"
    "#};
    fs::write(fixture.repo.dir.join(".sandbox.toml"), config).expect("Failed to write config");

    run_git(&fixture.repo.dir, &["add", ".sandbox.toml"]);
    run_git(&fixture.repo.dir, &["commit", "--amend", "--no-edit"]);

    // Verify the file was copied
    let output = fixture.run(&["cat", "/etc/myconfig.txt"]);
    assert!(
        output.status.success(),
        "Failed to read copied file: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "single file content"
    );

    // Verify it's a file, not a directory
    let output = fixture.run(&["test", "-f", "/etc/myconfig.txt"]);
    assert!(
        output.status.success(),
        "/etc/myconfig.txt should be a file, not a directory"
    );
}
