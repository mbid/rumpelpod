use assert_cmd::Command;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Output;

/// A test fixture that creates a temporary git repository in /tmp.
/// The repository is initialized with a README.md file and an initial commit.
/// The current directory is changed to the repository on creation.
/// On drop, the original directory is restored and the temp directory is cleaned up.
pub struct TestRepo {
    pub dir: PathBuf,
    pub initial_commit: String,
    original_dir: PathBuf,
}

impl TestRepo {
    /// Initialize a new test repository.
    ///
    /// Creates a temporary directory in /tmp, initializes a git repo with "master"
    /// as the initial branch, creates a README.md with "TEST" content, and makes
    /// an initial commit. Changes the current directory to the new repository.
    pub fn init() -> Self {
        let original_dir = env::current_dir().expect("Failed to get current directory");

        // Create temp directory with unique name
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = PathBuf::from(format!("/tmp/sandbox-test-{}", timestamp));
        fs::create_dir_all(&dir).expect("Failed to create temp directory");

        // Initialize git repo with master branch
        run_git(&dir, &["init", "--initial-branch=master"]);

        // Configure git user for commits
        run_git(&dir, &["config", "user.email", "test@example.com"]);
        run_git(&dir, &["config", "user.name", "Test User"]);

        // Create README.md
        fs::write(dir.join("README.md"), "TEST").expect("Failed to write README.md");

        // Make initial commit
        run_git(&dir, &["add", "README.md"]);
        run_git(&dir, &["commit", "-m", "Initial commit"]);

        // Get the initial commit hash
        let output = run_git(&dir, &["rev-parse", "HEAD"]);
        let initial_commit = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Change to the test directory
        env::set_current_dir(&dir).expect("Failed to change to test directory");

        TestRepo {
            dir,
            initial_commit,
            original_dir,
        }
    }
}

impl Drop for TestRepo {
    fn drop(&mut self) {
        // Restore original directory
        let _ = env::set_current_dir(&self.original_dir);

        // Clean up temp directory
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn run_git(dir: &PathBuf, args: &[&str]) -> Output {
    let output = std::process::Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("Failed to run git command");

    if !output.status.success() {
        panic!(
            "Git command failed: git {}\nstderr: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output
}

/// Run the sandbox binary with the given arguments.
fn run_sandbox(args: &[&str]) -> Output {
    Command::cargo_bin("sandbox")
        .expect("Failed to find sandbox binary")
        .args(args)
        .output()
        .expect("Failed to run sandbox command")
}

/// Run a command inside the sandbox and capture its output.
fn run_in_sandbox(sandbox_name: &str, command: &[&str]) -> Output {
    let mut args = vec!["enter", sandbox_name, "--runtime", "runc", "--"];
    args.extend(command);
    run_sandbox(&args)
}

#[test]
fn smoke_test_sandbox_enter() {
    let repo = TestRepo::init();

    // Copy the minimal Dockerfile for the sandbox
    fs::write(
        repo.dir.join("Dockerfile"),
        include_str!("Dockerfile-debian"),
    )
    .expect("Failed to write Dockerfile");

    // Commit the Dockerfile so the sandbox branch can be created from a clean state
    run_git(&repo.dir, &["add", "Dockerfile"]);
    run_git(&repo.dir, &["commit", "-m", "Add Dockerfile"]);

    // Get the new commit hash (after adding Dockerfile)
    let output = run_git(&repo.dir, &["rev-parse", "HEAD"]);
    let expected_commit = String::from_utf8_lossy(&output.stdout).trim().to_string();

    let sandbox_name = "test-sandbox";

    // Test 1: Verify README.md content inside sandbox
    let output = run_in_sandbox(sandbox_name, &["cat", "README.md"]);
    assert!(
        output.status.success(),
        "Failed to read README.md in sandbox: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let readme_content = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        readme_content.trim(),
        "TEST",
        "README.md content mismatch. Got: '{}'",
        readme_content.trim()
    );

    // Test 2: Verify we're on the correct branch (sandbox name)
    let output = run_in_sandbox(sandbox_name, &["git", "branch", "--show-current"]);
    assert!(
        output.status.success(),
        "Failed to get current branch: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let current_branch = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        current_branch.trim(),
        sandbox_name,
        "Branch mismatch. Expected '{}', got '{}'",
        sandbox_name,
        current_branch.trim()
    );

    // Test 3: Verify we're on the correct commit
    let output = run_in_sandbox(sandbox_name, &["git", "rev-parse", "HEAD"]);
    assert!(
        output.status.success(),
        "Failed to get current commit: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let current_commit = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        current_commit.trim(),
        expected_commit,
        "Commit mismatch. Expected '{}', got '{}'",
        expected_commit,
        current_commit.trim()
    );

    // Clean up: delete the sandbox
    let output = run_sandbox(&["delete", sandbox_name]);
    assert!(
        output.status.success(),
        "Failed to delete sandbox: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
