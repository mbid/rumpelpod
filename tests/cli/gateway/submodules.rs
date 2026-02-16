use std::process::Command;

use rumpelpod::CommandExt;

use super::{get_branch_commit, get_gateway_path, get_remote_ref_commit};
use crate::common::{
    build_test_image, create_commit, pod_command, write_test_pod_config, TestDaemon, TestRepo,
};

/// Create a parent TestRepo that contains a git submodule pointing to
/// a second TestRepo.  Returns (parent, child_name) where child_name
/// is the submodule name/path.
fn create_test_repo_with_submodule() -> (TestRepo, TestRepo, String) {
    let child = TestRepo::new();
    create_commit(child.path(), "Child initial");

    let parent = TestRepo::new();

    let child_name = "child-sub";

    // Add the child repo as a submodule of the parent.
    // -c protocol.file.allow=always: needed because newer git versions
    // block file:// transport by default for security.
    Command::new("git")
        .args([
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &child.path().to_string_lossy(),
            child_name,
        ])
        .current_dir(parent.path())
        .success()
        .expect("git submodule add failed");

    Command::new("git")
        .args(["commit", "-m", "Add submodule"])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(parent.path())
        .success()
        .expect("git commit (submodule add) failed");

    (parent, child, child_name.to_string())
}

#[test]
fn submodule_pod_commit_syncs_to_host() {
    let (parent, _child, sub_name) = create_test_repo_with_submodule();

    let image_id = build_test_image(parent.path(), "").expect("Failed to build test image");
    write_test_pod_config(&parent, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "sub-commit-test";

    // Launch pod -- sets up parent and submodule gateways
    pod_command(&parent, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a commit inside the pod's submodule
    let commit_script = format!(
        "cd {sub_name} && \
         git config user.email test@example.com && \
         git config user.name TestUser && \
         git commit --allow-empty -m 'Pod submodule commit'"
    );
    pod_command(&parent, &daemon)
        .args(["enter", pod_name, "--", "sh", "-c", &commit_script])
        .success()
        .expect("Failed to create commit in pod submodule");

    // Get the commit hash from the pod's submodule
    let pod_sub_commit = pod_command(&parent, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "-C",
            &sub_name,
            "rev-parse",
            "HEAD",
        ])
        .success()
        .expect("Failed to get pod submodule commit");
    let pod_sub_commit = String::from_utf8_lossy(&pod_sub_commit).trim().to_string();

    // Derive the submodule gateway path from the actual parent gateway
    // (the daemon may canonicalize the repo path differently from the test).
    let parent_gateway = get_gateway_path(parent.path()).expect("parent gateway should exist");
    let sub_gateway = parent_gateway
        .parent()
        .unwrap()
        .join("submodules")
        .join(&sub_name)
        .join("gateway.git");
    assert!(
        sub_gateway.exists(),
        "Submodule gateway should exist at {}",
        sub_gateway.display()
    );

    let expected_branch = format!("rumpelpod/{}@{}", pod_name, pod_name);
    let gateway_commit = get_branch_commit(&sub_gateway, &expected_branch);
    assert_eq!(
        gateway_commit,
        Some(pod_sub_commit),
        "Submodule gateway should have branch '{}' with pod's commit",
        expected_branch
    );
}

#[test]
fn submodule_host_update_visible_in_pod() {
    let (parent, _child, sub_name) = create_test_repo_with_submodule();

    let image_id = build_test_image(parent.path(), "").expect("Failed to build test image");
    write_test_pod_config(&parent, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "sub-fetch-test";

    // Launch pod
    pod_command(&parent, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a commit in the host's submodule
    let host_sub_path = parent.path().join(&sub_name);
    Command::new("git")
        .args(["commit", "--allow-empty", "-m", "Host submodule update"])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(&host_sub_path)
        .success()
        .expect("Failed to commit in host submodule");

    let host_sub_commit: String = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&host_sub_path)
        .success()
        .expect("Failed to get host submodule commit")
        .try_into()
        .unwrap();
    let host_sub_commit = host_sub_commit.trim().to_string();

    // Fetch host refs inside the pod's submodule
    pod_command(&parent, &daemon)
        .args([
            "enter", pod_name, "--", "git", "-C", &sub_name, "fetch", "host",
        ])
        .success()
        .expect("Failed to fetch host in pod submodule");

    // The pod should see the new commit via host/HEAD
    let fetched_commit = pod_command(&parent, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "-C",
            &sub_name,
            "rev-parse",
            "host/HEAD",
        ])
        .success()
        .expect("Failed to get host/HEAD in pod submodule");
    let fetched_commit = String::from_utf8_lossy(&fetched_commit).trim().to_string();

    assert_eq!(
        fetched_commit, host_sub_commit,
        "Pod should see the host submodule commit via host/HEAD"
    );
}

#[test]
fn submodule_pod_commit_mirrored_to_host() {
    let (parent, _child, sub_name) = create_test_repo_with_submodule();

    let image_id = build_test_image(parent.path(), "").expect("Failed to build test image");
    write_test_pod_config(&parent, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "sub-mirror-test";

    // Launch pod
    pod_command(&parent, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a commit in the pod's submodule
    let commit_script = format!(
        "cd {sub_name} && \
         git config user.email test@example.com && \
         git config user.name TestUser && \
         git commit --allow-empty -m 'Mirror test commit'"
    );
    pod_command(&parent, &daemon)
        .args(["enter", pod_name, "--", "sh", "-c", &commit_script])
        .success()
        .expect("Failed to create commit in pod submodule");

    let pod_sub_commit = pod_command(&parent, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "-C",
            &sub_name,
            "rev-parse",
            "HEAD",
        ])
        .success()
        .expect("Failed to get pod submodule commit");
    let pod_sub_commit = String::from_utf8_lossy(&pod_sub_commit).trim().to_string();

    // The host submodule should have the pod's commit as a remote-tracking ref
    let host_sub_path = parent.path().join(&sub_name);
    let expected_ref = format!("rumpelpod/{}@{}", pod_name, pod_name);

    let remote_commit = get_remote_ref_commit(&host_sub_path, &expected_ref);
    assert_eq!(
        remote_commit,
        Some(pod_sub_commit),
        "Host submodule should have remote-tracking ref '{}' with pod's commit",
        expected_ref
    );
}

/// Create a three-level hierarchy: grandparent -> outer-sub -> inner-sub.
/// Returns (grandparent, outer_child, inner_child, outer_name, inner_displaypath).
fn create_test_repo_with_nested_submodules() -> (TestRepo, TestRepo, TestRepo, String, String) {
    let inner = TestRepo::new();
    create_commit(inner.path(), "Inner initial");

    let outer = TestRepo::new();

    let inner_name = "inner-sub";
    Command::new("git")
        .args([
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &inner.path().to_string_lossy(),
            inner_name,
        ])
        .current_dir(outer.path())
        .success()
        .expect("git submodule add (inner) failed");
    Command::new("git")
        .args(["commit", "-m", "Add inner submodule"])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(outer.path())
        .success()
        .expect("git commit (inner submodule) failed");

    let grandparent = TestRepo::new();

    let outer_name = "outer-sub";
    Command::new("git")
        .args([
            "-c",
            "protocol.file.allow=always",
            "submodule",
            "add",
            &outer.path().to_string_lossy(),
            outer_name,
        ])
        .current_dir(grandparent.path())
        .success()
        .expect("git submodule add (outer) failed");
    Command::new("git")
        .args(["commit", "-m", "Add outer submodule"])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(grandparent.path())
        .success()
        .expect("git commit (outer submodule) failed");

    let inner_displaypath = format!("{}/{}", outer_name, inner_name);
    (
        grandparent,
        outer,
        inner,
        outer_name.to_string(),
        inner_displaypath,
    )
}

#[test]
fn nested_submodule_pod_commit_syncs_to_host() {
    let (grandparent, _outer, _inner, _outer_name, inner_displaypath) =
        create_test_repo_with_nested_submodules();

    let image_id = build_test_image(grandparent.path(), "").expect("Failed to build test image");
    write_test_pod_config(&grandparent, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "nested-commit-test";

    // Launch pod -- sets up parent, outer, and inner submodule gateways
    pod_command(&grandparent, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a commit inside the pod's nested (inner) submodule
    let commit_script = format!(
        "cd {inner_displaypath} && \
         git config user.email test@example.com && \
         git config user.name TestUser && \
         git commit --allow-empty -m 'Pod nested submodule commit'"
    );
    pod_command(&grandparent, &daemon)
        .args(["enter", pod_name, "--", "sh", "-c", &commit_script])
        .success()
        .expect("Failed to create commit in pod nested submodule");

    // Get the commit hash from the pod's nested submodule
    let pod_commit = pod_command(&grandparent, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "-C",
            &inner_displaypath,
            "rev-parse",
            "HEAD",
        ])
        .success()
        .expect("Failed to get pod nested submodule commit");
    let pod_commit = String::from_utf8_lossy(&pod_commit).trim().to_string();

    // Derive the nested submodule gateway path from the parent gateway
    let parent_gateway = get_gateway_path(grandparent.path()).expect("parent gateway should exist");
    let inner_gateway = parent_gateway
        .parent()
        .unwrap()
        .join("submodules")
        .join(&inner_displaypath)
        .join("gateway.git");
    assert!(
        inner_gateway.exists(),
        "Nested submodule gateway should exist at {}",
        inner_gateway.display()
    );

    let expected_branch = format!("rumpelpod/{}@{}", pod_name, pod_name);
    let gateway_commit = get_branch_commit(&inner_gateway, &expected_branch);
    assert_eq!(
        gateway_commit,
        Some(pod_commit),
        "Nested submodule gateway should have branch '{}' with pod's commit",
        expected_branch
    );
}

#[test]
fn nested_submodule_host_update_visible_in_pod() {
    let (grandparent, _outer, _inner, _outer_name, inner_displaypath) =
        create_test_repo_with_nested_submodules();

    let image_id = build_test_image(grandparent.path(), "").expect("Failed to build test image");
    write_test_pod_config(&grandparent, &image_id);

    let daemon = TestDaemon::start();
    let pod_name = "nested-fetch-test";

    // Launch pod
    pod_command(&grandparent, &daemon)
        .args(["enter", pod_name, "--", "echo", "setup"])
        .success()
        .expect("Failed to run rumpel enter");

    // Create a commit in the host's nested submodule
    let host_inner_path = grandparent.path().join(&inner_displaypath);
    Command::new("git")
        .args([
            "commit",
            "--allow-empty",
            "-m",
            "Host nested submodule update",
        ])
        .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00+00:00")
        .current_dir(&host_inner_path)
        .success()
        .expect("Failed to commit in host nested submodule");

    let host_inner_commit: String = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(&host_inner_path)
        .success()
        .expect("Failed to get host nested submodule commit")
        .try_into()
        .unwrap();
    let host_inner_commit = host_inner_commit.trim().to_string();

    // Fetch host refs inside the pod's nested submodule
    pod_command(&grandparent, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "-C",
            &inner_displaypath,
            "fetch",
            "host",
        ])
        .success()
        .expect("Failed to fetch host in pod nested submodule");

    // The pod should see the new commit via host/HEAD
    let fetched_commit = pod_command(&grandparent, &daemon)
        .args([
            "enter",
            pod_name,
            "--",
            "git",
            "-C",
            &inner_displaypath,
            "rev-parse",
            "host/HEAD",
        ])
        .success()
        .expect("Failed to get host/HEAD in pod nested submodule");
    let fetched_commit = String::from_utf8_lossy(&fetched_commit).trim().to_string();

    assert_eq!(
        fetched_commit, host_inner_commit,
        "Pod should see the host nested submodule commit via host/HEAD"
    );
}
