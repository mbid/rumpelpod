use std::io::BufRead;
use std::process::Command;

use anyhow::{bail, Result};

use crate::cli::{PostCheckoutCommand, ReferenceTransactionCommand};
use crate::CommandExt;

// -- Claude Code hooks -------------------------------------------------------

/// Auto-approve all tool use by outputting a JSON allow decision.
/// Invoked as a Claude Code PermissionRequest hook.
pub fn claude_permission_request() -> Result<()> {
    println!(
        r#"{{"hookSpecificOutput":{{"hookEventName":"PermissionRequest","decision":{{"behavior":"allow"}}}}}}"#
    );
    Ok(())
}

const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// Read stdin lines in the git hook format: `oldvalue newvalue refname`.
fn read_ref_updates() -> Result<Vec<(String, String, String)>> {
    let stdin = std::io::stdin();
    let mut updates = Vec::new();
    for line in stdin.lock().lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        updates.push((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        ));
    }
    Ok(updates)
}

/// Run a git command, logging failures to stderr.
fn run_git(args: &[&str]) {
    if let Err(e) = Command::new("git").args(args).success() {
        eprintln!("rumpelpod hook: {e:#}");
    }
}

/// Resolve HEAD to a commit hash and push it to host/HEAD in the gateway.
fn push_head_to_gateway() {
    let out = match Command::new("git").args(["rev-parse", "HEAD"]).success() {
        Ok(out) => out,
        Err(_) => return,
    };
    let commit = String::from_utf8_lossy(&out).trim().to_string();
    if commit.is_empty() {
        return;
    }
    run_git(&[
        "push",
        "rumpelpod",
        &format!("{commit}:refs/heads/host/HEAD"),
        "--force",
        "--no-verify",
        "--quiet",
    ]);
}

// -- Pod repo hooks ----------------------------------------------------------

/// Pod reference-transaction: push branch updates to the gateway.
/// Runs after the ref update is committed, so failures are non-fatal.
pub fn reference_transaction(cmd: &ReferenceTransactionCommand) -> Result<()> {
    if cmd.state != "committed" {
        return Ok(());
    }

    for (_oldvalue, newvalue, refname) in read_ref_updates()? {
        let branch = match refname.strip_prefix("refs/heads/") {
            Some(b) => b,
            None => continue,
        };

        if newvalue == ZERO_OID {
            run_git(&["push", "rumpelpod", "--delete", branch, "--quiet"]);
        } else {
            run_git(&["push", "rumpelpod", branch, "--force", "--quiet"]);
        }
    }

    Ok(())
}

// -- Host repo hooks ---------------------------------------------------------

/// Host reference-transaction: push branch and HEAD updates to the gateway.
/// Runs after the ref update is committed, so failures are non-fatal.
pub fn host_reference_transaction(cmd: &ReferenceTransactionCommand) -> Result<()> {
    if cmd.state != "committed" {
        return Ok(());
    }

    for (_oldvalue, newvalue, refname) in read_ref_updates()? {
        if refname == "HEAD" {
            push_head_to_gateway();
            continue;
        }

        let branch = match refname.strip_prefix("refs/heads/") {
            Some(b) => b,
            None => continue,
        };

        if newvalue == ZERO_OID {
            run_git(&[
                "push",
                "rumpelpod",
                "--delete",
                &format!("host/{branch}"),
                "--no-verify",
                "--quiet",
            ]);
        } else {
            run_git(&[
                "push",
                "rumpelpod",
                &format!("{branch}:host/{branch}"),
                "--force",
                "--no-verify",
                "--quiet",
            ]);
        }
    }

    Ok(())
}

/// Host post-checkout: sync HEAD to gateway on branch switch.
/// Fallback for git versions where reference-transaction does not fire
/// for symbolic ref changes (e.g. Apple Git 2.39).
pub fn host_post_checkout(cmd: &PostCheckoutCommand) -> Result<()> {
    if cmd.flag != "1" {
        return Ok(());
    }
    push_head_to_gateway();
    Ok(())
}

// -- Gateway repo hooks ------------------------------------------------------

/// Gateway pre-receive: access control.  Pods can only push to their own
/// namespace.  This runs *before* refs are updated, so returning an error
/// rejects the push.
pub fn gateway_pre_receive() -> Result<()> {
    let pod_name = std::env::var("POD_NAME").ok();

    for (_old_oid, new_oid, refname) in read_ref_updates()? {
        if new_oid == ZERO_OID {
            continue;
        }
        check_push_access(&refname, pod_name.as_deref())?;
    }

    Ok(())
}

fn check_push_access(refname: &str, pod_name: Option<&str>) -> Result<()> {
    match pod_name {
        Some(name) => {
            let expected_suffix = format!("@{name}");
            let allowed =
                refname.starts_with("refs/heads/rumpelpod/") && refname.ends_with(&expected_suffix);
            if !allowed {
                eprintln!("error: pod '{name}' cannot push to '{refname}'");
                eprintln!("error: pods can only push to refs/heads/rumpelpod/*@{name}");
                bail!("access denied");
            }
        }
        None => {
            if !refname.starts_with("refs/heads/host/") {
                eprintln!("error: host can only push to refs/heads/host/*");
                eprintln!("error: attempted to push to '{refname}'");
                bail!("access denied");
            }
        }
    }
    Ok(())
}

/// Gateway post-receive: mirror pod refs to host repo as remote-tracking refs.
/// Runs after refs are updated, so failures are non-fatal.
pub fn gateway_post_receive() -> Result<()> {
    for (_oldvalue, newvalue, refname) in read_ref_updates()? {
        let branch = match refname.strip_prefix("refs/heads/rumpelpod/") {
            Some(b) => b,
            None => continue,
        };
        sync_pod_ref_to_host(&refname, &newvalue, branch);
    }

    Ok(())
}

/// Mirror a single pod ref update to the host repo.
fn sync_pod_ref_to_host(refname: &str, newvalue: &str, branch: &str) {
    // Parse "foo@bar" into branch_part="foo", pod_part="bar".
    let (branch_part, pod_part) = match branch.rsplit_once('@') {
        Some(pair) => pair,
        None => return,
    };
    let is_primary = branch_part == pod_part;

    if newvalue == ZERO_OID {
        run_git(&[
            "push",
            "host",
            "--delete",
            &format!("refs/remotes/rumpelpod/{branch}"),
            "--quiet",
        ]);
        if is_primary {
            run_git(&[
                "symbolic-ref",
                "--delete",
                &format!("refs/heads/rumpelpod/{pod_part}"),
            ]);
            run_git(&[
                "push",
                "host",
                "--delete",
                &format!("refs/remotes/rumpelpod/{pod_part}"),
                "--quiet",
            ]);
        }
    } else {
        run_git(&[
            "push",
            "host",
            &format!("{refname}:refs/remotes/rumpelpod/{branch}"),
            "--force",
            "--quiet",
        ]);
        if is_primary {
            run_git(&[
                "symbolic-ref",
                &format!("refs/heads/rumpelpod/{pod_part}"),
                refname,
            ]);
            run_git(&[
                "push",
                "host",
                &format!("{refname}:refs/remotes/rumpelpod/{pod_part}"),
                "--force",
                "--quiet",
            ]);
        }
    }
}
