use std::io::BufRead;
use std::process::{Command, Stdio};

use anyhow::Result;

use crate::cli::ReferenceTransactionCommand;

const ZERO_OID: &str = "0000000000000000000000000000000000000000";

pub fn reference_transaction(cmd: &ReferenceTransactionCommand) -> Result<()> {
    if cmd.state != "committed" {
        return Ok(());
    }

    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 3 {
            continue;
        }
        let (_oldvalue, newvalue, refname) = (parts[0], parts[1], parts[2]);

        let branch = match refname.strip_prefix("refs/heads/") {
            Some(b) => b,
            None => continue,
        };

        // Errors are silently ignored -- the gateway push is best-effort
        // and must never block local ref updates.
        let mut git = Command::new("git");
        git.stdout(Stdio::null()).stderr(Stdio::null());

        if newvalue == ZERO_OID {
            git.args(["push", "rumpelpod", "--delete", branch, "--quiet"]);
        } else {
            git.args(["push", "rumpelpod", branch, "--force", "--quiet"]);
        }

        let _ = git.status();
    }

    Ok(())
}
