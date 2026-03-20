//! Git repository utilities.
//!
//! This module provides utilities for working with git repositories,
//! particularly for locating the repository root from any subdirectory.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use git2::Repository;
use serde::{Deserialize, Serialize};

/// Git user identity (name and email) read from the host's effective config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitIdentity {
    pub name: Option<String>,
    pub email: Option<String>,
}

/// Discover the git repository root from the current working directory.
///
/// Returns the absolute path to the repository root (the directory containing `.git`).
/// Returns an error if the current directory is not inside a git repository.
pub fn get_repo_root() -> Result<PathBuf> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let repo = Repository::discover(&cwd).with_context(|| {
        format!(
            "Not inside a git repository: {}. \
             Rumpel commands must be run from within a git repository.",
            cwd.display()
        )
    })?;

    let workdir = repo.workdir();
    match workdir {
        Some(workdir) => Ok(workdir.to_path_buf()),
        None => {
            // Repository is bare (no working directory)
            Err(anyhow::anyhow!(
                "Cannot use rumpel in a bare git repository. \
                 Please run from within a repository with a working directory."
            ))
        }
    }
}

/// Read the effective git user.name and user.email for a repository,
/// respecting repo-level overrides via the config cascade.
pub fn get_git_user_config(repo_path: &Path) -> GitIdentity {
    let config = Repository::open(repo_path)
        .ok()
        .and_then(|r| r.config().ok());
    let name = config.as_ref().and_then(|c| c.get_string("user.name").ok());
    let email = config
        .as_ref()
        .and_then(|c| c.get_string("user.email").ok());
    GitIdentity { name, email }
}

/// Get the current branch name from a repository path.
///
/// Returns None if HEAD is detached (not pointing to a branch).
pub fn get_current_branch(repo_path: &std::path::Path) -> Option<String> {
    let repo = Repository::open(repo_path).ok()?;
    let head = repo.head().ok()?;

    if head.is_branch() {
        head.shorthand().map(|s| s.to_string())
    } else {
        None
    }
}

/// A git remote's name and fetch URL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitRemote {
    pub name: String,
    pub url: String,
}

/// Read the list of remotes (name + fetch URL) from a repository.
///
/// Skips remotes that have no URL configured. Results are sorted by
/// name so the output is stable regardless of git config ordering.
pub fn get_remotes(repo_path: &Path) -> Result<Vec<GitRemote>> {
    let repo = Repository::open(repo_path).context("opening repository")?;
    let remote_names = repo.remotes().context("listing remotes")?;
    let mut remotes = Vec::new();
    for name in remote_names.iter().flatten() {
        let remote = repo
            .find_remote(name)
            .with_context(|| format!("reading remote '{name}'"))?;
        if let Some(url) = remote.url() {
            remotes.push(GitRemote {
                name: name.to_string(),
                url: url.to_string(),
            });
        }
    }
    remotes.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(remotes)
}
