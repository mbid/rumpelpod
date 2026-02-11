//! Git repository utilities.
//!
//! This module provides utilities for working with git repositories,
//! particularly for locating the repository root from any subdirectory.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use git2::Repository;

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
        Some(path) => Ok(path.to_path_buf()),
        None => {
            // Repository is bare (no working directory)
            bail!(
                "Cannot use rumpel in a bare git repository. \
                 Please run from within a repository with a working directory."
            );
        }
    }
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
