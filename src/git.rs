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
             Sandbox commands must be run from within a git repository.",
            cwd.display()
        )
    })?;

    let workdir = repo.workdir();
    match workdir {
        Some(path) => Ok(path.to_path_buf()),
        None => {
            // Repository is bare (no working directory)
            bail!(
                "Cannot use sandbox in a bare git repository. \
                 Please run from within a repository with a working directory."
            );
        }
    }
}
