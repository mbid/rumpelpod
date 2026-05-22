// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Build release binaries for all platforms and create a GitHub release.
//!
//! Must be run from a clean checkout of a git tag.  Builds linux-amd64 and
//! linux-arm64 locally, and darwin-arm64 either locally (on mac) or via
//! `ssh macos` (on linux).
//!
//! Usage: cargo run --bin release

use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};

const LINUX_TARGETS: &[(&str, &str)] = &[
    ("x86_64-unknown-linux-musl", "rumpel-linux-amd64"),
    ("aarch64-unknown-linux-musl", "rumpel-linux-arm64"),
];

const DARWIN_TRIPLE: &str = "aarch64-apple-darwin";
const DARWIN_NAME: &str = "rumpel-darwin-arm64";

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<ExitCode> {
    let tag =
        tools::output(Command::new("git").args(["describe", "--tags", "--exact-match", "HEAD"]))
            .context("HEAD is not a tagged commit. Check out a tag first: git checkout v1.2.3")?;

    // Validate clean working tree.
    if Command::new("git")
        .args(["diff", "--quiet"])
        .status()
        .map(|s| !s.success())
        .unwrap_or(true)
        || Command::new("git")
            .args(["diff", "--cached", "--quiet"])
            .status()
            .map(|s| !s.success())
            .unwrap_or(true)
    {
        anyhow::bail!("working tree has uncommitted changes");
    }
    let untracked =
        tools::output(Command::new("git").args(["ls-files", "--others", "--exclude-standard"]))?;
    if !untracked.is_empty() {
        anyhow::bail!("working tree has untracked files");
    }

    eprintln!("==> Releasing {tag}");

    let staging = tempfile::tempdir().context("creating staging directory")?;

    // -- Linux builds (always local) -----------------------------------------

    for (triple, name) in LINUX_TARGETS {
        eprintln!("==> Building {name} ({triple})...");
        tools::run(Command::new("cargo").args([
            "build",
            "--release",
            "--bin",
            "rumpel",
            "--target",
            triple,
        ]))?;
        let src = Path::new("target")
            .join(triple)
            .join("release")
            .join("rumpel");
        let dst = staging.path().join(name);
        std::fs::copy(&src, &dst).with_context(|| {
            let src = src.display();
            let dst = dst.display();
            format!("copying {src} -> {dst}")
        })?;
    }

    // -- macOS build ----------------------------------------------------------

    if cfg!(target_os = "macos") {
        eprintln!("==> Building {DARWIN_NAME} ({DARWIN_TRIPLE}) locally...");
        tools::run(Command::new("cargo").args([
            "build",
            "--release",
            "--bin",
            "rumpel",
            "--target",
            DARWIN_TRIPLE,
        ]))?;
        let src = Path::new("target")
            .join(DARWIN_TRIPLE)
            .join("release")
            .join("rumpel");
        std::fs::copy(&src, staging.path().join(DARWIN_NAME))?;
    } else {
        eprintln!("==> Building {DARWIN_NAME} ({DARWIN_TRIPLE}) on remote mac...");
        let hostname = tools::output(&mut Command::new("hostname"))?;
        let remote_dir = format!("/tmp/{hostname}/rumpelpod");

        // Clone the local repo to the mac (wipe any stale checkout first).
        tools::run(Command::new("ssh").args([
            "macos",
            &format!("rm -rf '{remote_dir}' && mkdir -p '{remote_dir}'"),
        ]))?;

        let clone_dir = staging.path().join("clone-for-mac");
        tools::run(Command::new("git").args([
            "clone",
            "--no-local",
            "--branch",
            &tag,
            ".",
            clone_dir.to_str().unwrap(),
        ]))?;

        // Pipe the clone as a tarball to the remote.
        let tar_cmd = format!(
            "tar -C {clone} -cf - . | ssh macos 'tar -C {remote} -xf -'",
            clone = clone_dir.display(),
            remote = remote_dir,
        );
        tools::run(Command::new("sh").args(["-c", &tar_cmd]))?;
        std::fs::remove_dir_all(&clone_dir).ok();

        let build_cmd = format!(
            "cd '{remote_dir}' && source \"$HOME/.cargo/env\" && cargo build --release --bin rumpel --target {DARWIN_TRIPLE}"
        );
        tools::run(Command::new("ssh").args(["macos", &build_cmd]))?;

        tools::run(Command::new("scp").args([
            &format!("macos:{remote_dir}/target/{DARWIN_TRIPLE}/release/rumpel"),
            staging.path().join(DARWIN_NAME).to_str().unwrap(),
        ]))?;

        tools::run(Command::new("ssh").args(["macos", &format!("rm -rf '{remote_dir}'")]))?;
    }

    // -- Package and upload ---------------------------------------------------

    let tarball_name = format!("rumpel-{tag}.tar.gz");
    let tarball = staging.path().join(&tarball_name);
    eprintln!("==> Packaging {tarball_name}...");
    tools::run(
        Command::new("tar")
            .args([
                "-C",
                staging.path().to_str().unwrap(),
                "-czf",
                tarball.to_str().unwrap(),
            ])
            .args(["rumpel-linux-amd64", "rumpel-linux-arm64", DARWIN_NAME]),
    )?;

    eprintln!("==> Creating GitHub release {tag}...");
    tools::run(Command::new("gh").args([
        "release",
        "create",
        &tag,
        tarball.to_str().unwrap(),
        "--title",
        &tag,
    ]))?;

    eprintln!("==> Done: {tag} released.");
    Ok(ExitCode::SUCCESS)
}
