// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Verify that the checked-in THIRD-PARTY-NOTICES matches what `cargo about`
//! would generate from the current workspace.
//!
//! Runs in the pipeline so that any Cargo.lock change forces a matching
//! THIRD-PARTY-NOTICES update before merge. The regeneration command is
//! printed on mismatch.
//!
//! Requires `cargo-about` to be installed (it is part of the devcontainer
//! image; install locally with `cargo install cargo-about --locked`).

use std::path::{Path, PathBuf};
use std::process::Command;

const REGENERATE_CMD: &str =
    "cargo about generate -c tools/attribution/about.toml tools/attribution/about.hbs -o THIRD-PARTY-NOTICES";

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the rumpelpod crate; workspace root is one up.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root above crate dir")
        .to_path_buf()
}

#[test]
fn third_party_notices_is_up_to_date() {
    let root = workspace_root();

    // Write to a tempfile with `-o` so our comparison matches exactly
    // what the regeneration command produces (stdout output would add a
    // trailing newline that `-o` does not).
    let tempdir = tempfile::tempdir().expect("creating tempdir");
    let generated_path = tempdir.path().join("THIRD-PARTY-NOTICES");

    let output = Command::new("cargo")
        .current_dir(&root)
        .args([
            "about",
            "generate",
            "-c",
            "tools/attribution/about.toml",
            "tools/attribution/about.hbs",
            "-o",
        ])
        .arg(&generated_path)
        .output()
        .expect("cargo-about not found; install with `cargo install cargo-about --locked`");

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("cargo about generate failed:\nstdout:\n{stdout}\nstderr:\n{stderr}");
    }

    let generated = std::fs::read_to_string(&generated_path).expect("reading generated output");
    let checked_in = std::fs::read_to_string(root.join("THIRD-PARTY-NOTICES"))
        .expect("reading THIRD-PARTY-NOTICES at workspace root");

    if generated != checked_in {
        panic!("THIRD-PARTY-NOTICES is stale. Regenerate with:\n  {REGENERATE_CMD}");
    }
}
