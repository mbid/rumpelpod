// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root above rumpelpod crate")
        .to_path_buf()
}

#[test]
fn pipeline_denies_warnings_without_overriding_target_rustflags() {
    let root = workspace_root();
    let workspace_manifest =
        fs::read_to_string(root.join("Cargo.toml")).expect("read workspace manifest");
    assert!(
        workspace_manifest.contains("[workspace.lints.rust]")
            && workspace_manifest.contains("warnings = \"deny\""),
        "the workspace did not deny Rust warnings"
    );
    for member in ["rumpelpod", "tools"] {
        let member_manifest = fs::read_to_string(root.join(member).join("Cargo.toml"))
            .unwrap_or_else(|error| panic!("read {member} manifest: {error}"));
        assert!(
            member_manifest.contains("[lints]\nworkspace = true"),
            "{member} did not inherit workspace lints"
        );
    }

    let pipeline =
        fs::read_to_string(root.join("tools/src/bin/pipeline.rs")).expect("read Cargo pipeline");
    assert!(
        pipeline.contains("command.env_remove(\"RUSTFLAGS\")")
            && !pipeline.contains(".env(\"RUSTFLAGS\""),
        "pipeline builds did not preserve target-specific Rust flags"
    );
    assert_eq!(
        pipeline.matches("tools::cargo_cmd()").count(),
        1,
        "a pipeline Cargo command bypassed the target-flag-preserving wrapper"
    );
}
