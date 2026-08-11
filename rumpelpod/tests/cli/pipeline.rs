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

#[test]
fn devcontainer_defers_daemon_install_to_pipeline() {
    let root = workspace_root();
    let config: serde_json::Value = json5::from_str(
        &fs::read_to_string(root.join(".devcontainer/devcontainer.json"))
            .expect("read development container configuration"),
    )
    .expect("parse development container configuration");
    assert!(
        config.get("postCreateCommand").is_none(),
        "daemon installation depended on a post-create lifecycle command"
    );

    let dockerfile =
        fs::read_to_string(root.join(".devcontainer/Dockerfile")).expect("read Dockerfile");
    assert!(
        dockerfile.contains("touch /var/lib/systemd/linger/${USER}"),
        "the image did not arrange a user manager at container boot"
    );
    assert!(
        dockerfile.contains("docker-compose"),
        "the combined development image could not run Compose pod tests"
    );
    assert!(
        !dockerfile.contains("system-install")
            && !dockerfile.contains("rumpelpod.socket")
            && !dockerfile.contains("rumpelpod.service"),
        "the image came with daemon units built from an unrelated revision"
    );
    assert!(
        dockerfile.contains("ENV RUMPELPOD_DEVCONTAINER=1")
            && dockerfile.contains("ENV XDG_RUNTIME_DIR=/run/user/${USER_ID}")
            && dockerfile
                .contains("ENV DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/${USER_ID}/bus"),
        "the image did not expose the deferred daemon installation environment"
    );

    let pipeline =
        fs::read_to_string(root.join("tools/src/bin/pipeline.rs")).expect("read Cargo pipeline");
    let build = pipeline
        .find(".args([\"build\", \"--all-targets\"])")
        .expect("pipeline did not build workspace binaries");
    let install = pipeline
        .find("install_devcontainer_daemon(release)?")
        .expect("pipeline did not install the development daemon");
    assert!(
        build < install
            && pipeline.contains("const DEVCONTAINER_ENV: &str = \"RUMPELPOD_DEVCONTAINER\"")
            && pipeline.contains("rumpel-linux-amd64")
            && pipeline.contains("rumpel-linux-arm64")
            && pipeline.contains("--user\", \"show-environment")
            && pipeline.contains(".arg(\"system-install\")")
            && pipeline.contains("[\"vscode\", \"--check\"]"),
        "the marked pipeline did not install its daemon and check the extension"
    );

    let ci_pipeline =
        fs::read_to_string(root.join("ci/run-pipeline.sh")).expect("read CI pipeline script");
    assert!(
        ci_pipeline.contains("manager_ready=0")
            && ci_pipeline.contains("docker inspect --format '{{.State.Running}}'")
            && ci_pipeline.contains("docker logs devcontainer"),
        "CI did not report a failed devcontainer boot"
    );
}
