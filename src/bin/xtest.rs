//! Build cross-architecture rumpel binaries and run cargo test.
//!
//! This ensures tests run against a binary that has all cross-arch
//! siblings available next to it, matching the production layout.
//!
//! Usage: cargo xtest [args for cargo test...]

use std::path::Path;
use std::process::{self, Command};

/// (cargo target triple, binary name in flat layout)
const LINUX_TARGETS: &[(&str, &str)] = &[
    ("x86_64-unknown-linux-musl", "rumpel-linux-amd64"),
    ("aarch64-unknown-linux-musl", "rumpel-linux-arm64"),
];

fn main() {
    let code = run();
    process::exit(code);
}

fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut targets: Vec<(&str, &str)> = Vec::new();

    if cfg!(target_os = "macos") {
        targets.push(("aarch64-apple-darwin", "rumpel-darwin-arm64"));
    }
    targets.extend_from_slice(LINUX_TARGETS);

    for (triple, _) in &targets {
        eprint!("Building rumpel for {triple}... ");
        let status = Command::new("cargo")
            .args(["build", "--bin", "rumpel", "--target", triple])
            .status()
            .unwrap_or_else(|e| {
                eprintln!("failed to run cargo build: {e}");
                process::exit(1);
            });
        if !status.success() {
            return status.code().unwrap_or(1);
        }
        eprintln!("ok");
    }

    // Flat binary directory matching the production layout
    let tmp = tempfile::tempdir().unwrap_or_else(|e| {
        eprintln!("failed to create temp dir: {e}");
        process::exit(1);
    });

    let native_triple = if cfg!(target_os = "macos") {
        "aarch64-apple-darwin"
    } else if cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-musl"
    } else {
        "aarch64-unknown-linux-musl"
    };

    for (triple, name) in &targets {
        let src = Path::new("target")
            .join(triple)
            .join("debug")
            .join("rumpel");
        let dst = tmp.path().join(name);
        std::fs::copy(&src, &dst).unwrap_or_else(|e| {
            eprintln!("failed to copy {} -> {}: {e}", src.display(), dst.display());
            process::exit(1);
        });
    }

    // The test helpers invoke "rumpel" by name
    let native_src = Path::new("target")
        .join(native_triple)
        .join("debug")
        .join("rumpel");
    let rumpel = tmp.path().join("rumpel");
    std::fs::copy(&native_src, &rumpel).unwrap_or_else(|e| {
        eprintln!("failed to copy native binary: {e}");
        process::exit(1);
    });

    let status = Command::new("cargo")
        .arg("test")
        .args(&args)
        .env("RUMPEL_BIN", &rumpel)
        .status()
        .unwrap_or_else(|e| {
            eprintln!("failed to run cargo test: {e}");
            process::exit(1);
        });

    // tmp is dropped here, cleaning up the copies
    status.code().unwrap_or(1)
}
