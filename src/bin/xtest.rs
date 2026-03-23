//! Build cross-architecture rumpel binaries and run cargo test.
//!
//! This ensures tests run against a binary that has all cross-arch
//! siblings available next to it, matching the production layout.
//!
//! By default, rumpel binaries are built with opt-level=z and no debug
//! info to keep them small (~28 MB vs ~263 MB).  Every test copies this
//! binary into a Docker image, so size directly affects test speed.
//!
//! Set `XTEST_OPT_LEVEL` to override the optimization level (0/1/2/3/s/z).
//! Set `XTEST_DEBUG` to override the debug info level (0/1/2).
//!
//! Usage: cargo xtest [args for cargo test...]

use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, ExitCode};

use anyhow::{Context, Result};
use rumpelpod::CommandExt;

/// (cargo target triple, binary name in flat layout)
const LINUX_TARGETS: &[(&str, &str)] = &[
    ("x86_64-unknown-linux-musl", "rumpel-linux-amd64"),
    ("aarch64-unknown-linux-musl", "rumpel-linux-arm64"),
];

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// `cargo run` injects CARGO_PKG_*, CARGO_MANIFEST_DIR, OUT_DIR, etc. into
/// the binary it launches.  Child cargo processes inherit these, and Cargo
/// fingerprints them into dependency build scripts.  On the next `cargo xtest`
/// (launched from a shell without those vars) the fingerprints mismatch and
/// ring + its dependents recompile.  Strip everything Cargo injects.
fn cargo_cmd() -> Command {
    let mut cmd = Command::new("cargo");
    for (key, _) in std::env::vars() {
        let dominated = key.starts_with("CARGO_")
            || key.starts_with("DEP_")
            || matches!(
                key.as_str(),
                "OUT_DIR" | "TARGET" | "HOST" | "NUM_JOBS" | "OPT_LEVEL" | "PROFILE" | "DEBUG"
            );
        if dominated {
            cmd.env_remove(&key);
        }
    }
    cmd
}

fn run() -> Result<ExitCode> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let opt_level = std::env::var("XTEST_OPT_LEVEL").unwrap_or_else(|_| "z".to_string());
    let debug = std::env::var("XTEST_DEBUG").unwrap_or_else(|_| "0".to_string());

    let mut targets: Vec<(&str, &str)> = Vec::new();
    if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        targets.push(("aarch64-apple-darwin", "rumpel-darwin-arm64"));
    }
    targets.extend_from_slice(LINUX_TARGETS);

    for (triple, _) in &targets {
        eprint!("Building rumpel for {triple}... ");
        cargo_cmd()
            .args(["build", "--bin", "rumpel", "--target", triple])
            .env("CARGO_PROFILE_DEV_OPT_LEVEL", &opt_level)
            .env("CARGO_PROFILE_DEV_DEBUG", &debug)
            .success()
            .with_context(|| format!("building rumpel for {triple}"))?;
        eprintln!("ok");
    }

    let tmp = tempfile::tempdir().context("creating temp dir")?;

    for (triple, name) in &targets {
        let src = Path::new("target")
            .join(triple)
            .join("debug")
            .join("rumpel");
        let dst = tmp.path().join(name);
        std::fs::copy(&src, &dst).with_context(|| {
            let src = src.display();
            let dst = dst.display();
            format!("copying {src} -> {dst}")
        })?;
    }

    let native_name = if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        "rumpel-darwin-arm64"
    } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "rumpel-linux-amd64"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "rumpel-linux-arm64"
    } else {
        return Err(anyhow::anyhow!(
            "unsupported host platform: {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ));
    };
    symlink(native_name, tmp.path().join("rumpel"))
        .context("symlinking rumpel to native binary")?;

    let path = std::env::var("PATH").context("PATH not set")?;
    let tmp_path = tmp.path().display();
    let path = format!("{tmp_path}:{path}");

    let status = cargo_cmd()
        .arg("test")
        .args(&args)
        .env("PATH", &path)
        .status()
        .context("running cargo test")?;

    Ok(if status.success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
