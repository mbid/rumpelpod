//! Build a "prepared" Docker image that pre-installs the rumpel binary,
//! a repo clone, and (optionally) the Claude CLI on top of the resolved
//! devcontainer image.  This avoids repeating expensive setup steps every
//! time a container is created.

use std::fmt::Write;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

use crate::config::Host;
use crate::image::{BuildOutputFn, BuildResult, Image, OutputLine};

/// GCS bucket hosting Claude Code releases (mirrors pod/pty.rs).
const CLAUDE_CODE_DIST_BUCKET: &str =
    "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases";

/// Bump this when the Dockerfile template changes in a way that
/// invalidates previously built prepared images.
const SCHEMA_VERSION: u32 = 1;

/// Information about the Claude CLI on the host, used to pin the
/// exact version inside the prepared image.
struct HostClaudeInfo {
    version: String,
}

/// Try to detect Claude CLI on the host and return its version.
///
/// `claude --version` outputs e.g. "2.1.79 (Claude Code)"; we extract
/// just the semver portion.
fn detect_host_claude() -> Option<HostClaudeInfo> {
    let output = Command::new("claude")
        .arg("--version")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // Take only the first whitespace-delimited token (the version number).
    let version = raw.split_whitespace().next()?.to_string();
    if version.is_empty() {
        return None;
    }
    Some(HostClaudeInfo { version })
}

/// Find all `rumpel-linux-{amd64,arm64}` binaries next to the running
/// executable.  Returns (filename, full_path) pairs.
fn find_rumpel_binaries() -> Result<Vec<(String, PathBuf)>> {
    let exe = std::env::current_exe().context("resolving own binary path")?;
    let exe_dir = exe.parent().context("resolving executable directory")?;

    let mut binaries = Vec::new();
    for name in ["rumpel-linux-amd64", "rumpel-linux-arm64"] {
        let path = exe_dir.join(name);
        if path.exists() {
            binaries.push((name.to_string(), path));
        }
    }
    if binaries.is_empty() {
        return Err(anyhow::anyhow!(
            "no rumpel-linux-* binaries found next to {}",
            exe.display()
        ));
    }
    Ok(binaries)
}

/// Hash the content of the running rumpel binary (the current exe).
fn hash_rumpel_binary() -> Result<Vec<u8>> {
    let exe = std::env::current_exe().context("resolving own binary path")?;
    let data = fs::read(&exe).with_context(|| {
        let exe = exe.display();
        format!("reading {exe}")
    })?;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    Ok(hasher.finalize().to_vec())
}

/// Compute a deterministic tag for the prepared image.
///
/// Inputs hashed: base image tag, rumpel binary content, container repo
/// path, user, Claude CLI version (if available), schema version.
fn compute_prepared_tag(
    base_image: &str,
    rumpel_hash: &[u8],
    container_repo_path: &Path,
    user: &str,
    claude_info: Option<&HostClaudeInfo>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base_image.as_bytes());
    hasher.update(rumpel_hash);
    hasher.update(container_repo_path.as_os_str().as_encoded_bytes());
    hasher.update(user.as_bytes());
    if let Some(info) = claude_info {
        hasher.update(info.version.as_bytes());
    }
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    let hash = hex::encode(&hasher.finalize()[..8]);
    format!("rumpelpod-prepared-{hash}")
}

/// Generate the Dockerfile content for the prepared image.
///
/// The gateway bare repo is passed as a named build context (`gateway`)
/// and bind-mounted at build time so its contents never end up in an
/// image layer.
fn generate_dockerfile(
    base_image: &str,
    container_repo_path: &Path,
    user: &str,
    claude_info: Option<&HostClaudeInfo>,
) -> String {
    let repo_path = container_repo_path.display();

    // Build the Dockerfile line-by-line to avoid rustfmt mangling
    // indentation inside formatdoc! string literals.
    let mut df = String::new();
    writeln!(df, "FROM {base_image}").unwrap();
    writeln!(df, "USER root").unwrap();
    writeln!(df).unwrap();
    writeln!(df, "# Install rumpel binary -- pick arch at build time").unwrap();
    writeln!(df, "COPY rumpel-linux-* /tmp/").unwrap();
    // Single RUN to keep image layers minimal.
    writeln!(df, "RUN set -e; \\").unwrap();
    writeln!(df, "    mkdir -p /opt/rumpelpod/bin; \\").unwrap();
    writeln!(df, "    case \"$(uname -m)\" in \\").unwrap();
    writeln!(
        df,
        "      x86_64)  cp /tmp/rumpel-linux-amd64 /opt/rumpelpod/bin/rumpel ;; \\"
    )
    .unwrap();
    writeln!(
        df,
        "      aarch64) cp /tmp/rumpel-linux-arm64 /opt/rumpelpod/bin/rumpel ;; \\"
    )
    .unwrap();
    writeln!(df, "      *) echo \"unsupported arch\" >&2; exit 1 ;; \\").unwrap();
    writeln!(df, "    esac; \\").unwrap();
    writeln!(df, "    chmod +x /opt/rumpelpod/bin/rumpel; \\").unwrap();
    writeln!(df, "    rm -f /tmp/rumpel-linux-*").unwrap();
    writeln!(df).unwrap();
    writeln!(
        df,
        "# Clone repo from gateway bare repo (bind-mounted, not copied into layer)"
    )
    .unwrap();
    writeln!(
        df,
        "RUN --mount=type=bind,from=gateway,target=/tmp/gateway \\"
    )
    .unwrap();
    writeln!(df, "    if [ ! -d '{repo_path}/.git' ]; then \\").unwrap();
    writeln!(
        df,
        "      git clone file:///tmp/gateway '{repo_path}' && \\"
    )
    .unwrap();
    writeln!(df, "      chown -R {user} '{repo_path}'; \\").unwrap();
    writeln!(df, "    fi").unwrap();

    if let Some(info) = claude_info {
        let version = &info.version;
        writeln!(df).unwrap();
        writeln!(
            df,
            "# Install Claude CLI at the version pinned from the host"
        )
        .unwrap();
        writeln!(df, "RUN set -e; \\").unwrap();
        writeln!(
            df,
            "    if command -v claude >/dev/null 2>&1 || [ -x /opt/rumpelpod/bin/claude ]; then \\"
        )
        .unwrap();
        writeln!(df, "      exit 0; \\").unwrap();
        writeln!(df, "    fi; \\").unwrap();
        writeln!(df, "    BUCKET='{CLAUDE_CODE_DIST_BUCKET}'; \\").unwrap();
        writeln!(df, "    VERSION='{version}'; \\").unwrap();
        writeln!(df, "    PLATFORM=$(case \"$(uname -m)\" in x86_64) echo linux-x64;; aarch64) echo linux-arm64;; *) echo unsupported; exit 1;; esac); \\").unwrap();
        writeln!(df, "    if command -v curl >/dev/null 2>&1; then \\").unwrap();
        writeln!(df, "      curl -fsSL -o /opt/rumpelpod/bin/claude \"$BUCKET/$VERSION/$PLATFORM/claude\"; \\").unwrap();
        writeln!(df, "    elif command -v wget >/dev/null 2>&1; then \\").unwrap();
        writeln!(
            df,
            "      wget -qO /opt/rumpelpod/bin/claude \"$BUCKET/$VERSION/$PLATFORM/claude\"; \\"
        )
        .unwrap();
        writeln!(df, "    else \\").unwrap();
        writeln!(df, "      exit 0; \\").unwrap();
        writeln!(df, "    fi; \\").unwrap();
        writeln!(df, "    chmod +x /opt/rumpelpod/bin/claude").unwrap();
    }

    // Restore the original user so the container starts with the same
    // default USER as the base image.
    writeln!(df).unwrap();
    writeln!(df, "USER {user}").unwrap();

    df
}

/// Assemble the build context directory with the Dockerfile and binaries.
///
/// The gateway is NOT included here -- it is passed separately via
/// `--build-context` so buildx can transfer it efficiently and the
/// Dockerfile bind-mounts it without baking it into a layer.
fn assemble_build_context(
    base_image: &str,
    container_repo_path: &Path,
    user: &str,
    claude_info: Option<&HostClaudeInfo>,
) -> Result<tempfile::TempDir> {
    let dockerfile = generate_dockerfile(base_image, container_repo_path, user, claude_info);
    let binaries = find_rumpel_binaries()?;

    let tmp = tempfile::tempdir().context("creating build context temp dir")?;
    fs::write(tmp.path().join("Dockerfile"), dockerfile)
        .context("writing Dockerfile to build context")?;
    for (name, path) in &binaries {
        fs::copy(path, tmp.path().join(name)).with_context(|| {
            let path = path.display();
            format!("copying {path} to build context")
        })?;
    }

    Ok(tmp)
}

/// Run `docker buildx build` and stream output through the callback.
///
/// Uses `--build-context` to pass the gateway bare repo to the builder.
/// Buildx misidentifies bare git repos (paths containing a HEAD file)
/// as remote git URLs, so we create a symlink without the `.git` suffix
/// to force local-directory treatment.
fn run_docker_build(
    tag: &str,
    build_context: &Path,
    gateway_path: &Path,
    docker_host: &Host,
    on_output: Option<BuildOutputFn>,
) -> Result<()> {
    // Symlink the gateway to a name without `.git` so buildx treats it
    // as a plain directory rather than a git URL.
    let gateway_link = build_context.join("gateway-link");
    std::os::unix::fs::symlink(gateway_path, &gateway_link).with_context(|| {
        let gw = gateway_path.display();
        format!("symlinking gateway {gw}")
    })?;

    let mut cmd = Command::new("docker");

    match docker_host {
        Host::Localhost | Host::Ssh { .. } => {
            if let Some(uri) = docker_host.docker_host_uri() {
                cmd.args(["-H", &uri]);
            }
            cmd.args(["buildx", "build", "--load"]);
            cmd.arg(format!("-t={tag}"));
        }
        Host::Kubernetes {
            context,
            registry: Some(ref registry),
            ref pull_registry,
            ..
        } => {
            let push_reg = pull_registry.as_deref().unwrap_or(registry);
            let builder = crate::image::ensure_buildx_builder(context, push_reg)?;
            cmd.args(["buildx", "build"]);
            cmd.args(["--builder", &builder]);
            let dest = format!("{push_reg}:{tag}");
            cmd.arg(format!("--output=type=image,name={dest},push=true"));
        }
        Host::Kubernetes { registry: None, .. } => {
            return Err(anyhow::anyhow!(
                "Building prepared images for Kubernetes requires a registry"
            ));
        }
    }

    let gateway_link = gateway_link.display();
    cmd.arg(format!("--build-context=gateway={gateway_link}"));

    let dockerfile = build_context.join("Dockerfile");
    let dockerfile = dockerfile.display();
    cmd.arg(format!("-f={dockerfile}"));
    cmd.arg(build_context.display().to_string());

    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().context("spawning docker build")?;

    let child_stdout = child.stdout.take().expect("stdout was piped");
    let child_stderr = child.stderr.take().expect("stderr was piped");

    let callback = on_output.map(|cb| std::sync::Arc::new(std::sync::Mutex::new(cb)));
    let callback_for_stderr = callback.clone();

    let stdout_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stderr_buf = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
    let stdout_buf_clone = stdout_buf.clone();
    let stderr_buf_clone = stderr_buf.clone();

    let stdout_thread = std::thread::spawn(move || {
        for line in BufReader::new(child_stdout).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            stdout_buf_clone.lock().unwrap().push_str(&line);
            stdout_buf_clone.lock().unwrap().push('\n');
            if let Some(ref cb) = callback {
                cb.lock().unwrap()(OutputLine::Stdout(line));
            }
        }
    });

    let stderr_thread = std::thread::spawn(move || {
        for line in BufReader::new(child_stderr).lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            stderr_buf_clone.lock().unwrap().push_str(&line);
            stderr_buf_clone.lock().unwrap().push('\n');
            if let Some(ref cb) = callback_for_stderr {
                cb.lock().unwrap()(OutputLine::Stderr(line));
            }
        }
    });

    let status = child.wait()?;
    stdout_thread.join().expect("stdout reader panicked");
    stderr_thread.join().expect("stderr reader panicked");

    if !status.success() {
        let stdout = stdout_buf.lock().unwrap();
        let stderr = stderr_buf.lock().unwrap();
        return Err(anyhow::anyhow!(
            "docker build (prepared image) failed:\nSTDOUT: {stdout}\nSTDERR: {stderr}"
        ));
    }

    Ok(())
}

/// Tag an image by its sha256 digest so `docker build FROM` can reference it.
///
/// `docker build` cannot resolve bare `sha256:...` image IDs in FROM
/// lines.  Tagging it with a friendly name works around this.
fn ensure_buildable_tag(image: &str, docker_host: &Host) -> Result<String> {
    if !image.starts_with("sha256:") {
        return Ok(image.to_string());
    }
    let friendly = format!("rumpelpod-base-{}", &image[7..23]);
    let mut cmd = Command::new("docker");
    if let Some(uri) = docker_host.docker_host_uri() {
        cmd.args(["-H", &uri]);
    }
    cmd.args(["tag", image, &friendly]);
    let status = cmd
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("tagging base image for prepared build")?;
    if !status.success() {
        return Err(anyhow::anyhow!(
            "failed to tag image '{image}' as '{friendly}'"
        ));
    }
    Ok(friendly)
}

/// Build (or reuse a cached) prepared image on top of `base_image`.
///
/// The prepared image includes the rumpel binary, a git clone of the
/// repo from the gateway, and optionally the Claude CLI.
///
/// Returns a `BuildResult` indicating the final image tag and whether
/// a build actually ran.
pub fn build_prepared_image(
    base_image: &Image,
    docker_host: &Host,
    gateway_path: &Path,
    container_repo_path: &Path,
    user: &str,
    on_output: Option<BuildOutputFn>,
) -> Result<BuildResult> {
    let rumpel_hash = hash_rumpel_binary()?;
    let claude_info = detect_host_claude();

    let tag = compute_prepared_tag(
        &base_image.0,
        &rumpel_hash,
        container_repo_path,
        user,
        claude_info.as_ref(),
    );

    // Check cache: for Docker hosts check locally, for k8s we always
    // rebuild (buildx handles caching via registry layers).
    if docker_host.is_docker() && crate::image::image_exists(&tag, docker_host) {
        return Ok(BuildResult {
            image: Image(tag),
            built: false,
        });
    }

    // `docker build FROM` cannot resolve bare sha256 digests; tag them first.
    let buildable_base = ensure_buildable_tag(&base_image.0, docker_host)?;

    let build_ctx = assemble_build_context(
        &buildable_base,
        container_repo_path,
        user,
        claude_info.as_ref(),
    )?;

    run_docker_build(&tag, build_ctx.path(), gateway_path, docker_host, on_output)?;

    let final_image = match docker_host {
        Host::Kubernetes {
            registry: Some(ref registry),
            ref pull_registry,
            ..
        } => {
            let pull_reg = pull_registry.as_deref().unwrap_or(registry);
            Image(format!("{pull_reg}:{tag}"))
        }
        _ => Image(tag),
    };

    Ok(BuildResult {
        image: final_image,
        built: true,
    })
}
