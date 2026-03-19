//! Build a "prepared" Docker image that pre-installs the rumpel binary,
//! a repo clone, and (optionally) the Claude CLI on top of the resolved
//! devcontainer image.  This avoids repeating expensive setup steps every
//! time a container is created.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result};
use indoc::formatdoc;
use sha2::{Digest, Sha256};

use crate::cli::PrepareImageCommand;
use crate::config::Host;
use crate::image::{BuildResult, Image};
use crate::CommandExt;

/// GCS bucket hosting Claude Code releases (mirrors pod/pty.rs).
const CLAUDE_CODE_DIST_BUCKET: &str =
    "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases";

/// Bump this when the Dockerfile template changes in a way that
/// invalidates previously built prepared images.
const SCHEMA_VERSION: u32 = 2;

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
///
/// After the rumpel binary is installed, remaining setup (repo clone,
/// Claude CLI) is delegated to `rumpel prepare-image` so the logic
/// lives in Rust instead of shell.
fn generate_dockerfile(
    base_image: &str,
    container_repo_path: &Path,
    user: &str,
    claude_info: Option<&HostClaudeInfo>,
) -> String {
    let repo_path = container_repo_path.display();
    let rumpel = crate::daemon::RUMPEL_CONTAINER_BIN;

    let claude_flag = match claude_info {
        Some(info) => format!(" \\\n      --claude-version '{}'", info.version),
        None => String::new(),
    };

    formatdoc! {r#"
        FROM {base_image}
        USER root

        COPY rumpel-linux-* /tmp/
        RUN set -e; \
            mkdir -p /opt/rumpelpod/bin; \
            case "$(uname -m)" in \
              x86_64)  cp /tmp/rumpel-linux-amd64 {rumpel} ;; \
              aarch64) cp /tmp/rumpel-linux-arm64 {rumpel} ;; \
              *) echo "unsupported arch" >&2; exit 1 ;; \
            esac; \
            chmod +x {rumpel}; \
            rm -f /tmp/rumpel-linux-*

        RUN --mount=type=bind,from=gateway,target=/tmp/gateway \
            {rumpel} prepare-image \
              --gateway /tmp/gateway \
              --repo-path '{repo_path}' \
              --user '{user}'{claude_flag}

        USER {user}
    "#}
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

/// Run `docker buildx build`, suppressing output on success.
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

    cmd.success().context("building prepared image")?;
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

    run_docker_build(&tag, build_ctx.path(), gateway_path, docker_host)?;

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

// ---------------------------------------------------------------------------
// `rumpel prepare-image` subcommand -- runs inside the container at build time
// ---------------------------------------------------------------------------

/// Clone the repo and optionally install the Claude CLI.
///
/// Invoked as a Dockerfile RUN step after the rumpel binary itself has
/// been copied in.  Replaces what used to be shell scripting.
pub fn run_prepare_image(cmd: &PrepareImageCommand) -> Result<()> {
    if !cmd.repo_path.join(".git").exists() {
        let gateway = cmd.gateway.display();
        let status = Command::new("git")
            .args(["clone", &format!("file://{gateway}")])
            .arg(&cmd.repo_path)
            .status()
            .context("cloning repository from gateway")?;
        if !status.success() {
            return Err(anyhow::anyhow!("git clone failed"));
        }

        let status = Command::new("chown")
            .args(["-R", &cmd.user])
            .arg(&cmd.repo_path)
            .status()
            .context("setting repository ownership")?;
        if !status.success() {
            return Err(anyhow::anyhow!("chown failed"));
        }
    }

    if let Some(ref version) = cmd.claude_version {
        install_claude_cli(version)?;
    }

    Ok(())
}

/// Download and install the Claude CLI at a specific version.
///
/// Skips if a `claude` binary is already present.
fn install_claude_cli(version: &str) -> Result<()> {
    let bin_path = Path::new(crate::daemon::CLAUDE_CONTAINER_BIN);
    if bin_path.exists() {
        return Ok(());
    }
    if Command::new("claude")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
    {
        return Ok(());
    }

    let platform = match std::env::consts::ARCH {
        "x86_64" => "linux-x64",
        "aarch64" => "linux-arm64",
        other => return Err(anyhow::anyhow!("unsupported architecture '{other}'")),
    };

    let url = format!("{CLAUDE_CODE_DIST_BUCKET}/{version}/{platform}/claude");
    let client = reqwest::blocking::Client::new();
    let data = client
        .get(&url)
        .send()
        .with_context(|| format!("downloading Claude CLI from {url}"))?
        .error_for_status()
        .with_context(|| format!("downloading Claude CLI from {url}"))?
        .bytes()
        .with_context(|| format!("reading Claude CLI binary from {url}"))?;

    if let Some(parent) = bin_path.parent() {
        fs::create_dir_all(parent).context("creating /opt/rumpelpod/bin")?;
    }
    fs::write(bin_path, &data).context("writing Claude CLI binary")?;
    fs::set_permissions(bin_path, fs::Permissions::from_mode(0o755))
        .context("making Claude CLI binary executable")?;

    Ok(())
}
