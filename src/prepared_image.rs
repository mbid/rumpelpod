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
use crate::git::GitRemote;
use crate::image::{BuildResult, Image};
use crate::CommandExt;

/// GCS bucket hosting Claude Code releases (mirrors pod/pty.rs).
const CLAUDE_CODE_DIST_BUCKET: &str =
    "https://storage.googleapis.com/claude-code-dist-86c565f3-f756-42ad-8dfa-d59b1c096819/claude-code-releases";

/// Bump this when the Dockerfile template changes in a way that
/// invalidates previously built prepared images.
const SCHEMA_VERSION: u32 = 4;

/// Where the gateway bare repo is bind-mounted during `docker build`.
/// Must match the `--mount` target in `generate_dockerfile`.
const BUILD_GATEWAY_PATH: &str = "/tmp/gateway";

/// Remotes managed by rumpelpod itself.  These point to local gateway
/// paths that change across daemon restarts (and test runs), so they
/// must not influence the prepared image tag.
const MANAGED_REMOTES: &[&str] = &["host", "rumpelpod"];

/// Information about the Claude CLI on the host, used to pin the
/// exact version inside the prepared image.
struct HostClaudeInfo {
    version: String,
}

/// Build-time version string that changes whenever the source or git
/// state changes.  Used instead of hashing the (potentially huge)
/// binary at runtime.
const RUMPEL_VERSION_INFO: &str = env!("RUMPELPOD_VERSION_INFO");

/// Try to detect Claude CLI on the host and return its version.
///
/// Uses the client-provided path if available, falling back to a
/// PATH search (for backwards compatibility with older clients).
/// `claude --version` outputs e.g. "2.1.79 (Claude Code)"; we
/// extract just the semver portion.
fn detect_host_claude(claude_cli_path: Option<&Path>) -> Option<HostClaudeInfo> {
    let bin = match claude_cli_path {
        Some(path) => path.to_path_buf(),
        None => PathBuf::from("claude"),
    };
    let output = Command::new(&bin)
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

/// Compute a deterministic tag for the prepared image.
///
/// Inputs hashed: base image tag, rumpel version, container repo path,
/// user, Claude CLI version (if available), user-configured remotes,
/// schema version.
fn compute_prepared_tag(
    base_image: &str,
    container_repo_path: &Path,
    user: &str,
    claude_info: Option<&HostClaudeInfo>,
    host_remotes: &[GitRemote],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(base_image.as_bytes());
    hasher.update(RUMPEL_VERSION_INFO.as_bytes());
    hasher.update(container_repo_path.as_os_str().as_encoded_bytes());
    hasher.update(user.as_bytes());
    if let Some(info) = claude_info {
        hasher.update(info.version.as_bytes());
    }
    for remote in host_remotes {
        if MANAGED_REMOTES.contains(&remote.name.as_str()) {
            continue;
        }
        hasher.update(remote.name.as_bytes());
        hasher.update(b"=");
        hasher.update(remote.url.as_bytes());
        hasher.update(b"\0");
    }
    hasher.update(SCHEMA_VERSION.to_le_bytes());
    let hash = hex::encode(&hasher.finalize()[..8]);
    format!("rumpelpod-prepared-{hash}")
}

/// Probe the base image's default USER by running a dummy build.
///
/// We cannot inspect the image directly because it may live on a remote
/// builder or registry.  A minimal `docker buildx build` with
/// `--progress=plain` runs `id -un` inside the image and we parse the
/// username from the build log.  The base image layers are already
/// cached, so this adds negligible overhead.
fn probe_base_image_user(base_image: &str, docker_host: &Host) -> Result<String> {
    let tmp = tempfile::tempdir().context("creating probe build context")?;
    let marker = "RUMPELPOD_BASE_USER";
    let dockerfile = formatdoc! {r#"
        FROM {base_image}
        RUN echo {marker}=$(id -un)
    "#};
    fs::write(tmp.path().join("Dockerfile"), dockerfile).context("writing probe Dockerfile")?;

    let build_host = match docker_host {
        Host::Kubernetes { .. } => &Host::Localhost,
        other => other,
    };
    let mut cmd = Command::new("docker");
    if let Some(uri) = build_host.docker_host_uri() {
        cmd.args(["-H", &uri]);
    }
    cmd.args(["buildx", "build"]);
    cmd.args(["--progress=plain", "--no-cache"]);
    let dockerfile_path = tmp.path().join("Dockerfile");
    let dockerfile_path = dockerfile_path.display();
    cmd.arg(format!("-f={dockerfile_path}"));
    cmd.arg(tmp.path().display().to_string());

    let output = cmd.combined_output().context("probing base image user")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "probe build failed:\n{}",
            output.combined_output
        ));
    }

    // Parse "RUMPELPOD_BASE_USER=<name>" from the build log.
    // Take the last match: buildx --progress=plain prints the RUN
    // instruction itself (containing the unexpanded `$(id -un)`)
    // before the actual command output with the resolved username.
    let prefix = format!("{marker}=");
    let mut found_user = None;
    for line in output.combined_output.lines() {
        if let Some(pos) = line.find(&prefix) {
            let user = line[pos + prefix.len()..].trim();
            if !user.is_empty() {
                found_user = Some(user.to_string());
            }
        }
    }
    found_user.context("failed to parse base image user from build log")
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
    host_remotes: &[GitRemote],
) -> String {
    let repo_path = container_repo_path.display();
    let rumpel = crate::daemon::RUMPEL_CONTAINER_BIN;

    let claude_flag = match claude_info {
        Some(info) => format!(" \\\n      --claude-version '{}'", info.version),
        None => String::new(),
    };

    let remote_flags: String = host_remotes
        .iter()
        .map(|r| format!(" \\\n      --remote '{}={}'", r.name, r.url))
        .collect();

    formatdoc! {r#"
        FROM {base_image}

        ARG TARGETARCH
        ARG BASE_USER=root
        USER root

        COPY --chmod=755 rumpel-linux-${{TARGETARCH}} {rumpel}

        RUN --mount=type=bind,from=gateway,target={BUILD_GATEWAY_PATH} \
            {rumpel} prepare-image \
              --repo-path '{repo_path}' \
              --user '{user}'{claude_flag}{remote_flags}

        USER ${{BASE_USER}}
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
    host_remotes: &[GitRemote],
) -> Result<tempfile::TempDir> {
    let dockerfile = generate_dockerfile(
        base_image,
        container_repo_path,
        user,
        claude_info,
        host_remotes,
    );
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
    base_user: &str,
) -> Result<()> {
    // Symlink the gateway to a name without `.git` so buildx treats it
    // as a plain directory rather than a git URL.
    let gateway_link = build_context.join("gateway-link");
    std::os::unix::fs::symlink(gateway_path, &gateway_link).with_context(|| {
        let gw = gateway_path.display();
        format!("symlinking gateway {gw}")
    })?;

    let build_host = match docker_host {
        Host::Kubernetes { .. } => &Host::Localhost,
        other => other,
    };

    let mut cmd = Command::new("docker");
    if let Some(uri) = build_host.docker_host_uri() {
        cmd.args(["-H", &uri]);
    }
    cmd.args(["buildx", "build", "--load"]);
    cmd.arg(format!("-t={tag}"));

    let gateway_link = gateway_link.display();
    cmd.arg(format!("--build-context=gateway={gateway_link}"));
    cmd.arg(format!("--build-arg=BASE_USER={base_user}"));

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
    host_remotes: &[GitRemote],
    claude_cli_path: Option<&Path>,
) -> Result<BuildResult> {
    let claude_info = detect_host_claude(claude_cli_path);

    let tag = compute_prepared_tag(
        &base_image.0,
        container_repo_path,
        user,
        claude_info.as_ref(),
        host_remotes,
    );

    // Check local cache first.
    if docker_host.is_docker() && crate::image::image_exists(&tag, docker_host) {
        return Ok(BuildResult {
            image: Image(tag),
            built: false,
        });
    }

    // When a buildx builder is configured, build and push via that builder.
    if let Host::Kubernetes {
        ref registry,
        ref push_registry,
        ref builder,
        ..
    } = docker_host
    {
        if let (Some(registry), Some(builder)) = (registry, builder) {
            let push_reg = push_registry.as_deref().unwrap_or(registry);
            return build_prepared_image_via_buildx(
                base_image,
                gateway_path,
                container_repo_path,
                host_remotes,
                claude_info.as_ref(),
                &tag,
                builder,
                push_reg,
                registry,
            );
        }
    }

    // `docker build FROM` cannot resolve bare sha256 digests; tag them first.
    let buildable_base = ensure_buildable_tag(&base_image.0, docker_host)?;

    let base_user = probe_base_image_user(&buildable_base, docker_host)?;

    let build_ctx = assemble_build_context(
        &buildable_base,
        container_repo_path,
        user,
        claude_info.as_ref(),
        host_remotes,
    )?;

    run_docker_build(
        &tag,
        build_ctx.path(),
        gateway_path,
        docker_host,
        &base_user,
    )?;

    let final_image = match docker_host {
        Host::Kubernetes {
            push_registry: Some(ref push_reg),
            ..
        } => {
            let dest = crate::image::push_to_registry(&tag, push_reg)?;
            Image(dest)
        }
        Host::Kubernetes {
            registry: Some(ref registry),
            ..
        } => {
            let dest = crate::image::push_to_registry(&tag, registry)?;
            Image(dest)
        }
        _ => Image(tag),
    };

    Ok(BuildResult {
        image: final_image,
        built: true,
    })
}

/// Build the prepared image via a named docker buildx builder and
/// push it to the registry.
///
/// Uses the same Dockerfile as local builds but probes the base image
/// user through the builder (since the base image may only be reachable
/// from the builder, not from localhost).
#[allow(clippy::too_many_arguments)]
fn build_prepared_image_via_buildx(
    base_image: &Image,
    gateway_path: &Path,
    container_repo_path: &Path,
    host_remotes: &[GitRemote],
    claude_info: Option<&HostClaudeInfo>,
    tag: &str,
    builder: &str,
    push_registry: &str,
    pull_registry: &str,
) -> Result<BuildResult> {
    let push_tag = format!("{push_registry}:{tag}");
    let pull_tag = format!("{pull_registry}:{tag}");

    // Check if the image already exists locally.
    if crate::image::image_exists(tag, &Host::Localhost) {
        let _ = crate::image::push_to_registry(tag, push_registry);
        return Ok(BuildResult {
            image: Image(pull_tag),
            built: false,
        });
    }

    // Probe the base image user via the builder so it works even when
    // the base image is in a registry only the builder can reach.
    // The probed user is used both as BASE_USER (final Dockerfile USER)
    // and as the --user for prepare-image (chown target), because the
    // devcontainer config's containerUser may not be set and the pod
    // will run as the image's default USER.
    let base_user = probe_base_image_user_via_buildx(&base_image.0, builder)?;

    let build_ctx = assemble_build_context(
        &base_image.0,
        container_repo_path,
        &base_user,
        claude_info,
        host_remotes,
    )?;

    // Symlink the gateway to a name without `.git` so buildx treats it
    // as a plain directory rather than a git URL.
    let gateway_link = build_ctx.path().join("gateway-link");
    std::os::unix::fs::symlink(gateway_path, &gateway_link).with_context(|| {
        let gw = gateway_path.display();
        format!("symlinking gateway {gw}")
    })?;

    let mut cmd = Command::new("docker");
    cmd.args(["buildx", "build"]);
    cmd.args(["--builder", builder]);
    cmd.args(["--push"]);
    cmd.args(["--provenance=false", "--sbom=false"]);
    cmd.args(["-t", &push_tag]);

    let gateway_link_display = gateway_link.display();
    cmd.arg(format!("--build-context=gateway={gateway_link_display}"));
    cmd.arg(format!("--build-arg=BASE_USER={base_user}"));

    let dockerfile = build_ctx.path().join("Dockerfile");
    let dockerfile_display = dockerfile.display();
    cmd.arg(format!("-f={dockerfile_display}"));
    cmd.arg(build_ctx.path().display().to_string());

    use crate::CommandExt;
    cmd.success()
        .context("building prepared image via buildx")?;

    Ok(BuildResult {
        image: Image(pull_tag),
        built: true,
    })
}

/// Probe the base image's default USER via a buildx builder.
///
/// Same approach as `probe_base_image_user` but routes through the
/// named builder so images in registries only the builder can reach
/// are accessible.
fn probe_base_image_user_via_buildx(base_image: &str, builder: &str) -> Result<String> {
    let tmp = tempfile::tempdir().context("creating probe build context")?;
    let marker = "RUMPELPOD_BASE_USER";
    let dockerfile = formatdoc! {r#"
        FROM {base_image}
        RUN echo {marker}=$(id -un)
    "#};
    fs::write(tmp.path().join("Dockerfile"), dockerfile).context("writing probe Dockerfile")?;

    let mut cmd = Command::new("docker");
    cmd.args(["buildx", "build"]);
    cmd.args(["--builder", builder]);
    cmd.args(["--progress=plain", "--no-cache"]);
    let dockerfile_path = tmp.path().join("Dockerfile");
    let dockerfile_path = dockerfile_path.display();
    cmd.arg(format!("-f={dockerfile_path}"));
    cmd.arg(tmp.path().display().to_string());

    use crate::CommandExt;
    let output = cmd
        .combined_output()
        .context("probing base image user via buildx")?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "probe build failed:\n{}",
            output.combined_output
        ));
    }

    let prefix = format!("{marker}=");
    let mut found_user = None;
    for line in output.combined_output.lines() {
        if let Some(pos) = line.find(&prefix) {
            let user = line[pos + prefix.len()..].trim();
            if !user.is_empty() {
                found_user = Some(user.to_string());
            }
        }
    }
    found_user.context("failed to parse base image user from build log")
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
        let status = Command::new("git")
            .args(["clone", &format!("file://{BUILD_GATEWAY_PATH}")])
            .arg(&cmd.repo_path)
            .status()
            .context("cloning repository from gateway")?;
        if !status.success() {
            return Err(anyhow::anyhow!("git clone failed"));
        }
    }

    // Ensure the repo is owned by the container user.  The base image
    // may have created it under a different UID (e.g. COPY --chown).
    let status = Command::new("chown")
        .args(["-R", &cmd.user])
        .arg(&cmd.repo_path)
        .status()
        .context("setting repository ownership")?;
    if !status.success() {
        return Err(anyhow::anyhow!("chown failed"));
    }

    // Configure host remotes in the cloned repo so they match the
    // host's configuration from the start.
    configure_remotes(&cmd.repo_path, &cmd.remotes)?;

    if let Some(ref version) = cmd.claude_version {
        install_claude_cli(version)?;
    }

    // Let the container user write to /opt/rumpelpod (e.g. the server token
    // file).  The binary keeps its 755 permissions regardless of owner.
    let status = Command::new("chown")
        .args(["-R", &cmd.user, "/opt/rumpelpod"])
        .status()
        .context("setting /opt/rumpelpod ownership")?;
    if !status.success() {
        return Err(anyhow::anyhow!("chown /opt/rumpelpod failed"));
    }

    Ok(())
}

/// Parse "NAME=URL" remote specs and add/update them in the repo.
///
/// Also removes any pre-existing remotes (from the base image) that
/// are not in the provided list and not rumpelpod-managed.
fn configure_remotes(repo_path: &Path, remote_specs: &[String]) -> Result<()> {
    if remote_specs.is_empty() {
        return Ok(());
    }

    let parsed: Vec<(&str, &str)> = remote_specs
        .iter()
        .map(|s| {
            s.split_once('=')
                .with_context(|| format!("invalid --remote spec '{s}', expected NAME=URL"))
        })
        .collect::<Result<_>>()?;

    // List existing remotes in the repo.
    let existing_output = Command::new("git")
        .args(["remote"])
        .current_dir(repo_path)
        .output()
        .context("listing existing remotes")?;
    let existing: Vec<&str> = std::str::from_utf8(&existing_output.stdout)
        .context("non-UTF-8 remote names")?
        .lines()
        .collect();

    let managed = MANAGED_REMOTES;

    // Remove stale remotes that are not in the host list and not managed.
    for name in &existing {
        if managed.contains(name) {
            continue;
        }
        if !parsed.iter().any(|(n, _)| n == name) {
            Command::new("git")
                .args(["remote", "remove", name])
                .current_dir(repo_path)
                .status()
                .with_context(|| format!("removing remote '{name}'"))?;
        }
    }

    // Add or update remotes from the host.
    for (name, url) in &parsed {
        if managed.contains(name) {
            continue;
        }
        if existing.contains(name) {
            Command::new("git")
                .args(["remote", "set-url", name, url])
                .current_dir(repo_path)
                .status()
                .with_context(|| format!("setting URL for remote '{name}'"))?;
        } else {
            Command::new("git")
                .args(["remote", "add", name, url])
                .current_dir(repo_path)
                .status()
                .with_context(|| format!("adding remote '{name}'"))?;
        }
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
