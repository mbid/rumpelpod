use std::collections::HashMap;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

use anyhow::{Context, Result};
use log::{info, trace};

use crate::cli::EnterCommand;
use crate::config::{load_toml_config, Host};
use crate::daemon;
use crate::daemon::protocol::{
    Daemon, DaemonClient, LaunchProgress, LaunchResult, PodLaunchParams, PodName,
};
use crate::devcontainer::{
    shell_escape, BuildOptions, DevContainer, GpuRequirement, HostRequirements, MountType,
    SubstitutionContext, UserEnvProbe,
};
use crate::git::{get_current_branch, get_git_user_config, get_repo_root};
use crate::image::OutputLine;

/// Dockerfile used when a project has no devcontainer.json.
const DEFAULT_DOCKERFILE: &str = indoc::indoc! {"
    FROM debian:testing

    RUN apt-get update \
     && apt-get install -y --no-install-recommends \
            ca-certificates \
            curl \
            git \
            jq \
            less \
            openssh-client \
            screen \
            sudo \
            unzip \
            vim \
            wget

    RUN useradd -m -s /bin/bash user \
     && echo 'user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/user
    USER user
"};

/// Compute the path relative from `base` to `path`.
/// Both paths must be absolute and `path` must be under `base`.
fn relative_path<'a>(base: &Path, path: &'a Path) -> Result<&'a Path> {
    path.strip_prefix(base)
        .with_context(|| format!("{} is not under {}", path.display(), base.display()))
}

/// Map the host's current directory into the corresponding container path.
fn container_workdir(devcontainer: &DevContainer, repo_root: &Path) -> Result<PathBuf> {
    let current_dir = std::env::current_dir().context("Failed to get current directory")?;
    let container_repo_path = devcontainer.container_repo_path(repo_root);
    let relative = relative_path(repo_root, &current_dir)?;
    Ok(container_repo_path.join(relative))
}

/// Parse a human-readable size string (e.g. "4gb", "512MB") into bytes.
///
/// Supports "tb", "gb", "mb", "kb" suffixes (case-insensitive).
/// Returns None if the string cannot be parsed.
pub fn parse_size_string(s: &str) -> Option<u64> {
    let s = s.trim().to_lowercase();

    let suffixes: &[(&str, u64)] = &[
        ("tb", 1024 * 1024 * 1024 * 1024),
        ("gb", 1024 * 1024 * 1024),
        ("mb", 1024 * 1024),
        ("kb", 1024),
    ];

    for (suffix, multiplier) in suffixes {
        if let Some(num_str) = s.strip_suffix(suffix) {
            return num_str.trim().parse::<u64>().ok().map(|n| n * multiplier);
        }
    }

    // No suffix -- treat as raw bytes.
    s.parse::<u64>().ok()
}

/// Log hostRequirements and decide whether to enforce them based on host type.
fn check_host_requirements(requirements: &HostRequirements, docker_host: &Host) {
    let mut parts: Vec<String> = Vec::new();

    if let Some(cpus) = requirements.cpus {
        parts.push(format!("cpus={}", cpus));
    }
    if let Some(ref memory) = requirements.memory {
        match parse_size_string(memory) {
            Some(bytes) => parts.push(format!("memory={} ({} bytes)", memory, bytes)),
            None => parts.push(format!("memory={} (unparseable)", memory)),
        }
    }
    if let Some(ref storage) = requirements.storage {
        match parse_size_string(storage) {
            Some(bytes) => parts.push(format!("storage={} ({} bytes)", storage, bytes)),
            None => parts.push(format!("storage={} (unparseable)", storage)),
        }
    }
    if let Some(ref gpu) = requirements.gpu {
        match gpu {
            GpuRequirement::Required(true) => parts.push("gpu=required".to_string()),
            GpuRequirement::Required(false) => {}
            GpuRequirement::Optional(s) => parts.push(format!("gpu={}", s)),
            GpuRequirement::Detailed(details) => parts.push(format!("gpu={:?}", details)),
        }
    }

    if parts.is_empty() {
        return;
    }

    info!("hostRequirements: {}", parts.join(", "));

    // Localhost and remote Docker: the user controls their hardware, so we
    // only log.  A future orchestrator backend (e.g. Kubernetes) should match
    // here and use the parsed values to select an appropriate node or instance
    // type.
    match docker_host {
        Host::Localhost | Host::Ssh { .. } => {
            info!("Running on local/remote Docker -- hostRequirements are advisory only");
        }
        Host::Kubernetes { .. } => {
            info!("Running on Kubernetes -- hostRequirements set as pod resource requests");
        }
    }
}

/// Load devcontainer.json, validate it, and prepare it for the daemon.
///
/// Resolves `${localEnv:...}` and normalizes build paths to repo-root-relative.
/// Returns the DevContainer, parsed Host, and an optional TempDir that holds the
/// default Dockerfile (must be kept alive until the build completes).
pub fn load_and_resolve(
    repo_root: &Path,
    host_override: Option<Host>,
) -> Result<(DevContainer, Host, Option<tempfile::TempDir>)> {
    let toml_config = load_toml_config(repo_root)?;
    let docker_host = if let Some(h) = host_override {
        h
    } else if let Some(ref host_str) = toml_config.host {
        Host::parse(host_str).context("Invalid host in .rumpelpod.toml")?
    } else if let Some(ref k8s) = toml_config.k8s {
        Host::Kubernetes {
            context: k8s.context.clone(),
            namespace: k8s
                .namespace
                .clone()
                .unwrap_or_else(|| "default".to_string()),
            registry: k8s.registry.clone(),
            pull_registry: k8s.pull_registry.clone(),
        }
    } else {
        Host::Localhost
    };

    let (mut devcontainer, devcontainer_dir) = DevContainer::find_and_load(repo_root)?
        .map(|(dc, dir)| {
            dc.warn_unsupported_fields();
            (dc, dir)
        })
        .unwrap_or_else(|| (DevContainer::default(), repo_root.to_path_buf()));

    let default_image_dir = if devcontainer.image.is_none() && !devcontainer.has_build() {
        let dir = write_default_dockerfile()?;
        eprintln!("warning: no image or build configured, building default image");
        let dockerfile = dir.path().join("Dockerfile").to_string_lossy().to_string();
        let context = dir.path().to_string_lossy().to_string();
        devcontainer.build = Some(BuildOptions {
            dockerfile: Some(dockerfile),
            context: Some(context),
            ..Default::default()
        });
        Some(dir)
    } else {
        devcontainer.resolve_build_paths(&devcontainer_dir, repo_root);
        None
    };

    // Resolve ${localEnv:...} before sending to the daemon, since the daemon
    // does not have access to the calling user's environment variables.
    devcontainer = devcontainer.substitute(&SubstitutionContext {
        resolve_local_env: true,
        ..Default::default()
    });

    // Read --env-file entries from runArgs on the client side and merge them
    // into containerEnv. This must happen after localEnv substitution (env
    // file paths may use ${localEnv:...}) and before sending to the daemon,
    // since the files live on the client's filesystem.
    devcontainer
        .resolve_env_files(repo_root)
        .context("resolving --env-file from runArgs")?;

    if let Some(ref requirements) = devcontainer.host_requirements {
        check_host_requirements(requirements, &docker_host);
    }

    Ok((devcontainer, docker_host, default_image_dir))
}

/// Write the embedded default Dockerfile to a temporary directory.
fn write_default_dockerfile() -> Result<tempfile::TempDir> {
    let dir = tempfile::tempdir().context("creating temp dir for default Dockerfile")?;
    std::fs::write(dir.path().join("Dockerfile"), DEFAULT_DOCKERFILE)
        .context("writing default Dockerfile")?;
    Ok(dir)
}

/// Launch a pod and return the container ID and user.
/// This is shared logic between `enter` and `agent` commands.
pub fn launch_pod(pod_name: &str, host_override: Option<Host>) -> Result<LaunchResult> {
    let t = Instant::now();
    let repo_root = get_repo_root()?;
    let (devcontainer, docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, host_override)?;
    trace!("launch_pod config: {:?}", t.elapsed());

    // Reject bind mounts early for remote Docker
    if docker_host.is_remote() {
        for m in devcontainer.resolved_mounts()? {
            if m.mount_type == MountType::Bind {
                return Err(anyhow::anyhow!(
                    "bind mounts are not supported with remote Docker hosts. \
                     The source path '{}' would reference the remote filesystem, \
                     not your local machine. Use volume or tmpfs mounts instead.",
                    m.source.as_deref().unwrap_or("<none>")
                ));
            }
        }
    }

    let host_branch = get_current_branch(&repo_root);
    let git_identity = get_git_user_config(&repo_root);

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let t = Instant::now();
    let mut progress = client.launch_pod(PodLaunchParams {
        pod_name: PodName(pod_name.to_string()),
        repo_path: repo_root,
        host_branch,
        host: docker_host,
        devcontainer,
        git_identity: Some(git_identity),
    })?;
    for line in &mut progress {
        match line {
            OutputLine::Stdout(s) => println!("{}", s),
            OutputLine::Stderr(s) => eprintln!("{}", s),
        }
    }
    let result = progress.finish()?;
    trace!("launch_pod daemon RPC: {:?}", t.elapsed());

    Ok(result)
}

/// Merge probed environment variables with remoteEnv overrides.
/// Probed env provides the base (vars discovered from shell init files),
/// remoteEnv takes precedence on conflicts.
pub fn merge_env(
    probed: HashMap<String, String>,
    remote: Vec<(String, String)>,
) -> Vec<(String, String)> {
    let mut merged = probed;
    for (key, value) in remote {
        merged.insert(key, value);
    }
    merged.into_iter().collect()
}

/// Resolve `${containerEnv:VAR}` placeholders via the in-container HTTP server
/// instead of `docker exec`. Works for any host type including Kubernetes.
pub fn resolve_remote_env_via_pod(
    remote_env: &HashMap<String, String>,
    pod: &crate::pod::PodClient,
) -> Vec<(String, String)> {
    // Regex would be overkill -- just scan for ${containerEnv:...} patterns
    // and resolve them by running printenv in the container.
    remote_env
        .iter()
        .map(|(key, value)| {
            let resolved = resolve_container_env_vars(value, pod);
            (key.clone(), resolved)
        })
        .collect()
}

/// Replace `${containerEnv:VAR}` and `${containerEnv:VAR:default}` patterns
/// in a string by reading the variable from the container via PodClient.
fn resolve_container_env_vars(value: &str, pod: &crate::pod::PodClient) -> String {
    let mut result = String::new();
    let mut rest = value;

    while let Some(start) = rest.find("${containerEnv:") {
        result.push_str(&rest[..start]);
        let after_prefix = &rest[start + "${containerEnv:".len()..];
        if let Some(end) = after_prefix.find('}') {
            let inner = &after_prefix[..end];
            let (var_name, default) = if let Some(colon) = inner.find(':') {
                (&inner[..colon], Some(&inner[colon + 1..]))
            } else {
                (inner, None)
            };

            let val = pod
                .run(&["printenv", var_name], None, None, &[], None, Some(5))
                .ok()
                .filter(|r| r.exit_code == 0)
                .and_then(|r| {
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD
                        .decode(&r.stdout)
                        .ok()
                })
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .map(|s| s.trim_end_matches('\n').to_string());

            result.push_str(&val.unwrap_or_else(|| default.unwrap_or_default().to_string()));
            rest = &after_prefix[end + 1..];
        } else {
            // Unclosed brace, keep literal
            result.push_str(&rest[..start + "${containerEnv:".len()]);
            rest = after_prefix;
        }
    }
    result.push_str(rest);
    result
}

pub fn enter(cmd: &EnterCommand) -> Result<()> {
    let t_total = Instant::now();

    let t = Instant::now();
    let repo_root = get_repo_root()?;
    trace!("get_repo_root: {:?}", t.elapsed());

    let host_override = cmd.host_args.resolve()?;

    let t = Instant::now();
    let (devcontainer, _docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, host_override.clone())?;
    trace!("load_and_resolve: {:?}", t.elapsed());

    let container_repo_path = devcontainer.container_repo_path(&repo_root);
    let workdir = container_workdir(&devcontainer, &repo_root)?;
    let remote_env_map = devcontainer.remote_env.clone().unwrap_or_default();

    let effective_probe = devcontainer
        .user_env_probe
        .clone()
        .unwrap_or(UserEnvProbe::LoginInteractiveShell);

    let t = Instant::now();
    let result = launch_pod(&cmd.name, host_override)?;
    trace!("launch_pod: {:?}", t.elapsed());

    let mut command = cmd.command.clone();
    if command.is_empty() {
        command.push(result.user_shell.clone());
        if let Some(flags) = effective_probe.shell_flags_interactive() {
            command.push(flags.to_string());
        }
    }

    // Resolve ${containerEnv:VAR} via the in-container HTTP server (works for all host types).
    let pod = crate::pod::PodClient::new(&result.container_url, &result.container_token)?;
    let remote_env = resolve_remote_env_via_pod(&remote_env_map, &pod);
    let merged_env = merge_env(result.probed_env, remote_env);

    let status = match &result.host {
        Host::Kubernetes {
            context, namespace, ..
        } => {
            // kubectl exec has no --workdir or -e, so wrap in sh -c
            let env_prefix: String = merged_env
                .iter()
                .map(|(k, v)| format!("{}={}", k, shell_escape(v)))
                .collect::<Vec<_>>()
                .join(" ");
            let cmd_str = command
                .iter()
                .map(|s| shell_escape(s))
                .collect::<Vec<_>>()
                .join(" ");
            let wrapper = if env_prefix.is_empty() {
                format!(
                    "cd {} && exec {}",
                    shell_escape(&workdir.to_string_lossy()),
                    cmd_str
                )
            } else {
                format!(
                    "cd {} && exec env {} {}",
                    shell_escape(&workdir.to_string_lossy()),
                    env_prefix,
                    cmd_str,
                )
            };

            let mut kubectl = Command::new("kubectl");
            kubectl.args(["--context", context]);
            kubectl.args(["--namespace", namespace]);
            kubectl.args(["exec"]);
            if std::io::stdin().is_terminal() {
                kubectl.arg("-it");
            } else {
                kubectl.arg("-i");
            }
            kubectl.arg(&result.container_id.0);
            kubectl.args(["--", "sh", "-c", &wrapper]);

            trace!("total enter startup: {:?}", t_total.elapsed());
            kubectl.status()?
        }

        Host::Localhost | Host::Ssh { .. } => {
            let docker_socket = result
                .docker_socket
                .as_ref()
                .context("docker_socket is required for Docker hosts")?;

            // The host subdir may not exist in the container yet
            if workdir != container_repo_path {
                let docker_host_arg = format!("unix://{}", docker_socket.display());
                let mkdir_status = Command::new("docker")
                    .args(["-H", &docker_host_arg])
                    .args(["exec", "--user", &result.user, &result.container_id.0])
                    .args(["mkdir", "-p", &workdir.to_string_lossy()])
                    .status()
                    .context("Failed to create workdir in container")?;
                if !mkdir_status.success() {
                    return Err(anyhow::anyhow!(
                        "Failed to create workdir {} in container",
                        workdir.display()
                    ));
                }
            }

            let mut docker_cmd = Command::new("docker");
            docker_cmd.args(["-H", &format!("unix://{}", docker_socket.display())]);
            docker_cmd.arg("exec");
            docker_cmd.args(["--user", &result.user]);
            docker_cmd.args(["--workdir", &workdir.to_string_lossy()]);

            for (key, value) in &merged_env {
                docker_cmd.args(["-e", &format!("{}={}", key, value)]);
            }

            docker_cmd.arg("-i");
            if std::io::stdin().is_terminal() {
                docker_cmd.arg("-t");
            }
            docker_cmd.arg(&result.container_id.0);
            docker_cmd.args(&command);

            trace!("total enter startup: {:?}", t_total.elapsed());
            docker_cmd.status()?
        }
    };

    if !status.success() {
        return Err(anyhow::anyhow!("exec exited with status {}", status));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_size_gb() {
        assert_eq!(parse_size_string("4gb"), Some(4 * 1024 * 1024 * 1024));
    }

    #[test]
    fn parse_size_case_insensitive() {
        assert_eq!(parse_size_string("512MB"), Some(512 * 1024 * 1024));
    }

    #[test]
    fn parse_size_tb() {
        assert_eq!(
            parse_size_string("2tb"),
            Some(2 * 1024 * 1024 * 1024 * 1024)
        );
    }

    #[test]
    fn parse_size_kb() {
        assert_eq!(parse_size_string("128kb"), Some(128 * 1024));
    }

    #[test]
    fn parse_size_raw_bytes() {
        assert_eq!(parse_size_string("1048576"), Some(1048576));
    }

    #[test]
    fn parse_size_invalid() {
        assert_eq!(parse_size_string("not-a-number"), None);
    }

    #[test]
    fn parse_size_whitespace() {
        assert_eq!(parse_size_string(" 8 gb "), Some(8 * 1024 * 1024 * 1024));
    }
}
