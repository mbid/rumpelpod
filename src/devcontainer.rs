//! Type definitions for deserializing devcontainer.json files.
//!
//! This module implements types according to the Dev Container specification.
//! See <https://containers.dev/implementors/json_reference/> for details.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// A devcontainer.json configuration.
///
/// This struct represents all possible configurations: image-based, Dockerfile-based,
/// or Docker Compose-based dev containers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DevContainer {
    // ========================
    // General properties
    // ========================
    /// A name for the dev container displayed in the UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Ports that should always be forwarded from the container to the local machine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forward_ports: Option<Vec<Port>>,

    /// Port-specific attributes for forwarded ports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports_attributes: Option<HashMap<String, PortAttributes>>,

    /// Default attributes for ports not specified in portsAttributes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_ports_attributes: Option<PortAttributes>,

    /// Environment variables for the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_env: Option<HashMap<String, String>>,

    /// Environment variables for the devcontainer tools/processes (not the container itself).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_env: Option<HashMap<String, String>>,

    /// User to run devcontainer tools as inside the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_user: Option<String>,

    /// User for all operations inside the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_user: Option<String>,

    /// Whether to update the container user's UID/GID to match the local user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_remote_user_uid: Option<bool>,

    /// Shell type for probing user environment variables.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_env_probe: Option<UserEnvProbe>,

    /// Whether to override the container's default command.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_command: Option<bool>,

    /// Action when the tool window is closed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shutdown_action: Option<ShutdownAction>,

    /// Whether to use the tini init process.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Whether to run the container in privileged mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    /// Linux capabilities to add to the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_add: Option<Vec<String>>,

    /// Security options for the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_opt: Option<Vec<String>>,

    /// Additional mounts for the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<Mount>>,

    /// Dev Container Features to install.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<HashMap<String, serde_json::Value>>,

    /// Override the automatic Feature install order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_feature_install_order: Option<Vec<String>>,

    /// Product-specific customizations (e.g., VS Code settings).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub customizations: Option<HashMap<String, serde_json::Value>>,

    // ========================
    // Image/Dockerfile specific
    // ========================
    /// The container image to use (for image-based containers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Docker build configuration (for Dockerfile-based containers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildOptions>,

    /// Legacy: Dockerfile path (prefer build.dockerfile).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,

    /// Legacy: Build context (prefer build.context).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,

    /// Ports to publish when the container is running.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_port: Option<AppPort>,

    /// Override the default workspace mount.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_mount: Option<String>,

    /// Path to open when connecting to the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub workspace_folder: Option<String>,

    /// Docker CLI arguments for running the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_args: Option<Vec<String>>,

    // ========================
    // Docker Compose specific
    // ========================
    /// Path(s) to Docker Compose file(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_compose_file: Option<StringOrArray>,

    /// The service to connect to in Docker Compose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// Services to start in Docker Compose.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_services: Option<Vec<String>>,

    // ========================
    // Lifecycle scripts
    // ========================
    /// Command to run on the host during initialization.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialize_command: Option<LifecycleCommand>,

    /// Command to run after creating the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_create_command: Option<LifecycleCommand>,

    /// Command to run when new content is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_content_command: Option<LifecycleCommand>,

    /// Command to run after the container is assigned to a user.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_create_command: Option<LifecycleCommand>,

    /// Command to run each time the container starts.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_start_command: Option<LifecycleCommand>,

    /// Command to run each time a tool attaches.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_attach_command: Option<LifecycleCommand>,

    /// Which command to wait for before connecting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wait_for: Option<WaitFor>,

    // ========================
    // Host requirements
    // ========================
    /// Minimum host requirements for the container.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_requirements: Option<HostRequirements>,
}

/// Docker build options for Dockerfile-based containers.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BuildOptions {
    /// Path to the Dockerfile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dockerfile: Option<String>,

    /// Build context path relative to devcontainer.json.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,

    /// Build arguments.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<HashMap<String, String>>,

    /// Additional build options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,

    /// Target stage in a multi-stage build.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Image(s) to use as cache.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_from: Option<StringOrArray>,
}

/// Port attributes for port forwarding configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct PortAttributes {
    /// Display name for the port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    /// Protocol handling for the port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<PortProtocol>,

    /// Action when the port is auto-forwarded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_auto_forward: Option<OnAutoForward>,

    /// Whether to require the same local port.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub require_local_port: Option<bool>,

    /// Whether to auto-elevate for low ports.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub elevate_if_needed: Option<bool>,
}

/// Minimum host requirements.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct HostRequirements {
    /// Minimum number of CPUs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpus: Option<u32>,

    /// Minimum memory (e.g., "4gb").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,

    /// Minimum storage (e.g., "32gb").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,

    /// GPU requirements.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gpu: Option<GpuRequirement>,
}

/// GPU requirement specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GpuRequirement {
    /// Simple boolean: GPU required or not.
    Required(bool),
    /// String "optional" for optional GPU.
    Optional(String),
    /// Detailed GPU requirements.
    Detailed(GpuDetails),
}

/// Detailed GPU requirements.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GpuDetails {
    /// Minimum number of GPU cores.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cores: Option<u32>,

    /// Minimum GPU memory.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<String>,
}

/// A mount specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Mount {
    /// String mount specification (Docker --mount format).
    String(String),
    /// Object mount specification.
    Object(MountObject),
}

/// Object-based mount specification.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct MountObject {
    /// Mount type (bind, volume, tmpfs).
    #[serde(rename = "type")]
    pub mount_type: MountType,

    /// Source path or volume name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Target path in the container.
    pub target: String,

    /// Whether the mount is read-only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,
}

/// Type of mount.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    #[default]
    Bind,
    Volume,
    Tmpfs,
}

impl Mount {
    /// Parse a string-format mount ("type=X,source=Y,target=Z") into a MountObject.
    pub fn to_mount_object(&self) -> Result<MountObject> {
        match self {
            Mount::Object(obj) => Ok(obj.clone()),
            Mount::String(s) => MountObject::parse_string(s),
        }
    }
}

impl MountObject {
    /// Parse a Docker --mount style string: comma-separated key=value pairs.
    ///
    /// Supported keys: type, source, src, target, destination, dst, readonly, ro
    fn parse_string(s: &str) -> Result<Self> {
        let mut mount_type = None;
        let mut source = None;
        let mut target = None;
        let mut read_only = None;

        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "type" => mount_type = Some(value.to_string()),
                    "source" | "src" => source = Some(value.to_string()),
                    "target" | "destination" | "dst" => target = Some(value.to_string()),
                    "readonly" | "ro" => {
                        read_only = Some(value == "true" || value == "1");
                    }
                    _ => {} // Ignore unknown keys for forward compat
                }
            } else if part == "readonly" || part == "ro" {
                read_only = Some(true);
            }
        }

        let target = target.ok_or_else(|| anyhow::anyhow!("mount string missing 'target': {s}"))?;

        let mount_type = match mount_type.as_deref() {
            Some("bind") => MountType::Bind,
            Some("volume") => MountType::Volume,
            Some("tmpfs") => MountType::Tmpfs,
            Some(other) => anyhow::bail!("unsupported mount type: {other}"),
            None => MountType::Bind, // Docker default
        };

        Ok(MountObject {
            mount_type,
            source,
            target,
            read_only,
        })
    }
}

/// A lifecycle command (can be string, array, or object for parallel execution).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LifecycleCommand {
    /// Single command string (run in shell).
    String(String),
    /// Command as array (no shell).
    Array(Vec<String>),
    /// Named commands for parallel execution.
    Object(HashMap<String, StringOrArray>),
}

/// A port specification (can be number or string like "host:container").
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Port {
    /// Port number.
    Number(u16),
    /// Port string (e.g., "8080" or "db:5432").
    String(String),
}

/// A value that can be either a string or an array of strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StringOrArray {
    String(String),
    Array(Vec<String>),
}

/// A value that can be a single port, string, or array.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AppPort {
    Number(u16),
    String(String),
    Array(Vec<Port>),
}

/// Shell type for user environment probing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum UserEnvProbe {
    None,
    InteractiveShell,
    LoginShell,
    LoginInteractiveShell,
}

impl UserEnvProbe {
    /// Shell flags for wrapping a command with `-c`, e.g. `bash -lic '...'`.
    /// Returns `None` for `UserEnvProbe::None` (no wrapping needed).
    pub fn shell_flags_exec(&self) -> Option<&str> {
        match self {
            UserEnvProbe::None => None,
            UserEnvProbe::InteractiveShell => Some("-ic"),
            UserEnvProbe::LoginShell => Some("-lc"),
            UserEnvProbe::LoginInteractiveShell => Some("-lic"),
        }
    }

    /// Shell flags for launching an interactive shell, e.g. `bash -li`.
    /// Returns `None` for `UserEnvProbe::None` (no special flags).
    pub fn shell_flags_interactive(&self) -> Option<&str> {
        match self {
            UserEnvProbe::None => None,
            UserEnvProbe::InteractiveShell => Some("-i"),
            UserEnvProbe::LoginShell => Some("-l"),
            UserEnvProbe::LoginInteractiveShell => Some("-li"),
        }
    }
}

/// Escape a string for safe embedding inside single-quoted shell arguments.
pub fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Shutdown action when the tool window is closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShutdownAction {
    None,
    StopContainer,
    StopCompose,
}

/// Port protocol.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortProtocol {
    Http,
    Https,
}

/// Action when a port is auto-forwarded.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OnAutoForward {
    Notify,
    OpenBrowser,
    OpenBrowserOnce,
    OpenPreview,
    Silent,
    Ignore,
}

/// Which lifecycle command to wait for before connecting.
///
/// Variant order matches the lifecycle execution order so that derived
/// `Ord` gives the correct comparison semantics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WaitFor {
    InitializeCommand,
    OnCreateCommand,
    UpdateContentCommand,
    PostCreateCommand,
    PostStartCommand,
    PostAttachCommand,
}

impl DevContainer {
    /// Load a devcontainer.json from the given path using json5 (supports comments).
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        json5::from_str(&contents).with_context(|| format!("Failed to parse {}", path.display()))
    }

    /// Find and load a devcontainer.json from standard locations in the repo.
    ///
    /// Searches for:
    /// 1. `.devcontainer/devcontainer.json`
    /// 2. `.devcontainer.json`
    ///
    /// Returns the DevContainer and the directory containing the devcontainer.json file.
    pub fn find_and_load(repo_root: &Path) -> Result<Option<(Self, PathBuf)>> {
        let candidates = [
            repo_root.join(".devcontainer/devcontainer.json"),
            repo_root.join(".devcontainer.json"),
        ];

        for candidate in &candidates {
            if candidate.exists() {
                let dc = Self::load(candidate)?;
                let dc_dir = candidate
                    .parent()
                    .expect("devcontainer.json must have a parent directory")
                    .to_path_buf();
                return Ok(Some((dc, dc_dir)));
            }
        }

        Ok(None)
    }

    /// Check for unsupported fields and emit warnings to stderr.
    ///
    /// These properties are intentionally not supported (see docs/devcontainer.md
    /// "Intentionally Unsupported") but may appear in devcontainer.json files
    /// shared with other tools like VS Code.
    ///
    /// - `initializeCommand`: runs on the host, which does not generalize to
    ///   non-local backends (e.g. Kubernetes).
    /// - `features` / `overrideFeatureInstallOrder`: Dev Container Features
    ///   require an OCI registry client and a custom image build pipeline.
    ///   Out of scope -- use a Dockerfile instead.
    pub fn warn_unsupported_fields(&self) {
        let fields: &[(&str, bool)] = &[
            ("workspaceMount", self.workspace_mount.is_some()),
            ("appPort", self.app_port.is_some()),
            ("dockerComposeFile", self.docker_compose_file.is_some()),
            ("service", self.service.is_some()),
            ("runServices", self.run_services.is_some()),
            ("initializeCommand", self.initialize_command.is_some()),
            ("features", self.features.is_some()),
            (
                "overrideFeatureInstallOrder",
                self.override_feature_install_order.is_some(),
            ),
        ];

        for (name, present) in fields {
            if *present {
                eprintln!(
                    "warning: devcontainer.json contains '{name}' which is not supported by rumpelpod"
                );
            }
        }
    }

    /// The effective waitFor target for this configuration.
    ///
    /// Commands at or before this target block the enter; commands after
    /// it run in the background.
    pub fn effective_wait_for(&self) -> WaitFor {
        self.wait_for
            .clone()
            .unwrap_or(WaitFor::UpdateContentCommand)
    }

    /// Get the user to run as (prefers remoteUser over containerUser).
    pub fn user(&self) -> Option<&str> {
        self.remote_user
            .as_deref()
            .or(self.container_user.as_deref())
    }

    /// Compute the container workspace path, defaulting to `/workspaces/<basename>`.
    pub fn container_repo_path(&self, repo_root: &Path) -> PathBuf {
        self.workspace_folder
            .as_ref()
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                let basename = repo_root
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| "workspace".to_string());
                PathBuf::from(format!("/workspaces/{}", basename))
            })
    }

    /// Whether `--network=host` is present in `runArgs`.
    pub fn has_host_network(&self) -> bool {
        let args = match &self.run_args {
            Some(args) => args,
            None => return false,
        };
        let mut iter = args.iter();
        while let Some(arg) = iter.next() {
            if arg == "--network=host" {
                return true;
            }
            if arg == "--network" {
                if let Some(value) = iter.next() {
                    if value == "host" {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Apply variable substitution to all properties that the spec says
    /// support it.
    ///
    /// Callers choose which variables are available via the context.
    /// Variables whose lookup is `None` are left as literal text for a
    /// later phase to resolve.
    ///
    /// `build.args` only gets `${localEnv:...}` per spec -- all other
    /// variable types are stripped from its context automatically.
    /// Apply variable substitution to all properties that the spec says
    /// support it.
    ///
    /// Uses exhaustive destructuring so that adding a new field to
    /// DevContainer without handling it here is a compile error.
    ///
    /// `build.args` only gets `${localEnv:...}` per spec.
    pub fn substitute(self, ctx: &SubstitutionContext) -> Self {
        let sub = |s: String| substitute_vars(&s, ctx);
        let sub_opt = |s: Option<String>| s.map(&sub);
        let sub_env = |env: Option<HashMap<String, String>>| {
            env.map(|m| m.into_iter().map(|(k, v)| (k, sub(v))).collect())
        };
        let sub_vec = |v: Option<Vec<String>>| v.map(|v| v.into_iter().map(&sub).collect());

        let DevContainer {
            name,
            forward_ports,
            ports_attributes,
            other_ports_attributes,
            container_env,
            remote_env,
            remote_user,
            container_user,
            update_remote_user_uid,
            user_env_probe,
            override_command,
            shutdown_action,
            init,
            privileged,
            cap_add,
            security_opt,
            mounts,
            features,
            override_feature_install_order,
            customizations,
            image,
            build,
            dockerfile,
            context,
            app_port,
            workspace_mount,
            workspace_folder,
            run_args,
            docker_compose_file,
            service,
            run_services,
            initialize_command,
            on_create_command,
            update_content_command,
            post_create_command,
            post_start_command,
            post_attach_command,
            wait_for,
            host_requirements,
        } = self;

        let build = build.map(|b| {
            let restricted = SubstitutionContext {
                resolve_local_env: ctx.resolve_local_env,
                ..Default::default()
            };
            BuildOptions {
                args: b.args.map(|m| {
                    m.into_iter()
                        .map(|(k, v)| (k, substitute_vars(&v, &restricted)))
                        .collect()
                }),
                // Build-time properties do not support substitution
                dockerfile: b.dockerfile,
                context: b.context,
                options: b.options,
                target: b.target,
                cache_from: b.cache_from,
            }
        });

        let mounts = mounts.map(|v| {
            v.into_iter()
                .map(|m| match m {
                    Mount::String(s) => Mount::String(sub(s)),
                    Mount::Object(obj) => Mount::Object(MountObject {
                        source: sub_opt(obj.source),
                        target: sub(obj.target),
                        mount_type: obj.mount_type,
                        read_only: obj.read_only,
                    }),
                })
                .collect()
        });

        DevContainer {
            name: sub_opt(name),
            run_args: sub_vec(run_args),
            workspace_mount: sub_opt(workspace_mount),
            workspace_folder: sub_opt(workspace_folder),
            container_env: sub_env(container_env),
            remote_env: sub_env(remote_env),
            container_user: sub_opt(container_user),
            remote_user: sub_opt(remote_user),
            mounts,
            initialize_command: substitute_lifecycle_command(initialize_command, ctx),
            on_create_command: substitute_lifecycle_command(on_create_command, ctx),
            update_content_command: substitute_lifecycle_command(update_content_command, ctx),
            post_create_command: substitute_lifecycle_command(post_create_command, ctx),
            post_start_command: substitute_lifecycle_command(post_start_command, ctx),
            post_attach_command: substitute_lifecycle_command(post_attach_command, ctx),
            build,
            // These properties do not support variable substitution per spec
            forward_ports,
            ports_attributes,
            other_ports_attributes,
            update_remote_user_uid,
            user_env_probe,
            override_command,
            shutdown_action,
            init,
            privileged,
            cap_add,
            security_opt,
            features,
            override_feature_install_order,
            customizations,
            image,
            dockerfile,
            context,
            app_port,
            docker_compose_file,
            service,
            run_services,
            wait_for,
            host_requirements,
        }
    }

    /// Normalize build paths: merge legacy `dockerfile`/`context` into the
    /// `build` struct and make all paths relative to `repo_root`.
    ///
    /// Must be called on the client side before sending to the daemon, since
    /// the daemon doesn't know the devcontainer.json directory.
    /// No-op if no build is configured (image-based container).
    pub fn resolve_build_paths(&mut self, devcontainer_dir: &Path, repo_root: &Path) {
        // Merge legacy top-level dockerfile into build.dockerfile
        let dockerfile = self
            .dockerfile
            .take()
            .or_else(|| self.build.as_ref().and_then(|b| b.dockerfile.clone()));

        let dockerfile = match dockerfile {
            Some(d) => d,
            None => return, // No build configured
        };

        let context = self
            .build
            .as_ref()
            .and_then(|b| b.context.clone())
            .or_else(|| self.context.take())
            .unwrap_or_else(|| ".".to_string());

        let resolved_dockerfile = devcontainer_dir
            .join(&dockerfile)
            .strip_prefix(repo_root)
            .expect("dockerfile must be under repo_root")
            .to_string_lossy()
            .to_string();
        let resolved_context = devcontainer_dir
            .join(&context)
            .strip_prefix(repo_root)
            .expect("context must be under repo_root")
            .to_string_lossy()
            .to_string();

        let build = self.build.get_or_insert_with(BuildOptions::default);
        build.dockerfile = Some(resolved_dockerfile);
        build.context = Some(resolved_context);
    }

    /// Whether this devcontainer uses a Dockerfile build (vs a pre-built image).
    pub fn has_build(&self) -> bool {
        self.dockerfile.is_some() || self.build.as_ref().is_some_and(|b| b.dockerfile.is_some())
    }

    /// Parse mounts into resolved `MountObject`s.
    ///
    /// Should be called after variable substitution so that references like
    /// `${devcontainerId}` have already been replaced.  Any remaining `${`
    /// indicates a typo or unsupported variable and is rejected early with a
    /// clear error (Docker would fail with a cryptic message otherwise).
    pub fn resolved_mounts(&self) -> Result<Vec<MountObject>> {
        let mounts = match &self.mounts {
            Some(mounts) => mounts
                .iter()
                .map(|m| m.to_mount_object())
                .collect::<Result<Vec<_>>>()
                .context("parsing mounts from devcontainer.json")?,
            None => return Ok(Vec::new()),
        };

        for m in &mounts {
            for field in [m.source.as_deref(), Some(m.target.as_str())]
                .into_iter()
                .flatten()
            {
                if field.contains("${") {
                    anyhow::bail!(
                        "unresolved variable in mount: '{field}'. \
                         Check for typos in variable references."
                    );
                }
            }
        }

        Ok(mounts)
    }
}

/// Apply variable substitution to a lifecycle command.
fn substitute_lifecycle_command(
    cmd: Option<LifecycleCommand>,
    ctx: &SubstitutionContext,
) -> Option<LifecycleCommand> {
    let sub = |s: String| substitute_vars(&s, ctx);
    cmd.map(|c| match c {
        LifecycleCommand::String(s) => LifecycleCommand::String(sub(s)),
        LifecycleCommand::Array(arr) => {
            LifecycleCommand::Array(arr.into_iter().map(&sub).collect())
        }
        LifecycleCommand::Object(map) => LifecycleCommand::Object(
            map.into_iter()
                .map(|(k, v)| {
                    let v = match v {
                        StringOrArray::String(s) => StringOrArray::String(sub(s)),
                        StringOrArray::Array(arr) => {
                            StringOrArray::Array(arr.into_iter().map(&sub).collect())
                        }
                    };
                    (k, v)
                })
                .collect(),
        ),
    })
}

/// Context for variable substitution.
///
/// Each field is `Option` (or `false`) because different call sites have
/// access to different variables. When a field is absent, references to
/// that variable type are left as literal text so a later call can resolve
/// them.
#[derive(Default)]
pub struct SubstitutionContext {
    /// When true, `${localEnv:VAR}` is resolved via `std::env::var`.
    pub resolve_local_env: bool,

    /// `${localWorkspaceFolder}` value, if known.
    pub local_workspace_folder: Option<String>,

    /// `${localWorkspaceFolderBasename}` value, if known.
    pub local_workspace_folder_basename: Option<String>,

    /// `${containerWorkspaceFolder}` value, if known.
    pub container_workspace_folder: Option<String>,

    /// `${containerWorkspaceFolderBasename}` value, if known.
    pub container_workspace_folder_basename: Option<String>,

    /// `${devcontainerId}` value, if known.
    pub devcontainer_id: Option<String>,

    /// When set, `${containerEnv:VAR}` is resolved by running
    /// `docker exec printenv` against this running container.
    pub container_env_source: Option<ContainerEnvSource>,
}

/// Everything needed to read an environment variable from a running container
/// via `docker exec printenv`.
pub struct ContainerEnvSource {
    pub docker_socket: PathBuf,
    pub container_id: String,
}

/// Substitute all known variable patterns in a single string value.
///
/// Variables that cannot be resolved in the current context are left as-is
/// so a later substitution call can resolve them.
pub fn substitute_vars(value: &str, ctx: &SubstitutionContext) -> String {
    let mut result = value.to_string();
    let mut i = 0;
    while i < result.len() {
        if !result[i..].starts_with("${") {
            i += 1;
            continue;
        }
        let start = i;
        let after_dollar_brace = start + 2;
        let Some(close) = result[after_dollar_brace..].find('}') else {
            break;
        };
        let close = after_dollar_brace + close;
        let inner = &result[after_dollar_brace..close];

        let replacement = resolve_variable(inner, ctx);
        match replacement {
            Some(val) => {
                result = format!("{}{}{}", &result[..start], val, &result[close + 1..]);
                i = start + val.len();
            }
            None => {
                // Leave unresolved -- skip past this reference
                i = close + 1;
            }
        }
    }
    result
}

/// Try to resolve a single variable reference (the text between `${` and `}`).
///
/// Returns `None` when the variable type is not available in the current
/// context, meaning the literal `${...}` should be kept for a later call.
fn resolve_variable(inner: &str, ctx: &SubstitutionContext) -> Option<String> {
    if let Some(rest) = inner.strip_prefix("localEnv:") {
        if !ctx.resolve_local_env {
            return None;
        }
        let (var_name, default) = split_var_default(rest);
        let val = std::env::var(var_name).ok();
        return Some(val.unwrap_or_else(|| default.unwrap_or_default().to_string()));
    }

    if let Some(rest) = inner.strip_prefix("containerEnv:") {
        let src = ctx.container_env_source.as_ref()?;
        let (var_name, default) = split_var_default(rest);
        let val = read_container_env_var(&src.docker_socket, &src.container_id, var_name);
        return Some(val.unwrap_or_else(|| default.unwrap_or_default().to_string()));
    }

    match inner {
        "localWorkspaceFolder" => ctx.local_workspace_folder.clone(),
        "localWorkspaceFolderBasename" => ctx.local_workspace_folder_basename.clone(),
        "containerWorkspaceFolder" => ctx.container_workspace_folder.clone(),
        "containerWorkspaceFolderBasename" => ctx.container_workspace_folder_basename.clone(),
        "devcontainerId" => ctx.devcontainer_id.clone(),
        _ => None,
    }
}

/// Read a single environment variable from a running container via
/// `docker exec printenv`.
fn read_container_env_var(
    docker_socket: &Path,
    container_id: &str,
    var_name: &str,
) -> Option<String> {
    let output = std::process::Command::new("docker")
        .args(["-H", &format!("unix://{}", docker_socket.display())])
        .args(["exec", container_id, "printenv", var_name])
        .output()
        .ok()?;
    if output.status.success() {
        Some(
            String::from_utf8_lossy(&output.stdout)
                .trim_end_matches('\n')
                .to_string(),
        )
    } else {
        None
    }
}

/// Split `"VAR:default"` into `("VAR", Some("default"))`, or `"VAR"` into
/// `("VAR", None)`.  The first colon is the separator.
fn split_var_default(s: &str) -> (&str, Option<&str>) {
    match s.split_once(':') {
        Some((var, default)) => (var, Some(default)),
        None => (s, None),
    }
}

/// /// Compute a stable `${devcontainerId}` from the repo path and pod name.
///
/// Per the spec this should be a SHA-256 hash that is stable across rebuilds
/// but unique per dev container instance.  We derive it from the two values
/// that uniquely identify a pod on the Docker host.
pub fn compute_devcontainer_id(repo_path: &Path, pod_name: &str) -> String {
    let label_json = serde_json::json!({
        "rumpelpod.name": pod_name,
        "rumpelpod.repo_path": repo_path.to_string_lossy(),
    });
    // Deterministic serialization (serde_json sorts keys in json! maps)
    let normalized = serde_json::to_string(&label_json).expect("JSON serialization cannot fail");
    let hash = Sha256::digest(normalized.as_bytes());
    hex::encode(hash)
}

/// Convenience wrapper: resolve `${localEnv:VAR}` using the real host
/// environment.  Used by `agent/mod.rs` for eagerly resolving remote_env.
pub fn resolve_local_env_vars(value: &str) -> String {
    let ctx = SubstitutionContext {
        resolve_local_env: true,
        ..Default::default()
    };
    substitute_vars(value, &ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn full_ctx() -> SubstitutionContext {
        SubstitutionContext {
            resolve_local_env: true,
            local_workspace_folder: Some("/home/user/project".to_string()),
            local_workspace_folder_basename: Some("project".to_string()),
            container_workspace_folder: Some("/workspaces/project".to_string()),
            container_workspace_folder_basename: Some("project".to_string()),
            devcontainer_id: Some("abc123def456".to_string()),
            container_env_source: None,
        }
    }

    #[test]
    fn substitute_local_env_from_real_env() {
        // PATH is always set in any reasonable environment
        let ctx = SubstitutionContext {
            resolve_local_env: true,
            ..Default::default()
        };
        let result = substitute_vars("${localEnv:PATH}", &ctx);
        assert!(!result.contains("${"), "should have resolved PATH");
        assert!(!result.is_empty());
    }

    #[test]
    fn substitute_local_env_missing_uses_empty() {
        let ctx = SubstitutionContext {
            resolve_local_env: true,
            ..Default::default()
        };
        assert_eq!(
            substitute_vars(
                "pre-${localEnv:RUMPELPOD_TEST_DEFINITELY_UNSET_12345}-post",
                &ctx
            ),
            "pre--post"
        );
    }

    #[test]
    fn substitute_local_env_with_default() {
        let ctx = SubstitutionContext {
            resolve_local_env: true,
            ..Default::default()
        };
        assert_eq!(
            substitute_vars(
                "${localEnv:RUMPELPOD_TEST_DEFINITELY_UNSET_12345:fallback}",
                &ctx
            ),
            "fallback"
        );
    }

    #[test]
    fn substitute_local_env_set_ignores_default() {
        // PATH is always set
        let ctx = SubstitutionContext {
            resolve_local_env: true,
            ..Default::default()
        };
        let result = substitute_vars("${localEnv:PATH:fallback}", &ctx);
        assert_ne!(result, "fallback");
        assert!(!result.contains("${"));
    }

    #[test]
    fn substitute_workspace_vars() {
        let ctx = full_ctx();
        assert_eq!(
            substitute_vars("${localWorkspaceFolder}", &ctx),
            "/home/user/project"
        );
        assert_eq!(
            substitute_vars("${localWorkspaceFolderBasename}", &ctx),
            "project"
        );
        assert_eq!(
            substitute_vars("${containerWorkspaceFolder}", &ctx),
            "/workspaces/project"
        );
        assert_eq!(
            substitute_vars("${containerWorkspaceFolderBasename}", &ctx),
            "project"
        );
    }

    #[test]
    fn substitute_devcontainer_id() {
        let ctx = full_ctx();
        assert_eq!(
            substitute_vars("vol-${devcontainerId}-data", &ctx),
            "vol-abc123def456-data"
        );
    }

    #[test]
    fn substitute_leaves_unknown_vars_intact() {
        let ctx = SubstitutionContext::default();
        let input = "${unknownVar}";
        assert_eq!(substitute_vars(input, &ctx), input);
    }

    #[test]
    fn substitute_skips_unavailable_context() {
        // resolve_local_env is false, so ${localEnv:...} should be preserved
        let ctx = SubstitutionContext {
            devcontainer_id: Some("id123".to_string()),
            ..Default::default()
        };
        assert_eq!(
            substitute_vars("${localEnv:FOO}-${devcontainerId}", &ctx),
            "${localEnv:FOO}-id123"
        );
    }

    #[test]
    fn substitute_multiple_vars_in_one_string() {
        let ctx = full_ctx();
        assert_eq!(
            substitute_vars("${localWorkspaceFolder}:${containerWorkspaceFolder}", &ctx),
            "/home/user/project:/workspaces/project"
        );
    }

    #[test]
    fn substitute_no_vars() {
        let ctx = full_ctx();
        assert_eq!(substitute_vars("plain string", &ctx), "plain string");
    }

    #[test]
    fn substitute_unclosed_brace() {
        let ctx = full_ctx();
        assert_eq!(
            substitute_vars("${localWorkspaceFolder", &ctx),
            "${localWorkspaceFolder"
        );
    }

    #[test]
    fn devcontainer_id_stable_across_calls() {
        let id1 = compute_devcontainer_id(Path::new("/repo"), "sandbox1");
        let id2 = compute_devcontainer_id(Path::new("/repo"), "sandbox1");
        assert_eq!(id1, id2);
    }

    #[test]
    fn devcontainer_id_differs_by_name() {
        let id1 = compute_devcontainer_id(Path::new("/repo"), "a");
        let id2 = compute_devcontainer_id(Path::new("/repo"), "b");
        assert_ne!(id1, id2);
    }

    #[test]
    fn devcontainer_id_differs_by_path() {
        let id1 = compute_devcontainer_id(Path::new("/repo1"), "s");
        let id2 = compute_devcontainer_id(Path::new("/repo2"), "s");
        assert_ne!(id1, id2);
    }

    #[test]
    fn devcontainer_id_is_hex_sha256() {
        let id = compute_devcontainer_id(Path::new("/repo"), "name");
        assert_eq!(id.len(), 64);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn substitute_method_covers_all_fields() {
        let ctx = SubstitutionContext {
            local_workspace_folder: Some("/host/project".to_string()),
            ..Default::default()
        };
        let dc = DevContainer {
            name: Some("${localWorkspaceFolder}".to_string()),
            run_args: Some(vec!["--label=${localWorkspaceFolder}".to_string()]),
            container_env: Some(HashMap::from([(
                "K".to_string(),
                "${localWorkspaceFolder}".to_string(),
            )])),
            remote_env: Some(HashMap::from([(
                "R".to_string(),
                "${localWorkspaceFolder}".to_string(),
            )])),
            container_user: Some("${localWorkspaceFolder}".to_string()),
            remote_user: Some("${localWorkspaceFolder}".to_string()),
            ..Default::default()
        };
        let dc = dc.substitute(&ctx);
        assert_eq!(dc.name.unwrap(), "/host/project");
        assert_eq!(dc.run_args.unwrap()[0], "--label=/host/project");
        assert_eq!(dc.container_env.unwrap()["K"], "/host/project");
        assert_eq!(dc.remote_env.unwrap()["R"], "/host/project");
        assert_eq!(dc.container_user.unwrap(), "/host/project");
        assert_eq!(dc.remote_user.unwrap(), "/host/project");
    }

    #[test]
    fn substitute_build_args_only_gets_local_env() {
        let ctx = SubstitutionContext {
            resolve_local_env: true,
            devcontainer_id: Some("id123".to_string()),
            ..Default::default()
        };
        let dc = DevContainer {
            build: Some(BuildOptions {
                args: Some(HashMap::from([
                    // Use PATH which is always set
                    ("PATH_VAL".to_string(), "${localEnv:PATH}".to_string()),
                    // devcontainerId should NOT be resolved in build.args
                    ("ID".to_string(), "${devcontainerId}".to_string()),
                ])),
                ..Default::default()
            }),
            ..Default::default()
        };
        let dc = dc.substitute(&ctx);
        let args = dc.build.unwrap().args.unwrap();
        assert!(!args["PATH_VAL"].contains("${"));
        assert_eq!(args["ID"], "${devcontainerId}");
    }
}
