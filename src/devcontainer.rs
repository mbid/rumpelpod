//! Type definitions for deserializing devcontainer.json files.
//!
//! This module implements types according to the Dev Container specification.
//! See <https://containers.dev/implementors/json_reference/> for details.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MountType {
    #[default]
    Bind,
    Volume,
    Tmpfs,
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WaitFor {
    InitializeCommand,
    OnCreateCommand,
    UpdateContentCommand,
    PostCreateCommand,
    PostStartCommand,
    PostAttachCommand,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_image() {
        let json = r#"{"image": "mcr.microsoft.com/devcontainers/base:ubuntu"}"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.image,
            Some("mcr.microsoft.com/devcontainers/base:ubuntu".to_string())
        );
    }

    #[test]
    fn test_parse_dockerfile_build() {
        let json = r#"{
            "name": "My Dev Container",
            "build": {
                "dockerfile": "Dockerfile",
                "context": "..",
                "args": {"VARIANT": "20"}
            }
        }"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, Some("My Dev Container".to_string()));
        let build = config.build.unwrap();
        assert_eq!(build.dockerfile, Some("Dockerfile".to_string()));
        assert_eq!(build.context, Some("..".to_string()));
        assert_eq!(build.args.unwrap().get("VARIANT"), Some(&"20".to_string()));
    }

    #[test]
    fn test_parse_docker_compose() {
        let json = r#"{
            "dockerComposeFile": ["docker-compose.yml", "docker-compose.dev.yml"],
            "service": "app",
            "workspaceFolder": "/workspace"
        }"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();
        assert_eq!(config.service, Some("app".to_string()));
        assert_eq!(config.workspace_folder, Some("/workspace".to_string()));
        match config.docker_compose_file {
            Some(StringOrArray::Array(arr)) => {
                assert_eq!(arr.len(), 2);
                assert_eq!(arr[0], "docker-compose.yml");
            }
            _ => panic!("Expected array"),
        }
    }

    #[test]
    fn test_parse_lifecycle_commands() {
        let json = r#"{
            "image": "ubuntu",
            "postCreateCommand": "npm install",
            "postStartCommand": ["echo", "started"],
            "postAttachCommand": {
                "server": "npm start",
                "client": ["npm", "run", "client"]
            }
        }"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();

        match config.post_create_command {
            Some(LifecycleCommand::String(s)) => assert_eq!(s, "npm install"),
            _ => panic!("Expected string command"),
        }

        match config.post_start_command {
            Some(LifecycleCommand::Array(arr)) => {
                assert_eq!(arr, vec!["echo", "started"]);
            }
            _ => panic!("Expected array command"),
        }

        match config.post_attach_command {
            Some(LifecycleCommand::Object(obj)) => {
                assert!(obj.contains_key("server"));
                assert!(obj.contains_key("client"));
            }
            _ => panic!("Expected object command"),
        }
    }

    #[test]
    fn test_parse_features() {
        let json = r#"{
            "image": "ubuntu",
            "features": {
                "ghcr.io/devcontainers/features/git:1": {},
                "ghcr.io/devcontainers/features/node:1": {
                    "version": "18"
                }
            }
        }"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();
        let features = config.features.unwrap();
        assert!(features.contains_key("ghcr.io/devcontainers/features/git:1"));
        assert!(features.contains_key("ghcr.io/devcontainers/features/node:1"));
    }

    #[test]
    fn test_parse_mounts() {
        let json = r#"{
            "image": "ubuntu",
            "mounts": [
                "source=myvolume,target=/data,type=volume",
                {"type": "bind", "source": "/host/path", "target": "/container/path"}
            ]
        }"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();
        let mounts = config.mounts.unwrap();
        assert_eq!(mounts.len(), 2);
    }

    #[test]
    fn test_parse_forward_ports() {
        let json = r#"{
            "image": "ubuntu",
            "forwardPorts": [3000, "db:5432", 8080]
        }"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();
        let ports = config.forward_ports.unwrap();
        assert_eq!(ports.len(), 3);
    }

    #[test]
    fn test_parse_host_requirements() {
        let json = r#"{
            "image": "ubuntu",
            "hostRequirements": {
                "cpus": 4,
                "memory": "8gb",
                "storage": "32gb",
                "gpu": true
            }
        }"#;
        let config: DevContainer = serde_json::from_str(json).unwrap();
        let reqs = config.host_requirements.unwrap();
        assert_eq!(reqs.cpus, Some(4));
        assert_eq!(reqs.memory, Some("8gb".to_string()));
    }

    #[test]
    fn test_roundtrip() {
        let config = DevContainer {
            name: Some("Test".to_string()),
            image: Some("ubuntu:latest".to_string()),
            remote_user: Some("vscode".to_string()),
            forward_ports: Some(vec![
                Port::Number(3000),
                Port::String("db:5432".to_string()),
            ]),
            ..Default::default()
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: DevContainer = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, config.name);
        assert_eq!(parsed.image, config.image);
        assert_eq!(parsed.remote_user, config.remote_user);
    }
}
