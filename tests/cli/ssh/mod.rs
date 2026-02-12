//! Integration tests for SSH remote Docker functionality.
//!
//! These tests verify that pods can be created on remote Docker hosts
//! accessed via SSH tunneling. The tests start a Docker container that runs
//! both an SSH server and a Docker daemon (in privileged mode), simulating
//! a remote Docker host.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use indoc::formatdoc;
use tempfile::TempDir;

use crate::common::{
    build_docker_image, pod_command, DockerBuild, ImageId, TestDaemon, TestRepo, TEST_REPO_PATH,
    TEST_USER_UID,
};
use rumpelpod::CommandExt;

/// Test user for SSH connections.
pub const SSH_USER: &str = "testuser";

/// Timeout for waiting for services to become available.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(30);

/// A container simulating a remote Docker host with SSH access.
///
/// This is a test fixture similar to `TestRepo` and `TestDaemon`.
/// It manages a Docker container running both an SSH server and a Docker daemon.
///
/// On drop, the container is stopped and removed.
pub struct SshRemoteHost {
    /// Docker container ID.
    container_id: String,
    /// IP address of the container (used on Linux for direct connection).
    ip_address: String,
    /// Published SSH port on localhost (used on macOS Docker Desktop where
    /// container IPs are not routable from the host).
    published_port: Option<u16>,
    /// Temporary directory containing SSH keys.
    _temp_dir: TempDir,
    /// Path to the private key file.
    private_key_path: PathBuf,
    /// Docker network name.
    network_name: String,
}

impl SshRemoteHost {
    /// Start a new SSH remote host container.
    ///
    /// This builds (if necessary) and starts a container with SSH and Docker,
    /// generates SSH keys, and configures the container to accept connections.
    pub fn start() -> Self {
        let image_id = build_remote_docker_image().expect("Failed to build remote docker image");

        // Create temporary directory for SSH keys
        let temp_dir =
            TempDir::with_prefix("rumpelpod-ssh-test-").expect("Failed to create temp dir for SSH");
        let private_key_path = temp_dir.path().join("id_ed25519");
        let public_key_path = temp_dir.path().join("id_ed25519.pub");

        // Create a dedicated network to ensure IP stability
        let network_name = temp_dir
            .path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        Command::new("docker")
            .args(["network", "create", &network_name])
            .success()
            .expect("Failed to create docker network");

        // Generate SSH key pair
        Command::new("ssh-keygen")
            .args(["-t", "ed25519"])
            .args(["-f", &private_key_path.to_string_lossy()])
            .args(["-N", ""]) // Empty passphrase
            .args(["-q"]) // Quiet
            .success()
            .expect("Failed to run ssh-keygen");

        // Read the public key
        let public_key =
            std::fs::read_to_string(&public_key_path).expect("Failed to read public key");

        // Start the container with privileged mode for nested Docker.
        // On macOS Docker Desktop, container IPs are inside the VM and not
        // routable from the host, so we publish the SSH port.
        let mut run_args = vec!["run", "-d", "--privileged", "--network"];
        run_args.push(&network_name);
        if cfg!(target_os = "macos") {
            run_args.push("-p");
            run_args.push("0:22");
        }
        let image_str = image_id.to_string();
        run_args.push(&image_str);

        let stdout = Command::new("docker")
            .args(&run_args)
            .success()
            .expect("Failed to start remote docker container");

        let container_id = String::from_utf8_lossy(&stdout).trim().to_string();

        // Get the container's IP address (used on Linux for direct access)
        let ip_address = get_container_ip(&container_id).expect("Failed to get container IP");

        // On macOS, find the published port for SSH
        let published_port = if cfg!(target_os = "macos") {
            Some(get_published_port(&container_id, 22).expect("Failed to get published SSH port"))
        } else {
            None
        };

        let host = SshRemoteHost {
            container_id,
            ip_address,
            published_port,
            _temp_dir: temp_dir,
            private_key_path,
            network_name,
        };

        // Install the public key for the test user
        host.install_public_key(&public_key);

        // Wait for SSH and Docker to be ready
        host.wait_for_services();

        host
    }

    /// Restart the remote host container.
    ///
    /// If `ssh_config` is provided, also verifies that SSH is connectable from
    /// outside (not just that sshd is listening internally). This catches cases
    /// where sshd is up but not yet accepting connections.
    pub fn restart(&mut self, ssh_config: Option<&Path>) {
        Command::new("docker")
            .args(["restart", &self.container_id])
            .success()
            .expect("Failed to restart remote host container");

        // Wait for services to come back up
        self.wait_for_services();

        // Update IP address in case it changed
        self.ip_address = get_container_ip(&self.container_id).expect("Failed to get container IP");
        if self.published_port.is_some() {
            self.published_port = Some(
                get_published_port(&self.container_id, 22)
                    .expect("Failed to get published SSH port"),
            );
        }

        // Verify SSH is actually connectable from outside, not just listening
        if let Some(config) = ssh_config {
            self.wait_for_ssh_connectivity(config);
        }
    }

    /// Wait until we can actually execute a command over SSH.
    ///
    /// This is stronger than checking that sshd is listening: it verifies the
    /// full SSH handshake and command execution path works.
    fn wait_for_ssh_connectivity(&self, ssh_config: &Path) {
        let start = Instant::now();
        while start.elapsed() < SERVICE_TIMEOUT {
            let result = self.ssh_command(ssh_config, &["true"]);
            if result.is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!(
            "SSH connectivity not established within {:?}",
            SERVICE_TIMEOUT
        );
    }

    /// Get the SSH connection string for this remote host (ssh://user@host format).
    pub fn ssh_spec(&self) -> String {
        if let Some(port) = self.published_port {
            format!("ssh://{}@127.0.0.1:{}", SSH_USER, port)
        } else {
            format!("ssh://{}@{}", SSH_USER, self.ip_address)
        }
    }

    /// Get the container's IP address (for the ignored reconnect test).
    pub fn ip_address(&self) -> &str {
        &self.ip_address
    }

    /// Get the SSH host identifier used in SSH config Host directives.
    pub fn ssh_host(&self) -> String {
        if self.published_port.is_some() {
            "127.0.0.1".to_string()
        } else {
            self.ip_address.clone()
        }
    }

    /// Get the path to the private key for this remote host.
    pub fn private_key_path(&self) -> &Path {
        &self.private_key_path
    }

    /// Install the SSH public key for the test user.
    fn install_public_key(&self, public_key: &str) {
        let setup_script = formatdoc! {r#"
            mkdir -p /home/{SSH_USER}/.ssh
            chmod 700 /home/{SSH_USER}/.ssh
            echo '{public_key}' >> /home/{SSH_USER}/.ssh/authorized_keys
            chmod 600 /home/{SSH_USER}/.ssh/authorized_keys
            chown -R {SSH_USER}:{SSH_USER} /home/{SSH_USER}/.ssh
        "#};

        Command::new("docker")
            .args(["exec", &self.container_id, "sh", "-c", &setup_script])
            .success()
            .expect("Failed to install SSH public key");
    }

    /// Wait for SSH and Docker services to be ready.
    fn wait_for_services(&self) {
        self.wait_for_docker();
        self.wait_for_ssh();
    }

    fn wait_for_docker(&self) {
        let start = Instant::now();
        while start.elapsed() < SERVICE_TIMEOUT {
            let status = Command::new("docker")
                .args(["exec", &self.container_id, "docker", "info"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if matches!(status, Ok(s) if s.success()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!(
            "Docker did not become available within {:?}",
            SERVICE_TIMEOUT
        );
    }

    fn wait_for_ssh(&self) {
        let start = Instant::now();
        while start.elapsed() < SERVICE_TIMEOUT {
            let status = Command::new("docker")
                .args([
                    "exec",
                    &self.container_id,
                    "sh",
                    "-c",
                    "ss -tlnp | grep -q ':22'",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if matches!(status, Ok(s) if s.success()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!("SSH did not become available within {:?}", SERVICE_TIMEOUT);
    }

    /// Run an SSH command on this remote host.
    pub fn ssh_command(&self, ssh_config: &Path, command: &[&str]) -> Result<Vec<u8>> {
        let config_path = ssh_config.to_string_lossy();
        let user_host = self.ssh_spec();

        let mut ssh_args = vec!["-F", &config_path, &user_host];
        ssh_args.extend(command.iter().copied());

        Command::new("ssh")
            .args(&ssh_args)
            .success()
            .context("running SSH command")
    }

    /// Load a Docker image into this remote host's Docker daemon.
    ///
    /// Returns the image ID as seen by the remote Docker daemon, which may
    /// differ from the local ID when Docker engine versions differ (e.g.
    /// Docker Desktop vs docker.io in Debian).
    pub fn load_image(&self, image_id: &ImageId) -> Result<ImageId> {
        // Save image to a tar file
        let tar_path = self._temp_dir.path().join("image.tar");
        Command::new("docker")
            .args([
                "save",
                "-o",
                &tar_path.to_string_lossy(),
                &image_id.to_string(),
            ])
            .success()
            .context("saving docker image")?;

        // Copy tar file to the remote container
        let remote_tar = "/tmp/image.tar";
        Command::new("docker")
            .args([
                "cp",
                &tar_path.to_string_lossy(),
                &format!("{}:{}", self.container_id, remote_tar),
            ])
            .success()
            .context("copying image tar to remote")?;

        // Load the image on the remote Docker daemon.
        // Parse the output ("Loaded image ID: sha256:...") to get the
        // remote image ID, which may differ from the local one.
        let load_output = Command::new("docker")
            .args([
                "exec",
                &self.container_id,
                "docker",
                "load",
                "-i",
                remote_tar,
            ])
            .success()
            .context("loading image on remote docker")?;

        let load_str = String::from_utf8_lossy(&load_output);
        let remote_id = load_str
            .lines()
            .find_map(|line| {
                line.strip_prefix("Loaded image ID: ")
                    .or_else(|| line.strip_prefix("Loaded image: "))
            })
            .map(|s| s.trim().to_string())
            .with_context(|| format!("parsing docker load output: {}", load_str))?;

        // Clean up the tar file
        let _ = Command::new("docker")
            .args(["exec", &self.container_id, "rm", remote_tar])
            .success();

        Ok(ImageId(remote_id))
    }
}

impl Drop for SshRemoteHost {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .output();
        let _ = Command::new("docker")
            .args(["network", "rm", &self.network_name])
            .output();
    }
}

/// Get the host port that Docker published for a given container port.
fn get_published_port(container_id: &str, container_port: u16) -> Result<u16> {
    let stdout = Command::new("docker")
        .args([
            "inspect",
            "-f",
            &format!(
                "{{{{(index (index .NetworkSettings.Ports \"{}/tcp\") 0).HostPort}}}}",
                container_port
            ),
            container_id,
        ])
        .success()
        .context("getting published port")?;

    let port_str = String::from_utf8_lossy(&stdout).trim().to_string();
    port_str
        .parse()
        .with_context(|| format!("parsing published port: {:?}", port_str))
}

/// Get a container's IP address.
fn get_container_ip(container_id: &str) -> Result<String> {
    let stdout = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_id,
        ])
        .success()
        .context("getting container IP")?;

    let ip = String::from_utf8_lossy(&stdout).trim().to_string();
    if ip.is_empty() {
        anyhow::bail!("container has no IP address");
    }

    Ok(ip)
}

/// Build the Docker image for the remote Docker host test container.
fn build_remote_docker_image() -> Result<ImageId> {
    let dockerfile = formatdoc! {r#"
        FROM debian:13

        # Install SSH server, Docker, and utilities
        RUN apt-get update && apt-get install -y \
            openssh-server \
            docker.io \
            git \
            iproute2 \
            && rm -rf /var/lib/apt/lists/*

        # Create test user with Docker access
        RUN useradd -m -u {TEST_USER_UID} -s /bin/bash {SSH_USER} \
            && usermod -aG docker {SSH_USER}

        # Configure SSH: create required directories and generate host keys
        # GatewayPorts=clientspecified allows remote port forwards to bind to non-localhost addresses
        RUN mkdir -p /run/sshd \
            && ssh-keygen -A \
            && sed -i 's/#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config \
            && sed -i 's/#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config \
            && sed -i 's/#PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config \
            && echo 'GatewayPorts clientspecified' >> /etc/ssh/sshd_config

        # Startup script that runs both SSH and Docker.
        # After a container restart, stale PID and socket files from the previous
        # dockerd/containerd can prevent startup (dockerd sees the old containerd PID
        # file, thinks it is "still running", and hangs). We clean those up first.
        RUN echo '#!/bin/bash\n\
            set -e\n\
            rm -f /var/run/docker.pid\n\
            rm -f /var/run/docker/containerd/containerd.pid\n\
            rm -f /var/run/docker/containerd/containerd.sock*\n\
            dockerd &\n\
            for i in $(seq 1 60); do\n\
                if docker info >/dev/null 2>&1; then break; fi\n\
                sleep 1\n\
            done\n\
            exec /usr/sbin/sshd -D\n\
        ' > /start.sh && chmod +x /start.sh

        CMD ["/start.sh"]
    "#};

    build_docker_image(DockerBuild {
        dockerfile,
        build_context: None,
    })
}

/// SSH configuration for test daemons.
///
/// This holds the path to an SSH config file and keeps the underlying
/// temp directory alive.
pub struct SshConfig {
    /// Path to the SSH config file.
    pub path: PathBuf,
    /// Temp directory containing the config and known_hosts file.
    _temp_dir: TempDir,
}

/// Create an SSH config file for the given remote hosts.
///
/// The config file provides isolation from the user's SSH configuration:
/// - Uses a separate known_hosts file
/// - Configures each host with its specific identity file
/// - Sets IdentitiesOnly to prevent using ssh-agent keys
pub fn create_ssh_config(hosts: &[&SshRemoteHost]) -> SshConfig {
    let temp_dir = TempDir::with_prefix("rumpelpod-ssh-config-")
        .expect("Failed to create temp dir for SSH config");
    let config_path = temp_dir.path().join("config");
    let known_hosts_path = temp_dir.path().join("known_hosts");

    let mut config = formatdoc! {r#"
        # SSH config for rumpelpod integration tests
        # Auto-generated - provides isolation from user's SSH configuration

        # Global settings
        Host *
            UserKnownHostsFile {known_hosts}
            StrictHostKeyChecking accept-new
            BatchMode yes
            ConnectTimeout 10

    "#,
        known_hosts = known_hosts_path.display(),
    };

    // Add host-specific settings
    for host in hosts {
        let mut host_config = formatdoc! {r#"
            Host {ssh_host}
                IdentityFile {key}
                IdentitiesOnly yes
        "#,
            ssh_host = host.ssh_host(),
            key = host.private_key_path().display(),
        };
        if let Some(port) = host.published_port {
            host_config.push_str(&format!("    Port {}\n", port));
        }
        host_config.push('\n');
        config.push_str(&host_config);
    }

    std::fs::write(&config_path, config).expect("Failed to write SSH config");

    SshConfig {
        path: config_path,
        _temp_dir: temp_dir,
    }
}

/// Write config files for a remote Docker host test.
///
/// Writes a devcontainer.json with the image/workspace/runtime settings,
/// and a .rumpelpod.toml with only the host specification.
pub fn write_remote_pod_config(repo: &TestRepo, image_id: &ImageId, remote_spec: &str) {
    let devcontainer_dir = repo.path().join(".devcontainer");
    std::fs::create_dir_all(&devcontainer_dir).expect("Failed to create .devcontainer dir");

    let devcontainer_json = formatdoc! {r#"
        {{
            "image": "{image_id}",
            "workspaceFolder": "{TEST_REPO_PATH}",
            "runArgs": ["--runtime=runc"]
        }}
    "#};
    std::fs::write(
        devcontainer_dir.join("devcontainer.json"),
        devcontainer_json,
    )
    .expect("Failed to write devcontainer.json");

    let config = formatdoc! {r#"
        host = "{remote_spec}"
    "#};
    std::fs::write(repo.path().join(".rumpelpod.toml"), config)
        .expect("Failed to write .rumpelpod.toml");
}

// Tests
// Note: These tests require privileged Docker containers, which may not be
// available in all CI environments.

#[test]
fn ssh_smoke_test() {
    let repo = TestRepo::new();

    // Build test image locally
    let image_id =
        crate::common::build_test_image(repo.path(), "").expect("Failed to build test image");

    // Start remote host and load the image
    let remote = SshRemoteHost::start();
    let remote_image_id = remote
        .load_image(&image_id)
        .expect("Failed to load image into remote Docker");

    // Create SSH config and start daemon
    let ssh_config = create_ssh_config(&[&remote]);
    let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

    // Write pod config using the remote image ID (may differ from local
    // when Docker engine versions differ, e.g. Docker Desktop vs docker.io)
    write_remote_pod_config(&repo, &remote_image_id, &remote.ssh_spec());

    // Enter the pod on the remote Docker host
    let pod_name = "remote-test";
    let output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "hello from remote"])
        .output()
        .expect("rumpel enter failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "rumpel enter failed: stdout={}, stderr={}",
        stdout,
        stderr
    );
    assert_eq!(stdout.trim(), "hello from remote");

    // Verify container exists on remote host
    let remote_containers = remote
        .ssh_command(
            &ssh_config.path,
            &["docker", "ps", "--format", "{{.Names}}"],
        )
        .expect("docker ps failed");
    let remote_containers_str = String::from_utf8_lossy(&remote_containers);

    // The container name usually contains the pod name.
    assert!(
        remote_containers_str.contains(pod_name),
        "remote container should exist: {}",
        remote_containers_str
    );
}

#[ignore]
#[test]
fn ssh_reconnect_test() {
    let repo = TestRepo::new();

    // Build test image locally
    let image_id =
        crate::common::build_test_image(repo.path(), "").expect("Failed to build test image");

    // Start remote host and load the image
    let mut remote = SshRemoteHost::start();
    let remote_image_id = remote
        .load_image(&image_id)
        .expect("Failed to load image into remote Docker");

    // Create SSH config and start daemon
    let ssh_config = create_ssh_config(&[&remote]);
    let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

    // Write pod config
    write_remote_pod_config(&repo, &remote_image_id, &remote.ssh_spec());

    // Enter the pod on the remote Docker host
    let pod_name = "reconnect-test";
    let output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "hello from remote"])
        .output()
        .expect("rumpel enter failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "first rumpel enter failed: stdout={}, stderr={}",
        stdout,
        stderr
    );
    assert_eq!(stdout.trim(), "hello from remote");

    // Restart the remote host, verifying SSH connectivity before proceeding.
    // This ensures the daemon can reconnect immediately rather than racing
    // against sshd startup.
    let old_ip = remote.ip_address().to_string();
    remote.restart(Some(&ssh_config.path));
    assert_eq!(
        remote.ip_address(),
        old_ip,
        "IP address changed after restart, test cannot proceed"
    );

    // Try to enter again
    let output = pod_command(&repo, &daemon)
        .args(["enter", pod_name, "--", "echo", "hello again"])
        .output()
        .expect("rumpel enter failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "second rumpel enter failed: stdout={}, stderr={}",
        stdout,
        stderr
    );
    assert_eq!(stdout.trim(), "hello again");
}
