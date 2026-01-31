//! Integration tests for SSH remote Docker functionality.
//!
//! These tests verify that sandboxes can be created on remote Docker hosts
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
    build_docker_image, sandbox_command, DockerBuild, ImageId, TestDaemon, TestRepo,
    TEST_REPO_PATH, TEST_USER_UID,
};

/// Test user for SSH connections.
pub const SSH_USER: &str = "testuser";

/// Timeout for waiting for services to become available.
const SERVICE_TIMEOUT: Duration = Duration::from_secs(60);

/// A container simulating a remote Docker host with SSH access.
///
/// This is a test fixture similar to `TestRepo` and `TestDaemon`.
/// It manages a Docker container running both an SSH server and a Docker daemon.
///
/// On drop, the container is stopped and removed.
pub struct SshRemoteHost {
    /// Docker container ID.
    container_id: String,
    /// IP address of the container.
    ip_address: String,
    /// Temporary directory containing SSH keys.
    _temp_dir: TempDir,
    /// Path to the private key file.
    private_key_path: PathBuf,
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
            TempDir::with_prefix("sandbox-ssh-test-").expect("Failed to create temp dir for SSH");
        let private_key_path = temp_dir.path().join("id_ed25519");
        let public_key_path = temp_dir.path().join("id_ed25519.pub");

        // Generate SSH key pair
        let status = Command::new("ssh-keygen")
            .args(["-t", "ed25519"])
            .args(["-f", &private_key_path.to_string_lossy()])
            .args(["-N", ""]) // Empty passphrase
            .args(["-q"]) // Quiet
            .status()
            .expect("Failed to run ssh-keygen");
        assert!(status.success(), "ssh-keygen failed");

        // Read the public key
        let public_key =
            std::fs::read_to_string(&public_key_path).expect("Failed to read public key");

        // Start the container with privileged mode for nested Docker
        // No port publishing - we connect directly to the container IP
        let output = Command::new("docker")
            .args(["run", "-d", "--privileged", &image_id.to_string()])
            .output()
            .expect("Failed to start remote docker container");

        assert!(
            output.status.success(),
            "Failed to start remote docker container: {}",
            String::from_utf8_lossy(&output.stderr)
        );

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Get the container's IP address
        let ip_address = get_container_ip(&container_id).expect("Failed to get container IP");

        let host = SshRemoteHost {
            container_id,
            ip_address,
            _temp_dir: temp_dir,
            private_key_path,
        };

        // Install the public key for the test user
        host.install_public_key(&public_key);

        // Wait for SSH and Docker to be ready
        host.wait_for_services();

        host
    }

    /// Get the SSH connection string for this remote host (user@host format).
    pub fn ssh_spec(&self) -> String {
        format!("{}@{}", SSH_USER, self.ip_address)
    }

    /// Get the IP address of this remote host.
    pub fn ip_address(&self) -> &str {
        &self.ip_address
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

        let output = Command::new("docker")
            .args(["exec", &self.container_id, "sh", "-c", &setup_script])
            .output()
            .expect("Failed to install SSH public key");

        assert!(
            output.status.success(),
            "Failed to install SSH public key: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Wait for SSH and Docker services to be ready.
    fn wait_for_services(&self) {
        let start = Instant::now();

        // Wait for Docker first (it takes longer)
        while start.elapsed() < SERVICE_TIMEOUT {
            let status = Command::new("docker")
                .args(["exec", &self.container_id, "docker", "info"])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if matches!(status, Ok(s) if s.success()) {
                break;
            }
            std::thread::sleep(Duration::from_millis(500));
        }

        // Wait for SSH
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

        panic!(
            "Services did not become available within {:?}",
            SERVICE_TIMEOUT
        );
    }

    /// Run an SSH command on this remote host.
    pub fn ssh_command(&self, ssh_config: &Path, command: &[&str]) -> Result<Vec<u8>> {
        let config_path = ssh_config.to_string_lossy();
        let user_host = self.ssh_spec();

        let mut ssh_args = vec!["-F", &config_path, &user_host];
        ssh_args.extend(command.iter().copied());

        let output = Command::new("ssh")
            .args(&ssh_args)
            .output()
            .context("running SSH command")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("SSH command failed: {}", stderr);
        }

        Ok(output.stdout)
    }

    /// Load a Docker image into this remote host's Docker daemon.
    pub fn load_image(&self, image_id: &ImageId) -> Result<()> {
        // Save image to a tar file
        let tar_path = self._temp_dir.path().join("image.tar");
        let status = Command::new("docker")
            .args([
                "save",
                "-o",
                &tar_path.to_string_lossy(),
                &image_id.to_string(),
            ])
            .status()
            .context("saving docker image")?;
        if !status.success() {
            anyhow::bail!("docker save failed");
        }

        // Copy tar file to the remote container
        let remote_tar = "/tmp/image.tar";
        let status = Command::new("docker")
            .args([
                "cp",
                &tar_path.to_string_lossy(),
                &format!("{}:{}", self.container_id, remote_tar),
            ])
            .status()
            .context("copying image tar to remote")?;
        if !status.success() {
            anyhow::bail!("docker cp failed");
        }

        // Load the image on the remote Docker daemon
        let output = Command::new("docker")
            .args([
                "exec",
                &self.container_id,
                "docker",
                "load",
                "-i",
                remote_tar,
            ])
            .output()
            .context("loading image on remote docker")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("docker load on remote failed: {}", stderr);
        }

        // Clean up the tar file
        let _ = Command::new("docker")
            .args(["exec", &self.container_id, "rm", remote_tar])
            .status();

        Ok(())
    }
}

impl Drop for SshRemoteHost {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_id])
            .output();
    }
}

/// Get a container's IP address.
fn get_container_ip(container_id: &str) -> Result<String> {
    let output = Command::new("docker")
        .args([
            "inspect",
            "-f",
            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
            container_id,
        ])
        .output()
        .context("getting container IP")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker inspect failed: {}", stderr);
    }

    let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
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

        # Startup script that runs both SSH and Docker
        RUN echo '#!/bin/bash\n\
            set -e\n\
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
    let temp_dir = TempDir::with_prefix("sandbox-ssh-config-")
        .expect("Failed to create temp dir for SSH config");
    let config_path = temp_dir.path().join("config");
    let known_hosts_path = temp_dir.path().join("known_hosts");

    let mut config = formatdoc! {r#"
        # SSH config for sandbox integration tests
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
        config.push_str(&formatdoc! {r#"
            Host {ip}
                IdentityFile {key}
                IdentitiesOnly yes

        "#,
            ip = host.ip_address(),
            key = host.private_key_path().display(),
        });
    }

    std::fs::write(&config_path, config).expect("Failed to write SSH config");

    SshConfig {
        path: config_path,
        _temp_dir: temp_dir,
    }
}

/// Write a sandbox config that uses a remote Docker host.
pub fn write_remote_sandbox_config(repo: &TestRepo, image_id: &ImageId, remote_spec: &str) {
    let config = formatdoc! {r#"
        runtime = "runc"
        image = "{image_id}"
        repo-path = "{TEST_REPO_PATH}"
        host = "{remote_spec}"
    "#};
    std::fs::write(repo.path().join(".sandbox.toml"), config)
        .expect("Failed to write .sandbox.toml");
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
    remote
        .load_image(&image_id)
        .expect("Failed to load image into remote Docker");

    // Create SSH config and start daemon
    let ssh_config = create_ssh_config(&[&remote]);
    let daemon = TestDaemon::start_with_ssh_config(&ssh_config.path);

    // Write sandbox config
    write_remote_sandbox_config(&repo, &image_id, &remote.ssh_spec());

    // Enter the sandbox on the remote Docker host
    let sandbox_name = "remote-test";
    let output = sandbox_command(&repo, &daemon)
        .args(["enter", sandbox_name, "--", "echo", "hello from remote"])
        .output()
        .expect("sandbox enter failed to execute");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "sandbox enter failed: stdout={}, stderr={}",
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

    // The container name usually contains the sandbox name.
    assert!(
        remote_containers_str.contains(sandbox_name),
        "remote container should exist: {}",
        remote_containers_str
    );
}
