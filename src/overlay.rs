use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

/// Configuration for an overlay mount using Docker volumes.
/// Overlay provides copy-on-write semantics: reads come from lower (original),
/// writes go to upper, and the merged view is presented at the mount point.
#[derive(Debug, Clone)]
pub struct Overlay {
    /// Human-readable name for this overlay (e.g., "claude", "config")
    pub name: String,
    /// The original directory to overlay (read-only lower layer)
    pub lower: PathBuf,
    /// Directory for storing modifications (upper layer)
    pub upper: PathBuf,
    /// Work directory required by overlayfs
    pub work: PathBuf,
    /// Docker volume name for this overlay
    pub volume_name: String,
}

impl Overlay {
    /// Create a new overlay configuration for a directory.
    ///
    /// # Arguments
    /// * `name` - Identifier for this overlay
    /// * `lower` - Source directory (will be read-only lower layer)
    /// * `overlay_base` - Base directory where upper/work dirs will be created
    /// * `volume_prefix` - Prefix for the Docker volume name
    pub fn new(name: &str, lower: &Path, overlay_base: &Path, volume_prefix: &str) -> Self {
        let overlay_dir = overlay_base.join(name);
        Overlay {
            name: name.to_string(),
            lower: lower.to_path_buf(),
            upper: overlay_dir.join("upper"),
            work: overlay_dir.join("work"),
            volume_name: format!("{}-{}", volume_prefix, name),
        }
    }

    /// Create the necessary directories for the overlay.
    pub fn create_dirs(&self) -> Result<()> {
        std::fs::create_dir_all(&self.upper)
            .with_context(|| format!("Failed to create upper dir: {}", self.upper.display()))?;
        std::fs::create_dir_all(&self.work)
            .with_context(|| format!("Failed to create work dir: {}", self.work.display()))?;
        Ok(())
    }

    /// Create the Docker volume with overlay configuration.
    /// Docker will handle the overlayfs mount internally.
    pub fn create_volume(&self) -> Result<()> {
        self.create_dirs()?;

        // Check if volume already exists
        if self.volume_exists()? {
            return Ok(());
        }

        let overlay_opts = format!(
            "lowerdir={},upperdir={},workdir={}",
            self.lower.display(),
            self.upper.display(),
            self.work.display()
        );

        let status = Command::new("docker")
            .args([
                "volume",
                "create",
                "-d",
                "local",
                "-o",
                "type=overlay",
                "-o",
                &format!("o={}", overlay_opts),
                "-o",
                "device=overlay",
                &self.volume_name,
            ])
            .stdout(Stdio::null())
            .status()
            .context("Failed to run docker volume create")?;

        if !status.success() {
            bail!(
                "Failed to create overlay volume '{}' for {}",
                self.volume_name,
                self.name
            );
        }

        Ok(())
    }

    /// Check if the Docker volume exists.
    pub fn volume_exists(&self) -> Result<bool> {
        let output = Command::new("docker")
            .args(["volume", "inspect", &self.volume_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("Failed to run docker volume inspect")?;

        Ok(output.success())
    }

    /// Remove the Docker volume.
    pub fn remove_volume(&self) -> Result<()> {
        if !self.volume_exists()? {
            return Ok(());
        }

        let status = Command::new("docker")
            .args(["volume", "rm", &self.volume_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("Failed to run docker volume rm")?;

        if !status.success() {
            bail!("Failed to remove volume: {}", self.volume_name);
        }

        Ok(())
    }

    /// Get Docker mount arguments for this overlay.
    /// Returns the arguments to pass to `docker run`.
    pub fn docker_mount_args(&self, target: &Path) -> Vec<String> {
        vec![
            "--mount".to_string(),
            format!(
                "type=volume,source={},target={}",
                self.volume_name,
                target.display()
            ),
        ]
    }

    /// Clean up the overlay: remove volume and optionally the upper/work directories.
    pub fn cleanup(&self, remove_dirs: bool) -> Result<()> {
        // Remove the Docker volume
        let _ = self.remove_volume();

        if remove_dirs {
            // Remove the overlay directory (contains upper, work)
            if let Some(overlay_dir) = self.upper.parent() {
                if overlay_dir.exists() {
                    std::fs::remove_dir_all(overlay_dir).with_context(|| {
                        format!("Failed to remove overlay dir: {}", overlay_dir.display())
                    })?;
                }
            }
        }

        Ok(())
    }
}
