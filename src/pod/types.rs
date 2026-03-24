//! Shared request/response types for the pod HTTP protocol.
//!
//! Used by both the in-container server (`pod::server`) and the
//! host-side client (`pod::client`).

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::git::GitIdentity;

// ---------------------------------------------------------------------------
// Filesystem
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct FsReadRequest {
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsReadResponse {
    /// Base64-encoded file content.
    pub content: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsWriteRequest {
    pub path: PathBuf,
    /// Base64-encoded file content.
    pub content: String,
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsStatRequest {
    pub path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsStatResponse {
    pub exists: bool,
    pub is_dir: bool,
    pub is_file: bool,
    pub owner: Option<String>,
}

// ---------------------------------------------------------------------------
// Git (internal types used by server-side impl functions)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSetupRequest {
    pub repo_path: PathBuf,
    pub url: String,
    pub token: String,
    pub pod_name: String,
    pub host_branch: Option<String>,
    /// Git user identity from the host to write into the pod's .git/config.
    pub git_identity: Option<GitIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmoduleEntry {
    pub name: String,
    pub path: String,
    pub displaypath: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSetupSubmodulesRequest {
    pub repo_path: PathBuf,
    pub submodules: Vec<SubmoduleEntry>,
    pub base_url: String,
    pub token: String,
    pub pod_name: String,
    #[serde(default)]
    pub is_first_entry: bool,
}

// Git (snapshot/patch for change transfer)

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSnapshotRequest {
    pub repo_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSnapshotResponse {
    /// Base64-encoded patch, or null if there are no changes.
    pub patch: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitApplyPatchRequest {
    pub repo_path: PathBuf,
    /// Base64-encoded patch content.
    pub patch: String,
    #[serde(default)]
    pub created_files: Vec<String>,
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub home: String,
    pub shell: String,
    pub uid: u32,
    pub gid: u32,
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct RunRequest {
    pub cmd: Vec<String>,
    pub workdir: Option<PathBuf>,
    #[serde(default)]
    pub env: Vec<String>,
    /// Base64-encoded stdin data.
    pub stdin: Option<String>,
    pub timeout_secs: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RunResponse {
    pub exit_code: i32,
    /// Base64-encoded stdout.
    pub stdout: String,
    /// Base64-encoded stderr.
    pub stderr: String,
    #[serde(default)]
    pub timed_out: bool,
}

// ---------------------------------------------------------------------------
// Copy (tar-based file transfer)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct CpDownloadRequest {
    pub path: PathBuf,
    #[serde(default)]
    pub follow_symlinks: bool,
}

// Download is GET /cp with query parameters from CpDownloadRequest,
// returning a streamed tar body. Upload is POST /cp with a tar body
// and X-Path header.

// ---------------------------------------------------------------------------
// Enter (high-level: repo init + SSH + git setup + env probe)
// ---------------------------------------------------------------------------

/// All-in-one pod entry: ensures the repo exists, configures SSH relay and
/// git remotes, sets up submodules, probes the user environment, and returns
/// user info.  Replaces the old sequence of ssh_configure +
/// ensure_repo_initialized + git_setup + git_setup_submodules + probe_env +
/// user_info calls.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnterRequest {
    pub repo_path: PathBuf,
    /// Base URL of the git HTTP bridge (tunneled into the container).
    /// The git remote URL is derived as `{base_url}/gateway.git`.
    pub base_url: String,
    /// Bearer token for git HTTP and SSH relay authentication.
    pub token: String,
    pub pod_name: String,
    pub host_branch: Option<String>,
    pub git_identity: Option<GitIdentity>,
    #[serde(default)]
    pub submodules: Vec<SubmoduleEntry>,
    /// Controls submodule cloning.  True on first pod creation.
    #[serde(default)]
    pub is_first_entry: bool,
    /// Shell flags for env probe (e.g. "-lic").  None to skip probing.
    pub shell_flags: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnterResponse {
    pub user_info: UserInfoResponse,
    pub probed_env: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Write home files (batch write config files under $HOME)
// ---------------------------------------------------------------------------

/// Write multiple files under the container user's home directory in one call.
/// Replaces the old sequence of user_info + fs_mkdir + fs_write calls used by
/// copy_claude_config_via_pod.
#[derive(Debug, Serialize, Deserialize)]
pub struct WriteHomeFilesRequest {
    /// Files to write, with paths relative to the user's home directory.
    #[serde(default)]
    pub files: Vec<HomeFileEntry>,
    /// Optional tar archive to extract under the home directory.
    #[serde(default)]
    pub tar_extracts: Vec<TarExtractEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeFileEntry {
    /// Path relative to home (e.g. ".claude/settings.json").
    pub path: String,
    /// Base64-encoded file content.
    pub content: String,
    /// Create parent directories if they do not exist.
    #[serde(default)]
    pub create_parents: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TarExtractEntry {
    /// Directory relative to home where the tar should be extracted.
    pub dest: String,
    /// Base64-encoded tar data.
    pub data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct WriteHomeFilesResponse {
    /// The home directory that was written to.
    pub home: String,
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

// ---------------------------------------------------------------------------
// Base64 helpers
// ---------------------------------------------------------------------------

pub fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

pub fn base64_decode(s: &str) -> Result<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(s)
        .context("base64 decode")
}
