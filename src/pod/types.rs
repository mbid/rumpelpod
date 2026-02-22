//! Shared request/response types for the pod HTTP protocol.
//!
//! Used by both the in-container server (`pod::server`) and the
//! host-side client (`pod::client`).

use std::collections::HashMap;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

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
    pub owner: Option<String>,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct FsMkdirRequest {
    pub path: PathBuf,
    pub owner: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FsChownRequest {
    pub paths: Vec<PathBuf>,
    pub owner: String,
}

// ---------------------------------------------------------------------------
// Git
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct GitCloneRequest {
    pub url: String,
    pub dest: PathBuf,
    pub auth_header: Option<String>,
    #[serde(default)]
    pub lfs: bool,
    /// Run git as this user so working tree files have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSetupRemotesRequest {
    pub repo_path: PathBuf,
    pub url: String,
    pub token: String,
    pub pod_name: String,
    pub host_branch: Option<String>,
    #[serde(default)]
    pub direct_config: bool,
    /// Run git as this user so fetched objects have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitInstallHookRequest {
    pub repo_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitInstallHookResponse {
    pub first_install: bool,
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
    #[serde(default)]
    pub direct_config: bool,
    /// Run git as this user so submodule files have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSanitizeRequest {
    pub repo_path: PathBuf,
    /// Run git as this user so restored files have correct ownership.
    pub user: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GitSnapshotRequest {
    pub repo_path: PathBuf,
    pub user: Option<String>,
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
    pub user: Option<String>,
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoRequest {
    pub user: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UserInfoResponse {
    pub home: String,
    pub shell: String,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeEnvRequest {
    pub user: String,
    pub shell_flags: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProbeEnvResponse {
    pub env: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Command execution
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct RunRequest {
    pub cmd: Vec<String>,
    pub user: Option<String>,
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
