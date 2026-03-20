//! Typed HTTP client for the in-container server.
//!
//! Follows the `DaemonClient` pattern from `daemon::protocol`: wraps
//! `reqwest::blocking::Client`, one method per endpoint, returns `Result<T>`.
//! Callers see synchronous method calls.

use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use retry::delay::Exponential;
use serde::{Deserialize, Serialize};

use super::types::*;
use crate::git::GitIdentity;

#[derive(Debug, Serialize, Deserialize)]
struct ErrorResponse {
    error: String,
}

pub struct PodClient {
    client: reqwest::blocking::Client,
    url: String,
    token: String,
}

impl PodClient {
    /// Connect to the container server, waiting for it to become ready.
    ///
    /// Used by the daemon where no user-facing output is needed.
    pub fn new(url: &str, token: &str) -> Result<Self> {
        Self::build(url, token, false)
    }

    /// Connect to the container server, printing progress to stderr.
    ///
    /// Used by CLI commands so the user sees feedback on slow connections.
    pub fn connect(url: &str, token: &str) -> Result<Self> {
        Self::build(url, token, true)
    }

    fn build(url: &str, token: &str, verbose: bool) -> Result<Self> {
        let client = reqwest::blocking::Client::builder()
            .timeout(None)
            .gzip(true)
            .build()
            .expect("failed to build reqwest client");
        let pod = Self {
            client,
            url: url.trim_end_matches('/').to_string(),
            token: token.to_string(),
        };
        pod.wait_ready(verbose)?;
        Ok(pod)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Block until the container server responds to /health, or give up.
    ///
    /// Uses exponential backoff (100ms doubling up to 5s) so high-latency
    /// links (e.g. remote Docker over slow WiFi) get enough time without
    /// hammering the connection.
    fn wait_ready(&self, verbose: bool) -> Result<()> {
        let url = &self.url;
        let poll_client = reqwest::blocking::Client::builder()
            .build()
            .expect("failed to build poll client");

        let max_delay = Duration::from_secs(5);
        let delays = Exponential::from_millis(100).map(move |d| d.min(max_delay));
        let mut attempt = 0u32;

        retry::retry(delays.take(20), || {
            attempt += 1;
            match poll_client.get(format!("{url}/health")).send() {
                Ok(resp) if resp.status().is_success() => {
                    if verbose && attempt > 1 {
                        eprintln!("Connected to container server after {attempt} attempts");
                    }
                    Ok(())
                }
                Ok(resp) => {
                    if verbose {
                        let status = resp.status();
                        eprintln!(
                            "Waiting for container server (attempt {attempt}, status {status})..."
                        );
                    }
                    Err(())
                }
                Err(e) => {
                    if verbose {
                        eprintln!("Waiting for container server (attempt {attempt}: {e})...");
                    }
                    Err(())
                }
            }
        })
        .map_err(|_| anyhow::anyhow!("container server at {url} did not become ready"))
    }

    // -------------------------------------------------------------------
    // Filesystem
    // -------------------------------------------------------------------

    pub fn fs_read(&self, path: &Path) -> Result<Vec<u8>> {
        let resp: FsReadResponse = self.post(
            "/fs/read",
            &FsReadRequest {
                path: path.to_path_buf(),
            },
        )?;
        base64_decode(&resp.content)
    }

    pub fn fs_write(&self, path: &Path, content: &[u8], create_parents: bool) -> Result<()> {
        self.post_unit(
            "/fs/write",
            &FsWriteRequest {
                path: path.to_path_buf(),
                content: base64_encode(content),
                create_parents,
            },
        )
    }

    pub fn fs_stat(&self, path: &Path) -> Result<FsStatResponse> {
        self.post(
            "/fs/stat",
            &FsStatRequest {
                path: path.to_path_buf(),
            },
        )
    }

    pub fn fs_mkdir(&self, path: &Path) -> Result<()> {
        self.post_unit(
            "/fs/mkdir",
            &FsMkdirRequest {
                path: path.to_path_buf(),
            },
        )
    }

    // -------------------------------------------------------------------
    // Git
    // -------------------------------------------------------------------

    pub fn git_clone(
        &self,
        url: &str,
        dest: &Path,
        auth_header: Option<&str>,
        lfs: bool,
    ) -> Result<()> {
        self.post_unit(
            "/git/clone",
            &GitCloneRequest {
                url: url.to_string(),
                dest: dest.to_path_buf(),
                auth_header: auth_header.map(String::from),
                lfs,
            },
        )
    }

    pub fn git_setup(
        &self,
        repo_path: &Path,
        url: &str,
        token: &str,
        pod_name: &str,
        host_branch: Option<&str>,
        git_identity: Option<&GitIdentity>,
    ) -> Result<()> {
        self.post_unit(
            "/git/setup",
            &GitSetupRequest {
                repo_path: repo_path.to_path_buf(),
                url: url.to_string(),
                token: token.to_string(),
                pod_name: pod_name.to_string(),
                host_branch: host_branch.map(String::from),
                git_identity: git_identity.cloned(),
            },
        )
    }

    pub fn git_install_hook(&self, repo_path: &Path) -> Result<bool> {
        let resp: GitInstallHookResponse = self.post(
            "/git/install-hook",
            &GitInstallHookRequest {
                repo_path: repo_path.to_path_buf(),
            },
        )?;
        Ok(resp.first_install)
    }

    pub fn git_setup_submodules(
        &self,
        repo_path: &Path,
        submodules: &[SubmoduleEntry],
        base_url: &str,
        token: &str,
        pod_name: &str,
        is_first_entry: bool,
    ) -> Result<()> {
        self.post_unit(
            "/git/setup-submodules",
            &GitSetupSubmodulesRequest {
                repo_path: repo_path.to_path_buf(),
                submodules: submodules.to_vec(),
                base_url: base_url.to_string(),
                token: token.to_string(),
                pod_name: pod_name.to_string(),
                is_first_entry,
            },
        )
    }

    pub fn git_sanitize(&self, repo_path: &Path) -> Result<()> {
        self.post_unit(
            "/git/sanitize",
            &GitSanitizeRequest {
                repo_path: repo_path.to_path_buf(),
            },
        )
    }

    pub fn git_snapshot(&self, repo_path: &Path) -> Result<Option<Vec<u8>>> {
        let resp: GitSnapshotResponse = self.post(
            "/git/snapshot",
            &GitSnapshotRequest {
                repo_path: repo_path.to_path_buf(),
            },
        )?;
        match resp.patch {
            Some(b64) => Ok(Some(base64_decode(&b64)?)),
            None => Ok(None),
        }
    }

    pub fn git_apply_patch(
        &self,
        repo_path: &Path,
        patch: &[u8],
        created_files: &[String],
    ) -> Result<()> {
        self.post_unit(
            "/git/apply-patch",
            &GitApplyPatchRequest {
                repo_path: repo_path.to_path_buf(),
                patch: base64_encode(patch),
                created_files: created_files.to_vec(),
            },
        )
    }

    // -------------------------------------------------------------------
    // Environment
    // -------------------------------------------------------------------

    pub fn user_info(&self) -> Result<UserInfoResponse> {
        self.post("/env/user-info", &serde_json::json!({}))
    }

    pub fn probe_env(&self, shell_flags: &str) -> Result<HashMap<String, String>> {
        let resp: ProbeEnvResponse = self.post(
            "/env/probe",
            &ProbeEnvRequest {
                shell_flags: shell_flags.to_string(),
            },
        )?;
        Ok(resp.env)
    }

    // -------------------------------------------------------------------
    // Copy (tar-based file transfer)
    // -------------------------------------------------------------------

    /// Download a file or directory from the container as a tar stream.
    ///
    /// The archive uses the wrapper format (`_/<name>/...`) so the caller
    /// can distinguish files from directories by inspecting the tar entries.
    /// Returns a reader over the response body; data is streamed without
    /// buffering the entire archive in memory.
    pub fn cp_download(&self, path: &Path, follow_symlinks: bool) -> Result<impl std::io::Read> {
        let base = &self.url;
        let token = &self.token;
        let url = format!("{base}/cp");
        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {token}"))
            .query(&CpDownloadRequest {
                path: path.to_path_buf(),
                follow_symlinks,
            })
            .send()
            .with_context(|| format!("sending request to {url}"))?;

        if !response.status().is_success() {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "unknown error".to_string(),
            });
            let err = &error.error;
            return Err(anyhow::anyhow!("GET /cp: {err}"));
        }

        Ok(response)
    }

    /// Upload a tar archive and extract it at `path` in the container.
    ///
    /// The archive must use the wrapper format (`_/<name>/...`).
    /// The reader is gzip-compressed on-the-fly and streamed as the
    /// request body; neither the tar nor the compressed data is buffered.
    pub fn cp_upload(
        &self,
        path: &Path,
        reader: impl std::io::Read + Send + 'static,
    ) -> Result<()> {
        use flate2::read::GzEncoder;
        use flate2::Compression;

        let gz_reader = GzEncoder::new(reader, Compression::fast());
        let body = reqwest::blocking::Body::new(gz_reader);

        let base = &self.url;
        let token = &self.token;
        let url = format!("{base}/cp");
        let path_display = path.display();
        let req = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/x-tar")
            .header("Content-Encoding", "gzip")
            .header("X-Path", format!("{path_display}"));
        let response = req
            .body(body)
            .send()
            .with_context(|| format!("sending request to {url}"))?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "unknown error".to_string(),
            });
            let err = &error.error;
            Err(anyhow::anyhow!("POST /cp: {err}"))
        }
    }

    // -------------------------------------------------------------------
    // Command execution
    // -------------------------------------------------------------------

    pub fn run(
        &self,
        cmd: &[&str],
        workdir: Option<&Path>,
        env: &[String],
        stdin: Option<&[u8]>,
        timeout_secs: Option<u64>,
    ) -> Result<RunResponse> {
        self.post(
            "/run",
            &RunRequest {
                cmd: cmd.iter().map(|s| s.to_string()).collect(),
                workdir: workdir.map(|p| p.to_path_buf()),
                env: env.to_vec(),
                stdin: stdin.map(base64_encode),
                timeout_secs,
            },
        )
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    fn post<Req: Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        body: &Req,
    ) -> Result<Resp> {
        let base = &self.url;
        let token = &self.token;
        let url = format!("{base}{path}");
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .json(body)
            .send()
            .with_context(|| format!("sending request to {url}"))?;

        if response.status().is_success() {
            response
                .json()
                .with_context(|| format!("parsing response from {path}"))
        } else {
            let error: ErrorResponse = response.json().unwrap_or_else(|_| ErrorResponse {
                error: "unknown error".to_string(),
            });
            let err = &error.error;
            Err(anyhow::anyhow!("{path}: {err}"))
        }
    }

    fn post_unit<Req: Serialize>(&self, path: &str, body: &Req) -> Result<()> {
        let _: serde_json::Value = self.post(path, body)?;
        Ok(())
    }
}
