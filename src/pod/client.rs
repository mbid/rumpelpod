//! Typed HTTP client for the in-container server.
//!
//! Follows the `DaemonClient` pattern from `daemon::protocol`: wraps
//! `reqwest::blocking::Client`, one method per endpoint, returns `Result<T>`.
//! Callers see synchronous method calls.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use flate2::read::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

use super::types::*;
use crate::jitter;
use crate::RetryPolicy;

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
    /// `policy` controls whether the readiness poll retries indefinitely
    /// (`UserBlocking`) or gives up after a fixed number of attempts
    /// (`Background`).
    pub fn new(url: &str, token: &str, policy: RetryPolicy) -> Result<Self> {
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
        pod.wait_ready(policy)?;
        Ok(pod)
    }

    /// Connect to the container server, printing progress to stderr.
    ///
    /// Convenience for CLI commands where a user is waiting.
    pub fn connect(url: &str, token: &str) -> Result<Self> {
        Self::new(url, token, RetryPolicy::UserBlocking)
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn token(&self) -> &str {
        &self.token
    }

    /// Block until the container server responds to /health.
    ///
    /// Uses exponential backoff (100ms doubling up to 5s) so high-latency
    /// links (e.g. remote Docker over slow WiFi) get enough time without
    /// hammering the connection.
    ///
    /// `UserBlocking` retries indefinitely with progress on stderr.
    /// `Background` gives up after 20 attempts.
    fn wait_ready(&self, policy: RetryPolicy) -> Result<()> {
        let url = &self.url;
        let poll_client = reqwest::blocking::Client::builder()
            .build()
            .expect("failed to build poll client");

        let max_delay = Duration::from_secs(5);
        let mut delay = Duration::from_millis(100);
        let mut attempt = 0u32;
        let verbose = policy == RetryPolicy::UserBlocking;

        loop {
            attempt += 1;
            match poll_client.get(format!("{url}/health")).send() {
                Ok(resp) if resp.status().is_success() => {
                    if verbose && attempt > 1 {
                        eprintln!("Connected to container server after {attempt} attempts");
                    }
                    return Ok(());
                }
                Ok(resp) => {
                    if verbose {
                        let status = resp.status();
                        eprintln!(
                            "Waiting for container server (attempt {attempt}, status {status})..."
                        );
                    }
                }
                Err(e) => {
                    if verbose {
                        eprintln!("Waiting for container server (attempt {attempt}: {e})...");
                    }
                }
            }
            if policy == RetryPolicy::Background && attempt >= 20 {
                return Err(anyhow::anyhow!(
                    "container server at {url} did not become ready"
                ));
            }
            std::thread::sleep(jitter(delay));
            delay = delay.saturating_mul(2).min(max_delay);
        }
    }

    // -------------------------------------------------------------------
    // Enter / write-home-files
    // -------------------------------------------------------------------

    pub fn enter(&self, req: &EnterRequest) -> Result<EnterResponse> {
        self.post("/enter", req)
    }

    /// Write multiple files under the container user's home directory.
    /// Returns the home directory path.
    pub fn write_home_files(
        &self,
        files: Vec<HomeFileEntry>,
        tar_extracts: Vec<TarExtractEntry>,
    ) -> Result<WriteHomeFilesResponse> {
        self.post(
            "/write-home-files",
            &WriteHomeFilesRequest {
                files,
                tar_extracts,
            },
        )
    }

    // -------------------------------------------------------------------
    // Filesystem (used by agents for ad-hoc file operations)
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

    // -------------------------------------------------------------------
    // Git (snapshot/patch for change transfer)
    // -------------------------------------------------------------------

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

    /// Populate bind mount targets inside the container from a single tar
    /// archive whose entries use absolute destination paths (leading slash
    /// stripped).  The reader is gzip-compressed on-the-fly and streamed.
    pub fn init_mounts(&self, reader: impl std::io::Read + Send + 'static) -> Result<()> {
        let gz_reader = GzEncoder::new(reader, Compression::fast());
        let body = reqwest::blocking::Body::new(gz_reader);

        let base = &self.url;
        let token = &self.token;
        let url = format!("{base}/init-mounts");
        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {token}"))
            .header("Content-Type", "application/x-tar")
            .header("Content-Encoding", "gzip")
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
            Err(anyhow::anyhow!("POST /init-mounts: {err}"))
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
