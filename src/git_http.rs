//! Git HTTP backend server for sandbox repositories.
//!
//! Provides HTTP access to meta.git repositories with branch-based access control.
//! Each sandbox gets its own HTTP server that:
//! - Allows fetching any branch (read access)
//! - Only allows pushing to the sandbox's own branch (write access via update hook)
//!
//! The server runs on the host and is accessible from inside containers via
//! `http://host.docker.internal:$SANDBOX_GIT_HTTP_PORT/meta.git`.

use anyhow::{Context, Result};
use log::{debug, error, info};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

/// A running git HTTP server instance.
pub struct GitHttpServer {
    /// The port the server is listening on (on the host).
    pub host_port: u16,
    /// Handle to signal shutdown.
    shutdown: Arc<AtomicBool>,
    /// Thread handle for the server.
    thread: Option<thread::JoinHandle<()>>,
}

impl GitHttpServer {
    /// Start a new git HTTP server for a sandbox.
    ///
    /// The server listens on a random available port on all interfaces and serves
    /// the meta.git repository with write access restricted to the given branch.
    /// The container can access it via `http://host.docker.internal:<port>/meta.git`.
    pub fn start(meta_git_dir: &Path, allowed_branch: &str) -> Result<Self> {
        // Bind to a random available port on all interfaces
        // (needed so Docker containers can reach it via the bridge network)
        let listener = TcpListener::bind("0.0.0.0:0").context("Failed to bind git HTTP server")?;
        let host_port = listener.local_addr()?.port();

        info!(
            "Starting git HTTP server on port {} for branch '{}'",
            host_port, allowed_branch
        );

        // Setup the update hook in meta.git to restrict pushes
        setup_update_hook(meta_git_dir, allowed_branch)?;

        // Enable receive-pack for authenticated pushes
        enable_receive_pack(meta_git_dir)?;

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_clone = Arc::clone(&shutdown);
        let meta_git_dir = meta_git_dir.to_path_buf();
        let allowed_branch = allowed_branch.to_string();

        // Set non-blocking so we can check shutdown flag
        listener
            .set_nonblocking(true)
            .context("Failed to set non-blocking")?;

        let thread = thread::spawn(move || {
            run_server(listener, meta_git_dir, allowed_branch, shutdown_clone);
        });

        Ok(GitHttpServer {
            host_port,
            shutdown,
            thread: Some(thread),
        })
    }

    /// Stop the server.
    pub fn stop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for GitHttpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Setup the update hook in meta.git to restrict pushes to the allowed branch.
fn setup_update_hook(meta_git_dir: &Path, allowed_branch: &str) -> Result<()> {
    let hooks_dir = meta_git_dir.join("hooks");
    std::fs::create_dir_all(&hooks_dir)?;

    let hook_path = hooks_dir.join("update");
    let hook_script = format!(
        r#"#!/bin/bash
# Auto-generated hook to restrict pushes to sandbox branch
refname="$1"
branch="${{refname#refs/heads/}}"
allowed_branch="{}"

if [ "$branch" != "$allowed_branch" ]; then
    echo "error: Push rejected. Only allowed to push to branch '$allowed_branch'" >&2
    exit 1
fi
exit 0
"#,
        allowed_branch
    );

    std::fs::write(&hook_path, hook_script)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)?;
    }

    debug!("Created update hook at {}", hook_path.display());
    Ok(())
}

/// Enable http.receivepack in the repository config.
fn enable_receive_pack(meta_git_dir: &Path) -> Result<()> {
    let status = Command::new("git")
        .current_dir(meta_git_dir)
        .args(["config", "http.receivepack", "true"])
        .status()
        .context("Failed to enable http.receivepack")?;

    if !status.success() {
        anyhow::bail!("Failed to enable http.receivepack");
    }
    Ok(())
}

/// Main server loop.
fn run_server(
    listener: TcpListener,
    meta_git_dir: PathBuf,
    allowed_branch: String,
    shutdown: Arc<AtomicBool>,
) {
    debug!("Git HTTP server running for branch '{}'", allowed_branch);

    while !shutdown.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, addr)) => {
                debug!("Git HTTP connection from {}", addr);
                let meta_git_dir = meta_git_dir.clone();
                thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &meta_git_dir) {
                        error!("Git HTTP error: {}", e);
                    }
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No connection available, sleep briefly and check shutdown
                thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => {
                error!("Git HTTP accept error: {}", e);
            }
        }
    }

    debug!("Git HTTP server shutting down");
}

/// Handle a single HTTP connection by invoking git-http-backend.
fn handle_connection(mut stream: TcpStream, meta_git_dir: &Path) -> Result<()> {
    // Set blocking for the actual request handling
    stream.set_nonblocking(false)?;

    // Read the HTTP request
    let mut reader = BufReader::new(&stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    if parts.len() < 2 {
        send_error(&mut stream, 400, "Bad Request")?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Read headers
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let value = value.trim().to_string();
            if key == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.push((key, value));
        }
    }

    // Read body if present
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body)?;
    }

    debug!(
        "Git HTTP: {} {} (body: {} bytes)",
        method, path, content_length
    );

    // Parse the URL to extract query string
    let (path, query_string) = if let Some(pos) = path.find('?') {
        (&path[..pos], &path[pos + 1..])
    } else {
        (path, "")
    };

    // Find git-http-backend
    let git_http_backend = find_git_http_backend()?;

    // Setup CGI environment
    let mut cmd = Command::new(&git_http_backend);
    let project_root = meta_git_dir.parent().unwrap_or(meta_git_dir);
    debug!(
        "Git HTTP backend: PROJECT_ROOT={}, PATH_INFO={}, QUERY_STRING={}",
        project_root.display(),
        path,
        query_string
    );
    cmd.env("GIT_PROJECT_ROOT", project_root);
    cmd.env("GIT_HTTP_EXPORT_ALL", "1");
    cmd.env("PATH_INFO", path);
    cmd.env("REQUEST_METHOD", method);
    cmd.env("QUERY_STRING", query_string);
    cmd.env(
        "CONTENT_TYPE",
        get_header(&headers, "content-type").unwrap_or_default(),
    );
    cmd.env("CONTENT_LENGTH", content_length.to_string());
    cmd.env("REMOTE_USER", "sandbox");
    cmd.env("REMOTE_ADDR", "127.0.0.1");

    // Pass Git-Protocol header if present
    if let Some(proto) = get_header(&headers, "git-protocol") {
        cmd.env("GIT_PROTOCOL", proto);
    }

    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd.spawn().context("Failed to spawn git-http-backend")?;

    // Write body to stdin
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(&body)?;
    }

    // Read response from git-http-backend
    let output = child.wait_with_output()?;

    // Parse CGI response and send HTTP response
    send_cgi_response(&mut stream, &output.stdout)?;

    if !output.stderr.is_empty() {
        debug!(
            "git-http-backend stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}

/// Find the git-http-backend executable.
fn find_git_http_backend() -> Result<PathBuf> {
    // Common locations
    let paths = [
        "/usr/lib/git-core/git-http-backend",
        "/usr/libexec/git-core/git-http-backend",
        "/usr/local/libexec/git-core/git-http-backend",
    ];

    for path in &paths {
        let p = PathBuf::from(path);
        if p.exists() {
            return Ok(p);
        }
    }

    // Try to find via git --exec-path
    let output = Command::new("git")
        .args(["--exec-path"])
        .output()
        .context("Failed to get git exec path")?;

    if output.status.success() {
        let exec_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let backend = PathBuf::from(&exec_path).join("git-http-backend");
        if backend.exists() {
            return Ok(backend);
        }
    }

    anyhow::bail!("Could not find git-http-backend")
}

/// Get a header value by name (case-insensitive).
fn get_header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    let name = name.to_lowercase();
    headers
        .iter()
        .find(|(k, _)| k == &name)
        .map(|(_, v)| v.as_str())
}

/// Send an HTTP error response.
fn send_error(stream: &mut TcpStream, code: u16, message: &str) -> Result<()> {
    let response = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
        code,
        message,
        message.len(),
        message
    );
    stream.write_all(response.as_bytes())?;
    Ok(())
}

/// Convert CGI response to HTTP response and send it.
fn send_cgi_response(stream: &mut TcpStream, cgi_output: &[u8]) -> Result<()> {
    // CGI output format: headers\r\n\r\nbody
    // We need to convert Status: header to HTTP status line

    let mut headers_end = 0;
    for i in 0..cgi_output.len().saturating_sub(3) {
        if &cgi_output[i..i + 4] == b"\r\n\r\n" {
            headers_end = i;
            break;
        }
    }

    if headers_end == 0 {
        // No proper header/body separation, just send as-is with default headers
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            cgi_output.len()
        );
        stream.write_all(response.as_bytes())?;
        stream.write_all(cgi_output)?;
        return Ok(());
    }

    let headers_part = &cgi_output[..headers_end];
    let body = &cgi_output[headers_end + 4..];

    // Parse CGI headers
    let headers_str = String::from_utf8_lossy(headers_part);
    let mut status_code = 200;
    let mut status_text = "OK";
    let mut http_headers = Vec::new();

    for line in headers_str.lines() {
        if let Some((key, value)) = line.split_once(':') {
            let key = key.trim();
            let value = value.trim();
            if key.eq_ignore_ascii_case("Status") {
                // Parse "200 OK" format
                let parts: Vec<&str> = value.splitn(2, ' ').collect();
                if let Some(code) = parts.first() {
                    status_code = code.parse().unwrap_or(200);
                }
                if let Some(text) = parts.get(1) {
                    status_text = text;
                }
            } else {
                http_headers.push(format!("{}: {}", key, value));
            }
        }
    }

    // Build HTTP response
    let mut response = format!("HTTP/1.1 {} {}\r\n", status_code, status_text);
    for header in &http_headers {
        response.push_str(header);
        response.push_str("\r\n");
    }
    response.push_str(&format!("Content-Length: {}\r\n", body.len()));
    response.push_str("\r\n");

    stream.write_all(response.as_bytes())?;
    stream.write_all(body)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::process::Command;

    #[test]
    fn test_find_git_http_backend() {
        // This test may fail on systems without git installed
        if Command::new("git").arg("--version").status().is_ok() {
            let result = find_git_http_backend();
            assert!(result.is_ok(), "Should find git-http-backend: {:?}", result);
        }
    }

    #[test]
    fn test_git_http_server_basic() {
        // Create a temporary bare git repository
        let tmpdir = tempfile::tempdir().unwrap();
        let meta_git = tmpdir.path().join("meta.git");

        Command::new("git")
            .args(["init", "--bare"])
            .arg(&meta_git)
            .output()
            .expect("Failed to create bare repo");

        // Start the server
        let server = GitHttpServer::start(&meta_git, "test-branch").unwrap();
        let port = server.host_port;

        // Give the server time to start
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Make a request to the server
        let mut stream =
            TcpStream::connect(format!("127.0.0.1:{}", port)).expect("Failed to connect");
        stream
            .write_all(b"GET /meta.git/info/refs?service=git-upload-pack HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();

        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        let response_str = String::from_utf8_lossy(&response);

        // Check that we got a valid response
        assert!(
            response_str.contains("HTTP/1.1 200") || response_str.contains("git-upload-pack"),
            "Expected successful response, got: {}",
            response_str
        );
    }

    #[test]
    fn test_git_http_server_ls_remote() {
        // Create a temporary bare git repository with a commit
        let tmpdir = tempfile::tempdir().unwrap();
        let meta_git = tmpdir.path().join("meta.git");
        let work_dir = tmpdir.path().join("work");

        // Create a working repo and push to bare
        std::fs::create_dir(&work_dir).unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(&work_dir)
            .output()
            .expect("Failed to init work repo");

        Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(&work_dir)
            .output()
            .unwrap();

        Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(&work_dir)
            .output()
            .unwrap();

        std::fs::write(work_dir.join("README"), "test").unwrap();
        Command::new("git")
            .args(["add", "README"])
            .current_dir(&work_dir)
            .output()
            .unwrap();

        Command::new("git")
            .args(["commit", "-m", "Initial"])
            .current_dir(&work_dir)
            .output()
            .unwrap();

        Command::new("git")
            .args(["clone", "--bare", "."])
            .arg(&meta_git)
            .current_dir(&work_dir)
            .output()
            .expect("Failed to create bare repo");

        // Start the server
        let server = GitHttpServer::start(&meta_git, "test-branch").unwrap();
        let port = server.host_port;

        // Give the server time to start
        std::thread::sleep(std::time::Duration::from_millis(100));

        // Use git ls-remote to test
        let output = Command::new("git")
            .args(["ls-remote", &format!("http://127.0.0.1:{}/meta.git", port)])
            .output()
            .expect("Failed to run git ls-remote");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        assert!(
            output.status.success(),
            "git ls-remote failed.\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );

        // Should see the master branch
        assert!(
            stdout.contains("refs/heads/master") || stdout.contains("refs/heads/main"),
            "Expected to see master/main branch.\nstdout: {}\nstderr: {}",
            stdout,
            stderr
        );
    }
}
