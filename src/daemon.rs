mod protocol;

use anyhow::{Context, Result};
use indoc::{formatdoc, indoc};
use listenfd::ListenFd;
use log::{debug, error, info};
use std::collections::HashMap;
use std::io::Read;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::config::{OverlayMode, Runtime, UserInfo};
use crate::docker;
use crate::git::GitSync;
use crate::git_http::GitHttpServer;
use crate::sandbox::SandboxInfo;
use crate::sandbox_config::SandboxConfig;

/// Environment variable to override the daemon socket path for testing.
pub const SOCKET_PATH_ENV: &str = "SANDBOX_DAEMON_SOCKET";

/// Get the daemon socket path.
/// Uses $SANDBOX_DAEMON_SOCKET if set, otherwise $XDG_RUNTIME_DIR/sandbox.sock.
pub fn socket_path() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(SOCKET_PATH_ENV) {
        return Ok(PathBuf::from(path));
    }

    let runtime_dir = std::env::var("XDG_RUNTIME_DIR").context(indoc! {"
        XDG_RUNTIME_DIR not set. This usually means you're not running in a
        systemd user session. The sandbox daemon requires systemd for socket activation.
    "})?;
    Ok(PathBuf::from(runtime_dir).join("sandbox.sock"))
}

struct DaemonServer {
    // No state for now. State resides in the docker service.
}

impl Daemon for DaemonServer {
    fn launch_sandbox(image: Image, repo_path: PathBuf) -> Result<ContainerId> {
        // TODO:
        // - Calculate combined hash for image + repo_path.
        // - Check whether running container with that label exists already.
        //   If a container exists but is stopped, delete, but warn!
        // - If not: docker run.
        //
        // Return container ID of running container.
    }
}
