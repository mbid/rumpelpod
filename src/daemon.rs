mod protocol;

use anyhow::{Context, Result};
use indoc::indoc;
use std::path::PathBuf;

use protocol::{ContainerId, Daemon, Image};

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
    fn launch_sandbox(&self, _image: Image, _repo_path: PathBuf) -> Result<ContainerId> {
        // TODO:
        // - Calculate combined hash for image + repo_path.
        // - Check whether running container with that label exists already.
        //   If a container exists but is stopped, delete, but warn!
        // - If not: docker run.
        //
        // Return container ID of running container.
        todo!()
    }
}

pub fn run_daemon() -> Result<()> {
    let daemon = DaemonServer {};
    protocol::serve_daemon(daemon);
}
