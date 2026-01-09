use anyhow::Result;
use std::path::PathBuf;
use url::Url;

/// Opaque wrapper for docker image names.
pub struct Image(pub String);

/// Opaque wrapper for container IDs.
pub struct ContainerId(pub String);

pub trait Daemon {
    // PUT /sandbox
    // with JSON content type for request and response bodies.
    fn launch_sandbox(&self, image: Image, repo_path: PathBuf) -> Result<ContainerId>;
}

pub struct DaemonClient {
    #[allow(dead_code)]
    url: Url,
}

impl DaemonClient {
    #[allow(dead_code)]
    pub fn new(_url: Url) -> Self {
        todo!()
    }
}

impl Daemon for DaemonClient {
    fn launch_sandbox(&self, _image: Image, _repo_path: PathBuf) -> Result<ContainerId> {
        // TODO: Use reqwest in blocking mode to make a request to the provided daemon URL.
        todo!()
    }
}

pub fn serve_daemon<D: Daemon>(_daemon: D) -> ! {
    // TODO: Put `daemon` in a shared state variable, then use axum to serve.
    todo!()
}
