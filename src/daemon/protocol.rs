pub trait Daemon {
    // PUT /sandbox
    // with JSON content type for request and response bodies.
    fn launch_sandbox(image: Image, repo_path: PathBuf) -> Result<ContainerId>;
}

struct DaemonClient {}

impl DaemonClient {
    fn new(url: Url) -> Self {
        todo!()
    }
}

impl Daemon for DaemonClient {
    fn launch_sandbox(image: Image, repo_path: PathBuf) -> Result<ContainerId> {
        // TODO: Use reqwest in blocking mode to make a request to the provided daemon URL.
        todo!()
    }
}

fn serve_daemon(listener: impl Server, daemon: impl Daemon) -> ! {
    // TODO: Put `daemon` in a shared state variable, then use axum to
}
