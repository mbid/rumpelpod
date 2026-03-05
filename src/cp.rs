use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

use crate::cli::CpCommand;
use crate::config::Host;
use crate::daemon::protocol::LaunchResult;
use crate::enter;
use crate::git::get_repo_root;

#[derive(Debug)]
enum CopyDirection {
    FromPod {
        pod_name: String,
        container_path: String,
        local_path: String,
    },
    ToPod {
        pod_name: String,
        local_path: String,
        container_path: String,
    },
}

/// Split a POD:PATH argument on the first colon.
/// Returns None for `-` (stdin/stdout) or strings starting with `:`,
/// since those are not pod references.
fn parse_pod_path(arg: &str) -> Option<(&str, &str)> {
    if arg == "-" {
        return None;
    }
    let colon_pos = arg.find(':')?;
    if colon_pos == 0 {
        return None;
    }
    Some((&arg[..colon_pos], &arg[colon_pos + 1..]))
}

fn parse_direction(src: &str, dest: &str) -> Result<CopyDirection> {
    let src_pod = parse_pod_path(src);
    let dest_pod = parse_pod_path(dest);

    match (src_pod, dest_pod) {
        (Some((pod, path)), None) => Ok(CopyDirection::FromPod {
            pod_name: pod.to_string(),
            container_path: path.to_string(),
            local_path: dest.to_string(),
        }),
        (None, Some((pod, path))) => Ok(CopyDirection::ToPod {
            pod_name: pod.to_string(),
            local_path: src.to_string(),
            container_path: path.to_string(),
        }),
        (None, None) => Err(anyhow::anyhow!(
            "Neither src nor dest uses POD:PATH syntax.\n\
                 Exactly one of src or dest must specify a pod, e.g. my-pod:/path/in/container"
        )),
        (Some(_), Some(_)) => Err(anyhow::anyhow!(
            "Both src and dest use POD:PATH syntax.\n\
                 Exactly one side must be a local path."
        )),
    }
}

/// Resolve a container path: if relative, make it relative to the container repo root.
fn resolve_container_path(container_path: &str, container_repo_path: &Path) -> String {
    if Path::new(container_path).is_absolute() {
        container_path.to_string()
    } else {
        container_repo_path
            .join(container_path)
            .to_string_lossy()
            .into_owned()
    }
}

fn container_repo_path() -> Result<PathBuf> {
    let repo_root = get_repo_root()?;
    let (devcontainer, _) = enter::load_and_resolve(&repo_root, None)?;
    Ok(devcontainer.container_repo_path(&repo_root))
}

pub fn cp(cmd: &CpCommand) -> Result<()> {
    let direction = parse_direction(&cmd.src, &cmd.dest)?;
    let repo_path = container_repo_path()?;

    let pod_name = match &direction {
        CopyDirection::FromPod { pod_name, .. } => pod_name.as_str(),
        CopyDirection::ToPod { pod_name, .. } => pod_name.as_str(),
    };

    let result = enter::launch_pod(pod_name, cmd.host_args.resolve()?)?;

    let (container_path, local_path, from_pod) = match &direction {
        CopyDirection::FromPod {
            container_path,
            local_path,
            ..
        } => (
            resolve_container_path(container_path, &repo_path),
            local_path.clone(),
            true,
        ),
        CopyDirection::ToPod {
            local_path,
            container_path,
            ..
        } => (
            resolve_container_path(container_path, &repo_path),
            local_path.clone(),
            false,
        ),
    };

    let status = match &result.host {
        Host::Kubernetes {
            context, namespace, ..
        } => {
            let (k8s_src, k8s_dest) = if from_pod {
                (
                    format!("{}:{container_path}", result.container_id.0),
                    local_path.clone(),
                )
            } else {
                (
                    local_path.clone(),
                    format!("{}:{container_path}", result.container_id.0),
                )
            };

            let mut kubectl = Command::new("kubectl");
            kubectl.args(["--context", context]);
            kubectl.args(["--namespace", namespace]);
            kubectl.arg("cp");
            kubectl.arg(&k8s_src);
            kubectl.arg(&k8s_dest);
            kubectl.status()?
        }
        Host::Localhost | Host::Ssh { .. } => {
            let docker_socket = result
                .docker_socket
                .as_ref()
                .context("docker_socket is required for Docker hosts")?;

            let (docker_src, docker_dest) = if from_pod {
                (
                    format!("{}:{container_path}", result.container_id.0),
                    local_path.clone(),
                )
            } else {
                (
                    local_path.clone(),
                    format!("{}:{container_path}", result.container_id.0),
                )
            };

            let mut docker_cmd = Command::new("docker");
            docker_cmd.args(["-H", &format!("unix://{}", docker_socket.display())]);
            docker_cmd.arg("cp");

            if cmd.archive {
                docker_cmd.arg("-a");
            }
            if cmd.follow_link {
                docker_cmd.arg("-L");
            }
            if cmd.quiet {
                docker_cmd.arg("-q");
            }

            docker_cmd.arg(&docker_src);
            docker_cmd.arg(&docker_dest);
            docker_cmd.status()?
        }
    };

    if !status.success() {
        return Err(anyhow::anyhow!("cp exited with status {}", status));
    }

    // When copying into the pod, fix ownership so files belong to the container user
    // rather than root (which is what docker/kubectl cp produces by default).
    if !from_pod && !cmd.archive {
        chown_in_container(&result, &container_path)?;
    }

    Ok(())
}

/// After copying files into a container, chown them to the container user.
fn chown_in_container(result: &LaunchResult, container_path: &str) -> Result<()> {
    let status = match &result.host {
        Host::Kubernetes {
            context, namespace, ..
        } => {
            // Wrap in sh so we can run as root via the container's entrypoint
            // mechanism; kubectl exec has no --user flag, but pods launched by
            // rumpelpod include a root-capable shell.
            let chown_cmd = format!("chown -R {} {container_path}", result.user);
            let mut kubectl = Command::new("kubectl");
            kubectl.args(["--context", context]);
            kubectl.args(["--namespace", namespace]);
            kubectl.args(["exec", &result.container_id.0, "--"]);
            kubectl.args(["sh", "-c", &chown_cmd]);
            kubectl.status()?
        }
        Host::Localhost | Host::Ssh { .. } => {
            let docker_socket = result
                .docker_socket
                .as_ref()
                .context("docker_socket is required for Docker hosts")?;

            let mut docker_cmd = Command::new("docker");
            docker_cmd.args(["-H", &format!("unix://{}", docker_socket.display())]);
            docker_cmd.args(["exec", "--user", "root", &result.container_id.0]);
            docker_cmd.args(["chown", "-R", &result.user, container_path]);
            docker_cmd.status()?
        }
    };

    if !status.success() {
        return Err(anyhow::anyhow!(
            "chown in container exited with status {status}"
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pod_path_normal() {
        assert_eq!(
            parse_pod_path("mypod:/foo/bar"),
            Some(("mypod", "/foo/bar"))
        );
    }

    #[test]
    fn parse_pod_path_stdin() {
        assert_eq!(parse_pod_path("-"), None);
    }

    #[test]
    fn parse_pod_path_leading_colon() {
        assert_eq!(parse_pod_path(":/foo"), None);
    }

    #[test]
    fn parse_pod_path_no_colon() {
        assert_eq!(parse_pod_path("/local/path"), None);
    }

    #[test]
    fn parse_direction_from_pod() {
        let dir = parse_direction("pod:/file", "/local").unwrap();
        assert!(matches!(dir, CopyDirection::FromPod { .. }));
    }

    #[test]
    fn parse_direction_to_pod() {
        let dir = parse_direction("/local", "pod:/file").unwrap();
        assert!(matches!(dir, CopyDirection::ToPod { .. }));
    }

    #[test]
    fn parse_direction_neither_fails() {
        let err = parse_direction("/a", "/b").unwrap_err();
        assert!(err.to_string().contains("POD:PATH"));
    }

    #[test]
    fn parse_direction_both_fails() {
        let err = parse_direction("a:/x", "b:/y").unwrap_err();
        assert!(err.to_string().contains("Both"));
    }

    #[test]
    fn resolve_absolute_path_unchanged() {
        let repo = Path::new("/workspaces/myrepo");
        assert_eq!(
            resolve_container_path("/tmp/file.txt", repo),
            "/tmp/file.txt"
        );
    }

    #[test]
    fn resolve_relative_path_prepends_repo_root() {
        let repo = Path::new("/workspaces/myrepo");
        assert_eq!(
            resolve_container_path("src/main.rs", repo),
            "/workspaces/myrepo/src/main.rs"
        );
    }

    #[test]
    fn resolve_bare_filename() {
        let repo = Path::new("/workspaces/myrepo");
        assert_eq!(
            resolve_container_path("file.txt", repo),
            "/workspaces/myrepo/file.txt"
        );
    }
}
