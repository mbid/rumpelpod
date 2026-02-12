use std::process::Command;

use anyhow::{bail, Result};

use crate::cli::CpCommand;
use crate::enter;

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
        (None, None) => {
            bail!(
                "Neither src nor dest uses POD:PATH syntax.\n\
                 Exactly one of src or dest must specify a pod, e.g. my-pod:/path/in/container"
            );
        }
        (Some(_), Some(_)) => {
            bail!(
                "Both src and dest use POD:PATH syntax.\n\
                 Exactly one side must be a local path."
            );
        }
    }
}

pub fn cp(cmd: &CpCommand) -> Result<()> {
    let direction = parse_direction(&cmd.src, &cmd.dest)?;

    let (pod_name, docker_src, docker_dest) = match &direction {
        CopyDirection::FromPod {
            pod_name,
            container_path,
            local_path,
        } => (
            pod_name.as_str(),
            format!("{{}}:{}", container_path),
            local_path.clone(),
        ),
        CopyDirection::ToPod {
            pod_name,
            local_path,
            container_path,
        } => (
            pod_name.as_str(),
            local_path.clone(),
            format!("{{}}:{}", container_path),
        ),
    };

    let result = enter::launch_pod(pod_name, cmd.host.as_deref())?;

    // Fill in the container ID
    let docker_src = docker_src.replace("{}", &result.container_id.0);
    let docker_dest = docker_dest.replace("{}", &result.container_id.0);

    let mut docker_cmd = Command::new("docker");
    docker_cmd.args(["-H", &format!("unix://{}", result.docker_socket.display())]);
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

    let status = docker_cmd.status()?;

    if !status.success() {
        bail!("docker cp exited with status {}", status);
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
}
