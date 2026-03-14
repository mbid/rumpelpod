use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli::CpCommand;
use crate::enter;
use crate::git::get_repo_root;
use crate::pod::PodClient;

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
    let (devcontainer, _, _default_image_dir) = enter::load_and_resolve(&repo_root, None)?;
    Ok(devcontainer.container_repo_path(&repo_root))
}

/// Create a gzip-compressed tar archive of a local path.
fn tar_local_path(local_path: &str, follow_symlinks: bool) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let path = Path::new(local_path);
    let path_display = path.display();
    let meta = std::fs::symlink_metadata(path).with_context(|| format!("stat {path_display}"))?;

    let buf = Vec::new();
    let encoder = GzEncoder::new(buf, Compression::fast());
    let mut archive = tar::Builder::new(encoder);
    archive.follow_symlinks(follow_symlinks);

    if meta.is_dir() {
        archive
            .append_dir_all(".", path)
            .with_context(|| format!("archiving directory {path_display}"))?;
    } else {
        let name = path
            .file_name()
            .with_context(|| format!("no file name in {path_display}"))?;
        archive
            .append_path_with_name(path, name)
            .with_context(|| format!("archiving file {path_display}"))?;
    }

    let encoder = archive
        .into_inner()
        .with_context(|| format!("finalizing tar for {path_display}"))?;
    encoder.finish().context("finishing gzip")
}

/// Extract a gzip-compressed tar archive to a local path.
fn untar_to_local(archive_data: &[u8], local_path: &str) -> Result<()> {
    use flate2::read::GzDecoder;

    let dest = Path::new(local_path);

    // If the archive contains a single file (not a directory), the caller
    // may have passed a file path as destination. Detect this by peeking
    // at the archive entries.
    let decoder = GzDecoder::new(archive_data);
    let mut peek_archive = tar::Archive::new(decoder);
    let entries: Vec<_> = peek_archive
        .entries()
        .context("reading tar entries")?
        .collect::<Result<Vec<_>, _>>()
        .context("iterating tar entries")?;

    let single_file = entries.len() == 1 && entries[0].header().entry_type().is_file();

    if single_file {
        // Extract the single file: if dest looks like a directory (exists and is_dir),
        // extract into it; otherwise treat dest as the target file path.
        let decoder = GzDecoder::new(archive_data);
        let mut archive = tar::Archive::new(decoder);
        let mut entries = archive.entries().context("reading tar entries")?;
        let mut entry = entries.next().unwrap()?;

        if dest.is_dir() {
            let name = entry.path()?.into_owned();
            let target = dest.join(name);
            let target_display = target.display();
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent for {target_display}"))?;
            }
            entry
                .unpack(&target)
                .with_context(|| format!("extracting to {target_display}"))?;
        } else {
            let dest_display = dest.display();
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)
                    .with_context(|| format!("creating parent for {dest_display}"))?;
            }
            entry
                .unpack(dest)
                .with_context(|| format!("extracting to {dest_display}"))?;
        }
    } else {
        // Directory archive: extract into dest
        let dest_display = dest.display();
        std::fs::create_dir_all(dest)
            .with_context(|| format!("creating destination {dest_display}"))?;
        let decoder = GzDecoder::new(archive_data);
        let mut archive = tar::Archive::new(decoder);
        archive
            .unpack(dest)
            .with_context(|| format!("extracting archive to {dest_display}"))?;
    }

    Ok(())
}

pub fn cp(cmd: &CpCommand) -> Result<()> {
    let direction = parse_direction(&cmd.src, &cmd.dest)?;
    let repo_path = container_repo_path()?;

    let pod_name = match &direction {
        CopyDirection::FromPod { pod_name, .. } => pod_name.as_str(),
        CopyDirection::ToPod { pod_name, .. } => pod_name.as_str(),
    };

    let result = enter::launch_pod(pod_name, cmd.host_args.resolve()?)?;
    let client = PodClient::new(&result.container_url, &result.container_token)?;

    match &direction {
        CopyDirection::FromPod {
            container_path,
            local_path,
            ..
        } => {
            let resolved = resolve_container_path(container_path, &repo_path);
            let archive = client.cp_download(Path::new(&resolved), cmd.follow_link)?;
            untar_to_local(&archive, local_path)?;
        }
        CopyDirection::ToPod {
            local_path,
            container_path,
            ..
        } => {
            let resolved = resolve_container_path(container_path, &repo_path);
            let archive = tar_local_path(local_path, cmd.follow_link)?;
            let owner = if cmd.archive {
                None
            } else {
                Some(result.user.as_str())
            };
            // For a single file, the destination is the target path directly.
            // The upload endpoint extracts the archive into a directory, so
            // figure out the parent.
            let local = Path::new(local_path);
            let local_meta = std::fs::symlink_metadata(local)?;
            let dest = if local_meta.is_dir() {
                Path::new(&resolved).to_path_buf()
            } else {
                Path::new(&resolved)
                    .parent()
                    .unwrap_or(Path::new("/"))
                    .to_path_buf()
            };
            client.cp_upload(&dest, &archive, owner)?;
        }
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

    #[test]
    fn tar_roundtrip_file() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("test.txt");
        std::fs::write(&src, "hello").unwrap();

        let archive = tar_local_path(src.to_str().unwrap(), false).unwrap();

        let dest = dir.path().join("out.txt");
        untar_to_local(&archive, dest.to_str().unwrap()).unwrap();

        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "hello");
    }

    #[test]
    fn tar_roundtrip_directory() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("srcdir");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("a.txt"), "aaa").unwrap();
        std::fs::write(src.join("b.txt"), "bbb").unwrap();

        let archive = tar_local_path(src.to_str().unwrap(), false).unwrap();

        let dest = dir.path().join("destdir");
        untar_to_local(&archive, dest.to_str().unwrap()).unwrap();

        assert_eq!(std::fs::read_to_string(dest.join("a.txt")).unwrap(), "aaa");
        assert_eq!(std::fs::read_to_string(dest.join("b.txt")).unwrap(), "bbb");
    }
}
