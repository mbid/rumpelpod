use anyhow::Result;

use crate::cli::RecreateCommand;
use crate::config::{load_toml_config, DescriptionFileSetting};
use crate::daemon;
use crate::daemon::protocol::{Daemon, DaemonClient, LaunchProgress, PodLaunchParams, PodName};
use crate::enter::{find_host_claude_cli, load_and_resolve};
use crate::git::{get_current_branch, get_git_user_config, get_repo_root};
use crate::image::OutputLine;

pub fn recreate(cmd: &RecreateCommand) -> Result<()> {
    let repo_root = get_repo_root()?;

    let (devcontainer, docker_host, _default_image_dir) =
        load_and_resolve(&repo_root, cmd.host_args.resolve()?)?;

    let host_branch = get_current_branch(&repo_root);
    let git_identity = get_git_user_config(&repo_root);
    let claude_cli_path = find_host_claude_cli();
    let toml_config = load_toml_config(&repo_root)?;

    let socket_path = daemon::socket_path()?;
    let client = DaemonClient::new_unix(&socket_path);

    let description_file = match &toml_config.merge.description_file {
        DescriptionFileSetting::Path(p) => Some(p.clone()),
        DescriptionFileSetting::Disabled => None,
    };
    let mut progress = client.recreate_pod(PodLaunchParams {
        pod_name: PodName(cmd.name.clone()),
        repo_path: repo_root,
        host_branch,
        host: docker_host,
        devcontainer,
        git_identity: Some(git_identity),
        claude_cli_path,
        inject_system_prompt: toml_config.claude.inject_system_prompt,
        description_file,
    })?;
    for line in &mut progress {
        match line {
            OutputLine::Stdout(s) => println!("{s}"),
            OutputLine::Stderr(s) => eprintln!("{s}"),
        }
    }
    progress.finish()?;

    let name = &cmd.name;
    println!("Pod '{name}' recreated successfully.");

    Ok(())
}
