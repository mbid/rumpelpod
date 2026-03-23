//! Handlers for `rumpel ssh <pod> add` and `rumpel ssh <pod> list`.

use anyhow::{Context, Result};

use crate::cli::{SshAction, SshCommand};
use crate::daemon;
use crate::daemon::protocol::{Daemon, PodName};
use crate::git::get_repo_root;

pub fn ssh(cmd: &SshCommand) -> Result<()> {
    let repo_root = get_repo_root()?;
    let socket_path = daemon::socket_path()?;
    let client = daemon::protocol::DaemonClient::new_unix(&socket_path);
    let pod_name = PodName(cmd.name.clone());

    match &cmd.action {
        SshAction::Add(args) => {
            let key_path = args.key_file.canonicalize().with_context(|| {
                let path = args.key_file.display();
                format!("key file not found: {path}")
            })?;

            let message = client.ssh_add_key(pod_name, repo_root, key_path)?;
            println!("{message}");
        }
        SshAction::List => {
            let keys = client.ssh_list_keys(pod_name, repo_root)?;
            println!("{keys}");
        }
    }

    Ok(())
}
