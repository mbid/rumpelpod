#[macro_use]
mod agent;
mod r#async;
mod cli;
mod command_ext;
mod config;

pub use command_ext::CommandExt;
mod daemon;
mod delete;
mod enter;
mod gateway;
mod git;
mod git_http_server;
mod list;
mod llm;
mod systemd;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command};

pub fn run() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Daemon => {
            daemon::run_daemon()?;
        }
        Command::SystemInstall => {
            systemd::system_install()?;
        }
        Command::SystemUninstall => {
            systemd::system_uninstall()?;
        }
        Command::Enter(ref cmd) => {
            enter::enter(cmd)?;
        }
        Command::List => {
            list::list()?;
        }
        Command::Delete(ref cmd) => {
            delete::delete(cmd)?;
        }
        Command::Agent(ref cmd) => {
            agent::agent(cmd)?;
        }
    }

    Ok(())
}
