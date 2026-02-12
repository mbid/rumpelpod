#[macro_use]
mod agent;
mod async_runtime;
mod claude;
mod cli;
mod command_ext;
pub mod config;
pub mod devcontainer;
mod docker_exec;

pub use command_ext::CommandExt;
pub mod daemon;
mod delete;
mod enter;
mod gateway;
mod git;
mod git_http_server;
pub(crate) mod image;
mod image_cmd;
mod list;
mod llm;
mod ports;
mod recreate;
mod review;
mod stop;
mod systemd;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Command, ImageSubcommand};

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
        Command::Stop(ref cmd) => {
            stop::stop(cmd)?;
        }
        Command::Delete(ref cmd) => {
            delete::delete(cmd)?;
        }
        Command::Ports(ref cmd) => {
            ports::ports(cmd)?;
        }
        Command::Recreate(ref cmd) => {
            recreate::recreate(cmd)?;
        }
        Command::Image(ref sub) => match sub {
            ImageSubcommand::Build(ref cmd) => image_cmd::build(cmd)?,
            ImageSubcommand::Fetch(ref cmd) => image_cmd::fetch(cmd)?,
        },
        Command::Review(ref cmd) => {
            review::review(cmd)?;
        }
        Command::Agent(ref cmd) => {
            agent::agent(cmd)?;
        }
        Command::Claude(ref cmd) => {
            claude::claude(cmd)?;
        }
    }

    Ok(())
}
