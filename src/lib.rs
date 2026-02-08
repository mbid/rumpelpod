#[macro_use]
mod agent;
mod async_runtime;
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
mod list;
mod llm;
mod ports;
mod recreate;
mod review;
mod stop;
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
        Command::Review(ref cmd) => {
            review::review(cmd)?;
        }
        Command::Agent(ref cmd) => {
            agent::agent(cmd)?;
        }
    }

    Ok(())
}
