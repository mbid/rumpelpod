#[macro_use]
mod agent;
mod r#async;
mod cli;
pub mod command_ext;
mod config;
mod daemon;
mod enter;
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
            list()?;
        }
        Command::Delete(_) => {
            delete()?;
        }
        Command::Agent(_) => {
            agent()?;
        }
    }

    Ok(())
}

fn list() -> Result<()> {
    todo!()
}

fn delete() -> Result<()> {
    todo!()
}

fn agent() -> Result<()> {
    // TODO: Contact daemon to launch sandbox.
    // Then launch agent loop.
    todo!()
}
