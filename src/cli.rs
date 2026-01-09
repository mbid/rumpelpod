use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use crate::config::Model;
use crate::daemon;
use crate::systemd as setup;

#[derive(Parser)]
#[command(name = "sandbox")]
#[command(about = "Docker-based sandbox for untrusted LLM agents")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

// TODO: Refactor these commands so that there's e.g. an EnterCommand struct, and the Enter variant
// here is just Enter(EnterCommand).
#[derive(Subcommand)]
pub enum Commands {
    /// Enter a sandbox (create if needed)
    Enter {
        /// Name for this sandbox instance
        name: String,

        /// Command to run inside the sandbox (default: interactive shell)
        #[arg(last = true)]
        command: Vec<String>,
    },

    /// List all sandboxes for the current repository
    List,

    /// Delete a sandbox
    Delete {
        /// Name of the sandbox to delete
        name: String,
    },

    /// Run an LLM agent inside a sandbox
    Agent {
        /// Name of the sandbox to use
        name: String,

        /// Claude model to use (overrides config file)
        #[arg(short, long, value_enum)]
        model: Option<Model>,

        /// LLM response cache directory for deterministic testing.
        /// See llm-cache/README.md for documentation.
        #[arg(long, hide = true)]
        cache: Option<PathBuf>,
    },

    /// Run the sandbox daemon (manages sandboxes across all projects)
    #[command(hide = true)]
    Daemon,

    /// Install the sandbox daemon as a systemd user service
    SystemInstall,

    /// Uninstall the sandbox daemon from systemd
    SystemUninstall,
}

pub fn run() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon => {
            daemon::run_daemon()?;
        }
        Commands::SystemInstall => {
            setup::system_install()?;
        }
        Commands::SystemUninstall => {
            setup::system_uninstall()?;
        }
        Commands::Enter {
            name: _,
            command: _,
        } => {
            enter()?;
        }
        Commands::List => {
            list()?;
        }
        Commands::Delete { name: _ } => {
            delete()?;
        }
        Commands::Agent {
            name: _,
            model: _,
            cache: _,
        } => {
            agent()?;
        }
    }

    Ok(())
}

fn enter() -> Result<()> {
    // TODO: Contact daemon to launch sandbox.
    // Then `docker exec /bin/bash` into the container.
    todo!()
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
