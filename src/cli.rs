use anyhow::{bail, Result};
use clap::{Parser, Subcommand};
use indoc::formatdoc;
use std::path::{Path, PathBuf};

use crate::agent;
use crate::config::{Model, OverlayMode, Runtime, UserInfo};
use crate::daemon;
use crate::docker;
use crate::git;
use crate::llm::cache::LlmCache;
use crate::sandbox;
use crate::sandbox_config::{ImageConfig, SandboxConfig};
use crate::setup;

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
        Commands::Enter { name, command } => {
            enter()?;
        }
        Commands::List => {
            list()?;
        }
        Commands::Delete { name } => {
            delete()?;
        }
        Commands::Agent { name, model, cache } => {
            agent()?;
        }
    }

    Ok(())
}

fn enter(EnterCommand {}: EnterCommand) -> Result<()> {
    // TODO: Contact daemon to launch sandbox.
    // Then `docker exec /bin/bash` into the container.
}

fn list(ListCommand {}: ListCommand) -> Result<()> {
    let repo_root = git::find_repo_root()?;
    todo!()
}

fn delete(DeleteCommand { name }: DeleteCommand) -> Result<()> {
    let repo_root = git::find_repo_root()?;
    todo!()
}

fn agent(AgentCommand { name, model, cache }: AgentCommand) -> Result<()> {
    // TODO: Contact daemon to launch sandbox.
    // Then launch agent loop.
    todo!()
}
