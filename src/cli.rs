use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::Model;

#[derive(Parser)]
#[command(name = "sandbox")]
#[command(about = "Docker-based sandbox for untrusted LLM agents")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Enter a sandbox (create if needed)
    Enter(EnterCommand),

    /// List all sandboxes for the current repository
    List,

    /// Delete a sandbox
    Delete(DeleteCommand),

    /// Run an LLM agent inside a sandbox
    Agent(AgentCommand),

    /// Run the sandbox daemon (manages sandboxes across all projects)
    #[command(hide = true)]
    Daemon,

    /// Install the sandbox daemon as a systemd user service
    SystemInstall,

    /// Uninstall the sandbox daemon from systemd
    SystemUninstall,
}

#[derive(Args)]
pub struct EnterCommand {
    /// Name for this sandbox instance
    pub name: String,

    /// Command to run inside the sandbox (default: interactive shell)
    #[arg(last = true)]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct DeleteCommand {
    /// Name of the sandbox to delete
    pub name: String,
}

#[derive(Args)]
pub struct AgentCommand {
    /// Name of the sandbox to use
    pub name: String,

    /// Claude model to use (overrides config file)
    #[arg(short, long, value_enum)]
    pub model: Option<Model>,

    /// LLM response cache directory for deterministic testing.
    /// See llm-cache/README.md for documentation.
    #[arg(long, hide = true)]
    pub cache: Option<PathBuf>,
}
