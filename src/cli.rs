use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::Model;

#[derive(Parser)]
#[command(name = "sandbox")]
#[command(version)]
#[command(about = "Sandbox management tool for LLM agents")]
#[command(long_about = "Sandbox management tool for LLM agents.

Spawns isolated Docker containers with automatic git synchronization for running untrusted code safely. Each sandbox gets its own working copy of your repository where changes are isolated from the host filesystem.

SETUP:
  1. Create a .devcontainer/devcontainer.json for container settings
  2. Optionally create a .sandbox.toml for agent settings
  3. Run 'sandbox system-install' to start the background daemon
  4. Use 'sandbox enter <name>' to create and enter sandboxes

CONFIGURATION:
  .devcontainer/devcontainer.json (required):
    image            Docker image to use
    workspaceFolder  Where the repo is mounted inside the container
    containerUser    User inside container (default: image's USER)
    runArgs          Additional Docker arguments (e.g., --runtime)

  .sandbox.toml (optional):
    [agent]
    model            Default model for 'sandbox agent'

  See README.md for the full configuration reference.
")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Enter a sandbox (create if needed)
    #[command(long_about = "Enter a sandbox, creating it if it doesn't exist.

Sandboxes are identified by name and are specific to the current repository. The same name in different repositories refers to different sandboxes.

By default, opens an interactive shell. You can also run a specific command by passing it after '--'.

The working directory inside the sandbox corresponds to your current directory relative to the repository root.

Examples:
  sandbox enter dev              # Interactive shell in 'dev' sandbox
  sandbox enter test -- make     # Run 'make' in 'test' sandbox
  sandbox enter ci -- cargo test # Run tests in 'ci' sandbox
")]
    Enter(EnterCommand),

    /// List all sandboxes for the current repository
    #[command(long_about = "List all sandboxes for the current repository.

Shows sandbox name, status (running/stopped), and creation time.
")]
    List,

    /// Stop a running sandbox
    #[command(long_about = "Stop a sandbox container without removing it.

The container is stopped but preserved. Use 'sandbox enter' to restart it.
")]
    Stop(StopCommand),

    /// Delete a sandbox
    #[command(long_about = "Delete a sandbox and its associated container.

This stops the container if running and removes all sandbox state. Any uncommitted changes in the sandbox will be lost.
")]
    Delete(DeleteCommand),

    /// Review changes in a sandbox using git difftool
    #[command(long_about = "Review changes in a sandbox using git difftool.

Shows the diff between the sandbox's primary branch and the merge base with its upstream branch. This effectively shows all changes made in the sandbox since it diverged from the host branch.

The sandbox must have been created while the host was on a branch (not in detached HEAD state) for the upstream to be set.

Examples:
  sandbox review dev             # Review changes in 'dev' sandbox
")]
    Review(ReviewCommand),

    /// Show forwarded ports for a sandbox
    Ports(PortsCommand),

    /// Recreate a sandbox
    #[command(long_about = "Recreate a sandbox.

Takes a snapshot of dirty files (including untracked files), destroys the container, and creates a new one with the snapshot applied.
")]
    Recreate(RecreateCommand),

    /// Run an LLM agent inside a sandbox
    #[command(long_about = "Run an LLM agent inside a sandbox.

The agent runs autonomously, executing commands in the sandbox. All changes are isolated - safety comes from the sandbox, not from asking for permission.

Requires ANTHROPIC_API_KEY, XAI_API_KEY, or GEMINI_API_KEY environment variable depending on the model. Project-specific instructions can be provided in an AGENTS.md file.
")]
    Agent(AgentCommand),

    /// Launch Claude Code in a persistent screen session inside a sandbox
    #[command(
        long_about = "Launch Claude Code CLI inside a persistent screen session in a sandbox.

On first run, copies Claude Code config files (~/.claude.json, ~/.claude/settings.json) from the host into the container. Then attaches to or creates a GNU screen session running Claude Code.

Detach with Ctrl-a d to leave Claude Code running in the background. Re-run the same command to reattach. If Claude Code exits (e.g. /exit), the screen session ends and the next invocation creates a fresh one.

Requires 'screen' to be installed in the container image.

Examples:
  sandbox claude dev                    # Launch Claude Code in 'dev' sandbox
  sandbox claude dev -- --model opus    # Pass args to claude CLI
"
    )]
    Claude(ClaudeCommand),

    /// Run the sandbox daemon (internal)
    #[command(hide = true)]
    Daemon,

    /// Install the sandbox daemon as a systemd user service
    #[command(long_about = "Install the sandbox daemon as a systemd user service.

The daemon runs in the background and manages sandbox containers, handling git synchronization and container lifecycle. It starts automatically on login.

This is required before using other sandbox commands.
")]
    SystemInstall,

    /// Uninstall the sandbox daemon from systemd
    #[command(long_about = "Uninstall the sandbox daemon from systemd.

Stops the daemon and removes it from systemd. Existing sandbox containers are not automatically removed.
")]
    SystemUninstall,
}

#[derive(Args)]
pub struct EnterCommand {
    /// Name for this sandbox instance
    #[arg(help = "Name for this sandbox instance (e.g., 'dev', 'test')")]
    pub name: String,

    /// Remote Docker host specification (e.g., "user@host:port").
    /// Overrides .sandbox.toml setting.
    #[arg(long)]
    pub host: Option<String>,

    /// Command to run inside the sandbox (default: interactive shell)
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct StopCommand {
    /// Name of the sandbox to stop
    #[arg(help = "Name of the sandbox to stop")]
    pub name: String,
}

#[derive(Args)]
pub struct DeleteCommand {
    /// Name of the sandbox to delete
    #[arg(help = "Name of the sandbox to delete")]
    pub name: String,
}

#[derive(Args)]
pub struct RecreateCommand {
    /// Name of the sandbox to recreate
    #[arg(help = "Name of the sandbox to recreate")]
    pub name: String,

    /// Remote Docker host specification (e.g., "user@host:port").
    /// Overrides .sandbox.toml setting.
    #[arg(long)]
    pub host: Option<String>,
}

#[derive(Args)]
pub struct PortsCommand {
    /// Name of the sandbox
    pub name: String,
}

#[derive(Args)]
pub struct ReviewCommand {
    /// Name of the sandbox to review
    #[arg(help = "Name of the sandbox to review")]
    pub name: String,

    /// Skip prompting before opening each file
    #[arg(
        short = 'y',
        long = "yes",
        help = "Skip prompting before opening each file"
    )]
    pub yes: bool,
}

#[derive(Args)]
pub struct AgentCommand {
    /// Name of the sandbox to use
    #[arg(help = "Name of the sandbox to use")]
    pub name: String,

    /// Remote Docker host specification (e.g., "user@host:port").
    /// Overrides .sandbox.toml setting.
    #[arg(long)]
    pub host: Option<String>,

    /// Model to use (overrides config file)
    #[arg(short, long, value_enum, conflicts_with_all = ["custom_anthropic_model", "custom_gemini_model", "custom_xai_model"])]
    pub model: Option<Model>,

    /// Custom Anthropic model string (e.g. "claude-3-opus-20240229")
    /// Taken verbatim as the model string on the Anthropic API.
    /// Overrides --model and config file settings.
    #[arg(long, conflicts_with_all = ["model", "custom_gemini_model", "custom_xai_model"])]
    pub custom_anthropic_model: Option<String>,

    /// Custom Gemini model string (e.g. "gemini-1.5-pro")
    /// Taken verbatim as the model string on the Google AI Studio API.
    /// Overrides --model and config file settings.
    #[arg(long, conflicts_with_all = ["model", "custom_anthropic_model", "custom_xai_model"])]
    pub custom_gemini_model: Option<String>,

    /// Custom xAI model string (e.g. "grok-beta")
    /// Taken verbatim as the model string on the xAI API.
    /// Overrides --model and config file settings.
    #[arg(long, conflicts_with_all = ["model", "custom_anthropic_model", "custom_gemini_model"])]
    pub custom_xai_model: Option<String>,

    /// Start a new conversation instead of resuming
    #[arg(long, conflicts_with = "continue")]
    pub new: bool,

    /// Continue a specific conversation by recency (0 = most recent)
    #[arg(long = "continue", value_name = "N")]
    pub r#continue: Option<u32>,

    /// LLM response cache directory for deterministic testing.
    /// See llm-cache/README.md for documentation.
    #[arg(long, hide = true)]
    pub cache: Option<PathBuf>,

    /// Enable web search for Anthropic models
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "disable_anthropic_websearch")]
    pub enable_anthropic_websearch: bool,

    /// Disable web search for Anthropic models
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "enable_anthropic_websearch")]
    pub disable_anthropic_websearch: bool,

    /// Thinking budget in tokens (enables thinking mode)
    #[arg(long, value_name = "TOKENS")]
    pub thinking_budget: Option<u32>,
}

#[derive(Args)]
pub struct ClaudeCommand {
    /// Name for this sandbox instance
    #[arg(help = "Name for this sandbox instance (e.g., 'dev', 'test')")]
    pub name: String,

    /// Remote Docker host specification (e.g., "user@host:port").
    /// Overrides .sandbox.toml setting.
    #[arg(long)]
    pub host: Option<String>,

    /// Arguments forwarded to `claude` CLI
    #[arg(last = true, value_name = "ARGS")]
    pub args: Vec<String>,
}
