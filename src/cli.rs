use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::Model;

/// Validate that a pod name contains only Docker/git-safe characters:
/// ASCII alphanumeric, hyphens, underscores, and dots.
fn validate_pod_name(name: &str) -> Result<String, String> {
    if name.is_empty() {
        return Err("pod name must not be empty".to_string());
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_' && *c != '.')
    {
        return Err(format!(
            "invalid character '{}' in pod name -- \
             only ASCII letters, digits, hyphens, underscores, and dots are allowed",
            bad
        ));
    }
    Ok(name.to_string())
}

#[derive(Parser)]
#[command(name = "rumpelpod")]
#[command(version = env!("RUMPELPOD_VERSION_INFO"))]
#[command(about = "Pod management tool for LLM agents")]
#[command(long_about = "Pod management tool for LLM agents.

Spawns isolated Docker containers with automatic git synchronization for running untrusted code safely. Each pod gets its own working copy of your repository where changes are isolated from the host filesystem.

SETUP:
  1. Create a .devcontainer/devcontainer.json for container settings
  2. Optionally create a .rumpelpod.toml for agent settings
  3. Run 'rumpel system-install' to start the background daemon
  4. Use 'rumpel enter <name>' to create and enter pods

CONFIGURATION:
  .devcontainer/devcontainer.json (required):
    image            Docker image to use
    workspaceFolder  Where the repo is mounted inside the container
    containerUser    User inside container (default: image's USER)
    runArgs          Additional Docker arguments (e.g., --runtime)

  .rumpelpod.toml (optional):
    [agent]
    model            Default model for 'rumpel agent'

  See README.md for the full configuration reference.
")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Enter a pod (create if needed)
    #[command(long_about = "Enter a pod, creating it if it doesn't exist.

Pods are identified by name and are specific to the current repository. The same name in different repositories refers to different pods.

By default, opens an interactive shell. You can also run a specific command by passing it after '--'.

The working directory inside the pod corresponds to your current directory relative to the repository root.

Examples:
  rumpel enter dev              # Interactive shell in pod
  rumpel enter test -- make     # Run 'make' in 'test' pod
  rumpel enter ci -- cargo test # Run tests in 'ci' pod
")]
    Enter(EnterCommand),

    /// List all pods for the current repository
    #[command(long_about = "List all pods for the current repository.

Shows pod name, status (running/stopped), and creation time.
")]
    List,

    /// Stop a running pod
    #[command(long_about = "Stop a pod container without removing it.

The container is stopped but preserved. Use 'rumpel enter' to restart it.
")]
    Stop(StopCommand),

    /// Delete a pod
    #[command(long_about = "Delete a pod and its associated container.

This stops the container if running and removes all pod state. Any uncommitted changes in the pod will be lost.
")]
    Delete(DeleteCommand),

    /// Review changes in a pod using git difftool
    #[command(long_about = "Review changes in a pod using git difftool.

Shows the diff between the pod's primary branch and the merge base with its upstream branch. This effectively shows all changes made in the pod since it diverged from the host branch.

The pod must have been created while the host was on a branch (not in detached HEAD state) for the upstream to be set.

Examples:
  rumpel review dev             # Review changes in 'dev' pod
")]
    Review(ReviewCommand),

    /// Merge a pod's branch into the current branch and stop the pod
    #[command(trailing_var_arg = true)]
    Merge(MergeCommand),

    /// Show forwarded ports for a pod
    Ports(PortsCommand),

    /// Recreate a pod
    #[command(long_about = "Recreate a pod.

Takes a snapshot of dirty files (including untracked files), destroys the container, and creates a new one with the snapshot applied.
")]
    Recreate(RecreateCommand),

    /// Manage devcontainer images
    #[command(subcommand)]
    Image(ImageSubcommand),

    /// Run an LLM agent inside a pod
    #[command(long_about = "Run an LLM agent inside a pod.

The agent runs autonomously, executing commands in the pod. All changes are isolated - safety comes from the pod isolation, not from asking for permission.

Requires ANTHROPIC_API_KEY, XAI_API_KEY, or GEMINI_API_KEY environment variable depending on the model. Project-specific instructions can be provided in an AGENTS.md file.
")]
    Agent(AgentCommand),

    /// Copy files between host and a pod
    #[command(long_about = "Copy files between the host and a pod container.

Wraps 'docker cp' but uses pod names instead of container IDs. Exactly one of src or dest must use POD:PATH syntax to identify the pod.

Examples:
  rumpel cp dev:/app/output.txt ./output.txt   # Copy from pod to host
  rumpel cp ./input.txt dev:/app/input.txt     # Copy from host to pod
  rumpel cp -a dev:/app/dir ./dir              # Archive mode (preserve uid/gid)
")]
    Cp(CpCommand),

    /// Launch Claude Code in a persistent screen session inside a pod
    #[command(
        long_about = "Launch Claude Code CLI inside a persistent screen session in a pod.

On first run, copies Claude Code config files (~/.claude.json, ~/.claude/settings.json) from the host into the container. Then attaches to or creates a GNU screen session running Claude Code.

Detach with Ctrl-a d to leave Claude Code running in the background. Re-run the same command to reattach. If Claude Code exits (e.g. /exit), the screen session ends and the next invocation creates a fresh one.

Requires 'screen' to be installed in the container image.

Examples:
  rumpel claude dev                    # Launch Claude Code in 'dev' pod
  rumpel claude dev -- --model opus    # Pass args to claude CLI
"
    )]
    Claude(ClaudeCommand),

    /// Internal git hook handlers (invoked from git hooks inside containers)
    #[command(subcommand, hide = true)]
    GitHook(GitHookSubcommand),

    /// Internal Claude Code hook handlers
    #[command(subcommand, hide = true)]
    ClaudeHook(ClaudeHookSubcommand),

    /// Run the rumpelpod daemon (internal)
    #[command(hide = true)]
    Daemon,

    /// Install the rumpelpod daemon as a system service
    #[command(long_about = "Install the rumpelpod daemon as a system service.

Uses systemd on Linux and launchd on macOS. The daemon runs in the background and manages pod containers, handling git synchronization and container lifecycle. It starts automatically on login.

This is required before using other rumpel commands.
")]
    SystemInstall,

    /// Uninstall the rumpelpod daemon
    #[command(long_about = "Uninstall the rumpelpod daemon.

Stops the daemon and removes it from the system service manager. Existing pod containers are not automatically removed.
")]
    SystemUninstall,
}

#[derive(Args)]
pub struct EnterCommand {
    /// Name for this pod instance
    #[arg(help = "Name for this pod instance (e.g., 'dev', 'test')", value_parser = validate_pod_name)]
    pub name: String,

    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    /// Overrides .rumpelpod.toml setting.
    #[arg(long)]
    pub host: Option<String>,

    /// Command to run inside the pod (default: interactive shell)
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct StopCommand {
    /// Name of the pod to stop
    #[arg(help = "Name of the pod to stop", value_parser = validate_pod_name)]
    pub name: String,
}

#[derive(Args)]
pub struct DeleteCommand {
    /// Names of pods to delete
    #[arg(required = true, num_args = 1.., value_parser = validate_pod_name)]
    pub names: Vec<String>,

    /// Block until the container is fully removed
    #[arg(long)]
    pub wait: bool,

    /// Delete even if the pod has unmerged commits
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RecreateCommand {
    /// Name of the pod to recreate
    #[arg(help = "Name of the pod to recreate", value_parser = validate_pod_name)]
    pub name: String,

    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    /// Overrides .rumpelpod.toml setting.
    #[arg(long)]
    pub host: Option<String>,
}

#[derive(Args)]
pub struct PortsCommand {
    /// Name of the pod
    #[arg(value_parser = validate_pod_name)]
    pub name: String,
}

#[derive(Args)]
pub struct ReviewCommand {
    /// Name of the pod to review
    #[arg(help = "Name of the pod to review", value_parser = validate_pod_name)]
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
#[command(trailing_var_arg = true)]
pub struct MergeCommand {
    /// Name of the pod to merge
    #[arg(help = "Name of the pod to merge", value_parser = validate_pod_name)]
    pub name: String,

    /// Arguments passed through to git merge (e.g. --no-ff, --squash)
    #[arg(allow_hyphen_values = true)]
    pub git_args: Vec<String>,
}

#[derive(Args)]
pub struct AgentCommand {
    /// Name of the pod to use
    #[arg(help = "Name of the pod to use", value_parser = validate_pod_name)]
    pub name: String,

    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    /// Overrides .rumpelpod.toml setting.
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
    /// Name for this pod instance
    #[arg(help = "Name for this pod instance (e.g., 'dev', 'test')", value_parser = validate_pod_name)]
    pub name: String,

    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    /// Overrides .rumpelpod.toml setting.
    #[arg(long)]
    pub host: Option<String>,

    /// Disable --dangerously-skip-permissions (which is on by default)
    #[arg(long, conflicts_with = "dangerously_skip_permissions_hook")]
    pub no_dangerously_skip_permissions: bool,

    /// Use a PermissionRequest hook instead of --dangerously-skip-permissions
    #[arg(long, hide = true)]
    pub dangerously_skip_permissions_hook: bool,

    /// Arguments forwarded to `claude` CLI
    #[arg(last = true, value_name = "ARGS")]
    pub args: Vec<String>,
}

#[derive(Args)]
pub struct CpCommand {
    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    /// Overrides .rumpelpod.toml setting.
    #[arg(long)]
    pub host: Option<String>,

    /// Archive mode (preserve uid/gid)
    #[arg(short = 'a', long = "archive")]
    pub archive: bool,

    /// Follow symlinks in src path
    #[arg(short = 'L', long = "follow-link")]
    pub follow_link: bool,

    /// Suppress progress output
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Source: either POD:PATH or a local path
    #[arg(value_name = "SRC")]
    pub src: String,

    /// Destination: either POD:PATH or a local path
    #[arg(value_name = "DEST")]
    pub dest: String,
}

#[derive(Subcommand)]
pub enum ImageSubcommand {
    /// Build the devcontainer image from its Dockerfile
    #[command(long_about = "Build the devcontainer image from its Dockerfile.

Requires 'build.dockerfile' in devcontainer.json. Skips the build if a cached image with a matching content hash already exists. Use --force to rebuild unconditionally.
")]
    Build(ImageBuildCommand),

    /// Pull the devcontainer image from its registry
    #[command(long_about = "Pull the devcontainer image from its registry.

Requires 'image' in devcontainer.json (not 'build'). Runs 'docker pull' so you get the latest version of the image.
")]
    Fetch(ImageFetchCommand),
}

#[derive(Args)]
pub struct ImageBuildCommand {
    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    /// Overrides .rumpelpod.toml setting.
    #[arg(long)]
    pub host: Option<String>,

    /// Rebuild even if the image already exists
    #[arg(long)]
    pub force: bool,

    /// Disable Docker layer cache (--no-cache)
    #[arg(long)]
    pub no_cache: bool,

    /// Pull the base image before building (--pull)
    #[arg(long)]
    pub pull: bool,
}

#[derive(Args)]
pub struct ImageFetchCommand {
    /// Docker host: "localhost" for local or "ssh://user@host" for remote.
    /// Overrides .rumpelpod.toml setting.
    #[arg(long)]
    pub host: Option<String>,
}

#[derive(Subcommand)]
pub enum GitHookSubcommand {
    /// Handle git reference-transaction hook events (pod repo)
    ReferenceTransaction(ReferenceTransactionCommand),

    /// Handle git reference-transaction hook events (host repo)
    HostReferenceTransaction(ReferenceTransactionCommand),

    /// Handle git post-checkout hook events (host repo)
    HostPostCheckout(PostCheckoutCommand),

    /// Handle git pre-receive hook events (gateway repo)
    GatewayPreReceive,

    /// Handle git post-receive hook events (gateway repo)
    GatewayPostReceive,
}

#[derive(Subcommand)]
pub enum ClaudeHookSubcommand {
    /// Auto-approve permission dialogs
    PermissionRequest,
}

#[derive(Args)]
pub struct ReferenceTransactionCommand {
    /// Transaction state: "prepared", "committed", or "aborted"
    pub state: String,
}

#[derive(Args)]
pub struct PostCheckoutCommand {
    /// Previous HEAD ref
    pub prev_ref: String,
    /// New HEAD ref
    pub new_ref: String,
    /// Checkout type: "0" for file checkout, "1" for branch checkout
    pub flag: String,
}
