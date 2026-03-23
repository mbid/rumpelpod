use std::path::PathBuf;

use anyhow::Result;
use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::{Host, Model};

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

/// Shared flags for selecting the target host (Docker or Kubernetes).
#[derive(Args, Clone, Debug)]
pub struct HostArgs {
    /// Docker host: "localhost" or "ssh://user@host".
    /// Overrides .rumpelpod.toml setting.
    #[arg(long, conflicts_with_all = ["k8s_context", "k8s_namespace"])]
    pub host: Option<String>,

    /// Kubernetes context name.
    /// Mutually exclusive with --host.
    #[arg(long)]
    pub k8s_context: Option<String>,

    /// Kubernetes namespace (default "default").
    /// Requires --k8s-context.
    #[arg(long, requires = "k8s_context")]
    pub k8s_namespace: Option<String>,

    /// Registry to push/pull built images (e.g. ECR, GHCR, Docker Hub).
    /// Requires --k8s-context.
    #[arg(long, requires = "k8s_context")]
    pub k8s_registry: Option<String>,
}

impl HostArgs {
    /// Build a Host from the CLI flags, if any were given.
    pub fn resolve(&self) -> Result<Option<Host>> {
        if let Some(ref ctx) = self.k8s_context {
            let namespace = self
                .k8s_namespace
                .clone()
                .unwrap_or_else(|| "default".to_string());
            if self.host.is_some() {
                return Err(anyhow::anyhow!(
                    "--host and --k8s-context are mutually exclusive"
                ));
            }
            Ok(Some(Host::Kubernetes {
                context: ctx.clone(),
                namespace,
                registry: self.k8s_registry.clone(),
                node_selector: None,
                tolerations: None,
            }))
        } else if let Some(ref h) = self.host {
            Ok(Some(Host::parse(h)?))
        } else {
            Ok(None)
        }
    }
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

    /// Stop running pods
    #[command(long_about = "Stop one or more pod containers without removing them.

The containers are stopped but preserved. Use 'rumpel enter' to restart them.
")]
    Stop(StopCommand),

    /// Delete a pod
    #[command(long_about = "Delete a pod and its associated container.

This stops the container if running and removes all pod state. Any uncommitted changes in the pod will be lost.
")]
    Delete(DeleteCommand),

    /// Remove all stopped pods
    #[command(
        long_about = "Remove all stopped, gone, and broken pods for the current repository.

Clean pods are deleted without prompting. Pods with unmerged commits require interactive confirmation or --force.
"
    )]
    Prune(PruneCommand),

    /// Review changes in a pod using git difftool
    #[command(long_about = "Review changes in a pod using git difftool.

Shows the diff between the pod's primary branch and the merge base with its upstream branch. This effectively shows all changes made in the pod since it diverged from the host branch.

The pod must have been created while the host was on a branch (not in detached HEAD state) for the upstream to be set.

Use -- <path>... to restrict the review to specific paths, like git difftool.

Examples:
  rumpel review dev               # Review all changes in 'dev' pod
  rumpel review dev -- src/       # Review only changes under src/
  rumpel review dev -- foo bar    # Review only foo and bar
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

Uses the in-container HTTP server to transfer tar archives, so no docker or kubectl CLI is needed on the host. Exactly one of src or dest must use POD:PATH syntax to identify the pod.

Examples:
  rumpel cp dev:/app/output.txt ./output.txt   # Copy from pod to host
  rumpel cp ./input.txt dev:/app/input.txt     # Copy from host to pod
  rumpel cp -a dev:/app/dir ./dir              # Archive mode (preserve uid/gid)
")]
    Cp(CpCommand),

    /// Launch Claude Code in a persistent session inside a pod
    #[command(
        long_about = "Launch Claude Code CLI inside a persistent session in a pod.

On first run, copies Claude Code config files (~/.claude.json, ~/.claude/settings.json) from the host into the container. Then attaches to or creates a persistent PTY session running Claude Code.

Detach with Ctrl-a d to leave Claude Code running in the background. Re-run the same command to reattach. If Claude Code exits (e.g. /exit), the session ends and the next invocation creates a fresh one.

Examples:
  rumpel claude dev                    # Launch Claude Code in 'dev' pod
  rumpel claude dev -- --model opus    # Pass args to claude CLI
"
    )]
    Claude(ClaudeCommand),

    /// Manage SSH keys available to a pod
    #[command(
        long_about = "Manage SSH private keys available to a pod via ssh-agent.

An ssh-agent runs on the host for each pod. The agent socket is relayed into the container so processes inside the pod can use the keys for authentication (e.g. git push over SSH) but cannot extract the private key material.

Examples:
  rumpel ssh dev add ~/.ssh/id_ed25519   # Add a key to 'dev' pod
  rumpel ssh dev list                    # List loaded keys
"
    )]
    Ssh(SshCommand),

    /// Internal git hook handlers (invoked from git hooks inside containers)
    #[command(subcommand, hide = true)]
    GitHook(GitHookSubcommand),

    /// Internal Claude Code hook handlers
    #[command(subcommand, hide = true)]
    ClaudeHook(ClaudeHookSubcommand),

    /// Run the rumpelpod daemon (internal)
    #[command(hide = true)]
    Daemon,

    /// Run the in-pod tunnel server (internal, started by daemon via kubectl exec)
    #[command(hide = true)]
    TunnelServer {
        /// Port to listen on
        #[arg(long, default_value_t = crate::tunnel::DEFAULT_TUNNEL_PORT)]
        port: u16,
    },

    /// Bridge stdin/stdout to a TCP connection (internal, started by daemon via exec)
    #[command(hide = true)]
    TcpProxy {
        /// Port to connect to on loopback
        #[arg(long)]
        port: u16,
    },

    /// Run the in-container HTTP server (internal, started by daemon)
    #[command(hide = true)]
    ContainerServe {
        /// Port to listen on (defaults to 7890)
        #[arg(long, default_value_t = crate::pod::DEFAULT_PORT)]
        port: u16,
        /// Bearer token for authenticating POST requests
        #[arg(long)]
        token: String,
    },

    /// Set up repo clone and Claude CLI during image build (internal)
    #[command(hide = true)]
    PrepareImage(PrepareImageCommand),

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

    #[command(flatten)]
    pub host_args: HostArgs,

    /// Command to run inside the pod (default: interactive shell)
    #[arg(last = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

#[derive(Args)]
pub struct StopCommand {
    /// Names of pods to stop
    #[arg(required = true, num_args = 1.., value_parser = validate_pod_name)]
    pub names: Vec<String>,

    /// Block until the container is fully stopped
    #[arg(long)]
    pub wait: bool,
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
pub struct PruneCommand {
    /// Delete even if pods have unmerged commits
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct RecreateCommand {
    /// Name of the pod to recreate
    #[arg(help = "Name of the pod to recreate", value_parser = validate_pod_name)]
    pub name: String,

    #[command(flatten)]
    pub host_args: HostArgs,
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

    /// Restrict review to specific paths (like git difftool -- <path>...)
    #[arg(last = true, value_name = "PATH")]
    pub paths: Vec<String>,
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

    #[command(flatten)]
    pub host_args: HostArgs,

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

#[derive(Clone, ValueEnum)]
pub enum ClaudeAction {
    /// Refresh authentication credentials in the pod from the host
    Reauth,
}

#[derive(Args)]
pub struct ClaudeCommand {
    /// Name for this pod instance
    #[arg(help = "Name for this pod instance (e.g., 'dev', 'test')", value_parser = validate_pod_name)]
    pub name: String,

    /// Action to perform (omit for interactive Claude Code session)
    pub action: Option<ClaudeAction>,

    #[command(flatten)]
    pub host_args: HostArgs,

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
    #[command(flatten)]
    pub host_args: HostArgs,

    /// Archive mode (preserve uid/gid)
    #[arg(short = 'a', long = "archive")]
    pub archive: bool,

    /// Follow symlinks in src path
    #[arg(short = 'L', long = "follow-link")]
    pub follow_link: bool,

    /// Source: either POD:PATH or a local path
    #[arg(value_name = "SRC")]
    pub src: String,

    /// Destination: either POD:PATH or a local path
    #[arg(value_name = "DEST")]
    pub dest: String,
}

#[derive(Args)]
pub struct PrepareImageCommand {
    /// Where to clone the repo inside the container
    #[arg(long)]
    pub repo_path: PathBuf,

    /// User to chown the repo to
    #[arg(long)]
    pub user: String,

    /// Claude CLI version to install (skip if not provided)
    #[arg(long)]
    pub claude_version: Option<String>,

    /// Host git remote to configure (NAME=URL, repeatable)
    #[arg(long = "remote")]
    pub remotes: Vec<String>,
}

#[derive(Subcommand)]
pub enum ImageSubcommand {
    /// Build the devcontainer image from its Dockerfile
    #[command(long_about = "Build the devcontainer image from its Dockerfile.

Requires 'build.dockerfile' in devcontainer.json.
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
    #[command(flatten)]
    pub host_args: HostArgs,

    /// Disable Docker layer cache (--no-cache)
    #[arg(long)]
    pub no_cache: bool,

    /// Pull the base image before building (--pull)
    #[arg(long)]
    pub pull: bool,
}

#[derive(Args)]
pub struct ImageFetchCommand {
    #[command(flatten)]
    pub host_args: HostArgs,
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

#[derive(Args)]
pub struct SshCommand {
    /// Name of the pod
    #[arg(value_parser = validate_pod_name)]
    pub name: String,

    #[command(subcommand)]
    pub action: SshAction,
}

#[derive(Subcommand)]
pub enum SshAction {
    /// Add an SSH private key to the pod's ssh-agent
    Add(SshAddArgs),
    /// List SSH keys loaded in the pod's ssh-agent
    List,
}

#[derive(Args)]
pub struct SshAddArgs {
    /// Path to the SSH private key file on the host
    #[arg(value_name = "KEY_FILE")]
    pub key_file: PathBuf,
}
