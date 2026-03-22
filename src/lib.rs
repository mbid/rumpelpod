#[macro_use]
mod agent;
mod async_runtime;
mod claude;
mod cli;
mod command_ext;
pub mod config;
mod cp;
pub mod devcontainer;
mod docker_exec;
mod exec_proxy;

pub use command_ext::CommandExt;
pub mod daemon;
mod delete;
mod enter;
mod gateway;
mod git;
mod git_http_server;
mod hook;
pub(crate) mod image;
mod image_cmd;
mod k8s;
mod list;
mod llm;
mod merge;
pub mod pod;
mod ports;
mod prepared_image;
mod prune;
mod pty_attach;
mod recreate;
mod review;
mod service;
mod stop;
mod tcp_proxy;
mod tunnel;

use std::time::Duration;

use anyhow::Result;
use clap::Parser;

/// Whether an operation should retry indefinitely (user can cancel) or
/// give up after a sensible limit (no user waiting).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryPolicy {
    /// A user is waiting and can cancel (e.g. Ctrl-C).  Retry
    /// indefinitely, reporting errors so the user knows what is happening.
    UserBlocking,
    /// No user is waiting.  Retry with sensible limits determined by the
    /// retry logic itself.
    Background,
}

/// Apply jitter to a delay so concurrent retriers don't stampede.
///
/// Returns a uniformly random duration in [delay/2, delay].
pub fn jitter(d: Duration) -> Duration {
    d.mul_f64(0.5 + rand::random::<f64>() * 0.5)
}

use cli::{ClaudeHookSubcommand, Cli, Command, GitHookSubcommand, ImageSubcommand};

pub fn run() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Command::Daemon => {
            daemon::run_daemon()?;
        }
        Command::TunnelServer { port } => {
            tunnel::run_tunnel_server(port);
        }
        Command::TcpProxy { port } => {
            tcp_proxy::run_tcp_proxy(port);
        }
        Command::ContainerServe { port, ref token } => {
            pod::run_container_server(port, token.clone());
        }
        Command::SystemInstall => {
            service::system_install()?;
        }
        Command::SystemUninstall => {
            service::system_uninstall()?;
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
        Command::Prune(ref cmd) => {
            prune::prune(cmd)?;
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
        Command::Merge(ref cmd) => {
            merge::merge(cmd)?;
        }
        Command::Agent(ref cmd) => {
            agent::agent(cmd)?;
        }
        Command::Cp(ref cmd) => {
            cp::cp(cmd)?;
        }
        Command::Claude(ref cmd) => {
            claude::claude(cmd)?;
        }
        Command::PrepareImage(ref cmd) => {
            prepared_image::run_prepare_image(cmd)?;
        }
        Command::GitHook(ref sub) => match sub {
            GitHookSubcommand::ReferenceTransaction(ref cmd) => {
                hook::reference_transaction(cmd)?;
            }
            GitHookSubcommand::HostReferenceTransaction(ref cmd) => {
                hook::host_reference_transaction(cmd)?;
            }
            GitHookSubcommand::HostPostCheckout(ref cmd) => {
                hook::host_post_checkout(cmd)?;
            }
            GitHookSubcommand::GatewayPreReceive => {
                hook::gateway_pre_receive()?;
            }
            GitHookSubcommand::GatewayPostReceive => {
                hook::gateway_post_receive()?;
            }
        },
        Command::ClaudeHook(ref sub) => match sub {
            ClaudeHookSubcommand::PermissionRequest => {
                hook::claude_permission_request()?;
            }
        },
    }

    Ok(())
}
