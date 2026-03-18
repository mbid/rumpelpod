#[path = "cli/agent/mod.rs"]
mod agent;
#[path = "cli/anthropic_url.rs"]
mod anthropic_url;
#[path = "cli/claude/mod.rs"]
mod claude;
#[path = "cli/common.rs"]
mod common;
#[path = "cli/container_name.rs"]
mod container_name;
#[path = "cli/cp.rs"]
mod cp;
#[path = "cli/delete.rs"]
mod delete;
#[path = "cli/devcontainer/mod.rs"]
mod devcontainer;
#[path = "cli/enter.rs"]
mod enter;
#[path = "cli/executor.rs"]
mod executor;
#[path = "cli/gateway/mod.rs"]
mod gateway;
#[path = "cli/k8s/mod.rs"]
mod k8s;
#[path = "cli/list.rs"]
mod list;
#[path = "cli/merge.rs"]
mod merge;
#[path = "cli/network.rs"]
mod network;
#[path = "cli/prune.rs"]
mod prune;
#[path = "cli/recreate.rs"]
mod recreate;
#[path = "cli/review.rs"]
mod review;
#[path = "cli/ssh/mod.rs"]
mod ssh;
#[path = "cli/stop.rs"]
mod stop;
#[cfg(target_os = "linux")]
#[path = "cli/systemd.rs"]
mod systemd;
#[path = "cli/version.rs"]
mod version;
