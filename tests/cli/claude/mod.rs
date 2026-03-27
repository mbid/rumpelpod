//! Integration tests for the `rumpel claude` subcommand.
//!
//! Tests verify that the claude CLI running inside a container can
//! communicate with the host via the LLM cache proxy routed through
//! the pod server and git HTTP server tunnel, producing deterministic,
//! offline-reproducible results.

pub(super) mod common;

mod detach;
mod install;
mod reauth;
mod smoke;
mod system_prompt;
mod tool_use;
