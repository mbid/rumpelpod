//! Integration tests for the `rumpel claude` subcommand.
//!
//! Tests verify that the claude CLI running inside a container can
//! communicate with the host via a caching HTTP proxy, producing
//! deterministic, offline-reproducible results.

pub(super) mod common;
pub(super) mod proxy;

mod skip_permissions;
mod smoke;
