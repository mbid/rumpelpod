//! Integration tests for the `sandbox agent` subcommand.
//!
//! Tests are organized into modules by feature area:
//! - smoke: Basic smoke tests run with every supported model (model-specific)
//! - file_tools: Basic file operations (edit, write) - shared implementation, single model
//! - bash_tool: Advanced bash tool functionality - shared implementation, single model
//! - web_tools: Web search and fetch functionality (model-specific implementations)
//! - history: Conversation history management - shared implementation, single model
//!
//! Tests for shared implementations only run with one model (Haiku) to reduce test time,
//! since the implementation is identical across all providers. Model-specific tests
//! (smoke, web_tools) run with all supported models.

mod common;

mod bash_tool;
mod file_tools;
mod history;
mod smoke;
mod startup;
mod temp_file_path;
mod web_tools;

// Re-export for other test modules
pub(super) use common::llm_cache_dir;
