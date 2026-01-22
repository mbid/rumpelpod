//! Integration tests for the `sandbox agent` subcommand.
//!
//! Tests are organized into modules by feature area:
//! - smoke: Basic smoke tests run with every supported model
//! - file_tools: Basic file operations (edit, write)
//! - bash_tool: Advanced bash tool functionality (output limits, error handling)
//! - web_tools: Web search and fetch functionality
//! - history: Conversation history management

mod common;

mod bash_tool;
mod file_tools;
mod history;
mod smoke;
mod web_tools;

// Re-export for other test modules
pub(super) use common::llm_cache_dir;
