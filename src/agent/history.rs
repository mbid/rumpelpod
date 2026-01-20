//! Conversation history management for agent sessions.
//!
//! Handles loading, saving, and selecting conversations to resume.

use std::io::{IsTerminal, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};

use crate::daemon::protocol::{ConversationSummary, Daemon, DaemonClient};
use crate::daemon::socket_path;

/// Tracks a conversation for saving after each assistant turn.
pub struct ConversationTracker {
    client: DaemonClient,
    id: Option<i64>,
    repo_path: std::path::PathBuf,
    sandbox_name: String,
    model: String,
    provider: String,
}

impl ConversationTracker {
    /// Create a new tracker for a conversation.
    ///
    /// If `id` is Some, updates will be applied to that existing conversation.
    /// If `id` is None, a new conversation will be created on first save.
    pub fn new(
        repo_path: std::path::PathBuf,
        sandbox_name: String,
        model: String,
        provider: String,
        id: Option<i64>,
    ) -> Result<Self> {
        let socket = socket_path()?;
        let client = DaemonClient::new_unix(&socket);
        Ok(Self {
            client,
            id,
            repo_path,
            sandbox_name,
            model,
            provider,
        })
    }

    /// Save the current conversation history.
    ///
    /// After the first save, subsequent saves update the same conversation.
    pub fn save(&mut self, history: &serde_json::Value) -> Result<()> {
        let returned_id = self.client.save_conversation(
            self.id,
            self.repo_path.clone(),
            self.sandbox_name.clone(),
            self.model.clone(),
            self.provider.clone(),
            history.clone(),
        )?;

        // Verify the ID is consistent - if we had an ID, it should not change
        if let Some(expected_id) = self.id {
            if returned_id != expected_id {
                bail!(
                    "Conversation ID changed unexpectedly: expected {}, got {}",
                    expected_id,
                    returned_id
                );
            }
        }

        self.id = Some(returned_id);
        Ok(())
    }
}

/// Result of resolving which conversation to use.
pub enum ConversationChoice {
    /// Start a new conversation (no history to load).
    New,
    /// Resume an existing conversation with the given ID.
    Resume(i64),
}

/// Format timestamp for display in picker.
///
/// Takes an ISO 8601 timestamp and formats it as "Mon-DD HH:MM".
fn format_timestamp(iso: &str) -> Result<String> {
    let dt = chrono::DateTime::parse_from_rfc3339(iso)
        .with_context(|| format!("Failed to parse timestamp: {}", iso))?;
    Ok(dt.format("%b-%d %H:%M").to_string())
}

/// Display a picker for selecting a conversation in TTY mode.
///
/// Returns the selected conversation ID.
fn show_picker(conversations: &[ConversationSummary]) -> Result<i64> {
    let mut stdout = std::io::stdout();

    println!(
        "Found {} existing conversations (use --new to start fresh):",
        conversations.len()
    );

    for (i, conv) in conversations.iter().enumerate() {
        let timestamp = format_timestamp(&conv.updated_at)?;
        println!("  {}) {} [{}]", i, timestamp, conv.model);
    }

    // Picker is only shown when there are 2+ conversations
    assert!(
        conversations.len() >= 2,
        "picker requires multiple conversations"
    );
    let max_index = conversations.len() - 1;
    loop {
        print!("Select [0-{}]: ", max_index);
        stdout.flush()?;

        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;

        let input = input.trim();
        if let Ok(n) = input.parse::<usize>() {
            if n < conversations.len() {
                return Ok(conversations[n].id);
            }
        }

        println!("Invalid selection, please try again.");
    }
}

/// Determine which conversation to use based on CLI flags and existing conversations.
///
/// Implements the startup behavior table from the design doc:
/// - No flag: resume if 1 conversation, picker if multiple (TTY), error if multiple (non-TTY)
/// - --new: always start new
/// - --continue=N: resume Nth most recent (0 = most recent)
pub fn resolve_conversation(
    repo_path: &Path,
    sandbox_name: &str,
    new_flag: bool,
    continue_flag: Option<u32>,
) -> Result<ConversationChoice> {
    // --new always starts fresh
    if new_flag {
        return Ok(ConversationChoice::New);
    }

    // Fetch existing conversations from daemon
    let socket = socket_path()?;
    let client = DaemonClient::new_unix(&socket);
    let conversations =
        client.list_conversations(repo_path.to_path_buf(), sandbox_name.to_string())?;

    // Handle --continue=N
    if let Some(n) = continue_flag {
        let n = n as usize;
        if conversations.is_empty() {
            bail!("No conversations exist for sandbox '{}'.", sandbox_name);
        }
        if n >= conversations.len() {
            bail!(
                "Conversation index {} out of range. Only {} conversation(s) exist.",
                n,
                conversations.len()
            );
        }
        // Conversations are already sorted by updated_at DESC, so index 0 is most recent
        return Ok(ConversationChoice::Resume(conversations[n].id));
    }

    // No flags provided - behavior depends on number of existing conversations
    match conversations.len() {
        0 => Ok(ConversationChoice::New),
        1 => {
            // Auto-resume the only conversation
            Ok(ConversationChoice::Resume(conversations[0].id))
        }
        _ => {
            // Multiple conversations exist
            if std::io::stdin().is_terminal() {
                // TTY: show picker
                let id = show_picker(&conversations)?;
                Ok(ConversationChoice::Resume(id))
            } else {
                // Non-TTY: error with helpful message
                bail!(
                    "Multiple conversations exist for sandbox '{}'.\n\
                     Use --continue=N to select (0 = most recent), or --new to start fresh.",
                    sandbox_name
                );
            }
        }
    }
}

/// Load conversation history by ID.
pub fn load_conversation(id: i64) -> Result<(serde_json::Value, String, String)> {
    let socket = socket_path()?;
    let client = DaemonClient::new_unix(&socket);
    let response = client
        .get_conversation(id)?
        .with_context(|| format!("Conversation {} not found", id))?;
    Ok((response.history, response.model, response.provider))
}

