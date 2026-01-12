//! SQLite database for persisting conversation history.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use indoc::indoc;
use rusqlite::Connection;

/// Summary of a conversation for listing.
#[derive(Debug, Clone)]
pub struct ConversationSummary {
    pub id: i64,
    pub model: String,
    pub updated_at: String,
}

/// Full conversation data.
#[derive(Debug, Clone)]
pub struct Conversation {
    #[allow(dead_code)] // Used for potential future features
    pub id: i64,
    pub model: String,
    pub history: serde_json::Value,
}

/// Get the database path.
/// Uses $XDG_STATE_HOME/sandbox/conversations.db
pub fn db_path() -> Result<PathBuf> {
    let state_base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".local/state")
        });

    Ok(state_base.join("sandbox").join("conversations.db"))
}

/// Open a database connection, creating the database and tables if needed.
pub fn open_db(path: &Path) -> Result<Connection> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }

    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database at {}", path.display()))?;

    init_db(&conn)?;

    Ok(conn)
}

/// Initialize the database schema if it doesn't exist.
fn init_db(conn: &Connection) -> Result<()> {
    conn.execute_batch(indoc! {"
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            repo_path TEXT NOT NULL,
            sandbox_name TEXT NOT NULL,
            model TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            history JSON NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_conversations_lookup
            ON conversations(repo_path, sandbox_name, updated_at DESC);
    "})
        .context("Failed to initialize database schema")?;

    Ok(())
}

/// Save or update a conversation.
///
/// If `id` is provided, updates the existing conversation.
/// Otherwise, creates a new conversation and returns its ID.
pub fn save_conversation(
    conn: &Connection,
    id: Option<i64>,
    repo_path: &Path,
    sandbox_name: &str,
    model: &str,
    history: &serde_json::Value,
) -> Result<i64> {
    let now = chrono::Utc::now().to_rfc3339();
    let repo_path_str = repo_path.to_string_lossy();
    let history_str = serde_json::to_string(history).context("Failed to serialize history")?;

    if let Some(id) = id {
        // Update existing conversation
        conn.execute(
            "UPDATE conversations SET model = ?, updated_at = ?, history = ? WHERE id = ?",
            rusqlite::params![model, now, history_str, id],
        )
        .context("Failed to update conversation")?;
        Ok(id)
    } else {
        // Insert new conversation
        conn.execute(
            "INSERT INTO conversations (repo_path, sandbox_name, model, created_at, updated_at, history)
             VALUES (?, ?, ?, ?, ?, ?)",
            rusqlite::params![repo_path_str, sandbox_name, model, now, now, history_str],
        )
        .context("Failed to insert conversation")?;
        Ok(conn.last_insert_rowid())
    }
}

/// List conversations for a given repo and sandbox, ordered by most recently updated.
pub fn list_conversations(
    conn: &Connection,
    repo_path: &Path,
    sandbox_name: &str,
) -> Result<Vec<ConversationSummary>> {
    let repo_path_str = repo_path.to_string_lossy();

    let mut stmt = conn
        .prepare(
            "SELECT id, model, updated_at FROM conversations
             WHERE repo_path = ? AND sandbox_name = ?
             ORDER BY updated_at DESC",
        )
        .context("Failed to prepare query")?;

    let rows = stmt
        .query_map(rusqlite::params![repo_path_str, sandbox_name], |row| {
            Ok(ConversationSummary {
                id: row.get(0)?,
                model: row.get(1)?,
                updated_at: row.get(2)?,
            })
        })
        .context("Failed to query conversations")?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.context("Failed to read conversation row")?);
    }

    Ok(result)
}

/// Get a conversation by ID.
pub fn get_conversation(conn: &Connection, id: i64) -> Result<Option<Conversation>> {
    let mut stmt = conn
        .prepare("SELECT id, model, history FROM conversations WHERE id = ?")
        .context("Failed to prepare query")?;

    let mut rows = stmt
        .query_map(rusqlite::params![id], |row| {
            let history_str: String = row.get(2)?;
            let history: serde_json::Value = serde_json::from_str(&history_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    2,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(Conversation {
                id: row.get(0)?,
                model: row.get(1)?,
                history,
            })
        })
        .context("Failed to query conversation")?;

    match rows.next() {
        Some(row) => Ok(Some(row.context("Failed to read conversation")?)),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db() -> (TempDir, Connection) {
        let temp_dir = TempDir::with_prefix("sandbox-db-test-").unwrap();
        let db_path = temp_dir.path().join("test.db");
        let conn = open_db(&db_path).unwrap();
        (temp_dir, conn)
    }

    #[test]
    fn test_save_and_get_conversation() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([{"role": "user", "content": "hello"}]);

        // Save new conversation
        let id = save_conversation(&conn, None, &repo_path, "dev", "sonnet", &history).unwrap();
        assert!(id > 0);

        // Get it back
        let conv = get_conversation(&conn, id).unwrap().unwrap();
        assert_eq!(conv.id, id);
        assert_eq!(conv.model, "sonnet");
        assert_eq!(conv.history, history);
    }

    #[test]
    fn test_update_conversation() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history1 = serde_json::json!([{"role": "user", "content": "hello"}]);
        let history2 = serde_json::json!([
            {"role": "user", "content": "hello"},
            {"role": "assistant", "content": "hi there"}
        ]);

        // Save initial
        let id = save_conversation(&conn, None, &repo_path, "dev", "sonnet", &history1).unwrap();

        // Update it
        let id2 = save_conversation(&conn, Some(id), &repo_path, "dev", "opus", &history2).unwrap();
        assert_eq!(id, id2);

        // Get updated version
        let conv = get_conversation(&conn, id).unwrap().unwrap();
        assert_eq!(conv.model, "opus");
        assert_eq!(conv.history, history2);
    }

    #[test]
    fn test_list_conversations() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([]);

        // Save multiple conversations
        let id1 = save_conversation(&conn, None, &repo_path, "dev", "sonnet", &history).unwrap();

        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));
        let id2 = save_conversation(&conn, None, &repo_path, "dev", "opus", &history).unwrap();

        // List should be ordered by updated_at DESC (most recent first)
        let list = list_conversations(&conn, &repo_path, "dev").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].id, id2); // Most recent first
        assert_eq!(list[1].id, id1);
    }

    #[test]
    fn test_list_conversations_filters_by_sandbox() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([]);

        // Save to different sandboxes
        save_conversation(&conn, None, &repo_path, "dev", "sonnet", &history).unwrap();
        save_conversation(&conn, None, &repo_path, "test", "opus", &history).unwrap();

        // List should only return matching sandbox
        let dev_list = list_conversations(&conn, &repo_path, "dev").unwrap();
        assert_eq!(dev_list.len(), 1);
        assert_eq!(dev_list[0].model, "sonnet");

        let test_list = list_conversations(&conn, &repo_path, "test").unwrap();
        assert_eq!(test_list.len(), 1);
        assert_eq!(test_list[0].model, "opus");
    }

    #[test]
    fn test_list_conversations_filters_by_repo() {
        let (_temp_dir, conn) = test_db();

        let repo1 = PathBuf::from("/home/user/project1");
        let repo2 = PathBuf::from("/home/user/project2");
        let history = serde_json::json!([]);

        // Save to different repos with same sandbox name
        save_conversation(&conn, None, &repo1, "dev", "sonnet", &history).unwrap();
        save_conversation(&conn, None, &repo2, "dev", "opus", &history).unwrap();

        // List should only return matching repo
        let repo1_list = list_conversations(&conn, &repo1, "dev").unwrap();
        assert_eq!(repo1_list.len(), 1);
        assert_eq!(repo1_list[0].model, "sonnet");

        let repo2_list = list_conversations(&conn, &repo2, "dev").unwrap();
        assert_eq!(repo2_list.len(), 1);
        assert_eq!(repo2_list[0].model, "opus");
    }

    #[test]
    fn test_get_nonexistent_conversation() {
        let (_temp_dir, conn) = test_db();

        let conv = get_conversation(&conn, 999).unwrap();
        assert!(conv.is_none());
    }
}
