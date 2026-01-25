//! SQLite database for persisting conversation history.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use indoc::indoc;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// Summary of a conversation for listing.
#[derive(Debug, Clone)]
pub struct ConversationSummary {
    pub id: i64,
    pub model: String,
    pub provider: String,
    pub updated_at: String,
}

/// Full conversation data.
#[derive(Debug, Clone)]
pub struct Conversation {
    #[allow(dead_code)] // Used for potential future features
    pub id: i64,
    pub model: String,
    pub provider: String,
    pub history: serde_json::Value,
}

/// Get the database path.
/// Uses $XDG_STATE_HOME/sandbox/db.sqlite
pub fn db_path() -> Result<PathBuf> {
    let state_base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".local/state")
        });

    Ok(state_base.join("sandbox").join("db.sqlite"))
}

const SCHEMA_SQL: &str = indoc! {"
    CREATE TABLE conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_path TEXT NOT NULL,
        sandbox_name TEXT NOT NULL,
        model TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        history JSON NOT NULL
    );

    CREATE INDEX idx_conversations_lookup
        ON conversations(repo_path, sandbox_name, updated_at DESC);

    CREATE TABLE db_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
"};

fn get_schema_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_SQL);
    hex::encode(hasher.finalize())
}

/// Open a database connection, creating the database and tables if needed.
pub fn open_db(path: &Path) -> Result<Connection> {
    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {}", parent.display()))?;
    }

    if !path.exists() {
        return create_and_init_db(path);
    }

    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database at {}", path.display()))?;

    // Check version
    let current_hash = get_schema_hash();
    let stored_hash: Result<String, _> = conn.query_row(
        "SELECT value FROM db_meta WHERE key = 'schema_version'",
        [],
        |row| row.get(0),
    );

    match stored_hash {
        Ok(hash) => {
            if hash != current_hash {
                bail!(
                    indoc! {"
                    Database schema mismatch.
                    Expected hash: {}
                    Found hash:    {}
                    
                    Please delete the database file to start over:
                    rm {}
                "},
                    current_hash,
                    hash,
                    path.display()
                );
            }
        }
        Err(rusqlite::Error::SqliteFailure(_, _)) | Err(rusqlite::Error::QueryReturnedNoRows) => {
            // Treat missing table or missing row as "no version".
            // Close connection, delete file, and start over.
            drop(conn);
            std::fs::remove_file(path).with_context(|| {
                format!("Failed to remove outdated database at {}", path.display())
            })?;
            return create_and_init_db(path);
        }
        Err(e) => {
            // Other errors (e.g. database corruption)
            return Err(e).context("Failed to read schema version from database");
        }
    }

    Ok(conn)
}

fn create_and_init_db(path: &Path) -> Result<Connection> {
    let mut conn = Connection::open(path)
        .with_context(|| format!("Failed to open new database at {}", path.display()))?;

    let tx = conn.transaction()?;

    tx.execute_batch(SCHEMA_SQL)
        .context("Failed to initialize database schema")?;

    let hash = get_schema_hash();
    tx.execute(
        "INSERT INTO db_meta (key, value) VALUES ('schema_version', ?)",
        [&hash],
    )
    .context("Failed to insert schema version")?;

    tx.commit()?;

    Ok(conn)
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
    provider: &str,
    history: &serde_json::Value,
) -> Result<i64> {
    let now = chrono::Utc::now().to_rfc3339();
    let repo_path_str = repo_path.to_string_lossy();
    let history_str = serde_json::to_string(history).context("Failed to serialize history")?;

    if let Some(id) = id {
        // Update existing conversation
        conn.execute(
            "UPDATE conversations SET model = ?, provider = ?, updated_at = ?, history = ? WHERE id = ?",
            rusqlite::params![model, provider, now, history_str, id],
        )
        .context("Failed to update conversation")?;
        Ok(id)
    } else {
        // Insert new conversation
        conn.execute(
            "INSERT INTO conversations (repo_path, sandbox_name, model, provider, created_at, updated_at, history)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            rusqlite::params![repo_path_str, sandbox_name, model, provider, now, now, history_str],
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
            "SELECT id, model, provider, updated_at FROM conversations
             WHERE repo_path = ? AND sandbox_name = ?
             ORDER BY updated_at DESC",
        )
        .context("Failed to prepare query")?;

    let rows = stmt
        .query_map(rusqlite::params![repo_path_str, sandbox_name], |row| {
            Ok(ConversationSummary {
                id: row.get(0)?,
                model: row.get(1)?,
                provider: row.get(2)?,
                updated_at: row.get(3)?,
            })
        })
        .context("Failed to query conversations")?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.context("Failed to read conversation row")?);
    }

    Ok(result)
}

/// Delete all conversations for a given repo and sandbox.
///
/// Returns the number of conversations deleted.
pub fn delete_conversations(
    conn: &Connection,
    repo_path: &Path,
    sandbox_name: &str,
) -> Result<usize> {
    let repo_path_str = repo_path.to_string_lossy();
    let count = conn
        .execute(
            "DELETE FROM conversations WHERE repo_path = ? AND sandbox_name = ?",
            rusqlite::params![repo_path_str, sandbox_name],
        )
        .context("Failed to delete conversations")?;
    Ok(count)
}

/// Get a conversation by ID.
pub fn get_conversation(conn: &Connection, id: i64) -> Result<Option<Conversation>> {
    let mut stmt = conn
        .prepare("SELECT id, model, provider, history FROM conversations WHERE id = ?")
        .context("Failed to prepare query")?;

    let mut rows = stmt
        .query_map(rusqlite::params![id], |row| {
            let history_str: String = row.get(3)?;
            let history: serde_json::Value = serde_json::from_str(&history_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    3,
                    rusqlite::types::Type::Text,
                    Box::new(e),
                )
            })?;
            Ok(Conversation {
                id: row.get(0)?,
                model: row.get(1)?,
                provider: row.get(2)?,
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
        let id = save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-sonnet-4-5",
            "anthropic",
            &history,
        )
        .unwrap();
        assert!(id > 0);

        // Get it back
        let conv = get_conversation(&conn, id).unwrap().unwrap();
        assert_eq!(conv.id, id);
        assert_eq!(conv.model, "claude-sonnet-4-5");
        assert_eq!(conv.provider, "anthropic");
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
        let id = save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-sonnet-4-5",
            "anthropic",
            &history1,
        )
        .unwrap();

        // Update it
        let id2 = save_conversation(
            &conn,
            Some(id),
            &repo_path,
            "dev",
            "claude-opus-4-5",
            "anthropic",
            &history2,
        )
        .unwrap();
        assert_eq!(id, id2);

        // Get updated version
        let conv = get_conversation(&conn, id).unwrap().unwrap();
        assert_eq!(conv.model, "claude-opus-4-5");
        assert_eq!(conv.provider, "anthropic");
        assert_eq!(conv.history, history2);
    }

    #[test]
    fn test_list_conversations() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([]);

        // Save multiple conversations
        let id1 = save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-sonnet-4-5",
            "anthropic",
            &history,
        )
        .unwrap();

        // Small delay to ensure different timestamps
        std::thread::sleep(std::time::Duration::from_millis(10));
        let id2 = save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-opus-4-5",
            "anthropic",
            &history,
        )
        .unwrap();

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
        save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-sonnet-4-5",
            "anthropic",
            &history,
        )
        .unwrap();
        save_conversation(
            &conn,
            None,
            &repo_path,
            "test",
            "claude-opus-4-5",
            "anthropic",
            &history,
        )
        .unwrap();

        // List should only return matching sandbox
        let dev_list = list_conversations(&conn, &repo_path, "dev").unwrap();
        assert_eq!(dev_list.len(), 1);
        assert_eq!(dev_list[0].model, "claude-sonnet-4-5");

        let test_list = list_conversations(&conn, &repo_path, "test").unwrap();
        assert_eq!(test_list.len(), 1);
        assert_eq!(test_list[0].model, "claude-opus-4-5");
    }

    #[test]
    fn test_list_conversations_filters_by_repo() {
        let (_temp_dir, conn) = test_db();

        let repo1 = PathBuf::from("/home/user/project1");
        let repo2 = PathBuf::from("/home/user/project2");
        let history = serde_json::json!([]);

        // Save to different repos with same sandbox name
        save_conversation(
            &conn,
            None,
            &repo1,
            "dev",
            "claude-sonnet-4-5",
            "anthropic",
            &history,
        )
        .unwrap();
        save_conversation(
            &conn,
            None,
            &repo2,
            "dev",
            "claude-opus-4-5",
            "anthropic",
            &history,
        )
        .unwrap();

        // List should only return matching repo
        let repo1_list = list_conversations(&conn, &repo1, "dev").unwrap();
        assert_eq!(repo1_list.len(), 1);
        assert_eq!(repo1_list[0].model, "claude-sonnet-4-5");

        let repo2_list = list_conversations(&conn, &repo2, "dev").unwrap();
        assert_eq!(repo2_list.len(), 1);
        assert_eq!(repo2_list[0].model, "claude-opus-4-5");
    }

    #[test]
    fn test_get_nonexistent_conversation() {
        let (_temp_dir, conn) = test_db();

        let conv = get_conversation(&conn, 999).unwrap();
        assert!(conv.is_none());
    }

    #[test]
    fn test_delete_conversations() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([]);

        // Save conversations in different sandboxes
        save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-sonnet-4-5",
            "anthropic",
            &history,
        )
        .unwrap();
        save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-opus-4-5",
            "anthropic",
            &history,
        )
        .unwrap();
        save_conversation(
            &conn,
            None,
            &repo_path,
            "test",
            "claude-haiku-4-5",
            "anthropic",
            &history,
        )
        .unwrap();

        // Delete conversations for "dev" sandbox
        let deleted = delete_conversations(&conn, &repo_path, "dev").unwrap();
        assert_eq!(deleted, 2);

        // "dev" should have no conversations
        let dev_list = list_conversations(&conn, &repo_path, "dev").unwrap();
        assert!(dev_list.is_empty());

        // "test" should still have its conversation
        let test_list = list_conversations(&conn, &repo_path, "test").unwrap();
        assert_eq!(test_list.len(), 1);
    }

    #[test]
    fn test_delete_conversations_nonexistent_sandbox() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Deleting from a sandbox that doesn't exist should succeed with 0 deleted
        let deleted = delete_conversations(&conn, &repo_path, "nonexistent").unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_db_versioning_recreation() {
        let temp_dir = TempDir::with_prefix("sandbox-db-test-versioning-").unwrap();
        let db_path = temp_dir.path().join("test.db");

        // 1. Create fresh DB
        {
            let conn = open_db(&db_path).unwrap();
            // Verify version exists
            let hash: String = conn
                .query_row(
                    "SELECT value FROM db_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(hash, get_schema_hash());
        }

        // 2. Corrupt DB (remove version)
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute("DELETE FROM db_meta WHERE key = 'schema_version'", [])
                .unwrap();
        }

        // 3. Open again - should detect missing version and re-create
        {
            let conn = open_db(&db_path).unwrap();
            let hash: String = conn
                .query_row(
                    "SELECT value FROM db_meta WHERE key = 'schema_version'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(hash, get_schema_hash());

            // Verify it was re-created (tables should be empty if we had added data,
            // but here we just check it opened successfully and has version)
        }
    }

    #[test]
    fn test_db_versioning_mismatch() {
        let temp_dir = TempDir::with_prefix("sandbox-db-test-mismatch-").unwrap();
        let db_path = temp_dir.path().join("test.db");

        // 1. Create DB with wrong version hash manually
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(SCHEMA_SQL).unwrap();
            conn.execute(
                "INSERT INTO db_meta (key, value) VALUES ('schema_version', 'wrong_hash')",
                [],
            )
            .unwrap();
        }

        // 2. Open should fail
        let result = open_db(&db_path);
        assert!(result.is_err());
        let err = result.err().unwrap();
        assert!(err.to_string().contains("Database schema mismatch"));
        assert!(err.to_string().contains("rm "));
    }
}
