//! SQLite database for persisting sandbox metadata and conversation history.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use indoc::indoc;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

/// Strongly-typed wrapper for sandbox database IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SandboxId(i64);

impl From<i64> for SandboxId {
    fn from(id: i64) -> Self {
        SandboxId(id)
    }
}

impl From<SandboxId> for i64 {
    fn from(id: SandboxId) -> Self {
        id.0
    }
}

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

/// Status of a sandbox in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// Sandbox is being initialized (container creation, git setup, etc.)
    Initializing,
    /// Sandbox is fully initialized and ready
    Ready,
    /// Sandbox initialization failed
    Error,
}

impl SandboxStatus {
    fn as_str(&self) -> &'static str {
        match self {
            SandboxStatus::Initializing => "initializing",
            SandboxStatus::Ready => "ready",
            SandboxStatus::Error => "error",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "initializing" => Some(SandboxStatus::Initializing),
            "ready" => Some(SandboxStatus::Ready),
            "error" => Some(SandboxStatus::Error),
            _ => None,
        }
    }
}

/// Host specification for local sandboxes.
pub const LOCAL_HOST: &str = "localhost";

/// Information about a sandbox from the database.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some fields used only in tests or for future features
pub struct SandboxRecord {
    pub id: SandboxId,
    pub repo_path: String,
    pub name: String,
    /// The host where the sandbox runs: "local" or an SSH URL like "user@host:port".
    pub host: String,
    pub status: SandboxStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
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
    CREATE TABLE sandboxes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_path TEXT NOT NULL,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'initializing',
        on_create_ran INTEGER NOT NULL DEFAULT 0,
        post_create_ran INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(repo_path, name)
    );

    CREATE INDEX idx_sandboxes_lookup
        ON sandboxes(repo_path, name);

    CREATE TABLE conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sandbox_id INTEGER NOT NULL REFERENCES sandboxes(id) ON DELETE CASCADE,
        model TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        history JSON NOT NULL
    );

    CREATE INDEX idx_conversations_lookup
        ON conversations(sandbox_id, updated_at DESC);

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

    // Enable foreign key enforcement
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .context("Failed to enable foreign keys")?;

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

    // Enable foreign key enforcement
    conn.execute_batch("PRAGMA foreign_keys = ON;")
        .context("Failed to enable foreign keys")?;

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

// --- Sandbox functions ---

/// Create a new sandbox record with status "initializing".
///
/// Returns the ID of the new sandbox.
/// Returns an error if a sandbox with this repo_path and name already exists.
pub fn create_sandbox(
    conn: &Connection,
    repo_path: &Path,
    name: &str,
    host: &str,
) -> Result<SandboxId> {
    let now = Utc::now().to_rfc3339();
    let repo_path_str = repo_path.to_string_lossy();

    conn.execute(
        "INSERT INTO sandboxes (repo_path, name, host, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            repo_path_str,
            name,
            host,
            SandboxStatus::Initializing.as_str(),
            now,
            now
        ],
    )
    .context("Failed to insert sandbox")?;

    Ok(SandboxId(conn.last_insert_rowid()))
}

/// Update the status of a sandbox.
pub fn update_sandbox_status(
    conn: &Connection,
    id: SandboxId,
    status: SandboxStatus,
) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE sandboxes SET status = ?, updated_at = ? WHERE id = ?",
        rusqlite::params![status.as_str(), now, i64::from(id)],
    )
    .context("Failed to update sandbox status")?;
    Ok(())
}

/// Get a sandbox by repo_path and name.
pub fn get_sandbox(
    conn: &Connection,
    repo_path: &Path,
    name: &str,
) -> Result<Option<SandboxRecord>> {
    let repo_path_str = repo_path.to_string_lossy();

    let mut stmt = conn
        .prepare(
            "SELECT id, repo_path, name, host, status, created_at, updated_at FROM sandboxes
             WHERE repo_path = ? AND name = ?",
        )
        .context("Failed to prepare query")?;

    let mut rows = stmt
        .query_map(rusqlite::params![repo_path_str, name], |row| {
            let status_str: String = row.get(4)?;
            let status = SandboxStatus::from_str(&status_str).unwrap_or(SandboxStatus::Error);
            Ok(SandboxRecord {
                id: SandboxId(row.get(0)?),
                repo_path: row.get(1)?,
                name: row.get(2)?,
                host: row.get(3)?,
                status,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .context("Failed to query sandbox")?;

    match rows.next() {
        Some(row) => Ok(Some(row.context("Failed to read sandbox")?)),
        None => Ok(None),
    }
}

/// Get a sandbox by ID.
#[allow(dead_code)] // Used in tests
pub fn get_sandbox_by_id(conn: &Connection, id: SandboxId) -> Result<Option<SandboxRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, repo_path, name, host, status, created_at, updated_at FROM sandboxes
             WHERE id = ?",
        )
        .context("Failed to prepare query")?;

    let mut rows = stmt
        .query_map(rusqlite::params![i64::from(id)], |row| {
            let status_str: String = row.get(4)?;
            let status = SandboxStatus::from_str(&status_str).unwrap_or(SandboxStatus::Error);
            Ok(SandboxRecord {
                id: SandboxId(row.get(0)?),
                repo_path: row.get(1)?,
                name: row.get(2)?,
                host: row.get(3)?,
                status,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .context("Failed to query sandbox")?;

    match rows.next() {
        Some(row) => Ok(Some(row.context("Failed to read sandbox")?)),
        None => Ok(None),
    }
}

/// List all sandboxes for a given repo path.
pub fn list_sandboxes(conn: &Connection, repo_path: &Path) -> Result<Vec<SandboxRecord>> {
    let repo_path_str = repo_path.to_string_lossy();

    let mut stmt = conn
        .prepare(
            "SELECT id, repo_path, name, host, status, created_at, updated_at FROM sandboxes
             WHERE repo_path = ?
             ORDER BY name ASC",
        )
        .context("Failed to prepare query")?;

    let rows = stmt
        .query_map(rusqlite::params![repo_path_str], |row| {
            let status_str: String = row.get(4)?;
            let status = SandboxStatus::from_str(&status_str).unwrap_or(SandboxStatus::Error);
            Ok(SandboxRecord {
                id: SandboxId(row.get(0)?),
                repo_path: row.get(1)?,
                name: row.get(2)?,
                host: row.get(3)?,
                status,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .context("Failed to query sandboxes")?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.context("Failed to read sandbox row")?);
    }

    Ok(result)
}

/// Delete a sandbox and all its conversations.
pub fn delete_sandbox(conn: &Connection, repo_path: &Path, name: &str) -> Result<bool> {
    let repo_path_str = repo_path.to_string_lossy();
    let count = conn
        .execute(
            "DELETE FROM sandboxes WHERE repo_path = ? AND name = ?",
            rusqlite::params![repo_path_str, name],
        )
        .context("Failed to delete sandbox")?;
    Ok(count > 0)
}

/// Check whether the on_create lifecycle command has already run for this sandbox.
pub fn has_on_create_run(conn: &Connection, id: SandboxId) -> Result<bool> {
    let ran: bool = conn
        .query_row(
            "SELECT on_create_ran FROM sandboxes WHERE id = ?",
            rusqlite::params![i64::from(id)],
            |row| row.get(0),
        )
        .context("Failed to query on_create_ran")?;
    Ok(ran)
}

/// Check whether the post_create lifecycle command has already run for this sandbox.
pub fn has_post_create_run(conn: &Connection, id: SandboxId) -> Result<bool> {
    let ran: bool = conn
        .query_row(
            "SELECT post_create_ran FROM sandboxes WHERE id = ?",
            rusqlite::params![i64::from(id)],
            |row| row.get(0),
        )
        .context("Failed to query post_create_ran")?;
    Ok(ran)
}

/// Mark the on_create lifecycle command as having been executed for this sandbox.
pub fn mark_on_create_ran(conn: &Connection, id: SandboxId) -> Result<()> {
    conn.execute(
        "UPDATE sandboxes SET on_create_ran = 1 WHERE id = ?",
        rusqlite::params![i64::from(id)],
    )
    .context("Failed to mark on_create_ran")?;
    Ok(())
}

/// Mark the post_create lifecycle command as having been executed for this sandbox.
pub fn mark_post_create_ran(conn: &Connection, id: SandboxId) -> Result<()> {
    conn.execute(
        "UPDATE sandboxes SET post_create_ran = 1 WHERE id = ?",
        rusqlite::params![i64::from(id)],
    )
    .context("Failed to mark post_create_ran")?;
    Ok(())
}

// --- Conversation functions ---

/// Save or update a conversation.
///
/// If `id` is provided, updates the existing conversation.
/// Otherwise, creates a new conversation and returns its ID.
///
/// Returns an error if the sandbox doesn't exist.
pub fn save_conversation(
    conn: &Connection,
    id: Option<i64>,
    repo_path: &Path,
    sandbox_name: &str,
    model: &str,
    provider: &str,
    history: &serde_json::Value,
) -> Result<i64> {
    let now = Utc::now().to_rfc3339();
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
        // Get sandbox - it must exist
        let sandbox = get_sandbox(conn, repo_path, sandbox_name)?
            .with_context(|| format!("Sandbox '{}' not found", sandbox_name))?;

        // Insert new conversation
        conn.execute(
            "INSERT INTO conversations (sandbox_id, model, provider, created_at, updated_at, history)
             VALUES (?, ?, ?, ?, ?, ?)",
            rusqlite::params![i64::from(sandbox.id), model, provider, now, now, history_str],
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
    // First get the sandbox ID
    let sandbox = get_sandbox(conn, repo_path, sandbox_name)?;
    let sandbox_id = match sandbox {
        Some(s) => s.id,
        None => return Ok(Vec::new()), // No sandbox means no conversations
    };

    let mut stmt = conn
        .prepare(
            "SELECT id, model, provider, updated_at FROM conversations
             WHERE sandbox_id = ?
             ORDER BY updated_at DESC",
        )
        .context("Failed to prepare query")?;

    let rows = stmt
        .query_map(rusqlite::params![i64::from(sandbox_id)], |row| {
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
#[allow(dead_code)] // Used in tests
pub fn delete_conversations(
    conn: &Connection,
    repo_path: &Path,
    sandbox_name: &str,
) -> Result<usize> {
    // First get the sandbox ID
    let sandbox = get_sandbox(conn, repo_path, sandbox_name)?;
    let sandbox_id = match sandbox {
        Some(s) => s.id,
        None => return Ok(0), // No sandbox means no conversations to delete
    };

    let count = conn
        .execute(
            "DELETE FROM conversations WHERE sandbox_id = ?",
            rusqlite::params![i64::from(sandbox_id)],
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

    // --- Sandbox tests ---

    #[test]
    fn test_create_and_get_sandbox() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Create a local sandbox
        let id = create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();
        assert!(i64::from(id) > 0);

        // Get it back
        let sandbox = get_sandbox(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(sandbox.id, id);
        assert_eq!(sandbox.name, "dev");
        assert_eq!(sandbox.host, LOCAL_HOST);
        assert_eq!(sandbox.status, SandboxStatus::Initializing);
    }

    #[test]
    fn test_create_sandbox_with_host() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Create a remote sandbox
        let id = create_sandbox(&conn, &repo_path, "remote", "user@host:22").unwrap();

        let sandbox = get_sandbox(&conn, &repo_path, "remote").unwrap().unwrap();
        assert_eq!(sandbox.id, id);
        assert_eq!(sandbox.host, "user@host:22");
    }

    #[test]
    fn test_create_sandbox_duplicate_fails() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Create first sandbox
        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();

        // Creating another with same name should fail
        let result = create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_sandbox_status() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        let id = create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();

        // Initial status is Initializing
        let sandbox = get_sandbox(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(sandbox.status, SandboxStatus::Initializing);

        // Update to Ready
        update_sandbox_status(&conn, id, SandboxStatus::Ready).unwrap();
        let sandbox = get_sandbox(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(sandbox.status, SandboxStatus::Ready);

        // Update to Error
        update_sandbox_status(&conn, id, SandboxStatus::Error).unwrap();
        let sandbox = get_sandbox(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(sandbox.status, SandboxStatus::Error);
    }

    #[test]
    fn test_list_sandboxes() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();
        create_sandbox(&conn, &repo_path, "test", "remote:22").unwrap();

        let sandboxes = list_sandboxes(&conn, &repo_path).unwrap();
        assert_eq!(sandboxes.len(), 2);
        // Should be sorted by name
        assert_eq!(sandboxes[0].name, "dev");
        assert_eq!(sandboxes[1].name, "test");
        assert_eq!(sandboxes[1].host, "remote:22");
    }

    #[test]
    fn test_list_sandboxes_filters_by_repo() {
        let (_temp_dir, conn) = test_db();

        let repo1 = PathBuf::from("/home/user/project1");
        let repo2 = PathBuf::from("/home/user/project2");

        create_sandbox(&conn, &repo1, "dev", LOCAL_HOST).unwrap();
        create_sandbox(&conn, &repo2, "dev", LOCAL_HOST).unwrap();

        let repo1_sandboxes = list_sandboxes(&conn, &repo1).unwrap();
        assert_eq!(repo1_sandboxes.len(), 1);
        assert_eq!(repo1_sandboxes[0].repo_path, repo1.to_string_lossy());

        let repo2_sandboxes = list_sandboxes(&conn, &repo2).unwrap();
        assert_eq!(repo2_sandboxes.len(), 1);
        assert_eq!(repo2_sandboxes[0].repo_path, repo2.to_string_lossy());
    }

    #[test]
    fn test_delete_sandbox() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();

        // Delete the sandbox
        let deleted = delete_sandbox(&conn, &repo_path, "dev").unwrap();
        assert!(deleted);

        // Should no longer exist
        let sandbox = get_sandbox(&conn, &repo_path, "dev").unwrap();
        assert!(sandbox.is_none());

        // Deleting again should return false
        let deleted = delete_sandbox(&conn, &repo_path, "dev").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_delete_sandbox_cascades_to_conversations() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([]);

        // Create sandbox and conversation
        let sandbox_id = create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();
        let conv_id = save_conversation(
            &conn,
            None,
            &repo_path,
            "dev",
            "claude-sonnet-4-5",
            "anthropic",
            &history,
        )
        .unwrap();

        // Verify conversation exists
        assert!(get_conversation(&conn, conv_id).unwrap().is_some());

        // Delete the sandbox
        delete_sandbox(&conn, &repo_path, "dev").unwrap();

        // Sandbox should be gone
        assert!(get_sandbox_by_id(&conn, sandbox_id).unwrap().is_none());

        // Conversation should also be gone (CASCADE)
        assert!(get_conversation(&conn, conv_id).unwrap().is_none());
    }

    // --- Conversation tests ---

    #[test]
    fn test_save_and_get_conversation() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([{"role": "user", "content": "hello"}]);

        // Create sandbox first
        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();

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

        // Create sandbox first
        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();

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

        // Create sandbox first
        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();

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

        // Create sandboxes first
        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();
        create_sandbox(&conn, &repo_path, "test", LOCAL_HOST).unwrap();

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

        // Create sandboxes first
        create_sandbox(&conn, &repo1, "dev", LOCAL_HOST).unwrap();
        create_sandbox(&conn, &repo2, "dev", LOCAL_HOST).unwrap();

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

        // Create sandboxes first
        create_sandbox(&conn, &repo_path, "dev", LOCAL_HOST).unwrap();
        create_sandbox(&conn, &repo_path, "test", LOCAL_HOST).unwrap();

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
