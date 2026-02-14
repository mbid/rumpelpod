//! SQLite database for persisting pod metadata and conversation history.

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};
use indoc::indoc;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use crate::config::DockerHost;

/// Strongly-typed wrapper for pod database IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PodId(i64);

impl From<i64> for PodId {
    fn from(id: i64) -> Self {
        PodId(id)
    }
}

impl From<PodId> for i64 {
    fn from(id: PodId) -> Self {
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

/// Status of a pod in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PodStatus {
    /// Pod is being initialized (container creation, git setup, etc.)
    Initializing,
    /// Pod is fully initialized and ready
    Ready,
    /// Pod initialization failed
    Error,
    /// Pod container is being deleted in the background
    Deleting,
    /// Background deletion failed after all retries
    DeleteFailed,
}

impl PodStatus {
    fn as_str(&self) -> &'static str {
        match self {
            PodStatus::Initializing => "initializing",
            PodStatus::Ready => "ready",
            PodStatus::Error => "error",
            PodStatus::Deleting => "deleting",
            PodStatus::DeleteFailed => "delete_failed",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "initializing" => Some(PodStatus::Initializing),
            "ready" => Some(PodStatus::Ready),
            "error" => Some(PodStatus::Error),
            "deleting" => Some(PodStatus::Deleting),
            "delete_failed" => Some(PodStatus::DeleteFailed),
            _ => None,
        }
    }
}

/// Host specification for local pods stored in the database.
pub const LOCALHOST_DB_STR: &str = "localhost";

/// Normalize a host string from the database to the current canonical format.
/// Handles format changes from older versions (e.g. explicit default SSH port).
fn normalize_host(host: String) -> String {
    DockerHost::from_db_string(&host)
        .map(|h| h.to_db_string())
        .unwrap_or(host)
}

/// Information about a pod from the database.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some fields used only in tests or for future features
pub struct PodRecord {
    pub id: PodId,
    pub repo_path: String,
    pub name: String,
    /// The host where the pod runs: "localhost" or "ssh://user@host".
    pub host: String,
    pub status: PodStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Get the database path.
/// Uses $XDG_STATE_HOME/rumpelpod/db.sqlite
pub fn db_path() -> Result<PathBuf> {
    let state_base = std::env::var("XDG_STATE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .expect("Could not determine home directory")
                .join(".local/state")
        });

    Ok(state_base.join("rumpelpod").join("db.sqlite"))
}

const SCHEMA_SQL: &str = indoc! {"
    CREATE TABLE pods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_path TEXT NOT NULL,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'initializing',
        on_create_ran INTEGER NOT NULL DEFAULT 0,
        post_create_ran INTEGER NOT NULL DEFAULT 0,
        claude_config_copied INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(repo_path, name)
    );

    CREATE INDEX idx_pods_lookup
        ON pods(repo_path, name);

    CREATE TABLE conversations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pod_id INTEGER NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
        model TEXT NOT NULL,
        provider TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        history JSON NOT NULL
    );

    CREATE INDEX idx_conversations_lookup
        ON conversations(pod_id, updated_at DESC);

    CREATE TABLE forwarded_ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pod_id INTEGER NOT NULL REFERENCES pods(id) ON DELETE CASCADE,
        container_port INTEGER NOT NULL,
        local_port INTEGER NOT NULL,
        label TEXT NOT NULL DEFAULT ''
    );

    CREATE INDEX idx_forwarded_ports_pod
        ON forwarded_ports(pod_id);

    CREATE UNIQUE INDEX idx_forwarded_ports_local
        ON forwarded_ports(local_port);

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

// --- Pod functions ---

/// Create a new pod record with status "initializing".
///
/// Returns the ID of the new pod.
/// Returns an error if a pod with this repo_path and name already exists.
pub fn create_pod(conn: &Connection, repo_path: &Path, name: &str, host: &str) -> Result<PodId> {
    let now = Utc::now().to_rfc3339();
    let repo_path_str = repo_path.to_string_lossy();

    conn.execute(
        "INSERT INTO pods (repo_path, name, host, status, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?)",
        rusqlite::params![
            repo_path_str,
            name,
            host,
            PodStatus::Initializing.as_str(),
            now,
            now
        ],
    )
    .context("Failed to insert pod")?;

    Ok(PodId(conn.last_insert_rowid()))
}

/// Update the status of a pod.
pub fn update_pod_status(conn: &Connection, id: PodId, status: PodStatus) -> Result<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE pods SET status = ?, updated_at = ? WHERE id = ?",
        rusqlite::params![status.as_str(), now, i64::from(id)],
    )
    .context("Failed to update pod status")?;
    Ok(())
}

/// Get a pod by repo_path and name.
pub fn get_pod(conn: &Connection, repo_path: &Path, name: &str) -> Result<Option<PodRecord>> {
    let repo_path_str = repo_path.to_string_lossy();

    let mut stmt = conn
        .prepare(
            "SELECT id, repo_path, name, host, status, created_at, updated_at FROM pods
             WHERE repo_path = ? AND name = ?",
        )
        .context("Failed to prepare query")?;

    let mut rows = stmt
        .query_map(rusqlite::params![repo_path_str, name], |row| {
            let status_str: String = row.get(4)?;
            let status = PodStatus::from_str(&status_str).unwrap_or(PodStatus::Error);
            Ok(PodRecord {
                id: PodId(row.get(0)?),
                repo_path: row.get(1)?,
                name: row.get(2)?,
                host: normalize_host(row.get(3)?),
                status,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .context("Failed to query pod")?;

    match rows.next() {
        Some(row) => Ok(Some(row.context("Failed to read pod")?)),
        None => Ok(None),
    }
}

/// Get a pod by ID.
#[allow(dead_code)] // Used in tests
pub fn get_pod_by_id(conn: &Connection, id: PodId) -> Result<Option<PodRecord>> {
    let mut stmt = conn
        .prepare(
            "SELECT id, repo_path, name, host, status, created_at, updated_at FROM pods
             WHERE id = ?",
        )
        .context("Failed to prepare query")?;

    let mut rows = stmt
        .query_map(rusqlite::params![i64::from(id)], |row| {
            let status_str: String = row.get(4)?;
            let status = PodStatus::from_str(&status_str).unwrap_or(PodStatus::Error);
            Ok(PodRecord {
                id: PodId(row.get(0)?),
                repo_path: row.get(1)?,
                name: row.get(2)?,
                host: normalize_host(row.get(3)?),
                status,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .context("Failed to query pod")?;

    match rows.next() {
        Some(row) => Ok(Some(row.context("Failed to read pod")?)),
        None => Ok(None),
    }
}

/// List all pods for a given repo path.
pub fn list_pods(conn: &Connection, repo_path: &Path) -> Result<Vec<PodRecord>> {
    let repo_path_str = repo_path.to_string_lossy();

    let mut stmt = conn
        .prepare(
            "SELECT id, repo_path, name, host, status, created_at, updated_at FROM pods
             WHERE repo_path = ?
             ORDER BY name ASC",
        )
        .context("Failed to prepare query")?;

    let rows = stmt
        .query_map(rusqlite::params![repo_path_str], |row| {
            let status_str: String = row.get(4)?;
            let status = PodStatus::from_str(&status_str).unwrap_or(PodStatus::Error);
            Ok(PodRecord {
                id: PodId(row.get(0)?),
                repo_path: row.get(1)?,
                name: row.get(2)?,
                host: normalize_host(row.get(3)?),
                status,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })
        .context("Failed to query podes")?;

    let mut result = Vec::new();
    for row in rows {
        result.push(row.context("Failed to read pod row")?);
    }

    Ok(result)
}

/// Delete a pod and all its conversations.
pub fn delete_pod(conn: &Connection, repo_path: &Path, name: &str) -> Result<bool> {
    let repo_path_str = repo_path.to_string_lossy();
    let count = conn
        .execute(
            "DELETE FROM pods WHERE repo_path = ? AND name = ?",
            rusqlite::params![repo_path_str, name],
        )
        .context("Failed to delete pod")?;
    Ok(count > 0)
}

/// Check whether the lifecycle command has already run for this pod.
pub fn has_on_create_run(conn: &Connection, id: PodId) -> Result<bool> {
    let ran: bool = conn
        .query_row(
            "SELECT on_create_ran FROM pods WHERE id = ?",
            rusqlite::params![i64::from(id)],
            |row| row.get(0),
        )
        .context("Failed to query on_create_ran")?;
    Ok(ran)
}

/// Check whether the lifecycle command has already run for this pod.
pub fn has_post_create_run(conn: &Connection, id: PodId) -> Result<bool> {
    let ran: bool = conn
        .query_row(
            "SELECT post_create_ran FROM pods WHERE id = ?",
            rusqlite::params![i64::from(id)],
            |row| row.get(0),
        )
        .context("Failed to query post_create_ran")?;
    Ok(ran)
}

/// Mark the lifecycle command as having been executed for this pod.
pub fn mark_on_create_ran(conn: &Connection, id: PodId) -> Result<()> {
    conn.execute(
        "UPDATE pods SET on_create_ran = 1 WHERE id = ?",
        rusqlite::params![i64::from(id)],
    )
    .context("Failed to mark on_create_ran")?;
    Ok(())
}

/// Mark the lifecycle command as having been executed for this pod.
pub fn mark_post_create_ran(conn: &Connection, id: PodId) -> Result<()> {
    conn.execute(
        "UPDATE pods SET post_create_ran = 1 WHERE id = ?",
        rusqlite::params![i64::from(id)],
    )
    .context("Failed to mark post_create_ran")?;
    Ok(())
}

/// Check whether Claude Code config files have been copied into this pod.
pub fn has_claude_config_copied(conn: &Connection, id: PodId) -> Result<bool> {
    let copied: bool = conn
        .query_row(
            "SELECT claude_config_copied FROM pods WHERE id = ?",
            rusqlite::params![i64::from(id)],
            |row| row.get(0),
        )
        .context("Failed to query claude_config_copied")?;
    Ok(copied)
}

/// Mark Claude Code config files as having been copied into this pod.
pub fn mark_claude_config_copied(conn: &Connection, id: PodId) -> Result<()> {
    conn.execute(
        "UPDATE pods SET claude_config_copied = 1 WHERE id = ?",
        rusqlite::params![i64::from(id)],
    )
    .context("Failed to mark claude_config_copied")?;
    Ok(())
}

// --- Conversation functions ---

/// Save or update a conversation.
///
/// If `id` is provided, updates the existing conversation.
/// Otherwise, creates a new conversation and returns its ID.
///
/// Returns an error if the pod doesn't exist.
pub fn save_conversation(
    conn: &Connection,
    id: Option<i64>,
    repo_path: &Path,
    pod_name: &str,
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
        // Get pod - it must exist
        let pod = get_pod(conn, repo_path, pod_name)?
            .with_context(|| format!("Pod '{}' not found", pod_name))?;

        // Insert new conversation
        conn.execute(
            "INSERT INTO conversations (pod_id, model, provider, created_at, updated_at, history)
             VALUES (?, ?, ?, ?, ?, ?)",
            rusqlite::params![i64::from(pod.id), model, provider, now, now, history_str],
        )
        .context("Failed to insert conversation")?;
        Ok(conn.last_insert_rowid())
    }
}

/// List conversations for a given repo and pod, ordered by most recently updated.
pub fn list_conversations(
    conn: &Connection,
    repo_path: &Path,
    pod_name: &str,
) -> Result<Vec<ConversationSummary>> {
    // First get the pod ID
    let pod = get_pod(conn, repo_path, pod_name)?;
    let pod_id = match pod {
        Some(s) => s.id,
        None => return Ok(Vec::new()), // No pod means no conversations
    };

    let mut stmt = conn
        .prepare(
            "SELECT id, model, provider, updated_at FROM conversations
             WHERE pod_id = ?
             ORDER BY updated_at DESC",
        )
        .context("Failed to prepare query")?;

    let rows = stmt
        .query_map(rusqlite::params![i64::from(pod_id)], |row| {
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

/// Delete all conversations for a given repo and pod.
///
/// Returns the number of conversations deleted.
#[allow(dead_code)] // Used in tests
pub fn delete_conversations(conn: &Connection, repo_path: &Path, pod_name: &str) -> Result<usize> {
    // First get the pod ID
    let pod = get_pod(conn, repo_path, pod_name)?;
    let pod_id = match pod {
        Some(s) => s.id,
        None => return Ok(0), // No pod means no conversations to delete
    };

    let count = conn
        .execute(
            "DELETE FROM conversations WHERE pod_id = ?",
            rusqlite::params![i64::from(pod_id)],
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

pub struct ForwardedPort {
    pub container_port: u16,
    pub local_port: u16,
    pub label: String,
}

pub fn insert_forwarded_port(
    conn: &Connection,
    pod_id: PodId,
    container_port: u16,
    local_port: u16,
    label: &str,
) -> Result<()> {
    conn.execute(
        "INSERT INTO forwarded_ports (pod_id, container_port, local_port, label)
         VALUES (?, ?, ?, ?)",
        rusqlite::params![pod_id.0, container_port, local_port, label],
    )
    .context("inserting forwarded port")?;
    Ok(())
}

pub fn list_forwarded_ports(conn: &Connection, pod_id: PodId) -> Result<Vec<ForwardedPort>> {
    let mut stmt = conn
        .prepare(
            "SELECT container_port, local_port, label
             FROM forwarded_ports WHERE pod_id = ?
             ORDER BY container_port",
        )
        .context("preparing forwarded ports query")?;

    let ports = stmt
        .query_map(rusqlite::params![pod_id.0], |row| {
            Ok(ForwardedPort {
                container_port: row.get(0)?,
                local_port: row.get(1)?,
                label: row.get(2)?,
            })
        })
        .context("querying forwarded ports")?
        .collect::<Result<Vec<_>, _>>()
        .context("reading forwarded port rows")?;

    Ok(ports)
}

pub fn get_all_allocated_local_ports(conn: &Connection) -> Result<Vec<u16>> {
    let mut stmt = conn
        .prepare("SELECT local_port FROM forwarded_ports")
        .context("preparing allocated ports query")?;

    let ports = stmt
        .query_map([], |row| row.get(0))
        .context("querying allocated ports")?
        .collect::<Result<Vec<_>, _>>()
        .context("reading allocated port rows")?;

    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn test_db() -> (TempDir, Connection) {
        let temp_dir = TempDir::with_prefix("rumpelpod-db-test-").unwrap();
        let db_path = temp_dir.path().join("test.db");
        let conn = open_db(&db_path).unwrap();
        (temp_dir, conn)
    }

    // --- Pod tests ---

    #[test]
    fn test_create_and_get_pod() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Create a local pod
        let id = create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();
        assert!(i64::from(id) > 0);

        // Get it back
        let pod = get_pod(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(pod.id, id);
        assert_eq!(pod.name, "dev");
        assert_eq!(pod.host, LOCALHOST_DB_STR);
        assert_eq!(pod.status, PodStatus::Initializing);
    }

    #[test]
    fn test_create_pod_with_host() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Create a remote pod (DB stores the ssh:// URL)
        let id = create_pod(&conn, &repo_path, "remote", "ssh://user@host").unwrap();

        let pod = get_pod(&conn, &repo_path, "remote").unwrap().unwrap();
        assert_eq!(pod.id, id);
        assert_eq!(pod.host, "ssh://user@host");
    }

    #[test]
    fn test_host_normalized_on_read() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Simulate a record written by an older version with explicit default port
        create_pod(&conn, &repo_path, "old", "ssh://dev:22").unwrap();
        create_pod(&conn, &repo_path, "old-user", "ssh://user@host:22").unwrap();

        // Reading back should normalize away the default port
        let s1 = get_pod(&conn, &repo_path, "old").unwrap().unwrap();
        assert_eq!(s1.host, "ssh://dev");

        let s2 = get_pod(&conn, &repo_path, "old-user").unwrap().unwrap();
        assert_eq!(s2.host, "ssh://user@host");

        // Non-default port should be preserved
        create_pod(&conn, &repo_path, "custom-port", "ssh://dev:2222").unwrap();
        let s3 = get_pod(&conn, &repo_path, "custom-port").unwrap().unwrap();
        assert_eq!(s3.host, "ssh://dev:2222");

        // list_pods should also normalize
        let all = list_pods(&conn, &repo_path).unwrap();
        let old = all.iter().find(|s| s.name == "old").unwrap();
        assert_eq!(old.host, "ssh://dev");
    }

    #[test]
    fn test_create_pod_duplicate_fails() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Create first pod
        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();

        // Creating another with same name should fail
        let result = create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR);
        assert!(result.is_err());
    }

    #[test]
    fn test_update_pod_status() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        let id = create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();

        // Initial status is Initializing
        let pod = get_pod(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(pod.status, PodStatus::Initializing);

        // Update to Ready
        update_pod_status(&conn, id, PodStatus::Ready).unwrap();
        let pod = get_pod(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(pod.status, PodStatus::Ready);

        // Update to Error
        update_pod_status(&conn, id, PodStatus::Error).unwrap();
        let pod = get_pod(&conn, &repo_path, "dev").unwrap().unwrap();
        assert_eq!(pod.status, PodStatus::Error);
    }

    #[test]
    fn test_list_pods() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();
        create_pod(&conn, &repo_path, "test", "ssh://remote").unwrap();

        let pods = list_pods(&conn, &repo_path).unwrap();
        assert_eq!(pods.len(), 2);
        // Should be sorted by name
        assert_eq!(pods[0].name, "dev");
        assert_eq!(pods[1].name, "test");
        assert_eq!(pods[1].host, "ssh://remote");
    }

    #[test]
    fn test_list_pods_filters_by_repo() {
        let (_temp_dir, conn) = test_db();

        let repo1 = PathBuf::from("/home/user/project1");
        let repo2 = PathBuf::from("/home/user/project2");

        create_pod(&conn, &repo1, "dev", LOCALHOST_DB_STR).unwrap();
        create_pod(&conn, &repo2, "dev", LOCALHOST_DB_STR).unwrap();

        let repo1_pods = list_pods(&conn, &repo1).unwrap();
        assert_eq!(repo1_pods.len(), 1);
        assert_eq!(repo1_pods[0].repo_path, repo1.to_string_lossy());

        let repo2_pods = list_pods(&conn, &repo2).unwrap();
        assert_eq!(repo2_pods.len(), 1);
        assert_eq!(repo2_pods[0].repo_path, repo2.to_string_lossy());
    }

    #[test]
    fn test_delete_pod() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();

        // Delete the pod
        let deleted = delete_pod(&conn, &repo_path, "dev").unwrap();
        assert!(deleted);

        // Should no longer exist
        let pod = get_pod(&conn, &repo_path, "dev").unwrap();
        assert!(pod.is_none());

        // Deleting again should return false
        let deleted = delete_pod(&conn, &repo_path, "dev").unwrap();
        assert!(!deleted);
    }

    #[test]
    fn test_delete_pod_cascades_to_conversations() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([]);

        // Create pod and conversation
        let pod_id = create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();
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

        // Delete the pod
        delete_pod(&conn, &repo_path, "dev").unwrap();

        // Pod should be gone
        assert!(get_pod_by_id(&conn, pod_id).unwrap().is_none());

        // Conversation should also be gone (CASCADE)
        assert!(get_conversation(&conn, conv_id).unwrap().is_none());
    }

    // --- Conversation tests ---

    #[test]
    fn test_save_and_get_conversation() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([{"role": "user", "content": "hello"}]);

        // Create pod first
        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();

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

        // Create pod first
        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();

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

        // Create pod first
        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();

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
    fn test_list_conversations_filters_by_pod() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");
        let history = serde_json::json!([]);

        // Create pods first
        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();
        create_pod(&conn, &repo_path, "test", LOCALHOST_DB_STR).unwrap();

        // Save to different pods
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

        // List should only return matching pod
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

        // Create pods first
        create_pod(&conn, &repo1, "dev", LOCALHOST_DB_STR).unwrap();
        create_pod(&conn, &repo2, "dev", LOCALHOST_DB_STR).unwrap();

        // Save to different repos with same pod name
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

        // Create pods first
        create_pod(&conn, &repo_path, "dev", LOCALHOST_DB_STR).unwrap();
        create_pod(&conn, &repo_path, "test", LOCALHOST_DB_STR).unwrap();

        // Save conversations in different pods
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

        // Delete conversations for "dev" pod
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
    fn test_delete_conversations_nonexistent_pod() {
        let (_temp_dir, conn) = test_db();

        let repo_path = PathBuf::from("/home/user/project");

        // Deleting from a pod that doesn't exist should succeed with 0 deleted
        let deleted = delete_conversations(&conn, &repo_path, "nonexistent").unwrap();
        assert_eq!(deleted, 0);
    }

    #[test]
    fn test_db_versioning_recreation() {
        let temp_dir = TempDir::with_prefix("rumpelpod-db-test-versioning-").unwrap();
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
        let temp_dir = TempDir::with_prefix("rumpelpod-db-test-mismatch-").unwrap();
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
