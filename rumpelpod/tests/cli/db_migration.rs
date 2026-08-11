// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs;

use indoc::indoc;
use rusqlite::Connection;
use sha2::{Digest, Sha256};

use rumpelpod::CommandExt;

use crate::common::{pod_command, write_test_devcontainer, TestDaemon, TestHome, TestRepo};
use crate::executor::ExecutorResources;

const PRE_COMPOSE_SCHEMA_SQL: &str = indoc! {"
    CREATE TABLE pods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_path TEXT NOT NULL,
        name TEXT NOT NULL,
        host TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'initializing',
        on_create_ran INTEGER NOT NULL DEFAULT 0,
        post_create_ran INTEGER NOT NULL DEFAULT 0,
        claude_config_copied INTEGER NOT NULL DEFAULT 0,
        token TEXT NOT NULL,
        image TEXT NOT NULL,
        devcontainer_json TEXT NOT NULL,
        local_env TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        UNIQUE(repo_path, name)
    );

    CREATE INDEX idx_pods_lookup
        ON pods(repo_path, name);

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

const PRE_COMPOSE_SCHEMA_HASH: &str =
    "ec97b2b08dddd29a2db5e026fb8bdaf2f2458743a797d713dcf72ad98b40d80e";

#[test]
fn pre_compose_database_preserves_data_and_accepts_new_pods() {
    let repo = TestRepo::new();
    let home = TestHome::new();
    let executor = ExecutorResources::setup(&home);
    write_test_devcontainer(&repo, "", ",\n    \"forwardPorts\": [9123]");
    fs::write(repo.path().join(".rumpelpod.json"), &executor.json).unwrap();

    let db_dir = home.path().join("state/rumpelpod");
    fs::create_dir_all(&db_dir).expect("create legacy database directory");
    let db_path = db_dir.join("db.sqlite");
    let conn = Connection::open(&db_path).expect("create legacy database");
    conn.execute_batch(PRE_COMPOSE_SCHEMA_SQL)
        .expect("initialize legacy schema");
    let mut hasher = Sha256::new();
    hasher.update(PRE_COMPOSE_SCHEMA_SQL);
    let schema_hash = hex::encode(hasher.finalize());
    assert_eq!(schema_hash, PRE_COMPOSE_SCHEMA_HASH);
    conn.execute(
        "INSERT INTO db_meta (key, value) VALUES ('schema_version', ?)",
        [&schema_hash],
    )
    .expect("record legacy schema version");
    conn.execute(
        "INSERT INTO db_meta (key, value) VALUES ('migration_sentinel', 'preserved')",
        [],
    )
    .expect("record migration sentinel");
    conn.execute(
        "INSERT INTO pods
            (repo_path, name, host, status, token, image, devcontainer_json,
             local_env, created_at, updated_at)
         VALUES ('/legacy/repo', 'legacy-pod', '\"Localhost\"', 'error',
                 'legacy-token', 'legacy-image', '{}', '[]',
                 '2000-01-01T00:00:00Z', '2000-01-01T00:00:00Z')",
        [],
    )
    .expect("insert legacy pod");
    let legacy_pod_id = conn.last_insert_rowid();
    conn.execute(
        "INSERT INTO forwarded_ports (pod_id, container_port, local_port, label)
         VALUES (?, 8080, 60000, 'legacy')",
        [legacy_pod_id],
    )
    .expect("insert legacy forwarded port");
    drop(conn);

    let mut daemon = TestDaemon::start(&home);
    pod_command(&repo, &daemon)
        .args(["enter", "--create", "new-pod", "--", "true"])
        .success()
        .expect("create pod after database migration");

    let conn = Connection::open(&db_path).expect("open migrated database");
    let sentinel: String = conn
        .query_row(
            "SELECT value FROM db_meta WHERE key = 'migration_sentinel'",
            [],
            |row| row.get(0),
        )
        .expect("read migration sentinel");
    assert_eq!(sentinel, "preserved");

    let legacy_compose: (String, String) = conn
        .query_row(
            "SELECT agent_service, compose_config FROM pods WHERE name = 'legacy-pod'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read migrated legacy pod");
    assert_eq!(legacy_compose, (String::new(), String::new()));
    let legacy_port: (String, u16, u16) = conn
        .query_row(
            "SELECT service, container_port, local_port FROM forwarded_ports
             WHERE pod_id = ?",
            [legacy_pod_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .expect("read migrated legacy forwarded port");
    assert_eq!(legacy_port, (String::new(), 8080, 60000));

    let new_pod_compose: (String, String) = conn
        .query_row(
            "SELECT agent_service, compose_config FROM pods WHERE name = 'new-pod'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("read newly created pod");
    assert_eq!(new_pod_compose, (String::new(), String::new()));
    let new_port_service: String = conn
        .query_row(
            "SELECT forwarded_ports.service
             FROM forwarded_ports
             JOIN pods ON pods.id = forwarded_ports.pod_id
             WHERE pods.name = 'new-pod'",
            [],
            |row| row.get(0),
        )
        .expect("read newly created forwarded port");
    assert_eq!(new_port_service, "");
    drop(conn);

    daemon.kill();
    drop(daemon);
    let daemon = TestDaemon::start(&home);
    pod_command(&repo, &daemon)
        .args(["enter", "new-pod", "--", "true"])
        .success()
        .expect("reopen migrated database and reconnect to new pod");
}
