CREATE TABLE meta (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE relay_secrets (
    name TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_unix INTEGER NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0,
    user_role TEXT NOT NULL,
    totp_secret TEXT,
    totp_pending TEXT,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until_unix INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    name TEXT NOT NULL,
    created_unix INTEGER NOT NULL,
    last_seen_unix INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    username TEXT NOT NULL,
    expires_unix INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE access_tokens (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    username TEXT NOT NULL,
    expires_unix INTEGER NOT NULL
);

CREATE TABLE web_sessions (
    token_hash TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    csrf TEXT NOT NULL,
    expires_unix INTEGER NOT NULL
);

CREATE TABLE nodes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key_hex TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    ceiling_json TEXT NOT NULL,
    hostname TEXT NOT NULL DEFAULT '',
    os TEXT NOT NULL DEFAULT '',
    arch TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    enrolled_unix INTEGER NOT NULL,
    last_seen_unix INTEGER,
    owner TEXT NOT NULL DEFAULT ''
);

CREATE TABLE enrollment_tokens (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    owner TEXT NOT NULL,
    created_unix INTEGER NOT NULL,
    expires_unix INTEGER NOT NULL,
    max_uses INTEGER NOT NULL,
    uses_remaining INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE token_uses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    used_unix INTEGER NOT NULL
);

CREATE TABLE clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0,
    owner TEXT NOT NULL DEFAULT ''
);

CREATE TABLE client_grants (
    client_id TEXT NOT NULL,
    node_id TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    PRIMARY KEY (client_id, node_id)
);

CREATE TABLE shares (
    node_id TEXT NOT NULL,
    username TEXT NOT NULL,
    policy_json TEXT NOT NULL,
    PRIMARY KEY (node_id, username)
);

CREATE TABLE audit_policies (
    scope TEXT NOT NULL,
    id TEXT NOT NULL,
    toml TEXT NOT NULL,
    PRIMARY KEY (scope, id)
);

CREATE TABLE approvals (
    approval_id TEXT PRIMARY KEY,
    node_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    category TEXT NOT NULL,
    summary TEXT NOT NULL,
    expires_unix INTEGER NOT NULL
);

CREATE INDEX idx_devices_user ON devices (username);
CREATE INDEX idx_nodes_owner ON nodes (owner);
CREATE INDEX idx_refresh_device ON refresh_tokens (device_id);
CREATE INDEX idx_access_device ON access_tokens (device_id);
