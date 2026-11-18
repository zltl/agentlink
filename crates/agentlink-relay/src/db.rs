//! SQLite (default) and PostgreSQL backends behind one API.
//!
//! Queries are written once with `?1` placeholders and adapted for each
//! driver. Schema changes live in `migrations/{sqlite,postgres}` and are
//! applied with sqlx's embedded migrator.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use agentlink_core::accounts::{
    self, Lockout, ACCESS_SKEW_SECS, ACCESS_TTL_SECS, REFRESH_TTL_SECS, WEB_TTL_SECS,
};
use agentlink_core::protocol::ApprovalInfo;
use agentlink_core::util::{self, unix_now};
use agentlink_core::{Error, NodePolicy, Result};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{AssertSqlSafe, PgPool, Row, SqlitePool};

use crate::models::{
    AccessSession, Caller, ClientRecord, Device, EnrolledNode, IssuedSession, IssuedToken,
    NodeMeta, Relation, TokenView, UserAccount, VisibleNode, WebSession,
};

const ADMIN_USER: &str = "admin";

pub struct OpenOptions<'a> {
    pub data_dir: &'a Path,
    pub database_url: Option<&'a str>,
    /// Postgres schema used by tests so they do not share `public`.
    pub schema: Option<&'a str>,
    /// Create `admin` with a random password when the user table is empty.
    pub bootstrap_admin: bool,
    /// When true, a missing legacy admin token is minted and dated. New
    /// deployments leave this false so no usable token is issued.
    pub mint_legacy_admin: bool,
}

pub struct Opened {
    pub db: Database,
    pub bootstrap_password: Option<String>,
    /// True only on the start that generated the admin token.
    pub admin_token_created: bool,
}

enum Backend {
    Sqlite(SqlitePool),
    Postgres(PgPool),
}

pub struct Database {
    backend: Backend,
    admin_token: String,
    admin_token_created_unix: i64,
    data_dir: PathBuf,
    schema: Option<String>,
}

#[derive(sqlx::FromRow)]
struct UserRow {
    username: String,
    password_hash: String,
    created_unix: i64,
    disabled: i64,
    user_role: String,
    totp_secret: Option<String>,
    totp_pending: Option<String>,
    failed_attempts: i64,
    locked_until_unix: i64,
}

#[derive(sqlx::FromRow)]
struct NodeRow {
    id: String,
    name: String,
    public_key_hex: String,
    policy_json: String,
    ceiling_json: String,
    hostname: String,
    os: String,
    arch: String,
    version: String,
    enrolled_unix: i64,
    last_seen_unix: Option<i64>,
    owner: String,
    has_display: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct DeviceRow {
    id: String,
    username: String,
    name: String,
    created_unix: i64,
    last_seen_unix: i64,
    revoked: i64,
}

#[derive(sqlx::FromRow)]
struct TokenRow {
    id: String,
    name: String,
    policy_json: String,
    owner: String,
    created_unix: i64,
    expires_unix: i64,
    max_uses: i64,
    uses_remaining: i64,
    revoked: i64,
}

#[derive(sqlx::FromRow)]
struct ClientRow {
    id: String,
    name: String,
    role: String,
    revoked: i64,
    owner: String,
}

#[derive(sqlx::FromRow)]
struct GrantRow {
    client_id: String,
    node_id: String,
    policy_json: String,
}

#[derive(sqlx::FromRow)]
struct ShareRow {
    node_id: String,
    username: String,
    policy_json: String,
}

#[derive(sqlx::FromRow)]
struct ApprovalRow {
    approval_id: String,
    node_id: String,
    client_id: String,
    category: String,
    summary: String,
    expires_unix: i64,
}

#[derive(sqlx::FromRow)]
struct AccessJoin {
    username: String,
    user_role: String,
    device_id: String,
    expires_unix: i64,
    revoked: i64,
    disabled: i64,
    refresh_hash: Option<String>,
}

#[derive(sqlx::FromRow)]
struct RefreshRow {
    token_hash: String,
    device_id: String,
    username: String,
    expires_unix: i64,
    revoked: i64,
    replaced_by: Option<String>,
    acknowledged: i64,
}

macro_rules! bind_query {
    ($query:expr,) => { $query };
    ($query:expr, $b:expr) => { $query.bind($b) };
    ($query:expr, $b:expr, $($rest:expr),+) => { bind_query!($query.bind($b), $($rest),+) };
}

macro_rules! exec {
    ($db:expr, $sql:expr $(, $b:expr)* $(,)?) => {{
        let sql: &str = $sql;
        match &$db.backend {
            Backend::Sqlite(pool) => {
                let adapted = adapt(sql, false);
                bind_query!(sqlx::query(AssertSqlSafe(adapted)), $($b),*)
                    .execute(pool)
                    .await
                    .map(|done| done.rows_affected())
                    .map_err(db_err)
            }
            Backend::Postgres(pool) => {
                let adapted = adapt(sql, true);
                bind_query!(sqlx::query(AssertSqlSafe(adapted)), $($b),*)
                    .execute(pool)
                    .await
                    .map(|done| done.rows_affected())
                    .map_err(db_err)
            }
        }
    }};
}

macro_rules! fetch_all {
    ($db:expr, $sql:expr $(, $b:expr)* $(,)?) => {{
        let sql: &str = $sql;
        match &$db.backend {
            Backend::Sqlite(pool) => {
                let adapted = adapt(sql, false);
                bind_query!(sqlx::query_as(AssertSqlSafe(adapted)), $($b),*)
                    .fetch_all(pool)
                    .await
                    .map_err(db_err)
            }
            Backend::Postgres(pool) => {
                let adapted = adapt(sql, true);
                bind_query!(sqlx::query_as(AssertSqlSafe(adapted)), $($b),*)
                    .fetch_all(pool)
                    .await
                    .map_err(db_err)
            }
        }
    }};
}

impl Database {
    pub async fn open(opts: OpenOptions<'_>) -> Result<Opened> {
        util::ensure_dir(opts.data_dir)?;
        let schema = opts.schema.map(|s| s.to_string());
        if let Some(schema) = &schema {
            validate_schema(schema)?;
        }
        let backend = if let Some(url) = opts.database_url.filter(|url| !url.trim().is_empty()) {
            if !url.starts_with("postgres://") && !url.starts_with("postgresql://") {
                return Err(Error::Message(
                    "AGENTLINK_DATABASE_URL must be a postgres:// URL".into(),
                ));
            }
            let schema_for_conn = schema.clone();
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .acquire_timeout(Duration::from_secs(10))
                .after_connect(move |conn, _| {
                    let schema_for_conn = schema_for_conn.clone();
                    Box::pin(async move {
                        if let Some(schema) = schema_for_conn {
                            sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA IF NOT EXISTS {schema}")))
                                .execute(&mut *conn)
                                .await?;
                            sqlx::query(AssertSqlSafe(format!("SET search_path TO {schema}")))
                                .execute(&mut *conn)
                                .await?;
                        }
                        Ok(())
                    })
                })
                .connect(url)
                .await
                .map_err(db_err)?;
            sqlx::migrate!("migrations/postgres")
                .run(&pool)
                .await
                .map_err(|err| Error::Message(format!("database migration: {err}")))?;
            Backend::Postgres(pool)
        } else {
            let path = opts.data_dir.join("relay.db");
            let options = SqliteConnectOptions::new()
                .filename(&path)
                .create_if_missing(true)
                .journal_mode(SqliteJournalMode::Wal)
                .synchronous(SqliteSynchronous::Normal)
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5));
            let pool = SqlitePoolOptions::new()
                .max_connections(8)
                .connect_with(options)
                .await
                .map_err(db_err)?;
            sqlx::migrate!("migrations/sqlite")
                .run(&pool)
                .await
                .map_err(|err| Error::Message(format!("database migration: {err}")))?;
            // SQLite creates relay.db / -wal / -shm with a default umask
            // (often 0644). The data dir is already 0700; tighten the files
            // after open so a crafted sibling WAL is not world-readable.
            protect_sqlite_files(opts.data_dir);
            Backend::Sqlite(pool)
        };
        let mut db = Database {
            backend,
            admin_token: String::new(),
            admin_token_created_unix: 0,
            data_dir: opts.data_dir.to_path_buf(),
            schema,
        };
        let (bootstrap_password, admin_token_created) =
            db.finish_open(opts.bootstrap_admin, opts.mint_legacy_admin).await?;
        Ok(Opened {
            db,
            bootstrap_password,
            admin_token_created,
        })
    }

    pub fn admin_token(&self) -> &str {
        &self.admin_token
    }

    /// Unix time recorded when `admin.token` was first stored.
    ///
    /// An existing install records this on the first start after the field
    /// exists, so `AGENTLINK_LEGACY_ADMIN_TTL_SECS` is measured from that start.
    pub fn admin_token_created_unix(&self) -> i64 {
        self.admin_token_created_unix
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn is_postgres(&self) -> bool {
        matches!(self.backend, Backend::Postgres(_))
    }

    pub async fn drop_test_schema(&self) -> Result<()> {
        let Some(schema) = &self.schema else {
            return Ok(());
        };
        validate_schema(schema)?;
        if let Backend::Postgres(pool) = &self.backend {
            sqlx::query(AssertSqlSafe(format!("DROP SCHEMA IF EXISTS {schema} CASCADE")))
                .execute(pool)
                .await
                .map_err(db_err)?;
        }
        Ok(())
    }

    async fn finish_open(
        &mut self,
        bootstrap_admin: bool,
        mint_legacy_admin: bool,
    ) -> Result<(Option<String>, bool)> {
        let ready = self.meta("schema_ready").await?.as_deref() == Some("1");
        if !ready {
            let store_path = self.data_dir.join("store.json");
            if store_path.exists() {
                self.import_store(&store_path).await?;
                rotate_backup(&store_path)?;
            }
        } else if self.data_dir.join("store.json").exists() {
            rotate_backup(&self.data_dir.join("store.json"))?;
        }
        let had_token = self.secret("admin_token").await?.is_some();
        let admin_token_created = !had_token && mint_legacy_admin;
        if admin_token_created {
            let token = util::random_token();
            self.set_secret("admin_token", &token).await?;
            self.set_secret("admin_token_created_unix", &util::unix_now().to_string())
                .await?;
        }
        self.admin_token = self.secret("admin_token").await?.unwrap_or_default();
        // Existing tokens with no recorded creation time must not be backdated
        // to "now" — that would restart their TTL. Leave the stamp missing
        // (created_unix = 0) so the gate treats them as unusable.
        self.admin_token_created_unix = self
            .secret("admin_token_created_unix")
            .await?
            .and_then(|text| text.parse().ok())
            .unwrap_or(0);
        if !self.admin_token.is_empty() {
            util::write_secret(
                &self.data_dir.join("admin.token"),
                self.admin_token.as_bytes(),
            )?;
        }
        let mut bootstrap_password = None;
        if bootstrap_admin && self.user_row(ADMIN_USER).await?.is_none() {
            let password = util::random_token();
            self.insert_user(ADMIN_USER, &password, "admin").await?;
            util::write_secret(
                &self.data_dir.join("bootstrap.password"),
                password.as_bytes(),
            )?;
            bootstrap_password = Some(password);
        }
        if !ready {
            self.set_meta("schema_ready", "1").await?;
        }
        Ok((bootstrap_password, admin_token_created))
    }

    pub async fn create_user(
        &self,
        username: &str,
        password: &str,
        role: &str,
    ) -> Result<UserAccount> {
        let username = username.trim().to_ascii_lowercase();
        if !accounts::valid_username(&username) {
            return Err(Error::Message(
                "username must be 1-32 chars, start with a letter, and use a-z, 0-9, _ or -".into(),
            ));
        }
        if !accounts::valid_role(role) {
            return Err(Error::Message("role must be admin or user".into()));
        }
        if password.chars().count() < 8 {
            return Err(Error::Message(
                "password must be at least 8 characters".into(),
            ));
        }
        if self.user_row(&username).await?.is_some() {
            return Err(Error::Message(format!("user '{username}' already exists")));
        }
        self.insert_user(&username, password, role).await?;
        self.account(&username)
            .await?
            .ok_or_else(|| Error::Message("user disappeared".into()))
    }

    pub async fn list_users(&self) -> Result<Vec<UserAccount>> {
        let rows: Vec<UserRow> = fetch_all!(
            self,
            "SELECT username, password_hash, created_unix, disabled, user_role, totp_secret, totp_pending, failed_attempts, locked_until_unix FROM users ORDER BY username",
        )?;
        Ok(rows.into_iter().map(account_from).collect())
    }

    pub async fn account(&self, username: &str) -> Result<Option<UserAccount>> {
        Ok(self.user_row(username).await?.map(account_from))
    }

    pub async fn set_password(&self, username: &str, password: &str) -> Result<()> {
        let username = username.trim().to_ascii_lowercase();
        if self.user_row(&username).await?.is_none() {
            return Err(Error::NotFound(format!("user '{username}'")));
        }
        if password.chars().count() < 8 {
            return Err(Error::Message(
                "password must be at least 8 characters".into(),
            ));
        }
        let hash = accounts::hash_password(password)?;
        exec!(
            self,
            "UPDATE users SET password_hash = ?1, failed_attempts = 0, locked_until_unix = 0 WHERE username = ?2",
            &hash,
            &username,
        )?;
        if username == ADMIN_USER {
            let path = self.data_dir.join("bootstrap.password");
            if path.exists() {
                let _ = std::fs::remove_file(path);
            }
        }
        self.delete_user_sessions(&username).await?;
        Ok(())
    }

    pub async fn set_disabled(&self, username: &str, disabled: bool) -> Result<()> {
        let username = canonical_user(username).await?;
        if self.user_row(&username).await?.is_none() {
            return Err(Error::NotFound(format!("user '{username}'")));
        }
        exec!(
            self,
            "UPDATE users SET disabled = ?1 WHERE username = ?2",
            i64::from(disabled),
            &username,
        )?;
        if disabled {
            self.delete_user_sessions(&username).await?;
        }
        Ok(())
    }

    pub async fn set_role(&self, username: &str, role: &str) -> Result<()> {
        let username = canonical_user(username).await?;
        if !accounts::valid_role(role) {
            return Err(Error::Message("role must be admin or user".into()));
        }
        if self.user_row(&username).await?.is_none() {
            return Err(Error::NotFound(format!("user '{username}'")));
        }
        exec!(
            self,
            "UPDATE users SET user_role = ?1 WHERE username = ?2",
            role,
            &username,
        )?;
        Ok(())
    }

    pub async fn remove_user(&self, username: &str) -> Result<()> {
        let username = canonical_user(username).await?;
        if self.user_row(&username).await?.is_none() {
            return Err(Error::NotFound(format!("user '{username}'")));
        }
        self.delete_user_sessions(&username).await?;
        // Drop machines this account owns before the username can be reused.
        // Ownership is the username string, so leaving the rows would hand the
        // next account with the same name full access.
        exec!(
            self,
            "DELETE FROM client_grants WHERE node_id IN (SELECT id FROM nodes WHERE owner = ?1)",
            &username,
        )?;
        exec!(
            self,
            "DELETE FROM shares WHERE node_id IN (SELECT id FROM nodes WHERE owner = ?1)",
            &username,
        )?;
        exec!(
            self,
            "DELETE FROM approvals WHERE node_id IN (SELECT id FROM nodes WHERE owner = ?1)",
            &username,
        )?;
        exec!(
            self,
            "DELETE FROM token_uses WHERE node_id IN (SELECT id FROM nodes WHERE owner = ?1)",
            &username,
        )?;
        exec!(self, "DELETE FROM nodes WHERE owner = ?1", &username)?;
        exec!(self, "DELETE FROM devices WHERE username = ?1", &username)?;
        exec!(self, "DELETE FROM shares WHERE username = ?1", &username)?;
        exec!(
            self,
            "DELETE FROM client_grants WHERE client_id IN (SELECT id FROM clients WHERE owner = ?1)",
            &username,
        )?;
        exec!(self, "DELETE FROM clients WHERE owner = ?1", &username)?;
        exec!(
            self,
            "DELETE FROM enrollment_tokens WHERE owner = ?1",
            &username,
        )?;
        exec!(
            self,
            "DELETE FROM audit_policies WHERE scope = 'user' AND id = ?1",
            &username,
        )?;
        exec!(self, "DELETE FROM users WHERE username = ?1", &username)?;
        Ok(())
    }

    /// Password and TOTP check. A successful result does not clear lockout;
    /// call [`note_success`] after the device signature is verified.
    pub async fn check_login(
        &self,
        username: &str,
        password: &str,
        totp: Option<&str>,
    ) -> Result<UserAccount> {
        let username = username.trim().to_ascii_lowercase();
        let row = self.user_row(&username).await?;
        let encoded = row
            .as_ref()
            .map(|row| row.password_hash.as_str())
            .unwrap_or("");
        let password_ok = accounts::verify_password(password, encoded);
        let Some(row) = row else {
            let _ = password_ok;
            return Err(Error::Auth("invalid username or password".into()));
        };
        let lock = Lockout {
            failed: row.failed_attempts.max(0) as u32,
            locked_until: row.locked_until_unix,
        };
        if lock.is_locked(unix_now()) {
            return Err(Error::Auth("account is temporarily locked".into()));
        }
        if !password_ok {
            self.note_failure(&row.username).await?;
            return Err(Error::Auth("invalid username or password".into()));
        }
        if row.disabled != 0 {
            return Err(Error::Auth("account is disabled".into()));
        }
        if row.totp_secret.as_deref().is_some() {
            match totp.map(str::trim).filter(|code| !code.is_empty()) {
                None => return Err(Error::Auth("totp code required".into())),
                Some(code)
                    if !accounts::totp_verify(
                        row.totp_secret.as_deref().unwrap_or(""),
                        code,
                        unix_now(),
                    ) =>
                {
                    self.note_failure(&row.username).await?;
                    return Err(Error::Auth("invalid totp code".into()));
                }
                Some(_) => {}
            }
        }
        Ok(account_from(row))
    }

    pub async fn note_success(&self, username: &str) -> Result<()> {
        exec!(
            self,
            "UPDATE users SET failed_attempts = 0, locked_until_unix = 0 WHERE username = ?1",
            username,
        )?;
        Ok(())
    }

    pub async fn note_failure(&self, username: &str) -> Result<Lockout> {
        let Some(row) = self.user_row(username).await? else {
            return Ok(Lockout::fresh());
        };
        let next = Lockout {
            failed: row.failed_attempts.max(0) as u32,
            locked_until: row.locked_until_unix,
        }
        .on_failure(unix_now());
        exec!(
            self,
            "UPDATE users SET failed_attempts = ?1, locked_until_unix = ?2 WHERE username = ?3",
            i64::from(next.failed),
            next.locked_until,
            username,
        )?;
        Ok(next)
    }

    pub async fn begin_totp(&self, username: &str) -> Result<(String, String)> {
        if self.user_row(username).await?.is_none() {
            return Err(Error::NotFound(format!("user '{username}'")));
        }
        let secret = accounts::totp_secret();
        exec!(
            self,
            "UPDATE users SET totp_pending = ?1 WHERE username = ?2",
            &secret,
            username,
        )?;
        let url = accounts::otpauth_url(&secret, username, "agentlink");
        Ok((secret, url))
    }

    pub async fn confirm_totp(&self, username: &str, code: &str) -> Result<()> {
        let Some(row) = self.user_row(username).await? else {
            return Err(Error::NotFound(format!("user '{username}'")));
        };
        let Some(pending) = row.totp_pending.filter(|s| !s.is_empty()) else {
            return Err(Error::Message(
                "totp enrollment has not been started".into(),
            ));
        };
        if !accounts::totp_verify(&pending, code, unix_now()) {
            return Err(Error::Auth("invalid totp code".into()));
        }
        exec!(
            self,
            "UPDATE users SET totp_secret = ?1, totp_pending = NULL WHERE username = ?2",
            &pending,
            username,
        )?;
        Ok(())
    }

    pub async fn disable_totp(&self, username: &str) -> Result<()> {
        if self.user_row(username).await?.is_none() {
            return Err(Error::NotFound(format!("user '{username}'")));
        }
        exec!(
            self,
            "UPDATE users SET totp_secret = NULL, totp_pending = NULL WHERE username = ?1",
            username,
        )?;
        Ok(())
    }

    pub async fn issue_session(
        &self,
        username: &str,
        device_public: &str,
        device_name: &str,
    ) -> Result<IssuedSession> {
        let account = self
            .account(username)
            .await?
            .ok_or_else(|| Error::Auth("account is disabled".into()))?;
        if account.disabled {
            return Err(Error::Auth("account is disabled".into()));
        }
        let device_id = normalize_key(device_public)?;
        let now = unix_now();
        let name = if device_name.trim().is_empty() {
            "device".to_string()
        } else {
            device_name.trim().chars().take(64).collect()
        };
        exec!(
            self,
            "INSERT INTO devices (id, username, name, created_unix, last_seen_unix, revoked) VALUES (?1, ?2, ?3, ?4, ?4, 0) ON CONFLICT (id) DO UPDATE SET username = ?2, name = ?3, last_seen_unix = ?4, revoked = 0",
            &device_id,
            username,
            &name,
            now,
        )?;
        let access = format!("atk.{}", util::random_token());
        let refresh = format!("rtk.{}", util::random_token());
        let access_expires = now + ACCESS_TTL_SECS;
        // Inactivity window, not a hard cap from the original login. Refresh slides it.
        let refresh_expires = now + REFRESH_TTL_SECS;
        self.insert_session_tokens(
            username,
            &device_id,
            &access,
            access_expires,
            &refresh,
            refresh_expires,
        )
        .await?;
        Ok(IssuedSession {
            user: account.username,
            role: account.role,
            device_id,
            access_token: access,
            access_expires_unix: access_expires,
            refresh_token: refresh,
            refresh_expires_unix: refresh_expires,
        })
    }

    pub async fn access_session(&self, token: &str) -> Result<Option<AccessSession>> {
        self.session_by_hash(&accounts::token_hash(token)).await
    }

    pub async fn session_by_hash(&self, token_hash: &str) -> Result<Option<AccessSession>> {
        let now = unix_now();
        let rows: Vec<AccessJoin> = fetch_all!(
            self,
            "SELECT a.username, u.user_role, a.device_id, a.expires_unix, d.revoked, u.disabled, a.refresh_hash FROM access_tokens a JOIN devices d ON d.id = a.device_id JOIN users u ON u.username = a.username WHERE a.token_hash = ?1",
            token_hash,
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        if row.expires_unix.saturating_add(ACCESS_SKEW_SECS) <= now
            || row.revoked != 0
            || row.disabled != 0
        {
            return Ok(None);
        }
        if let Some(refresh_hash) = row.refresh_hash.as_deref().filter(|hash| !hash.is_empty()) {
            // The client proved it stored this rotation by using the access token.
            // A later presentation of the previous refresh token is then a replay.
            let _ = exec!(
                self,
                "UPDATE refresh_tokens SET acknowledged = 1 WHERE token_hash = ?1 AND acknowledged = 0",
                refresh_hash,
            );
        }
        Ok(Some(AccessSession {
            user: row.username,
            role: row.user_role,
            device_id: row.device_id,
            token_hash: token_hash.to_string(),
            expires_unix: row.expires_unix,
        }))
    }

    /// Check whether an already-authenticated operator socket may stay open.
    ///
    /// Returns `true` when the socket's initial access token is still fresh, or
    /// when that row has not been deleted/revoked and the same active device
    /// holds a freshly rotated access token. Logout, device revocation, user
    /// disable, and password changes delete or mark those rows and still drop
    /// the socket immediately; a client that never refreshed also drops once
    /// its initial token passes `expires_unix + ACCESS_SKEW_SECS`.
    pub async fn active_socket_session_valid(&self, token_hash: &str) -> Result<bool> {
        if self.session_by_hash(token_hash).await?.is_some() {
            return Ok(true);
        }
        let now = unix_now();
        let rows: Vec<AccessJoin> = fetch_all!(
            self,
            "SELECT a.username, u.user_role, a.device_id, a.expires_unix, d.revoked, u.disabled, a.refresh_hash FROM access_tokens a JOIN devices d ON d.id = a.device_id JOIN users u ON u.username = a.username WHERE a.token_hash = ?1",
            token_hash,
        )?;
        let Some(initial) = rows.into_iter().next() else {
            return Ok(false);
        };
        if initial.revoked != 0 || initial.disabled != 0 {
            return Ok(false);
        }
        let fresh_cutoff = now.saturating_sub(ACCESS_SKEW_SECS);
        let live: Vec<AccessJoin> = fetch_all!(
            self,
            "SELECT a.username, u.user_role, a.device_id, a.expires_unix, d.revoked, u.disabled, a.refresh_hash FROM access_tokens a JOIN devices d ON d.id = a.device_id JOIN users u ON u.username = a.username WHERE a.username = ?1 AND a.device_id = ?2 AND a.expires_unix > ?3 LIMIT 1",
            &initial.username,
            &initial.device_id,
            fresh_cutoff,
        )?;
        if let Some(current) = live.into_iter().next() {
            if let Some(refresh_hash) = current.refresh_hash.as_deref().filter(|h| !h.is_empty()) {
                let _ = exec!(
                    self,
                    "UPDATE refresh_tokens SET acknowledged = 1 WHERE token_hash = ?1 AND acknowledged = 0",
                    refresh_hash,
                );
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Rotate a refresh token.
    ///
    /// The previous token stays redeemable until the replacement access token
    /// is used. A phone that loses the response, or is killed before it
    /// commits the new token, can present the same refresh token again and
    /// get a new pair. Once the replacement has been used, the old token is
    /// rejected. The access token already on an open socket is left in place
    /// until it expires on its own.
    pub async fn rotate_refresh(
        &self,
        refresh_token: &str,
        device_public: &str,
    ) -> Result<IssuedSession> {
        let device_id = normalize_key(device_public)?;
        let hash = accounts::token_hash(refresh_token);
        let now = unix_now();
        let Some(row) = self.refresh_row(&hash).await? else {
            return Err(refresh_rejected());
        };
        if row.device_id != device_id {
            return Err(refresh_rejected());
        }
        if let Some(successor) = filled(row.replaced_by.as_deref()) {
            return self
                .replace_unused_successor(&row, successor, &device_id, now)
                .await;
        }
        if row.revoked != 0 || row.expires_unix <= now {
            return Err(refresh_rejected());
        }
        self.rotate_live_refresh(&row, &device_id, now).await
    }

    async fn rotate_live_refresh(
        &self,
        row: &RefreshRow,
        device_id: &str,
        now: i64,
    ) -> Result<IssuedSession> {
        let account = self.active_device_account(&row.username, device_id).await?;
        let access = format!("atk.{}", util::random_token());
        let refresh = format!("rtk.{}", util::random_token());
        let refresh_hash = accounts::token_hash(&refresh);
        let claimed = exec!(
            self,
            "UPDATE refresh_tokens SET revoked = 1, replaced_by = ?1 WHERE token_hash = ?2 AND device_id = ?3 AND revoked = 0 AND replaced_by IS NULL AND expires_unix > ?4",
            &refresh_hash,
            &row.token_hash,
            device_id,
            now,
        )?;
        if claimed != 1 {
            if let Some(again) = self.refresh_row(&row.token_hash).await? {
                if again.device_id == device_id {
                    if let Some(successor) = filled(again.replaced_by.as_deref()) {
                        return self
                            .replace_unused_successor(&again, successor, device_id, now)
                            .await;
                    }
                }
            }
            return Err(refresh_rejected());
        }
        let access_expires = now + ACCESS_TTL_SECS;
        let refresh_expires = now + REFRESH_TTL_SECS;
        if let Err(err) = self
            .insert_session_tokens(
                &account.username,
                device_id,
                &access,
                access_expires,
                &refresh,
                refresh_expires,
            )
            .await
        {
            let _ = exec!(
                self,
                "UPDATE refresh_tokens SET revoked = 0, replaced_by = NULL WHERE token_hash = ?1 AND replaced_by = ?2 AND acknowledged = 0",
                &row.token_hash,
                &refresh_hash,
            );
            return Err(err);
        }
        self.touch_device(device_id).await?;
        Ok(IssuedSession {
            user: account.username,
            role: account.role,
            device_id: device_id.to_string(),
            access_token: access,
            access_expires_unix: access_expires,
            refresh_token: refresh,
            refresh_expires_unix: refresh_expires,
        })
    }

    /// The client presented a refresh token that already minted a successor.
    /// If that successor was never used, the response was lost: revoke it and
    /// issue another pair. If it was used, this is a replay.
    async fn replace_unused_successor(
        &self,
        parent: &RefreshRow,
        successor_hash: &str,
        device_id: &str,
        now: i64,
    ) -> Result<IssuedSession> {
        let Some(successor) = self.refresh_row(successor_hash).await? else {
            return Err(refresh_rejected());
        };
        if successor.device_id != device_id
            || successor.acknowledged != 0
            || successor.revoked != 0
            || filled(successor.replaced_by.as_deref()).is_some()
            || successor.expires_unix <= now
        {
            return Err(refresh_rejected());
        }
        let account = self
            .active_device_account(&parent.username, device_id)
            .await?;
        let claimed = exec!(
            self,
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?1 AND revoked = 0 AND acknowledged = 0 AND replaced_by IS NULL AND expires_unix > ?2",
            successor_hash,
            now,
        )?;
        if claimed != 1 {
            return Err(refresh_rejected());
        }
        let access = format!("atk.{}", util::random_token());
        let refresh = format!("rtk.{}", util::random_token());
        let refresh_hash = accounts::token_hash(&refresh);
        let access_expires = now + ACCESS_TTL_SECS;
        let refresh_expires = now + REFRESH_TTL_SECS;
        if let Err(err) = self
            .insert_session_tokens(
                &account.username,
                device_id,
                &access,
                access_expires,
                &refresh,
                refresh_expires,
            )
            .await
        {
            let _ = exec!(
                self,
                "UPDATE refresh_tokens SET revoked = 0 WHERE token_hash = ?1 AND acknowledged = 0 AND replaced_by IS NULL",
                successor_hash,
            );
            return Err(err);
        }
        let pointed = exec!(
            self,
            "UPDATE refresh_tokens SET replaced_by = ?1 WHERE token_hash = ?2 AND replaced_by = ?3",
            &refresh_hash,
            &parent.token_hash,
            successor_hash,
        )?;
        if pointed != 1 {
            let _ = self.delete_token_pair(&access, &refresh).await;
            let _ = exec!(
                self,
                "UPDATE refresh_tokens SET revoked = 0 WHERE token_hash = ?1 AND acknowledged = 0 AND replaced_by IS NULL",
                successor_hash,
            );
            return Err(refresh_rejected());
        }
        // The lost LoginOk's access token must not stay usable.
        exec!(
            self,
            "DELETE FROM access_tokens WHERE refresh_hash = ?1",
            successor_hash,
        )?;
        self.touch_device(device_id).await?;
        Ok(IssuedSession {
            user: account.username,
            role: account.role,
            device_id: device_id.to_string(),
            access_token: access,
            access_expires_unix: access_expires,
            refresh_token: refresh,
            refresh_expires_unix: refresh_expires,
        })
    }

    async fn active_device_account(
        &self,
        username: &str,
        device_id: &str,
    ) -> Result<crate::models::UserAccount> {
        let device = self.device(device_id).await?;
        if device.as_ref().map(|item| item.revoked).unwrap_or(true)
            || device.as_ref().map(|item| item.user.as_str()) != Some(username)
        {
            return Err(Error::Auth("device is revoked".into()));
        }
        let account = self
            .account(username)
            .await?
            .ok_or_else(|| Error::Auth("account is disabled".into()))?;
        if account.disabled {
            return Err(Error::Auth("account is disabled".into()));
        }
        Ok(account)
    }

    async fn insert_session_tokens(
        &self,
        username: &str,
        device_id: &str,
        access: &str,
        access_expires: i64,
        refresh: &str,
        refresh_expires: i64,
    ) -> Result<()> {
        let refresh_hash = accounts::token_hash(refresh);
        exec!(
            self,
            "INSERT INTO access_tokens (token_hash, device_id, username, expires_unix, refresh_hash) VALUES (?1, ?2, ?3, ?4, ?5)",
            &accounts::token_hash(access),
            device_id,
            username,
            access_expires,
            &refresh_hash,
        )?;
        if let Err(err) = exec!(
            self,
            "INSERT INTO refresh_tokens (token_hash, device_id, username, expires_unix, revoked, acknowledged) VALUES (?1, ?2, ?3, ?4, 0, 0)",
            &refresh_hash,
            device_id,
            username,
            refresh_expires,
        ) {
            let _ = exec!(
                self,
                "DELETE FROM access_tokens WHERE token_hash = ?1",
                &accounts::token_hash(access),
            );
            return Err(err);
        }
        Ok(())
    }

    async fn delete_token_pair(&self, access: &str, refresh: &str) -> Result<()> {
        exec!(
            self,
            "DELETE FROM access_tokens WHERE token_hash = ?1",
            &accounts::token_hash(access),
        )?;
        exec!(
            self,
            "DELETE FROM refresh_tokens WHERE token_hash = ?1",
            &accounts::token_hash(refresh),
        )?;
        Ok(())
    }

    async fn refresh_row(&self, token_hash: &str) -> Result<Option<RefreshRow>> {
        let rows: Vec<RefreshRow> = fetch_all!(
            self,
            "SELECT token_hash, device_id, username, expires_unix, revoked, replaced_by, acknowledged FROM refresh_tokens WHERE token_hash = ?1",
            token_hash,
        )?;
        Ok(rows.into_iter().next())
    }

    pub async fn end_session(&self, access_hash: &str, refresh_token: Option<&str>) -> Result<()> {
        exec!(
            self,
            "DELETE FROM access_tokens WHERE token_hash = ?1",
            access_hash,
        )?;
        if let Some(refresh_token) = refresh_token {
            self.revoke_refresh(refresh_token).await?;
        }
        Ok(())
    }

    pub async fn revoke_refresh(&self, refresh_token: &str) -> Result<()> {
        let hash = accounts::token_hash(refresh_token);
        if let Some(row) = self.refresh_row(&hash).await? {
            // Logout of a token whose replacement never reached the phone
            // must not leave that replacement alive.
            if let Some(successor) = filled(row.replaced_by.as_deref()) {
                exec!(
                    self,
                    "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?1 AND acknowledged = 0",
                    successor,
                )?;
                exec!(
                    self,
                    "DELETE FROM access_tokens WHERE refresh_hash = ?1",
                    successor,
                )?;
            }
        }
        exec!(
            self,
            "UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ?1",
            &hash,
        )?;
        Ok(())
    }

    /// Move a refresh token's deadline. Tests use this to simulate idle time.
    #[cfg(test)]
    pub async fn testing_set_refresh_expiry(
        &self,
        refresh_token: &str,
        expires_unix: i64,
    ) -> Result<()> {
        let affected = exec!(
            self,
            "UPDATE refresh_tokens SET expires_unix = ?1 WHERE token_hash = ?2",
            expires_unix,
            &accounts::token_hash(refresh_token),
        )?;
        if affected != 1 {
            return Err(Error::NotFound("refresh token".into()));
        }
        Ok(())
    }

    /// Move an access token's deadline. Tests use this to simulate clock skew.
    #[cfg(test)]
    pub async fn testing_set_access_expiry(
        &self,
        access_token: &str,
        expires_unix: i64,
    ) -> Result<()> {
        let affected = exec!(
            self,
            "UPDATE access_tokens SET expires_unix = ?1 WHERE token_hash = ?2",
            expires_unix,
            &accounts::token_hash(access_token),
        )?;
        if affected != 1 {
            return Err(Error::NotFound("access token".into()));
        }
        Ok(())
    }

    pub async fn device(&self, id: &str) -> Result<Option<Device>> {
        let rows: Vec<DeviceRow> = fetch_all!(
            self,
            "SELECT id, username, name, created_unix, last_seen_unix, revoked FROM devices WHERE id = ?1",
            id,
        )?;
        Ok(rows.into_iter().next().map(device_from))
    }

    pub async fn list_devices(&self, user: Option<&str>) -> Result<Vec<Device>> {
        let rows: Vec<DeviceRow> = if let Some(user) = user {
            fetch_all!(
                self,
                "SELECT id, username, name, created_unix, last_seen_unix, revoked FROM devices WHERE username = ?1 ORDER BY created_unix, id",
                user,
            )?
        } else {
            fetch_all!(
                self,
                "SELECT id, username, name, created_unix, last_seen_unix, revoked FROM devices ORDER BY username, created_unix, id",
            )?
        };
        Ok(rows.into_iter().map(device_from).collect())
    }

    pub async fn revoke_device(&self, id: &str, owner: Option<&str>) -> Result<Device> {
        let Some(device) = self.device(id).await? else {
            return Err(Error::NotFound(format!("device '{id}'")));
        };
        if let Some(owner) = owner {
            if device.user != owner {
                return Err(Error::NotFound(format!("device '{id}'")));
            }
        }
        exec!(self, "UPDATE devices SET revoked = 1 WHERE id = ?1", id)?;
        exec!(self, "DELETE FROM access_tokens WHERE device_id = ?1", id)?;
        exec!(
            self,
            "UPDATE refresh_tokens SET revoked = 1 WHERE device_id = ?1",
            id,
        )?;
        let mut device = device;
        device.revoked = true;
        Ok(device)
    }

    pub async fn touch_device(&self, id: &str) -> Result<()> {
        exec!(
            self,
            "UPDATE devices SET last_seen_unix = ?1 WHERE id = ?2",
            unix_now(),
            id,
        )?;
        Ok(())
    }

    pub async fn create_web_session(&self, username: &str) -> Result<(String, WebSession)> {
        let account = self
            .account(username)
            .await?
            .ok_or_else(|| Error::Auth("account is disabled".into()))?;
        if account.disabled {
            return Err(Error::Auth("account is disabled".into()));
        }
        let token = format!("stk.{}", util::random_token());
        let csrf = util::random_hex(16);
        let expires = unix_now() + WEB_TTL_SECS;
        exec!(
            self,
            "INSERT INTO web_sessions (token_hash, username, csrf, expires_unix) VALUES (?1, ?2, ?3, ?4)",
            &accounts::token_hash(&token),
            username,
            &csrf,
            expires,
        )?;
        Ok((
            token,
            WebSession {
                user: account.username,
                role: account.role,
                csrf,
                expires_unix: expires,
            },
        ))
    }

    pub async fn web_session(&self, token: &str) -> Result<Option<WebSession>> {
        let now = unix_now();
        let rows = fetch_optional_web(self, &accounts::token_hash(token)).await?;
        let Some((user, role, csrf, expires, disabled)) = rows else {
            return Ok(None);
        };
        if expires <= now || disabled != 0 {
            return Ok(None);
        }
        Ok(Some(WebSession {
            user,
            role,
            csrf,
            expires_unix: expires,
        }))
    }

    pub async fn delete_web_session(&self, token: &str) -> Result<()> {
        exec!(
            self,
            "DELETE FROM web_sessions WHERE token_hash = ?1",
            &accounts::token_hash(token),
        )?;
        Ok(())
    }

    pub async fn create_token(
        &self,
        owner: &str,
        name: &str,
        policy: NodePolicy,
        ttl_secs: u64,
        uses: u32,
    ) -> Result<IssuedToken> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Message("token name is required".into()));
        }
        if !(1..=7 * 24 * 3600).contains(&ttl_secs) {
            return Err(Error::Message(
                "token ttl must be between 1 second and 7 days".into(),
            ));
        }
        if !(1..=1000).contains(&uses) {
            return Err(Error::Message(
                "token uses must be between 1 and 1000".into(),
            ));
        }
        let id = util::random_hex(8);
        let token = util::random_token();
        let now = unix_now();
        let expires = now + ttl_secs as i64;
        exec!(
            self,
            "INSERT INTO enrollment_tokens (id, token_hash, name, policy_json, owner, created_unix, expires_unix, max_uses, uses_remaining, revoked) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?8, 0)",
            &id,
            &accounts::token_hash(&token),
            name,
            &policy_json(policy)?,
            owner,
            now,
            expires,
            i64::from(uses),
        )?;
        Ok(IssuedToken {
            id,
            token,
            name: name.to_string(),
            expires_unix: expires,
            policy,
            uses,
            owner: owner.to_string(),
        })
    }

    pub async fn list_tokens(&self, owner: Option<&str>) -> Result<Vec<TokenView>> {
        let rows: Vec<TokenRow> = if let Some(owner) = owner {
            fetch_all!(
                self,
                "SELECT id, name, policy_json, owner, created_unix, expires_unix, max_uses, uses_remaining, revoked FROM enrollment_tokens WHERE owner = ?1 ORDER BY created_unix DESC, id",
                owner,
            )?
        } else {
            fetch_all!(
                self,
                "SELECT id, name, policy_json, owner, created_unix, expires_unix, max_uses, uses_remaining, revoked FROM enrollment_tokens ORDER BY created_unix DESC, id",
            )?
        };
        rows.into_iter().map(token_from).collect()
    }

    pub async fn revoke_token(&self, id: &str, owner: Option<&str>) -> Result<TokenView> {
        let rows: Vec<TokenRow> = fetch_all!(
            self,
            "SELECT id, name, policy_json, owner, created_unix, expires_unix, max_uses, uses_remaining, revoked FROM enrollment_tokens WHERE id = ?1",
            id,
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Err(Error::NotFound(format!("token '{id}'")));
        };
        if let Some(owner) = owner {
            if row.owner != owner {
                return Err(Error::NotFound(format!("token '{id}'")));
            }
        }
        exec!(
            self,
            "UPDATE enrollment_tokens SET revoked = 1, uses_remaining = 0 WHERE id = ?1",
            id,
        )?;
        let mut view = token_from(row)?;
        view.revoked = true;
        view.uses_remaining = 0;
        Ok(view)
    }

    pub async fn enroll(
        &self,
        pairing_token: Option<&str>,
        public_hex: &str,
        meta: NodeMeta,
    ) -> Result<EnrolledNode> {
        let id = normalize_key(public_hex)?;
        let now = unix_now();
        if let Some(existing) = self.node_by_id(&id).await? {
            let mut node = existing;
            if let Some(token) = pairing_token.filter(|t| !t.is_empty()) {
                if let Some(rec) = self.take_token(token, now).await? {
                    self.ensure_can_claim(&rec.owner, &node.owner).await?;
                    node.policy = rec.policy;
                    if !rec.owner.is_empty() {
                        node.owner = rec.owner.clone();
                    }
                    if !rec.name.is_empty() && meta.name.is_empty() {
                        node.name = rec.name.clone();
                    }
                    exec!(
                        self,
                        "INSERT INTO token_uses (token_id, node_id, used_unix) VALUES (?1, ?2, ?3)",
                        &rec.id,
                        &id,
                        now,
                    )?;
                }
            }
            if !meta.name.is_empty() {
                node.name = meta.name;
            }
            node.hostname = meta.hostname;
            node.os = meta.os;
            node.arch = meta.arch;
            node.version = meta.version;
            node.ceiling = meta.ceiling;
            if let Some(flag) = meta.has_display {
                node.has_display = Some(flag);
            }
            node.last_seen_unix = Some(now);
            self.save_node(&node).await?;
            return Ok(node);
        }
        let token = pairing_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::Auth("node is not paired; pass a pairing token".into()))?;
        let rec = self.take_token(token, now).await?.ok_or_else(|| {
            Error::Auth("pairing token is invalid, expired, or already used".into())
        })?;
        let name = if meta.name.is_empty() {
            rec.name.clone()
        } else {
            meta.name
        };
        let node = EnrolledNode {
            id: id.clone(),
            name,
            public_key_hex: id.clone(),
            policy: rec.policy,
            ceiling: meta.ceiling,
            hostname: meta.hostname,
            os: meta.os,
            arch: meta.arch,
            version: meta.version,
            enrolled_unix: now,
            last_seen_unix: Some(now),
            owner: rec.owner.clone(),
            has_display: meta.has_display,
        };
        if let Err(err) = self.insert_node(&node).await {
            self.restore_token_use(&rec.id).await.ok();
            return Err(err);
        }
        exec!(
            self,
            "INSERT INTO token_uses (token_id, node_id, used_unix) VALUES (?1, ?2, ?3)",
            &rec.id,
            &id,
            now,
        )?;
        Ok(node)
    }

    /// Enroll a node for `owner` without consuming a pairing token.
    pub async fn enroll_self(
        &self,
        owner: &str,
        public_hex: &str,
        name: &str,
        policy: NodePolicy,
        meta: NodeMeta,
    ) -> Result<EnrolledNode> {
        let id = normalize_key(public_hex)?;
        let now = unix_now();
        let account = self
            .account(owner)
            .await?
            .ok_or_else(|| Error::Auth("account is disabled".into()))?;
        if account.disabled {
            return Err(Error::Auth("account is disabled".into()));
        }
        if let Some(mut node) = self.node_by_id(&id).await? {
            if node.owner != owner && account.role != "admin" {
                return Err(Error::Auth("node belongs to another user".into()));
            }
            if node.owner != owner && account.role == "admin" {
                node.owner = owner.to_string();
            }
            if !name.trim().is_empty() {
                node.name = name.trim().to_string();
            }
            node.policy = policy;
            node.hostname = meta.hostname;
            node.os = meta.os;
            node.arch = meta.arch;
            node.version = meta.version;
            node.ceiling = meta.ceiling;
            if let Some(flag) = meta.has_display {
                node.has_display = Some(flag);
            }
            node.last_seen_unix = Some(now);
            self.save_node(&node).await?;
            return Ok(node);
        }
        let node = EnrolledNode {
            id: id.clone(),
            name: if name.trim().is_empty() {
                "phone".into()
            } else {
                name.trim().to_string()
            },
            public_key_hex: id.clone(),
            policy,
            ceiling: meta.ceiling,
            hostname: meta.hostname,
            os: meta.os,
            arch: meta.arch,
            version: meta.version,
            enrolled_unix: now,
            last_seen_unix: Some(now),
            owner: owner.to_string(),
            has_display: meta.has_display,
        };
        self.insert_node(&node).await?;
        Ok(node)
    }

    pub async fn touch_node(&self, id: &str) -> Result<()> {
        exec!(
            self,
            "UPDATE nodes SET last_seen_unix = ?1 WHERE id = ?2",
            unix_now(),
            id,
        )?;
        Ok(())
    }

    pub async fn set_node_policy(
        &self,
        caller: &Caller,
        query: &str,
        policy: NodePolicy,
    ) -> Result<EnrolledNode> {
        let visible = self.access_to(caller, query).await?;
        if visible.relation == Relation::Shared {
            return Err(Error::PermissionDenied(
                "only the node owner can change its policy".into(),
            ));
        }
        let mut node = visible.node;
        node.policy = policy;
        self.save_node(&node).await?;
        Ok(node)
    }

    pub async fn resolve_node(&self, query: &str) -> Result<EnrolledNode> {
        let nodes = self.list_nodes().await?;
        if let Some(node) = nodes.iter().find(|node| node.id == query) {
            return Ok(node.clone());
        }
        let lower = query.to_ascii_lowercase();
        if let Some(node) = nodes.iter().find(|node| node.id == lower) {
            return Ok(node.clone());
        }
        let matches: Vec<_> = nodes
            .iter()
            .filter(|node| node.name == query)
            .cloned()
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().expect("len checked")),
            0 => Err(Error::NotFound(format!("node '{query}'"))),
            _ => Err(Error::Ambiguous(query.to_string())),
        }
    }

    pub async fn list_nodes(&self) -> Result<Vec<EnrolledNode>> {
        let rows: Vec<NodeRow> = fetch_all!(
            self,
            "SELECT id, name, public_key_hex, policy_json, ceiling_json, hostname, os, arch, version, enrolled_unix, last_seen_unix, owner, has_display FROM nodes ORDER BY name, id",
        )?;
        rows.into_iter().map(node_from).collect()
    }

    pub async fn visible(&self, caller: &Caller) -> Result<Vec<VisibleNode>> {
        let nodes = self.list_nodes().await?;
        let shares = self.share_rows().await?;
        Ok(nodes
            .into_iter()
            .filter_map(|node| visible_one(caller, node, &shares))
            .collect())
    }

    pub async fn access_to(&self, caller: &Caller, query: &str) -> Result<VisibleNode> {
        let nodes = self.visible(caller).await?;
        resolve_visible(&nodes, query)
    }

    pub async fn share(
        &self,
        caller: &Caller,
        node_query: &str,
        with_user: &str,
        policy: NodePolicy,
    ) -> Result<()> {
        let with_user = with_user.trim().to_ascii_lowercase();
        if self.account(&with_user).await?.is_none() {
            return Err(Error::NotFound(format!("user '{with_user}'")));
        }
        let visible = self.access_to(caller, node_query).await?;
        if visible.relation == Relation::Shared {
            return Err(Error::PermissionDenied(
                "only the node owner can share it".into(),
            ));
        }
        if visible.node.owner == with_user {
            return Err(Error::Message("the owner already has this node".into()));
        }
        // A share is full use of the machine. The requested preset is not a cap.
        let _requested = policy;
        let policy = NodePolicy::full();
        exec!(
            self,
            "INSERT INTO shares (node_id, username, policy_json) VALUES (?1, ?2, ?3) ON CONFLICT (node_id, username) DO UPDATE SET policy_json = ?3",
            &visible.node.id,
            &with_user,
            &policy_json(policy)?,
        )?;
        Ok(())
    }

    pub async fn unshare(&self, caller: &Caller, node_query: &str, with_user: &str) -> Result<()> {
        let with_user = with_user.trim().to_ascii_lowercase();
        let visible = self.access_to(caller, node_query).await?;
        if visible.relation == Relation::Shared && caller.user != with_user {
            return Err(Error::PermissionDenied(
                "only the node owner can unshare it".into(),
            ));
        }
        let affected = exec!(
            self,
            "DELETE FROM shares WHERE node_id = ?1 AND username = ?2",
            &visible.node.id,
            &with_user,
        )?;
        if affected == 0 {
            return Err(Error::NotFound(format!("share with '{with_user}'")));
        }
        Ok(())
    }

    pub async fn register_client(
        &self,
        owner: &str,
        name: &str,
        public_key: &str,
    ) -> Result<ClientRecord> {
        let id = normalize_key(public_key)?;
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Message("client name is required".into()));
        }
        if let Some(mut existing) = self.client_record(&id).await? {
            // Re-registering the same key must not move the client to another
            // account. That would let user B revoke or re-grant user A's agent.
            if !existing.owner.is_empty() && existing.owner != owner {
                return Err(Error::Auth("client belongs to another user".into()));
            }
            let owner = if existing.owner.is_empty() {
                owner.to_string()
            } else {
                existing.owner.clone()
            };
            exec!(
                self,
                "UPDATE clients SET name = ?1, revoked = 0, owner = ?2 WHERE id = ?3",
                name,
                &owner,
                &id,
            )?;
            existing.name = name.to_string();
            existing.revoked = false;
            existing.owner = owner;
            return Ok(existing);
        }
        exec!(
            self,
            "INSERT INTO clients (id, name, role, revoked, owner) VALUES (?1, ?2, 'agent', 0, ?3)",
            &id,
            name,
            owner,
        )?;
        Ok(ClientRecord {
            id,
            name: name.to_string(),
            role: "agent".into(),
            revoked: false,
            grants: HashMap::new(),
            owner: owner.to_string(),
        })
    }

    pub async fn set_grant(
        &self,
        caller: &Caller,
        client_id: &str,
        node_query: &str,
        policy: NodePolicy,
    ) -> Result<ClientRecord> {
        let client = self.resolve_client(client_id).await?;
        if !caller.admin && client.owner != caller.user {
            return Err(Error::NotFound(format!("client '{}'", client.name)));
        }
        if client.revoked {
            return Err(Error::Auth("client is revoked".into()));
        }
        let owner_caller = if caller.admin {
            caller.clone()
        } else {
            Caller {
                user: client.owner.clone(),
                admin: false,
            }
        };
        let visible = self.access_to(&owner_caller, node_query).await?;
        let cap = visible.access;
        if !policy_within(policy, cap) {
            return Err(Error::PermissionDenied(
                "grant cannot exceed your access to this node".into(),
            ));
        }
        exec!(
            self,
            "INSERT INTO client_grants (client_id, node_id, policy_json) VALUES (?1, ?2, ?3) ON CONFLICT (client_id, node_id) DO UPDATE SET policy_json = ?3",
            &client.id,
            &visible.node.id,
            &policy_json(policy)?,
        )?;
        self.client_record(&client.id)
            .await?
            .ok_or_else(|| Error::Message("client disappeared".into()))
    }

    pub async fn revoke_client(&self, caller: &Caller, client_id: &str) -> Result<ClientRecord> {
        let client = self.resolve_client(client_id).await?;
        if !caller.admin && client.owner != caller.user {
            return Err(Error::NotFound(format!("client '{}'", client.name)));
        }
        exec!(
            self,
            "UPDATE clients SET revoked = 1 WHERE id = ?1",
            &client.id,
        )?;
        exec!(
            self,
            "DELETE FROM client_grants WHERE client_id = ?1",
            &client.id,
        )?;
        let mut client = client;
        client.revoked = true;
        client.grants.clear();
        Ok(client)
    }

    pub async fn client_record(&self, id: &str) -> Result<Option<ClientRecord>> {
        let rows: Vec<ClientRow> = fetch_all!(
            self,
            "SELECT id, name, role, revoked, owner FROM clients WHERE id = ?1",
            id,
        )?;
        let Some(row) = rows.into_iter().next() else {
            return Ok(None);
        };
        let grants = self.grants_for(&row.id).await?;
        Ok(Some(client_from(row, grants)))
    }

    pub async fn list_clients(&self, owner: Option<&str>) -> Result<Vec<ClientRecord>> {
        let rows: Vec<ClientRow> = if let Some(owner) = owner {
            fetch_all!(
                self,
                "SELECT id, name, role, revoked, owner FROM clients WHERE owner = ?1 ORDER BY name, id",
                owner,
            )?
        } else {
            fetch_all!(
                self,
                "SELECT id, name, role, revoked, owner FROM clients ORDER BY name, id",
            )?
        };
        let grant_rows: Vec<GrantRow> = fetch_all!(
            self,
            "SELECT client_id, node_id, policy_json FROM client_grants",
        )?;
        let mut by_client: HashMap<String, HashMap<String, NodePolicy>> = HashMap::new();
        for grant in grant_rows {
            let policy = parse_policy(&grant.policy_json)?;
            by_client
                .entry(grant.client_id)
                .or_default()
                .insert(grant.node_id, policy);
        }
        Ok(rows
            .into_iter()
            .map(|row| {
                let grants = by_client.remove(&row.id).unwrap_or_default();
                client_from(row, grants)
            })
            .collect())
    }

    pub async fn set_node_audit(&self, node_id: &str, toml: &str) -> Result<()> {
        exec!(
            self,
            "INSERT INTO audit_policies (scope, id, toml) VALUES ('node', ?1, ?2) ON CONFLICT (scope, id) DO UPDATE SET toml = ?2",
            node_id,
            toml,
        )?;
        Ok(())
    }

    pub async fn set_user_audit(&self, username: &str, toml: &str) -> Result<()> {
        exec!(
            self,
            "INSERT INTO audit_policies (scope, id, toml) VALUES ('user', ?1, ?2) ON CONFLICT (scope, id) DO UPDATE SET toml = ?2",
            username,
            toml,
        )?;
        Ok(())
    }

    pub async fn audit_for_node(&self, node_id: &str) -> Result<Option<String>> {
        if let Some(toml) = self.policy_toml("node", node_id).await? {
            return Ok(Some(toml));
        }
        let Some(node) = self.node_by_id(node_id).await? else {
            return Ok(None);
        };
        if node.owner.is_empty() {
            return Ok(None);
        }
        self.policy_toml("user", &node.owner).await
    }

    pub async fn user_audit(&self, username: &str) -> Result<Option<String>> {
        self.policy_toml("user", username).await
    }

    pub async fn put_approval(&self, info: &ApprovalInfo) -> Result<()> {
        exec!(
            self,
            "INSERT INTO approvals (approval_id, node_id, client_id, category, summary, expires_unix) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT (approval_id) DO UPDATE SET node_id = ?2, client_id = ?3, category = ?4, summary = ?5, expires_unix = ?6",
            &info.approval_id,
            &info.node_id,
            &info.client_id,
            &info.category,
            &info.summary,
            info.expires_unix,
        )?;
        Ok(())
    }

    pub async fn remove_approval(&self, id: &str) -> Result<()> {
        exec!(self, "DELETE FROM approvals WHERE approval_id = ?1", id)?;
        Ok(())
    }

    pub async fn list_approvals(&self) -> Result<Vec<ApprovalInfo>> {
        let now = unix_now();
        exec!(self, "DELETE FROM approvals WHERE expires_unix <= ?1", now)?;
        let rows: Vec<ApprovalRow> = fetch_all!(
            self,
            "SELECT approval_id, node_id, client_id, category, summary, expires_unix FROM approvals ORDER BY expires_unix",
        )?;
        Ok(rows
            .into_iter()
            .map(|row| ApprovalInfo {
                approval_id: row.approval_id,
                node_id: row.node_id,
                client_id: row.client_id,
                category: row.category,
                summary: row.summary,
                expires_unix: row.expires_unix,
            })
            .collect())
    }

    async fn take_token(&self, token: &str, now: i64) -> Result<Option<TokenView>> {
        let hash = accounts::token_hash(token);
        let affected = exec!(
            self,
            "UPDATE enrollment_tokens SET uses_remaining = uses_remaining - 1 WHERE token_hash = ?1 AND uses_remaining > 0 AND revoked = 0 AND expires_unix > ?2",
            &hash,
            now,
        )?;
        if affected != 1 {
            return Ok(None);
        }
        let rows: Vec<TokenRow> = fetch_all!(
            self,
            "SELECT id, name, policy_json, owner, created_unix, expires_unix, max_uses, uses_remaining, revoked FROM enrollment_tokens WHERE token_hash = ?1",
            &hash,
        )?;
        rows.into_iter().next().map(token_from).transpose()
    }

    async fn restore_token_use(&self, id: &str) -> Result<()> {
        exec!(
            self,
            "UPDATE enrollment_tokens SET uses_remaining = uses_remaining + 1 WHERE id = ?1 AND revoked = 0",
            id,
        )?;
        Ok(())
    }

    async fn ensure_can_claim(&self, token_owner: &str, node_owner: &str) -> Result<()> {
        // Unowned legacy rows can be claimed. An empty token owner must not
        // rewrite policy on a node that already has an owner.
        if node_owner.is_empty() || token_owner == node_owner {
            return Ok(());
        }
        if token_owner.is_empty() {
            return Err(Error::Auth(
                "pairing token cannot claim a node owned by someone else".into(),
            ));
        }
        let role = self.account(token_owner).await?.map(|user| user.role);
        if role.as_deref() == Some("admin") {
            return Ok(());
        }
        Err(Error::Auth(
            "pairing token cannot claim a node owned by someone else".into(),
        ))
    }

    async fn node_by_id(&self, id: &str) -> Result<Option<EnrolledNode>> {
        let rows: Vec<NodeRow> = fetch_all!(
            self,
            "SELECT id, name, public_key_hex, policy_json, ceiling_json, hostname, os, arch, version, enrolled_unix, last_seen_unix, owner, has_display FROM nodes WHERE id = ?1",
            id,
        )?;
        rows.into_iter().next().map(node_from).transpose()
    }

    async fn insert_node(&self, node: &EnrolledNode) -> Result<()> {
        exec!(
            self,
            "INSERT INTO nodes (id, name, public_key_hex, policy_json, ceiling_json, hostname, os, arch, version, enrolled_unix, last_seen_unix, owner, has_display) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            &node.id,
            &node.name,
            &node.public_key_hex,
            &policy_json(node.policy)?,
            &policy_json(node.ceiling)?,
            &node.hostname,
            &node.os,
            &node.arch,
            &node.version,
            node.enrolled_unix,
            node.last_seen_unix,
            &node.owner,
            display_sql(node.has_display),
        )?;
        Ok(())
    }

    async fn save_node(&self, node: &EnrolledNode) -> Result<()> {
        exec!(
            self,
            "UPDATE nodes SET name = ?1, policy_json = ?2, ceiling_json = ?3, hostname = ?4, os = ?5, arch = ?6, version = ?7, last_seen_unix = ?8, owner = ?9, has_display = ?10 WHERE id = ?11",
            &node.name,
            &policy_json(node.policy)?,
            &policy_json(node.ceiling)?,
            &node.hostname,
            &node.os,
            &node.arch,
            &node.version,
            node.last_seen_unix,
            &node.owner,
            display_sql(node.has_display),
            &node.id,
        )?;
        Ok(())
    }

    async fn share_rows(&self) -> Result<Vec<ShareRow>> {
        fetch_all!(self, "SELECT node_id, username, policy_json FROM shares",)
    }

    async fn grants_for(&self, client_id: &str) -> Result<HashMap<String, NodePolicy>> {
        let rows: Vec<GrantRow> = fetch_all!(
            self,
            "SELECT client_id, node_id, policy_json FROM client_grants WHERE client_id = ?1",
            client_id,
        )?;
        let mut map = HashMap::new();
        for row in rows {
            map.insert(row.node_id, parse_policy(&row.policy_json)?);
        }
        Ok(map)
    }

    async fn resolve_client(&self, query: &str) -> Result<ClientRecord> {
        let lower = query.trim().to_ascii_lowercase();
        if let Some(client) = self.client_record(&lower).await? {
            return Ok(client);
        }
        let clients = self.list_clients(None).await?;
        let matches: Vec<_> = clients
            .into_iter()
            .filter(|client| client.name == query || client.id == query)
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().expect("len checked")),
            0 => Err(Error::NotFound(format!("client '{query}'"))),
            _ => Err(Error::Ambiguous(query.to_string())),
        }
    }

    async fn policy_toml(&self, scope: &str, id: &str) -> Result<Option<String>> {
        fetch_optional_text(
            self,
            "SELECT toml FROM audit_policies WHERE scope = ?1 AND id = ?2",
            scope,
            id,
        )
        .await
    }

    async fn insert_user(&self, username: &str, password: &str, role: &str) -> Result<()> {
        let hash = accounts::hash_password(password)?;
        exec!(
            self,
            "INSERT INTO users (username, password_hash, created_unix, disabled, user_role, failed_attempts, locked_until_unix) VALUES (?1, ?2, ?3, 0, ?4, 0, 0)",
            username,
            &hash,
            unix_now(),
            role,
        )?;
        Ok(())
    }

    async fn delete_user_sessions(&self, username: &str) -> Result<()> {
        exec!(
            self,
            "DELETE FROM access_tokens WHERE username = ?1",
            username
        )?;
        exec!(
            self,
            "UPDATE refresh_tokens SET revoked = 1 WHERE username = ?1",
            username,
        )?;
        exec!(
            self,
            "DELETE FROM web_sessions WHERE username = ?1",
            username
        )?;
        Ok(())
    }

    async fn user_row(&self, username: &str) -> Result<Option<UserRow>> {
        let rows: Vec<UserRow> = fetch_all!(
            self,
            "SELECT username, password_hash, created_unix, disabled, user_role, totp_secret, totp_pending, failed_attempts, locked_until_unix FROM users WHERE username = ?1",
            username,
        )?;
        Ok(rows.into_iter().next())
    }

    async fn meta(&self, name: &str) -> Result<Option<String>> {
        fetch_optional_text_one(self, "SELECT value FROM meta WHERE name = ?1", name).await
    }

    async fn set_meta(&self, name: &str, value: &str) -> Result<()> {
        exec!(
            self,
            "INSERT INTO meta (name, value) VALUES (?1, ?2) ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            name,
            value,
        )?;
        Ok(())
    }

    async fn secret(&self, name: &str) -> Result<Option<String>> {
        fetch_optional_text_one(
            self,
            "SELECT value FROM relay_secrets WHERE name = ?1",
            name,
        )
        .await
    }

    async fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        exec!(
            self,
            "INSERT INTO relay_secrets (name, value) VALUES (?1, ?2) ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            name,
            value,
        )?;
        Ok(())
    }

    async fn import_store(&self, path: &Path) -> Result<()> {
        let text = std::fs::read_to_string(path)?;
        let legacy: LegacyStore = serde_json::from_str(&text)?;
        if self.secret("admin_token").await?.is_none() {
            self.set_secret("admin_token", &legacy.admin_token).await?;
        }
        if self.user_row(ADMIN_USER).await?.is_none() {
            let password = util::random_token();
            self.insert_user(ADMIN_USER, &password, "admin").await?;
            util::write_secret(
                &self.data_dir.join("bootstrap.password"),
                password.as_bytes(),
            )?;
            self.set_meta("bootstrap_imported", "1").await?;
        }
        for (id, mut node) in legacy.nodes {
            if node.owner.is_empty() {
                node.owner = ADMIN_USER.into();
            }
            if node.id.is_empty() {
                node.id = id.clone();
            }
            if node.public_key_hex.is_empty() {
                node.public_key_hex = node.id.clone();
            }
            if self.node_by_id(&node.id).await?.is_none() {
                self.insert_node(&node).await?;
            }
        }
        for pairing in legacy.pairing {
            let uses_remaining = if pairing.used { 0 } else { 1 };
            let id = util::random_hex(8);
            let _ = exec!(
                self,
                "INSERT INTO enrollment_tokens (id, token_hash, name, policy_json, owner, created_unix, expires_unix, max_uses, uses_remaining, revoked) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 1, ?8, 0) ON CONFLICT (token_hash) DO NOTHING",
                &id,
                &accounts::token_hash(&pairing.token),
                &pairing.name,
                &policy_json(pairing.policy)?,
                ADMIN_USER,
                unix_now(),
                pairing.expires_unix,
                uses_remaining,
            );
        }
        for (id, client) in legacy.clients {
            let owner = ADMIN_USER;
            let cid = if client.id.is_empty() { id } else { client.id };
            if self.client_record(&cid).await?.is_none() {
                exec!(
                    self,
                    "INSERT INTO clients (id, name, role, revoked, owner) VALUES (?1, ?2, ?3, ?4, ?5)",
                    &cid,
                    &client.name,
                    &client.role,
                    i64::from(client.revoked),
                    owner,
                )?;
                for (node_id, policy) in client.grants {
                    exec!(
                        self,
                        "INSERT INTO client_grants (client_id, node_id, policy_json) VALUES (?1, ?2, ?3) ON CONFLICT (client_id, node_id) DO NOTHING",
                        &cid,
                        &node_id,
                        &policy_json(policy)?,
                    )?;
                }
            }
        }
        for (node_id, toml) in legacy.audit_policies {
            self.set_node_audit(&node_id, &toml).await?;
        }
        Ok(())
    }
}

#[derive(serde::Deserialize)]
struct LegacyStore {
    admin_token: String,
    #[serde(default)]
    nodes: HashMap<String, EnrolledNode>,
    #[serde(default)]
    pairing: Vec<LegacyPairing>,
    #[serde(default)]
    clients: HashMap<String, LegacyClient>,
    #[serde(default)]
    audit_policies: HashMap<String, String>,
}

#[derive(serde::Deserialize)]
struct LegacyPairing {
    token: String,
    name: String,
    policy: NodePolicy,
    expires_unix: i64,
    #[serde(default)]
    used: bool,
}

#[derive(serde::Deserialize)]
struct LegacyClient {
    #[serde(default)]
    id: String,
    name: String,
    role: String,
    #[serde(default)]
    revoked: bool,
    #[serde(default)]
    grants: HashMap<String, NodePolicy>,
}

fn account_from(row: UserRow) -> UserAccount {
    UserAccount {
        username: row.username,
        role: row.user_role,
        disabled: row.disabled != 0,
        created_unix: row.created_unix,
        totp_enabled: row
            .totp_secret
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(false),
        failed_attempts: row.failed_attempts.max(0) as u32,
        locked_until_unix: row.locked_until_unix,
    }
}

fn device_from(row: DeviceRow) -> Device {
    Device {
        id: row.id,
        user: row.username,
        name: row.name,
        created_unix: row.created_unix,
        last_seen_unix: row.last_seen_unix,
        revoked: row.revoked != 0,
    }
}

fn token_from(row: TokenRow) -> Result<TokenView> {
    Ok(TokenView {
        id: row.id,
        name: row.name,
        owner: row.owner,
        policy: parse_policy(&row.policy_json)?,
        created_unix: row.created_unix,
        expires_unix: row.expires_unix,
        max_uses: row.max_uses.max(0) as u32,
        uses_remaining: row.uses_remaining.max(0) as u32,
        revoked: row.revoked != 0,
    })
}

fn node_from(row: NodeRow) -> Result<EnrolledNode> {
    Ok(EnrolledNode {
        id: row.id,
        name: row.name,
        public_key_hex: row.public_key_hex,
        policy: parse_policy(&row.policy_json)?,
        ceiling: parse_policy(&row.ceiling_json)?,
        hostname: row.hostname,
        os: row.os,
        arch: row.arch,
        version: row.version,
        enrolled_unix: row.enrolled_unix,
        last_seen_unix: row.last_seen_unix,
        owner: row.owner,
        has_display: row.has_display.map(|value| value != 0),
    })
}

fn display_sql(flag: Option<bool>) -> Option<i64> {
    flag.map(i64::from)
}

fn client_from(row: ClientRow, grants: HashMap<String, NodePolicy>) -> ClientRecord {
    ClientRecord {
        id: row.id,
        name: row.name,
        role: row.role,
        revoked: row.revoked != 0,
        grants,
        owner: row.owner,
    }
}

fn visible_one(caller: &Caller, node: EnrolledNode, shares: &[ShareRow]) -> Option<VisibleNode> {
    let relation = if caller.admin {
        Relation::Admin
    } else if node.owner == caller.user {
        Relation::Owner
    } else if shares.iter().any(|share| {
        share.node_id == node.id
            && share.username == caller.user
            && parse_policy(&share.policy_json).is_ok()
    }) {
        Relation::Shared
    } else {
        return None;
    };
    // Whoever can see the machine can use all of it. Presets are not a cap.
    Some(VisibleNode {
        node,
        access: NodePolicy::full(),
        relation,
    })
}

fn resolve_visible(nodes: &[VisibleNode], query: &str) -> Result<VisibleNode> {
    if let Some(node) = nodes.iter().find(|node| node.node.id == query) {
        return Ok(node.clone());
    }
    let lower = query.to_ascii_lowercase();
    if let Some(node) = nodes.iter().find(|node| node.node.id == lower) {
        return Ok(node.clone());
    }
    let matches: Vec<_> = nodes
        .iter()
        .filter(|node| node.node.name == query)
        .cloned()
        .collect();
    match matches.len() {
        1 => Ok(matches.into_iter().next().expect("len checked")),
        0 => Err(Error::NotFound(format!("node '{query}'"))),
        _ => Err(Error::Ambiguous(query.to_string())),
    }
}

fn policy_within(grant: NodePolicy, cap: NodePolicy) -> bool {
    fn bit(want: bool, have: bool) -> bool {
        !want || have
    }
    bit(grant.allow_read, cap.allow_read)
        && bit(grant.allow_write, cap.allow_write)
        && bit(grant.allow_exec, cap.allow_exec)
        && bit(grant.allow_desktop, cap.allow_desktop)
        && bit(grant.allow_desktop_stream, cap.allow_desktop_stream)
        && bit(grant.allow_remote_view, cap.allow_remote_view)
        && bit(grant.allow_remote_control, cap.allow_remote_control)
}

fn policy_json(policy: NodePolicy) -> Result<String> {
    Ok(serde_json::to_string(&policy)?)
}

fn parse_policy(text: &str) -> Result<NodePolicy> {
    Ok(serde_json::from_str(text)?)
}

fn refresh_rejected() -> Error {
    Error::Auth("refresh token is invalid or revoked".into())
}

fn filled(value: Option<&str>) -> Option<&str> {
    value.filter(|text| !text.is_empty())
}

fn normalize_key(public_hex: &str) -> Result<String> {
    let id = public_hex.trim().to_ascii_lowercase();
    if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::Auth("public key must be 64 hex characters".into()));
    }
    Ok(id)
}

async fn canonical_user(username: &str) -> Result<String> {
    let username = username.trim().to_ascii_lowercase();
    if !accounts::valid_username(&username) {
        return Err(Error::Message("invalid username".into()));
    }
    Ok(username)
}

fn validate_schema(schema: &str) -> Result<()> {
    if schema.len() > 48
        || !schema
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        || !schema
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_lowercase())
    {
        return Err(Error::Message("invalid database schema name".into()));
    }
    Ok(())
}

fn rotate_backup(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let mut dest = path.with_extension("json.bak");
    if dest.exists() {
        dest = path.with_file_name(format!("store.json.bak.{}", unix_now()));
    }
    std::fs::rename(path, dest)?;
    Ok(())
}

fn db_err(err: sqlx::Error) -> Error {
    Error::Message(format!("database: {err}"))
}

/// Rewrites only `?N` placeholders to `$N` for Postgres. Values stay bound
/// separately. sqlx 0.9 requires that the resulting `String` be passed through
/// `AssertSqlSafe` after this audit; this function must not interpolate identifiers
/// or user data into the SQL text.
fn adapt(sql: &str, postgres: bool) -> String {
    let mut out = String::with_capacity(sql.len());
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '?' {
            let mut j = i + 1;
            let mut n: u32 = 0;
            let mut digits = false;
            while j < chars.len() && chars[j].is_ascii_digit() {
                digits = true;
                n = n * 10 + chars[j].to_digit(10).unwrap_or(0);
                j += 1;
            }
            if digits {
                if postgres {
                    out.push('$');
                } else {
                    out.push('?');
                }
                out.push_str(&n.to_string());
                i = j;
                continue;
            }
        }
        out.push(chars[i]);
        i += 1;
    }
    out
}

async fn fetch_optional_text(db: &Database, sql: &str, a: &str, b: &str) -> Result<Option<String>> {
    match &db.backend {
        Backend::Sqlite(pool) => {
            let adapted = adapt(sql, false);
            let row = sqlx::query(AssertSqlSafe(adapted))
                .bind(a)
                .bind(b)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
            Ok(row
                .map(|row| row.try_get::<String, _>(0))
                .transpose()
                .map_err(db_err)?)
        }
        Backend::Postgres(pool) => {
            let adapted = adapt(sql, true);
            let row = sqlx::query(AssertSqlSafe(adapted))
                .bind(a)
                .bind(b)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
            Ok(row
                .map(|row| row.try_get::<String, _>(0))
                .transpose()
                .map_err(db_err)?)
        }
    }
}

async fn fetch_optional_text_one(db: &Database, sql: &str, a: &str) -> Result<Option<String>> {
    match &db.backend {
        Backend::Sqlite(pool) => {
            let adapted = adapt(sql, false);
            let row = sqlx::query(AssertSqlSafe(adapted))
                .bind(a)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
            Ok(row
                .map(|row| row.try_get::<String, _>(0))
                .transpose()
                .map_err(db_err)?)
        }
        Backend::Postgres(pool) => {
            let adapted = adapt(sql, true);
            let row = sqlx::query(AssertSqlSafe(adapted))
                .bind(a)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
            Ok(row
                .map(|row| row.try_get::<String, _>(0))
                .transpose()
                .map_err(db_err)?)
        }
    }
}

async fn fetch_optional_web(
    db: &Database,
    hash: &str,
) -> Result<Option<(String, String, String, i64, i64)>> {
    let sql = "SELECT w.username, u.user_role, w.csrf, w.expires_unix, u.disabled FROM web_sessions w JOIN users u ON u.username = w.username WHERE w.token_hash = ?1";
    match &db.backend {
        Backend::Sqlite(pool) => {
            let adapted = adapt(sql, false);
            let row = sqlx::query(AssertSqlSafe(adapted))
                .bind(hash)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
            match row {
                None => Ok(None),
                Some(row) => Ok(Some((
                    row.try_get(0).map_err(db_err)?,
                    row.try_get(1).map_err(db_err)?,
                    row.try_get(2).map_err(db_err)?,
                    row.try_get(3).map_err(db_err)?,
                    row.try_get(4).map_err(db_err)?,
                ))),
            }
        }
        Backend::Postgres(pool) => {
            let adapted = adapt(sql, true);
            let row = sqlx::query(AssertSqlSafe(adapted))
                .bind(hash)
                .fetch_optional(pool)
                .await
                .map_err(db_err)?;
            match row {
                None => Ok(None),
                Some(row) => Ok(Some((
                    row.try_get(0).map_err(db_err)?,
                    row.try_get(1).map_err(db_err)?,
                    row.try_get(2).map_err(db_err)?,
                    row.try_get(3).map_err(db_err)?,
                    row.try_get(4).map_err(db_err)?,
                ))),
            }
        }
    }
}

fn protect_sqlite_files(data_dir: &Path) {
    for name in ["relay.db", "relay.db-wal", "relay.db-shm"] {
        let path = data_dir.join(name);
        if let Err(err) = util::restrict_existing_file(&path) {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "could not restrict sqlite file mode"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn sqlite_files_are_owner_only_and_postgres_urls_are_required() {
        let rejected = tempdir().unwrap();
        let err = match Database::open(OpenOptions {
            data_dir: rejected.path(),
            database_url: Some("sqlite:///tmp/evil.db"),
            schema: None,
            bootstrap_admin: false,
            mint_legacy_admin: false,
        })
        .await
        {
            Ok(_) => panic!("sqlite:// URLs must be rejected"),
            Err(err) => err.to_string(),
        };
        assert!(err.contains("postgres://"), "{err}");
        assert!(!err.to_lowercase().contains("attached"), "{err}");

        let dir = tempdir().unwrap();
        let opened = Database::open(OpenOptions {
            data_dir: dir.path(),
            database_url: None,
            schema: None,
            bootstrap_admin: false,
            mint_legacy_admin: false,
        })
        .await
        .expect("sqlite open");
        drop(opened.db);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700, "data dir {dir_mode:o}");
            let db = dir.path().join("relay.db");
            assert!(db.is_file(), "relay.db must exist");
            let mode = std::fs::metadata(&db).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "relay.db {mode:o}");
            for name in ["relay.db-wal", "relay.db-shm"] {
                let path = dir.path().join(name);
                if path.exists() {
                    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                    assert_eq!(mode, 0o600, "{name} {mode:o}");
                }
            }
        }
    }

    fn sqlite_pool(db: &Database) -> &SqlitePool {
        match &db.backend {
            Backend::Sqlite(pool) => pool,
            Backend::Postgres(_) => panic!("expected sqlite backend"),
        }
    }

    async fn open_sqlite(dir: &std::path::Path) -> Database {
        Database::open(OpenOptions {
            data_dir: dir,
            database_url: None,
            schema: None,
            bootstrap_admin: false,
            mint_legacy_admin: false,
        })
        .await
        .expect("sqlite open")
        .db
    }

    /// Official e5bf1198 fix in sqlite3WalReadFrame: when the WAL page size is
    /// smaller than the caller buffer, zero the tail instead of leaving
    /// uninitialized page-cache bytes.
    const SQLITE_E5BF_FIX: &str = "memset(pOut+sz, 0, nOut-sz)";

    fn official_libsqlite3_sys_0391_amalgamation() -> std::path::PathBuf {
        let home = std::env::var("CARGO_HOME").unwrap_or_else(|_| {
            format!(
                "{}/.cargo",
                std::env::var("HOME").expect("HOME")
            )
        });
        let root = std::path::Path::new(&home).join("registry/src");
        let mut found = Vec::new();
        if let Ok(idx_dirs) = std::fs::read_dir(&root) {
            for idx in idx_dirs.flatten() {
                let cand = idx
                    .path()
                    .join("libsqlite3-sys-0.39.1/sqlite3/sqlite3.c");
                if cand.is_file() {
                    found.push(cand);
                }
            }
        }
        assert_eq!(
            found.len(),
            1,
            "expected one official libsqlite3-sys 0.39.1 amalgamation under {root:?}, found {found:?}"
        );
        found.pop().unwrap()
    }

    #[tokio::test]
    async fn sqlite_runtime_is_3_54_1_and_amalgamation_has_official_e5bf_fix() {
        let amalgamation = official_libsqlite3_sys_0391_amalgamation();
        let src = std::fs::read_to_string(&amalgamation).expect("read sqlite3.c");
        assert!(
            src.contains("#define SQLITE_VERSION        \"3.54.1\""),
            "amalgamation {} is not SQLite 3.54.1",
            amalgamation.display()
        );
        assert!(
            src.contains("sqlite3WalReadFrame"),
            "missing sqlite3WalReadFrame in {}",
            amalgamation.display()
        );
        assert!(
            src.contains(SQLITE_E5BF_FIX),
            "official e5bf1198 zeroing fix not found in {}",
            amalgamation.display()
        );

        let dir = tempdir().unwrap();
        let db = open_sqlite(dir.path()).await;
        let pool = sqlite_pool(&db);
        let version: String = sqlx::query_scalar("SELECT sqlite_version()")
            .fetch_one(pool)
            .await
            .expect("sqlite_version");
        assert_eq!(version, "3.54.1", "linked runtime SQLite is {version}, not 3.54.1");
        let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(pool)
            .await
            .expect("journal_mode");
        assert_eq!(journal.to_lowercase(), "wal");
        drop(db);
    }

    #[tokio::test]
    async fn sqlite_wal_transaction_restart_and_old_schema_migrate() {
        // Fresh schema: write, transaction rollback, WAL, restart.
        let fresh = tempdir().unwrap();
        let db = open_sqlite(fresh.path()).await;
        let pool = sqlite_pool(&db);
        sqlx::query("INSERT INTO meta(name, value) VALUES ('probe', 'alive')")
            .execute(pool)
            .await
            .unwrap();
        let mut tx = pool.begin().await.unwrap();
        sqlx::query("UPDATE meta SET value = 'rolled' WHERE name = 'probe'")
            .execute(&mut *tx)
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        let value: String = sqlx::query_scalar("SELECT value FROM meta WHERE name = 'probe'")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(value, "alive", "rollback must not persist");
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        drop(db);

        let db = open_sqlite(fresh.path()).await;
        let value: String = sqlx::query_scalar("SELECT value FROM meta WHERE name = 'probe'")
            .fetch_one(sqlite_pool(&db))
            .await
            .unwrap();
        assert_eq!(value, "alive", "value must survive restart");
        drop(db);

        // Old schema: only 0001 applied. Then product open must apply 0002/0003.
        let complete = tempdir().unwrap();
        let complete_db = open_sqlite(complete.path()).await;
        let create_sql: String = sqlx::query_scalar(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = '_sqlx_migrations'",
        )
        .fetch_one(sqlite_pool(&complete_db))
        .await
        .unwrap();
        let (version, description, installed_on, success, checksum, execution_time): (
            i64,
            String,
            String,
            bool,
            Vec<u8>,
            i64,
        ) = sqlx::query_as(
            "SELECT version, description, installed_on, success, checksum, execution_time              FROM _sqlx_migrations WHERE version = 1",
        )
        .fetch_one(sqlite_pool(&complete_db))
        .await
        .expect("version 1 checksum from a complete migrate");
        drop(complete_db);

        let old = tempdir().unwrap();
        let old_path = old.path().join("relay.db");
        let options = SqliteConnectOptions::new()
            .filename(&old_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
        let old_pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!("../migrations/sqlite/0001_init.sql"))
            .execute(&old_pool)
            .await
            .expect("apply 0001 only");
        assert!(
            create_sql.starts_with("CREATE TABLE"),
            "unexpected migrations table sql: {create_sql}"
        );
        sqlx::query(AssertSqlSafe(create_sql))
            .execute(&old_pool)
            .await
            .expect("create _sqlx_migrations");
        sqlx::query(
            "INSERT INTO _sqlx_migrations              (version, description, installed_on, success, checksum, execution_time)              VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(version)
        .bind(&description)
        .bind(&installed_on)
        .bind(success)
        .bind(&checksum)
        .bind(execution_time)
        .execute(&old_pool)
        .await
        .unwrap();

        let refresh_cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('refresh_tokens')")
            .fetch_all(&old_pool)
            .await
            .unwrap();
        let node_cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('nodes')")
            .fetch_all(&old_pool)
            .await
            .unwrap();
        assert!(!refresh_cols.iter().any(|c| c == "replaced_by"), "0002 must not be present yet");
        assert!(!node_cols.iter().any(|c| c == "has_display"), "0003 must not be present yet");
        old_pool.close().await;

        let migrated = open_sqlite(old.path()).await;
        let pool = sqlite_pool(&migrated);
        let refresh_cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('refresh_tokens')")
            .fetch_all(pool)
            .await
            .unwrap();
        let node_cols: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info('nodes')")
            .fetch_all(pool)
            .await
            .unwrap();
        assert!(refresh_cols.iter().any(|c| c == "replaced_by"));
        assert!(refresh_cols.iter().any(|c| c == "acknowledged"));
        assert!(node_cols.iter().any(|c| c == "has_display"));
        sqlx::query("INSERT INTO meta(name, value) VALUES ('after-migrate', 'ok')")
            .execute(pool)
            .await
            .unwrap();
        let got: String = sqlx::query_scalar("SELECT value FROM meta WHERE name = 'after-migrate'")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(got, "ok");
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        drop(migrated);
    }
}
