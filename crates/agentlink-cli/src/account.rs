//! Username sessions: local relay accounts and remote user, share, and token commands.

use std::io::{IsTerminal, Write};
use std::path::Path;

use agentlink_core::{parse_access, Client};
use agentlink_relay::{Database, OpenOptions};
use anyhow::{anyhow, Result};
use clap::Subcommand;
use serde_json::json;

use super::emit;

#[derive(Subcommand, Debug)]
pub enum RelayAction {
    /// Manage accounts in this relay's database. Does not open the listen port.
    User {
        #[command(subcommand)]
        cmd: RelayUserCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum RelayUserCmd {
    /// Create an account. The first admin can be created before anyone can log in.
    Add {
        username: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        admin: bool,
    },
    /// List accounts in this relay's database.
    List,
    /// Set or rotate the password for an account.
    Passwd {
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Disable an account so it cannot sign in.
    Disable {
        username: String,
    },
    /// Re-enable a disabled account.
    Enable {
        username: String,
    },
    /// Permanently remove an account.
    Rm {
        username: String,
    },
    /// Change an account's role (`admin` or `user`).
    SetRole {
        username: String,
        role: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserAction {
    /// Create a user account on the relay.
    Add {
        username: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        admin: bool,
    },
    /// List user accounts on the relay.
    List,
    /// Change an account's password on the relay.
    Passwd {
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Disable a user account on the relay.
    Disable {
        username: String,
    },
    /// Re-enable a disabled user account on the relay.
    Enable {
        username: String,
    },
    /// Permanently remove a user account on the relay.
    Rm {
        username: String,
    },
    /// Change a user account's role (`admin` or `user`).
    SetRole {
        username: String,
        role: String,
    },
    /// Turn authenticator codes on or off for the logged-in account.
    Totp {
        #[command(subcommand)]
        action: TotpAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum TotpAction {
    /// Generate a new TOTP secret and provisioning URL.
    Enable,
    /// Verify a TOTP code to finish enabling authenticator login.
    Confirm { code: String },
    /// Disable TOTP authenticator codes for this account.
    Disable,
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
    /// Create a new enrollment token for pairing machines.
    Create {
        #[arg(long)]
        name: String,
        /// Kept for older scripts. Enrollment is full access for the owner.
        #[arg(long, default_value = "full")]
        access: String,
        #[arg(long, default_value_t = 15)]
        ttl_minutes: u64,
        #[arg(long, default_value_t = 1)]
        uses: u32,
    },
    /// List enrollment tokens.
    List,
    /// Revoke an enrollment token by id.
    Revoke {
        id: String,
    },
}

pub fn read_password(password_stdin: bool, label: &str) -> Result<String> {
    if password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    prompt_secret(label)
}

struct SecretTerminalGuard {
    bracketed_paste: bool,
}

impl SecretTerminalGuard {
    fn enter() -> Result<Self> {
        use crossterm::event::EnableBracketedPaste;
        use crossterm::execute;
        use crossterm::terminal::enable_raw_mode;
        enable_raw_mode().map_err(|err| anyhow!(err))?;
        let bracketed_paste = execute!(std::io::stderr(), EnableBracketedPaste).is_ok();
        Ok(Self { bracketed_paste })
    }
}

impl Drop for SecretTerminalGuard {
    fn drop(&mut self) {
        use crossterm::event::DisableBracketedPaste;
        use crossterm::execute;
        use crossterm::terminal::disable_raw_mode;
        if self.bracketed_paste {
            let _ = execute!(std::io::stderr(), DisableBracketedPaste);
        }
        let _ = disable_raw_mode();
    }
}

pub fn prompt_secret(label: &str) -> Result<String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        return Ok(line.trim_end_matches(['\r', '\n']).to_string());
    }
    eprint!("{label}");
    std::io::stderr().flush().ok();
    let _guard = SecretTerminalGuard::enter()?;
    let mut password = String::new();
    let result = loop {
        let event = match event::read() {
            Ok(event) => event,
            Err(err) => break Err(anyhow!(err)),
        };
        match event {
            Event::Paste(text) => {
                password.push_str(text.trim_end_matches(['\r', '\n']));
            }
            Event::Key(key) => {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Enter => break Ok(password),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        break Err(anyhow!("cancelled"));
                    }
                    KeyCode::Char(ch) => password.push(ch),
                    KeyCode::Backspace => {
                        password.pop();
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    };
    drop(_guard);
    eprintln!();
    result
}

pub async fn relay_user(
    data_dir: &Path,
    database_url: Option<&str>,
    cmd: &RelayUserCmd,
    json_mode: bool,
) -> Result<i32> {
    let opened = Database::open(OpenOptions {
        data_dir,
        database_url,
        schema: None,
        bootstrap_admin: false,
        mint_legacy_admin: false,
    })
    .await
    .map_err(|err| anyhow!(err.to_string()))?;
    let db = opened.db;
    match cmd {
        RelayUserCmd::Add {
            username,
            password_stdin,
            admin,
        } => {
            let password = read_password(*password_stdin, "password: ")?;
            let role = if *admin { "admin" } else { "user" };
            let user = db
                .create_user(username, &password, role)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                json_mode,
                json!({"ok": true, "username": user.username, "role": user.role}),
                || println!("added {} ({})", user.username, user.role),
            );
        }
        RelayUserCmd::List => {
            let users = db
                .list_users()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            let value = users
                .iter()
                .map(|user| {
                    json!({
                        "username": user.username,
                        "role": user.role,
                        "disabled": user.disabled,
                        "totp": user.totp_enabled,
                    })
                })
                .collect::<Vec<_>>();
            emit(json_mode, json!({"users": value}), || {
                for user in &users {
                    println!("{} {} disabled={}", user.username, user.role, user.disabled);
                }
            });
        }
        RelayUserCmd::Passwd {
            username,
            password_stdin,
        } => {
            let password = read_password(*password_stdin, "password: ")?;
            db.set_password(username, &password)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true, "username": username}), || {
                println!("password updated for {username}");
            });
        }
        RelayUserCmd::Disable { username } => {
            db.set_disabled(username, true)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                println!("disabled {username}")
            });
        }
        RelayUserCmd::Enable { username } => {
            db.set_disabled(username, false)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                println!("enabled {username}")
            });
        }
        RelayUserCmd::Rm { username } => {
            db.remove_user(username)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                println!("removed {username}")
            });
        }
        RelayUserCmd::SetRole { username, role } => {
            db.set_role(username, role)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true, "role": role}), || {
                println!("{username} is now {role}");
            });
        }
    }
    Ok(0)
}

pub async fn share_cmd(
    client: &Client,
    node: &str,
    with: &str,
    access: &str,
    json_mode: bool,
) -> Result<i32> {
    let policy = parse_access(access)?;
    client
        .share_node(node, with, policy)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    emit(
        json_mode,
        json!({"ok": true, "node": node, "with": with, "access": access}),
        || println!("shared {node} with {with} ({access})"),
    );
    Ok(0)
}

pub async fn unshare_cmd(client: &Client, node: &str, with: &str, json_mode: bool) -> Result<i32> {
    client
        .unshare_node(node, with)
        .await
        .map_err(|err| anyhow!(err.to_string()))?;
    emit(
        json_mode,
        json!({"ok": true, "node": node, "with": with}),
        || {
            println!("removed {with} from {node}");
        },
    );
    Ok(0)
}

pub async fn token_cmd(client: &Client, action: &TokenAction, json_mode: bool) -> Result<i32> {
    match action {
        TokenAction::Create {
            name,
            access,
            ttl_minutes,
            uses,
        } => {
            let policy = parse_access(access)?;
            let info = client
                .create_enrollment_token(name, policy, ttl_minutes.saturating_mul(60), *uses)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                json_mode,
                json!({
                    "id": info.id,
                    "token": info.token,
                    "name": info.name,
                    "access": info.policy.preset_name(),
                    "expires_unix": info.expires_unix,
                    "uses": info.uses,
                }),
                || {
                    eprintln!(
                        "enrollment token {} for {} ({}, {} uses)",
                        info.id,
                        info.name,
                        info.policy.preset_name(),
                        info.uses
                    );
                    println!("{}", info.token);
                },
            );
        }
        TokenAction::List => {
            let tokens = client
                .list_enrollment_tokens()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"tokens": tokens}), || {
                for token in &tokens {
                    println!(
                        "{} {} {} {} remaining={}",
                        token.id, token.name, token.state, token.owner, token.uses_remaining
                    );
                }
            });
        }
        TokenAction::Revoke { id } => {
            client
                .revoke_enrollment_token(id)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true, "id": id}), || {
                println!("revoked {id}")
            });
        }
    }
    Ok(0)
}

pub async fn user_cmd(client: &Client, action: &UserAction, json_mode: bool) -> Result<i32> {
    match action {
        UserAction::Add {
            username,
            password_stdin,
            admin,
        } => {
            let password = read_password(*password_stdin, "password: ")?;
            let created = client
                .user_add(username, &password, *admin)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, created, || println!("added {username}"));
        }
        UserAction::List => {
            let users = client
                .user_list()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"users": users}), || {
                for user in &users {
                    println!("{} {} disabled={}", user.username, user.role, user.disabled);
                }
            });
        }
        UserAction::Passwd {
            username,
            password_stdin,
        } => {
            let password = read_password(*password_stdin, "password: ")?;
            client
                .user_passwd(username, &password)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                println!("password updated")
            });
        }
        UserAction::Disable { username } => {
            client
                .user_set_disabled(username, true)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                println!("disabled {username}")
            });
        }
        UserAction::Enable { username } => {
            client
                .user_set_disabled(username, false)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                println!("enabled {username}")
            });
        }
        UserAction::Rm { username } => {
            client
                .user_remove(username)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                println!("removed {username}")
            });
        }
        UserAction::SetRole { username, role } => {
            client
                .user_set_role(username, role)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true, "role": role}), || {
                println!("{username} is now {role}")
            });
        }
        UserAction::Totp { action } => match action {
            TotpAction::Enable => {
                let (secret, url) = client
                    .totp_begin()
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                emit(json_mode, json!({"secret": secret, "url": url}), || {
                    println!("secret: {secret}");
                    println!("url: {url}");
                    eprintln!("confirm with: agentlink user totp confirm CODE");
                });
            }
            TotpAction::Confirm { code } => {
                client
                    .totp_confirm(code)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                emit(json_mode, json!({"ok": true}), || {
                    println!("authenticator enabled")
                });
            }
            TotpAction::Disable => {
                client
                    .totp_disable()
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                emit(json_mode, json!({"ok": true}), || {
                    println!("authenticator disabled")
                });
            }
        },
    }
    Ok(0)
}
