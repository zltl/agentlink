//! Username sessions: local relay accounts and remote user, share, and token commands.

use std::io::Write;
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
    List,
    Passwd {
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    Disable {
        username: String,
    },
    Enable {
        username: String,
    },
    Rm {
        username: String,
    },
    SetRole {
        username: String,
        role: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum UserAction {
    Add {
        username: String,
        #[arg(long)]
        password_stdin: bool,
        #[arg(long)]
        admin: bool,
    },
    List,
    Passwd {
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    Disable {
        username: String,
    },
    Enable {
        username: String,
    },
    Rm {
        username: String,
    },
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
    Enable,
    Confirm { code: String },
    Disable,
}

#[derive(Subcommand, Debug)]
pub enum TokenAction {
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
    List,
    Revoke {
        id: String,
    },
}

pub fn read_password(password_stdin: bool, label: &str) -> Result<String> {
    if password_stdin {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        return Ok(line.trim().to_string());
    }
    prompt_secret(label)
}

pub fn prompt_secret(label: &str) -> Result<String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
    use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
    eprint!("{label}");
    std::io::stderr().flush().ok();
    enable_raw_mode().map_err(|err| anyhow!(err))?;
    let mut password = String::new();
    let result = loop {
        let event = match event::read() {
            Ok(event) => event,
            Err(err) => break Err(anyhow!(err)),
        };
        let Event::Key(key) = event else { continue };
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
    };
    disable_raw_mode().ok();
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
                json!({"username": user.username, "role": user.role}),
                || eprintln!("added {} ({})", user.username, user.role),
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
                    eprintln!("{} {} disabled={}", user.username, user.role, user.disabled);
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
                eprintln!("password updated for {username}");
            });
        }
        RelayUserCmd::Disable { username } => {
            db.set_disabled(username, true)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                eprintln!("disabled {username}")
            });
        }
        RelayUserCmd::Enable { username } => {
            db.set_disabled(username, false)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                eprintln!("enabled {username}")
            });
        }
        RelayUserCmd::Rm { username } => {
            db.remove_user(username)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                eprintln!("removed {username}")
            });
        }
        RelayUserCmd::SetRole { username, role } => {
            db.set_role(username, role)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true, "role": role}), || {
                eprintln!("{username} is now {role}");
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
        || eprintln!("shared {node} with {with} ({access})"),
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
            eprintln!("removed {with} from {node}");
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
                    eprintln!(
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
                eprintln!("revoked {id}")
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
            emit(json_mode, created, || eprintln!("added {username}"));
        }
        UserAction::List => {
            let users = client
                .user_list()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"users": users}), || {
                for user in &users {
                    eprintln!("{} {} disabled={}", user.username, user.role, user.disabled);
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
                eprintln!("password updated")
            });
        }
        UserAction::Disable { username } => {
            client
                .user_set_disabled(username, true)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                eprintln!("disabled {username}")
            });
        }
        UserAction::Enable { username } => {
            client
                .user_set_disabled(username, false)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                eprintln!("enabled {username}")
            });
        }
        UserAction::Rm { username } => {
            client
                .user_remove(username)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                eprintln!("removed {username}")
            });
        }
        UserAction::SetRole { username, role } => {
            client
                .user_set_role(username, role)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_mode, json!({"ok": true}), || {
                eprintln!("{username} is now {role}")
            });
        }
        UserAction::Totp { action } => match action {
            TotpAction::Enable => {
                let (secret, url) = client
                    .totp_begin()
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                emit(json_mode, json!({"secret": secret, "url": url}), || {
                    eprintln!("secret: {secret}");
                    eprintln!("url: {url}");
                    eprintln!("confirm with: agentlink user totp confirm CODE");
                });
            }
            TotpAction::Confirm { code } => {
                client
                    .totp_confirm(code)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                emit(json_mode, json!({"ok": true}), || {
                    eprintln!("authenticator enabled")
                });
            }
            TotpAction::Disable => {
                client
                    .totp_disable()
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                emit(json_mode, json!({"ok": true}), || {
                    eprintln!("authenticator disabled")
                });
            }
        },
    }
    Ok(0)
}
