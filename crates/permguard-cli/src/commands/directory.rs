// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard host roles`, `host users`, `host providers`, and `login`, `logout`, `password`,
//! `factor` (WP-8.1, `5-command-line/2` Roles, Local users and sign-in, Identity providers).
//!
//! A password is read from standard input, never an argument or the environment, and never
//! printed. A deletion with `--revoke-grants` revokes the grants first, each its own plan and
//! run, so a crash between two steps only ever leaves less access.

use std::io::Read as _;
use std::process::ExitCode;

use permguard_control_client::host::Host;
use permguard_host::api::directory::{
    CreateRole, CreateUser, Link, Member, Plain, SetPassword, UpdateRole, UpdateUser,
};

use super::host::{online_host, render_json, request_id};
use crate::args::{
    FactorAction, Globals, ProvidersAction, RoleMembersAction, RolesAction, UsersAction, Who,
};
use crate::failure::{EXIT_READY, Failure};
use crate::trace::Trace;

pub(super) fn client(failure: permguard_control_client::catalog::Failure) -> Failure {
    Failure::from_client(&failure)
}

/// The password on standard input: typed at a terminal, one line read with echo off after a
/// prompt on standard error; piped, everything up to the end, one trailing line break dropped.
fn password_from_stdin() -> Result<String, Failure> {
    if let Some(typed) = typed_secret("Password: ")? {
        return Ok(typed);
    }
    let mut text = String::new();
    std::io::stdin()
        .take(4 * 1024)
        .read_to_string(&mut text)
        .map_err(|error| {
            Failure::usage(format!("reading the password from standard input: {error}"))
        })?;
    let password = text.strip_suffix('\n').unwrap_or(&text);
    let password = password.strip_suffix('\r').unwrap_or(password);
    if password.is_empty() {
        return Err(Failure::usage("standard input held no password"));
    }
    Ok(password.to_owned())
}

/// The two lines of `password`: the current password, then the new one; typed at a terminal, each
/// after its own prompt with echo off.
fn two_passwords_from_stdin() -> Result<(String, String), Failure> {
    if let Some(current) = typed_secret("Current password: ")? {
        let new = typed_secret("New password: ")?.unwrap_or_default();
        if new.is_empty() {
            return Err(Failure::usage("no new password was typed"));
        }
        return Ok((current, new));
    }
    let mut text = String::new();
    std::io::stdin()
        .take(8 * 1024)
        .read_to_string(&mut text)
        .map_err(|error| Failure::usage(format!("reading standard input: {error}")))?;
    let mut lines = text.lines();
    match (lines.next(), lines.next()) {
        (Some(current), Some(new)) if !current.is_empty() && !new.is_empty() => {
            Ok((current.to_owned(), new.to_owned()))
        }
        _ => Err(Failure::usage(
            "standard input holds the current password on one line and the new one on the next",
        )),
    }
}

/// One secret typed at the terminal standard input is, with echo off; `None` when standard input
/// is not a terminal, and is then read as piped.
#[cfg(unix)]
fn typed_secret(prompt: &str) -> Result<Option<String>, Failure> {
    use std::io::{BufRead as _, IsTerminal as _, Write as _};
    use std::os::fd::AsFd as _;

    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Ok(None);
    }
    let terminal = |error: rustix::io::Errno| {
        Failure::usage(format!("reading the password from the terminal: {error}"))
    };
    let fd = stdin.as_fd();
    let original = tcgetattr(fd).map_err(terminal)?;
    let mut hidden = original.clone();
    hidden.local_modes.remove(LocalModes::ECHO);
    hidden.local_modes.insert(LocalModes::ECHONL);
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    tcsetattr(fd, OptionalActions::Now, &hidden).map_err(terminal)?;
    let mut line = String::new();
    let read = stdin.lock().take(4 * 1024).read_line(&mut line);
    // Echo comes back whatever the read did.
    let restored = tcsetattr(fd, OptionalActions::Now, &original);
    read.map_err(|error| Failure::usage(format!("reading the password: {error}")))?;
    restored.map_err(terminal)?;
    let typed = line.trim_end_matches(['\n', '\r']);
    if typed.is_empty() {
        return Err(Failure::usage("no password was typed"));
    }
    Ok(Some(typed.to_owned()))
}

/// Elsewhere a terminal is not switched to echo off: a password is piped in.
#[cfg(not(unix))]
fn typed_secret(_prompt: &str) -> Result<Option<String>, Failure> {
    use std::io::IsTerminal as _;

    if std::io::stdin().is_terminal() {
        return Err(Failure::usage(
            "pipe the password into standard input: a terminal here would show it as it is typed",
        ));
    }
    Ok(None)
}

/// The principal `who` names: a local user, a provider's subject or issuer, or an exact one.
pub(super) fn principal_of(backend: &dyn Host, who: &Who) -> Result<String, Failure> {
    if let Some(local) = &who.local {
        return Ok(format!("user:{local}"));
    }
    if let Some(principal) = &who.principal {
        return Ok(principal.clone());
    }
    let providers = backend.providers().map_err(client)?;
    let issuer = |name: &str| {
        providers
            .providers
            .iter()
            .find(|provider| provider.name == name)
            .map(|provider| provider.issuer.clone())
            .ok_or_else(|| {
                Failure::usage(format!(
                    "no identity provider is named `{name}`: `permguard host providers list` names them"
                ))
            })
    };
    if let Some(user) = &who.user {
        let (name, value) = user
            .split_once(':')
            .filter(|(name, value)| !name.is_empty() && !value.is_empty())
            .ok_or_else(|| Failure::usage(format!("`{user}` is not `<provider>:<value>`")))?;
        return Ok(format!("oidc:{}#{value}", issuer(name)?));
    }
    if let Some(name) = &who.issuer {
        return Ok(format!("oidc:{}", issuer(name)?));
    }
    Err(Failure::usage(
        "name a member: --local, --user, --issuer or --principal",
    ))
}

/// Revokes every active grant of `principal`, each its own plan and run.
fn revoke_grants_of(backend: &dyn Host, principal: &str, trace: &Trace) -> Result<usize, Failure> {
    let grants = backend.grants(Some(principal), None).map_err(client)?;
    let mut revoked = 0;
    for grant in grants
        .grants
        .iter()
        .filter(|grant| grant.status == "active")
    {
        let planned = backend
            .plan_grant_revoke(
                &grant.grant_id,
                &permguard_host::api::PlanRevoke {
                    request_id: request_id(),
                    expected_revision: Some(grant.revision),
                },
            )
            .map_err(client)?;
        backend
            .run_grant_revoke(
                &grant.grant_id,
                &permguard_host::api::RunRevoke {
                    request_id: request_id(),
                    receipt: planned.receipt,
                },
            )
            .map_err(client)?;
        trace.say(format!("revoked grant {} of {principal}", grant.grant_id));
        revoked += 1;
    }
    Ok(revoked)
}

pub(super) fn roles(
    globals: &Globals,
    action: RolesAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let backend = online_host(globals, trace, false)?;
    match action {
        RolesAction::List => render_json(&backend.roles().map_err(client)?, globals, trace)?,
        RolesAction::Get { name } => {
            render_json(&backend.role(&name).map_err(client)?, globals, trace)?
        }
        RolesAction::Create {
            name,
            description,
            expected_revision,
        } => render_json(
            &backend
                .create_role(&CreateRole {
                    request_id: request_id(),
                    expected_revision,
                    name,
                    description,
                })
                .map_err(client)?,
            globals,
            trace,
        )?,
        RolesAction::Update {
            name,
            description,
            expected_revision,
        } => render_json(
            &backend
                .update_role(
                    &name,
                    &UpdateRole {
                        request_id: request_id(),
                        expected_revision,
                        description,
                    },
                )
                .map_err(client)?,
            globals,
            trace,
        )?,
        RolesAction::Delete {
            name,
            revoke_grants,
            expected_revision,
        } => {
            if revoke_grants {
                revoke_grants_of(backend.as_ref(), &format!("role:{name}"), trace)?;
            }
            render_json(
                &backend
                    .delete_role(
                        &name,
                        &Plain {
                            request_id: request_id(),
                            expected_revision,
                        },
                    )
                    .map_err(client)?,
                globals,
                trace,
            )?;
        }
        RolesAction::Members { action } => {
            let (role, who, add) = match action {
                RoleMembersAction::Add { role, who } => (role, who, true),
                RoleMembersAction::Remove { role, who } => (role, who, false),
            };
            let member = Member {
                request_id: request_id(),
                expected_revision: None,
                member: principal_of(backend.as_ref(), &who)?,
            };
            let answer = if add {
                backend.add_member(&role, &member)
            } else {
                backend.remove_member(&role, &member)
            }
            .map_err(client)?;
            render_json(&answer, globals, trace)?;
        }
        RolesAction::Grant {
            name,
            operations,
            selector,
            types,
            expires,
        } => render_json(
            &backend
                .create_grant(&permguard_host::api::CreateGrant {
                    request_id: request_id(),
                    expected_revision: None,
                    principal: format!("role:{name}"),
                    operations,
                    selector,
                    resource_types: types,
                    constraints: Default::default(),
                    expires_at: expires,
                })
                .map_err(client)?,
            globals,
            trace,
        )?,
        RolesAction::Apply { action } => {
            return super::roles_apply::apply(globals, backend.as_ref(), action, trace);
        }
        RolesAction::Of { who } => {
            let principal = principal_of(backend.as_ref(), &who)?;
            let roles = backend.roles_of(&principal).map_err(client)?;
            render_json(
                &serde_json::json!({"principal": principal, "roles": roles}),
                globals,
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

pub(super) fn users(
    globals: &Globals,
    server_config: Option<&std::path::Path>,
    action: UsersAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    if let UsersAction::Bootstrap {
        name,
        email,
        password_stdin,
    } = action
    {
        return bootstrap(globals, server_config, &name, email, password_stdin, trace);
    }
    let backend = online_host(globals, trace, false)?;
    let plain = || Plain {
        request_id: request_id(),
        expected_revision: None,
    };
    let answer: serde_json::Value = match action {
        UsersAction::List => serde_json::to_value(backend.users().map_err(client)?),
        UsersAction::Get { name } => serde_json::to_value(backend.user(&name).map_err(client)?),
        UsersAction::Create {
            name,
            email,
            display,
            password_stdin,
        } => serde_json::to_value(
            backend
                .create_user(&CreateUser {
                    request_id: request_id(),
                    expected_revision: None,
                    name,
                    email,
                    display,
                    password: if password_stdin {
                        Some(password_from_stdin()?)
                    } else {
                        None
                    },
                })
                .map_err(client)?,
        ),
        UsersAction::Update {
            name,
            email,
            display,
        } => serde_json::to_value(
            backend
                .update_user(
                    &name,
                    &UpdateUser {
                        request_id: request_id(),
                        expected_revision: None,
                        email,
                        display,
                    },
                )
                .map_err(client)?,
        ),
        UsersAction::Password { name, .. } => serde_json::to_value(
            backend
                .set_password(
                    &name,
                    &SetPassword {
                        request_id: request_id(),
                        password: password_from_stdin()?,
                    },
                )
                .map_err(client)?,
        ),
        UsersAction::Disable { name } => serde_json::to_value(
            backend
                .set_user_status(&name, false, &plain())
                .map_err(client)?,
        ),
        UsersAction::Enable { name } => serde_json::to_value(
            backend
                .set_user_status(&name, true, &plain())
                .map_err(client)?,
        ),
        UsersAction::FactorReset { name } => {
            serde_json::to_value(backend.reset_factor(&name, &plain()).map_err(client)?)
        }
        UsersAction::Unlock { name } => Ok(serde_json::json!({
            "user": name,
            "unlocked": backend.unlock_user(&name).map_err(client)?,
        })),
        UsersAction::Link { name, who } => {
            serde_json::to_value(link(backend.as_ref(), &name, &who, true)?)
        }
        UsersAction::Unlink { name, who } => {
            serde_json::to_value(link(backend.as_ref(), &name, &who, false)?)
        }
        UsersAction::Delete {
            name,
            revoke_grants,
        } => {
            if revoke_grants {
                revoke_grants_of(backend.as_ref(), &format!("user:{name}"), trace)?;
            }
            serde_json::to_value(backend.delete_user(&name, &plain()).map_err(client)?)
        }
        UsersAction::Bootstrap { .. } => unreachable!("answered above"),
    }
    .map_err(|error| Failure::internal(format!("rendering the Host answer: {error}")))?;
    render_json(&answer, globals, trace)?;
    Ok(ExitCode::from(EXIT_READY))
}

/// Links, or unlinks, the subject `who` names to the user `name`.
fn link(
    backend: &dyn Host,
    name: &str,
    who: &Who,
    linked: bool,
) -> Result<permguard_host::api::directory::Changed, Failure> {
    let subject = principal_of(backend, who)?;
    backend
        .link_user(
            name,
            linked,
            &Link {
                request_id: request_id(),
                subject,
            },
        )
        .map_err(client)
}

/// The first administrator, offline: a user and `authz.admin` on the Host, one operation each.
fn bootstrap(
    globals: &Globals,
    server_config: Option<&std::path::Path>,
    name: &str,
    email: Option<String>,
    password_stdin: bool,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    use permguard_host::authz::directory::{Change, Directory, Recovering, user_principal};
    use permguard_host::operations::journal::Initiator;

    if email.is_none() && !password_stdin {
        return Err(Failure::usage(
            "the first administrator signs in somehow: give it a password (--password-stdin) or an email its provider sign-in links (--email)",
        ));
    }
    let password = if password_stdin {
        let password = password_from_stdin()?;
        permguard_host::authz::password::check_policy(
            name,
            &password,
            permguard_host::authz::password::DEFAULT_MIN_LENGTH,
        )
        .map_err(Failure::usage)?;
        Some(permguard_host::authz::password::hash(&password).map_err(Failure::internal)?)
    } else {
        None
    };
    let volume = super::host::volume_of(globals)?;
    let held = super::host::claim(&volume, trace)?;
    let store = super::host::grant_store_of(&held, trace)?;
    let (directory, _) =
        Directory::open(&held).map_err(|error| Failure::unavailable(error.to_string()))?;
    let mutations = super::host::offline_engine(&held, server_config, trace)?;
    mutations
        .recover(&permguard_host::operations::grants::Grants(&store))
        .map_err(|error| Failure::unavailable(format!("recovering grant mutations: {error}")))?;
    mutations
        .recover(&Recovering(&directory))
        .map_err(|error| {
            Failure::unavailable(format!("recovering directory mutations: {error}"))
        })?;
    let now = permguard_host::authz::store::now();
    let principal = user_principal(name);
    let created = if directory.user(name).is_some() {
        false
    } else {
        permguard_host::operations::directory::change(
            &mutations,
            &directory,
            Initiator::System("bootstrap".to_owned()),
            Change::CreateUser {
                name: name.to_owned(),
                email: email.clone(),
                display: None,
                password,
            },
            "bootstrap",
            now,
            None,
        )
        .map_err(|error| Failure::usage(error.to_string()))?;
        true
    };
    let admin =
        permguard_core::authz::Principal::new(principal.as_str()).map_err(Failure::usage)?;
    let holds = store.allows_at(now).permits(
        &admin,
        permguard_core::authz::operations::AUTHZ_ADMIN,
        &permguard_core::authz::Resource::host(),
    );
    let granted = if holds {
        None
    } else {
        Some(
            permguard_host::operations::grants::issue(
                &mutations,
                &store,
                Initiator::System("bootstrap".to_owned()),
                permguard_host::authz::Issue {
                    principal: admin,
                    operations: vec![permguard_core::authz::operations::AUTHZ_ADMIN.to_owned()],
                    selector: permguard_core::authz::Selector::exactly(
                        permguard_core::authz::Resource::host(),
                    ),
                    resource_types: vec![permguard_core::authz::resource_types::HOST.to_owned()],
                    constraints: [("bootstrap".to_owned(), "first administrator".to_owned())]
                        .into(),
                    issued_by: "bootstrap".to_owned(),
                    expires_at: None,
                },
                now,
            )
            .map_err(|error| Failure::usage(error.to_string()))?
            .grant_id
            .to_string(),
        )
    };
    std::mem::forget(held);
    render_json(
        &serde_json::json!({
            "user": name,
            "principal": principal,
            "email": email,
            "created": created,
            "grant": granted,
            "already_administrator": holds,
        }),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}

pub(super) fn providers(
    globals: &Globals,
    action: ProvidersAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let backend = online_host(globals, trace, false)?;
    match action {
        ProvidersAction::List => {
            render_json(&backend.providers().map_err(client)?, globals, trace)?
        }
        ProvidersAction::Refresh { name } => {
            render_json(
                &backend.refresh_provider(&name).map_err(client)?,
                globals,
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

/// Where `login` keeps the session: `--token-file`, or `~/.permguard/session`.
fn session_file(globals: &Globals) -> Result<std::path::PathBuf, Failure> {
    match &globals.token_file {
        Some(path) => Ok(path.clone()),
        None => crate::settings::home_directory()
            .map(|home| home.join(".permguard").join("session"))
            .map_err(|_| {
                Failure::usage("no home directory: name the session's file with --token-file")
            }),
    }
}

fn signin_at(
    globals: &Globals,
    url: &str,
    with_session: bool,
    trace: &Trace,
) -> Result<permguard_control_client::signin::SignIn, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    let mut effective = globals.clone();
    if with_session {
        effective.token_file = Some(session_file(globals)?);
    } else {
        effective.token_file = None;
    }
    let tls = crate::target::tls(&effective, &store, trace)?;
    permguard_control_client::signin::SignIn::new(
        url,
        &tls,
        crate::narrator::for_run(globals.verbose),
    )
    .map_err(Failure::usage)
}

pub fn login(
    globals: &Globals,
    url: &str,
    user: &str,
    code: Option<&str>,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let password = password_from_stdin()?;
    let opened = signin_at(globals, url, false, trace)?
        .sign_in(user, &password, code)
        .map_err(client)?;
    let file = session_file(globals)?;
    crate::token::write(&file, &opened.token).map_err(Failure::unavailable)?;
    render_json(
        &serde_json::json!({
            "user": opened.user,
            "expires_at": permguard_core::time::to_rfc3339(i64::try_from(opened.expires_at).unwrap_or(i64::MAX)),
            "opened": opened.opened,
            "token_file": file,
        }),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}

pub fn logout(globals: &Globals, url: &str, trace: &Trace) -> Result<ExitCode, Failure> {
    let file = session_file(globals)?;
    signin_at(globals, url, true, trace)?
        .sign_out()
        .map_err(client)?;
    let _ = std::fs::remove_file(&file);
    render_json(
        &serde_json::json!({"signed_out": true, "token_file": file}),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}

pub fn password(globals: &Globals, url: &str, trace: &Trace) -> Result<ExitCode, Failure> {
    let (current, new) = two_passwords_from_stdin()?;
    signin_at(globals, url, true, trace)?
        .change_password(&current, &new)
        .map_err(client)?;
    render_json(&serde_json::json!({"changed": true}), globals, trace)?;
    Ok(ExitCode::from(EXIT_READY))
}

pub fn factor(
    globals: &Globals,
    url: &str,
    action: FactorAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let signin = signin_at(globals, url, true, trace)?;
    match action {
        FactorAction::Begin => {
            let enrollment = signin
                .begin_factor(&password_from_stdin()?)
                .map_err(client)?;
            render_json(&enrollment, globals, trace)?;
        }
        FactorAction::Confirm { code } => {
            signin.confirm_factor(&code).map_err(client)?;
            render_json(&serde_json::json!({"confirmed": true}), globals, trace)?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}
