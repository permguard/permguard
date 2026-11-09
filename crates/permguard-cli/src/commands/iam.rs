// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard iam …` (iteration 02, TC-6, `2-security/7` Security: command line): the IAM Host's
//! directory and access tokens through its Host listener. A `client_secret` goes to a new file
//! only its owner reads, never to the output; a token is never shown, only its `jti` and status.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use permguard_host::api::directory::Plain;
use permguard_host::api::service_accounts::{
    CreateCredential, CreateServiceAccount, UpdateServiceAccount,
};
use permguard_host::api::tokens::RevokeToken;

use super::directory::client;
use super::host::{Reserved, online_host, render_json, request_id};
use crate::args::{CredentialsAction, IamAction, ServiceAccountsAction, TokensAction};
use crate::failure::{EXIT_READY, Failure};
use crate::trace::Trace;

/// Runs one `iam …` command.
pub fn iam_command(
    globals: &crate::args::Globals,
    action: IamAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        IamAction::Grants { action } => super::host::grants(globals, action, trace),
        IamAction::Roles { action } => super::directory::roles(globals, action, trace),
        IamAction::Users { action } => super::directory::users(globals, action, trace),
        IamAction::Providers { action } => super::directory::providers(globals, action, trace),
        IamAction::Recovery { action } => super::directory::recovery(globals, action, trace),
        IamAction::ServiceAccounts { action } => service_accounts(globals, action, trace),
        IamAction::Credentials { action } => credentials(globals, action, trace),
        IamAction::Tokens { action } => tokens(globals, action, trace),
        IamAction::Token {
            scope,
            role,
            audience,
            target,
            out,
        } => {
            let mut asked = permguard_control_client::token_source::Asked {
                scope: scope.unwrap_or_default().replace(',', " "),
                audience,
                target,
            };
            if let Some(role) = role {
                asked = asked
                    .elevated(&role)
                    .map_err(|failure| Failure::from_client(&failure))?;
            }
            token(globals, asked, &out, trace)
        }
    }
}

fn plain() -> Plain {
    Plain {
        request_id: request_id(),
        expected_revision: None,
    }
}

fn service_accounts(
    globals: &crate::args::Globals,
    action: ServiceAccountsAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let backend = online_host(globals, trace, false)?;
    let answer = match action {
        ServiceAccountsAction::List => {
            serde_json::to_value(backend.service_accounts().map_err(client)?)
        }
        ServiceAccountsAction::Get { name } => {
            serde_json::to_value(backend.service_account(&name).map_err(client)?)
        }
        ServiceAccountsAction::Create {
            name,
            owner,
            description,
        } => serde_json::to_value(
            backend
                .create_service_account(&CreateServiceAccount {
                    request_id: request_id(),
                    expected_revision: None,
                    name,
                    owner,
                    description,
                })
                .map_err(client)?,
        ),
        ServiceAccountsAction::Update {
            name,
            owner,
            description,
        } => {
            if owner.is_none() && description.is_none() {
                return Err(Failure::usage(
                    "an update changes something: --owner or --description",
                ));
            }
            serde_json::to_value(
                backend
                    .update_service_account(
                        &name,
                        &UpdateServiceAccount {
                            request_id: request_id(),
                            expected_revision: None,
                            owner,
                            description,
                        },
                    )
                    .map_err(client)?,
            )
        }
        ServiceAccountsAction::Suspend { name } => serde_json::to_value(
            backend
                .set_service_account_status(&name, false, &plain())
                .map_err(client)?,
        ),
        ServiceAccountsAction::Resume { name } => serde_json::to_value(
            backend
                .set_service_account_status(&name, true, &plain())
                .map_err(client)?,
        ),
        ServiceAccountsAction::Delete { name } => serde_json::to_value(
            backend
                .delete_service_account(&name, &plain())
                .map_err(client)?,
        ),
    }
    .map_err(|error| Failure::internal(format!("rendering the IAM Host's answer: {error}")))?;
    render_json(&answer, globals, trace)?;
    Ok(ExitCode::from(EXIT_READY))
}

/// A public key file as the IAM Host takes it: [`crate::credentials::public_key`].
fn public_key_of(path: &Path) -> Result<BTreeMap<String, String>, Failure> {
    let bytes = std::fs::read(path)
        .map_err(|error| Failure::usage(format!("--public-key {}: {error}", path.display())))?;
    crate::credentials::public_key(&bytes)
        .map_err(|why| Failure::usage(format!("--public-key {}: {why}", path.display())))
}

/// A certificate binding: [`crate::credentials::certificate_binding`].
fn spki_binding(path: &Path) -> Result<String, Failure> {
    let bytes = std::fs::read(path)
        .map_err(|error| Failure::usage(format!("--certificate {}: {error}", path.display())))?;
    crate::credentials::certificate_binding(&bytes)
        .map_err(|why| Failure::usage(format!("--certificate {}: {why}", path.display())))
}

fn credentials(
    globals: &crate::args::Globals,
    action: CredentialsAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let backend = online_host(globals, trace, false)?;
    let answer = match action {
        CredentialsAction::List { account } => {
            serde_json::to_value(backend.credentials(&account).map_err(client)?)
        }
        CredentialsAction::Revoke { account, id } => serde_json::to_value(
            backend
                .revoke_credential(&account, &id, &plain())
                .map_err(client)?,
        ),
        CredentialsAction::Create {
            account,
            secret_out,
            public_key,
            certificate,
            san_uri,
            expires,
        } => {
            // The secret's file first: a file that exists is refused before the IAM Host makes a
            // secret nobody could keep.
            let reserved = secret_out.as_deref().map(Reserved::claim).transpose()?;
            let (kind, public_key, certificate) = match (public_key, certificate, san_uri) {
                (Some(path), None, None) => ("private_key_jwt", Some(public_key_of(&path)?), None),
                (None, Some(path), None) => ("tls_client_auth", None, Some(spki_binding(&path)?)),
                (None, None, Some(uri)) => ("tls_client_auth", None, Some(uri)),
                _ => ("client_secret", None, None),
            };
            let mut created = backend
                .create_credential(
                    &account,
                    &CreateCredential {
                        request_id: request_id(),
                        expected_revision: None,
                        kind: kind.to_owned(),
                        public_key,
                        certificate,
                        expires_at: expires,
                    },
                )
                .map_err(client)?;
            match (reserved, created.client_secret.take()) {
                (Some(reserved), Some(secret)) => {
                    reserved.fill(secret.as_bytes())?;
                    trace.say(format!(
                        "the secret of credential {} is written; it is not shown again",
                        created.credential.id
                    ));
                }
                (Some(_), None) => {
                    return Err(Failure::unavailable(
                        "the IAM Host answered no secret for a new client_secret credential",
                    ));
                }
                (None, _) => {}
            }
            serde_json::to_value(&created)
        }
    }
    .map_err(|error| Failure::internal(format!("rendering the IAM Host's answer: {error}")))?;
    render_json(&answer, globals, trace)?;
    Ok(ExitCode::from(EXIT_READY))
}

fn tokens(
    globals: &crate::args::Globals,
    action: TokensAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let backend = online_host(globals, trace, false)?;
    let answer = match action {
        TokensAction::List { subject, status } => {
            if status
                .as_deref()
                .is_some_and(|held| !matches!(held, "valid" | "suspended" | "invalid"))
            {
                return Err(Failure::usage(
                    "--status is one of valid, suspended or invalid",
                ));
            }
            let mut listed = backend.tokens().map_err(client)?;
            listed.tokens.retain(|token| {
                subject
                    .as_deref()
                    .is_none_or(|wanted| token.subject == wanted)
                    && status
                        .as_deref()
                        .is_none_or(|wanted| token.status == wanted)
            });
            serde_json::to_value(listed)
        }
        TokensAction::Revoke { jti } => serde_json::to_value(
            backend
                .revoke_token(
                    &jti,
                    &RevokeToken {
                        request_id: request_id(),
                    },
                )
                .map_err(client)?,
        ),
    }
    .map_err(|error| Failure::internal(format!("rendering the IAM Host's answer: {error}")))?;
    render_json(&answer, globals, trace)?;
    Ok(ExitCode::from(EXIT_READY))
}

fn token(
    globals: &crate::args::Globals,
    asked: permguard_control_client::token_source::Asked,
    out: &Path,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let reserved = Reserved::claim(out)?;
    // A configured client's token, or else the person's: the session --token-file holds,
    // exchanged at the IAM Host.
    let source = match crate::client_token::source(globals, asked.clone(), trace)? {
        Some(source) => source,
        None => crate::client_token::exchange(globals, asked, trace)?.ok_or_else(|| {
            Failure::usage(
                "no client is configured and no session is held: --client-id with \
                 --client-secret-file, --client-key-file or a certificate, and --iam-endpoint; \
                 or a session from `permguard login` in --token-file",
            )
        })?,
    };
    let issued = source
        .token()
        .map_err(|failure| Failure::from_client(&failure))?;
    reserved.fill(issued.token.expose())?;
    render_json(
        &serde_json::json!({
            "out": out,
            "expires_at": permguard_core::time::to_rfc3339(
                i64::try_from(issued.expires_at).unwrap_or(i64::MAX)
            ),
        }),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}
