// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard iam …` (iteration 02, TC-6, `2-security/7` Security: command line): the IAM Host's
//! directory and access tokens through its Host listener. A `client_secret` goes to a new file
//! only its owner reads, never to the output; a token is never shown, only its `jti` and status.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
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
            audience,
            target,
            out,
        } => token(globals, &scope, audience, target, &out, trace),
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

/// A public key file as the IAM Host takes it: an Ed25519 or P-256 JWK, or the same key in a
/// PEM `PUBLIC KEY` (SubjectPublicKeyInfo).
fn public_key_of(path: &Path) -> Result<BTreeMap<String, String>, Failure> {
    use rustls::pki_types::pem::PemObject as _;

    let read = |why: String| Failure::usage(format!("--public-key {}: {why}", path.display()));
    let bytes = std::fs::read(path).map_err(|error| read(error.to_string()))?;
    if bytes.len() > 64 * 1024 {
        return Err(read("larger than a public key".to_owned()));
    }
    if let Ok(jwk) = serde_json::from_slice::<BTreeMap<String, serde_json::Value>>(&bytes) {
        // The public members only: a JWK carrying `d` is a private key, refused.
        if jwk.contains_key("d") {
            return Err(read(
                "is a private key: give the public key, the private one never leaves its holder"
                    .to_owned(),
            ));
        }
        return Ok(jwk
            .into_iter()
            .filter(|(name, _)| matches!(name.as_str(), "kty" | "crv" | "x" | "y"))
            .filter_map(|(name, value)| value.as_str().map(|text| (name, text.to_owned())))
            .collect());
    }
    let der = rustls::pki_types::SubjectPublicKeyInfoDer::from_pem_slice(&bytes)
        .map_err(|_| read("is neither a JWK nor a PEM public key".to_owned()))?;
    let der = der.as_ref();
    // The two encodings RFC 8410 and RFC 5480 give, their fixed prefixes before the key.
    const ED25519: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    const P256: &[u8] = &[
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    if let Some(key) = der.strip_prefix(ED25519).filter(|key| key.len() == 32) {
        return Ok(BTreeMap::from([
            ("kty".to_owned(), "OKP".to_owned()),
            ("crv".to_owned(), "Ed25519".to_owned()),
            ("x".to_owned(), URL_SAFE_NO_PAD.encode(key)),
        ]));
    }
    if let Some(point) = der
        .strip_prefix(P256)
        .filter(|point| point.len() == 65 && point[0] == 0x04)
    {
        return Ok(BTreeMap::from([
            ("kty".to_owned(), "EC".to_owned()),
            ("crv".to_owned(), "P-256".to_owned()),
            ("x".to_owned(), URL_SAFE_NO_PAD.encode(&point[1..33])),
            ("y".to_owned(), URL_SAFE_NO_PAD.encode(&point[33..])),
        ]));
    }
    Err(read(
        "is neither an Ed25519 nor a P-256 public key".to_owned(),
    ))
}

/// The `spki:sha256:` binding of a PEM certificate's public key, as the IAM Host matches a
/// connection's certificate.
fn spki_binding(path: &Path) -> Result<String, Failure> {
    use rustls::pki_types::pem::PemObject as _;

    let read = |why: &str| Failure::usage(format!("--certificate {}: {why}", path.display()));
    let certificate = rustls::pki_types::CertificateDer::from_pem_file(path)
        .map_err(|_| read("is not a PEM certificate"))?;
    let identity = permguard_transport::identity_of(&certificate)
        .ok_or_else(|| read("does not parse as an X.509 certificate"))?;
    let digest = identity
        .spki_sha256()
        .ok_or_else(|| read("carries no public key"))?;
    Ok(format!("spki:sha256:{digest}"))
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
    scope: &str,
    audience: Vec<String>,
    target: Vec<String>,
    out: &Path,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let reserved = Reserved::claim(out)?;
    let asked = permguard_control_client::token_source::Asked {
        scope: scope.replace(',', " "),
        audience,
        target,
    };
    let source = crate::client_token::source(globals, asked, trace)?.ok_or_else(|| {
        Failure::usage(
            "no client is configured: --client-id with --client-secret-file, \
                 --client-key-file or a certificate, and --iam-endpoint",
        )
    })?;
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
