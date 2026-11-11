// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard authority …` (`2-security/7`): the Authority Plane's service accounts, their scopes
//! and access keys, and its tokens, over REST or gRPC as `--authority-endpoint`'s scheme says;
//! offline, a new key for `admin` on a stopped server's volume. A secret key is written once to a
//! new file only its owner reads, and never printed.

use std::path::Path;
use std::process::ExitCode;

use permguard_control_client::authority::{Authority, Scope, TokenAsk};
use permguard_control_client::tls::Credential;

use super::host::{Reserved, render_json, request_id, rooted_file, volume_of};
use crate::args::{
    AuthorityAction, Globals, KeysOfAccountAction, ScopesAction, ServiceAccountsAction,
    TokenAction, TokensAction,
};
use crate::failure::{EXIT_READY, Failure};
use crate::trace::Trace;

/// Reads `<operations>@<selector>`, the operations comma separated.
pub fn scope_of(text: &str) -> Result<Scope, Failure> {
    let (operations, selector) = text.rsplit_once('@').ok_or_else(|| {
        Failure::usage(format!(
            "`{text}` is not a scope: `<operations>@<selector>`, the operations comma separated"
        ))
    })?;
    let operations: Vec<String> = operations
        .split(',')
        .map(str::trim)
        .filter(|operation| !operation.is_empty())
        .map(str::to_owned)
        .collect();
    if operations.is_empty() || selector.trim().is_empty() {
        return Err(Failure::usage(format!(
            "`{text}` names no operation or no selector"
        )));
    }
    Ok(Scope {
        operations,
        selector: selector.trim().to_owned(),
    })
}

fn scopes_of(texts: &[String]) -> Result<Vec<Scope>, Failure> {
    texts.iter().map(|text| scope_of(text)).collect()
}

/// The Authority Plane, as the configured client: its own connection, and the client's token.
fn authority(
    globals: &Globals,
    trace: &Trace,
) -> Result<Box<dyn Authority + Send + Sync>, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    // The operator's own token when one is given, otherwise the client's.
    let bearer = match crate::target::base_tls(globals, &store, trace)?.token {
        Some(given) => Some(given),
        None => crate::client_token::token(globals, &store, trace)?,
    };
    authority_as(globals, &store, bearer, trace)
}

/// The Authority Plane over its own connection, presenting `bearer`.
fn authority_as(
    globals: &Globals,
    store: &crate::settings::Store,
    bearer: Option<Credential>,
    trace: &Trace,
) -> Result<Box<dyn Authority + Send + Sync>, Failure> {
    let url = crate::client_token::authority_endpoint(globals, store).ok_or_else(|| {
        Failure::usage(
            "the Authority Plane is reached at --authority-endpoint or \
             auth.client.authority_endpoint",
        )
    })?;
    let tls = permguard_control_client::tls::TlsOptions {
        token: bearer,
        ..crate::client_token::authority_tls(globals, store, trace)?
    };
    permguard_control_client::authority::client(
        &url,
        &tls,
        crate::narrator::for_run(globals.verbose),
    )
    .map_err(Failure::usage)
}

/// Without a client and without `--token-file`, there is no token in use.
fn no_client() -> Failure {
    Failure::usage(
        "no client is configured: --secret-key-file or auth.client.secret_file, with \
         --authority-endpoint or auth.client.authority_endpoint; or --token-file",
    )
}

/// What a token says of itself, read from its payload, unverified: the Authority Plane and every
/// Plane verify it, this only names it.
fn claims_of(token: &Credential) -> Result<serde_json::Value, Failure> {
    use base64::Engine as _;

    let unreadable = || Failure::usage("the token in use is not a JWT this command can read");
    let token = std::str::from_utf8(token.expose()).map_err(|_| unreadable())?;
    let payload = token.trim().split('.').nth(1).ok_or_else(unreadable)?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| unreadable())?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| unreadable())?;
    if claims["jti"].as_str().is_none() {
        return Err(unreadable());
    }
    Ok(claims)
}

/// A claim's time as RFC 3339, when the token states it.
fn time_of(claims: &serde_json::Value, claim: &str) -> Option<String> {
    claims[claim].as_i64().map(permguard_core::time::to_rfc3339)
}

/// `authority whoami`: the token in use, `--token-file`'s or the client's, kept or obtained now.
fn whoami(globals: &Globals, trace: &Trace) -> Result<ExitCode, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    let (token, kept_in) = match crate::target::base_tls(globals, &store, trace)?.token {
        Some(given) => (given, None),
        None => {
            let token =
                crate::client_token::token(globals, &store, trace)?.ok_or_else(no_client)?;
            (token, crate::client_token::client_cache(globals, &store)?)
        }
    };
    let claims = claims_of(&token)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let expires_in = claims["exp"].as_u64().map(|exp| exp.saturating_sub(now));
    render_json(
        &serde_json::json!({
            "account": claims["sub"],
            "access_key": claims["client_id"],
            "scopes": claims["permguard_scopes"],
            "jti": claims["jti"],
            "issuer": claims["iss"],
            "audience": claims["aud"],
            "issued_at": time_of(&claims, "iat"),
            "expires_at": time_of(&claims, "exp"),
            "expires_in": expires_in,
            "source": if kept_in.is_some() { "client" } else { "token file" },
            "kept_in": kept_in.map(|path| path.display().to_string()),
        }),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}

/// `authority token forget`: the client's kept token dropped, valid still until it expires.
fn forget(globals: &Globals, trace: &Trace) -> Result<ExitCode, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    let path = crate::client_token::client_cache(globals, &store)?.ok_or_else(no_client)?;
    let forgotten = match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(Failure::internal(format!("{}: {error}", path.display())));
        }
    };
    render_json(
        &serde_json::json!({
            "forgotten": forgotten,
            "kept_in": path.display().to_string(),
        }),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}

/// `authority token revoke`: the token in use, `--token-file`'s or the client's kept one, revoked
/// by its own bearer and dropped; never a token obtained only to be revoked.
fn revoke_in_use(globals: &Globals, trace: &Trace) -> Result<ExitCode, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    let (token, kept_in) = match crate::target::base_tls(globals, &store, trace)?.token {
        Some(given) => (given, None),
        None => match crate::client_token::kept(globals, &store)? {
            Some((issued, path)) => (issued.token, Some(path)),
            None => {
                crate::client_token::client_cache(globals, &store)?.ok_or_else(no_client)?;
                render_json(
                    &serde_json::json!({
                        "revoked": null,
                        "reason": "no token is kept for this client: nothing to revoke",
                    }),
                    globals,
                    trace,
                )?;
                return Ok(ExitCode::from(EXIT_READY));
            }
        },
    };
    let jti = claims_of(&token)?["jti"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let authority = authority_as(globals, &store, Some(token), trace)?;
    let revoked = authority.revoke_token(&request_id(), &jti);
    // Revoked now, or refused as revoked or expired already: either way it is not kept.
    if let Some(path) = &kept_in
        && revoked.as_ref().map_or_else(
            |failure| failure.reason == permguard_core::codes::common::UNAUTHENTICATED,
            |_| true,
        )
    {
        let _ = std::fs::remove_file(path);
    }
    render_json(&revoked.map_err(failed)?, globals, trace)?;
    Ok(ExitCode::from(EXIT_READY))
}

fn failed(failure: permguard_control_client::catalog::Failure) -> Failure {
    Failure::from_client(&failure)
}

/// Runs one `authority …` command.
pub fn authority_command(
    globals: &Globals,
    action: AuthorityAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        AuthorityAction::ServiceAccounts { action } => accounts(globals, action, trace),
        AuthorityAction::Scopes { action } => scopes(globals, action, trace),
        AuthorityAction::Keys { action } => keys(globals, action, trace),
        AuthorityAction::Tokens { action } => tokens(globals, action, trace),
        AuthorityAction::Whoami => whoami(globals, trace),
        AuthorityAction::Token {
            action: Some(TokenAction::Forget),
            ..
        } => forget(globals, trace),
        AuthorityAction::Token {
            action: Some(TokenAction::Revoke),
            ..
        } => revoke_in_use(globals, trace),
        AuthorityAction::Token {
            action: None,
            scope,
            lifetime,
            out,
        } => {
            let out = out.ok_or_else(|| Failure::usage("the token is written to --out <file>"))?;
            token(globals, scope, lifetime, &out, trace)
        }
        AuthorityAction::AdminKey { secret_out } => admin_key(globals, &secret_out, trace),
    }
}

fn accounts(
    globals: &Globals,
    action: ServiceAccountsAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let authority = authority(globals, trace)?;
    match action {
        ServiceAccountsAction::List => {
            render_json(
                &authority.service_accounts().map_err(failed)?,
                globals,
                trace,
            )?;
        }
        ServiceAccountsAction::Get { name } => {
            render_json(
                &authority.service_account(&name).map_err(failed)?,
                globals,
                trace,
            )?;
        }
        ServiceAccountsAction::Create {
            name,
            description,
            scopes,
        } => {
            let scopes = scopes_of(&scopes)?;
            let created = authority
                .create_service_account(&request_id(), &name, &description, &scopes)
                .map_err(failed)?;
            render_json(&created, globals, trace)?;
        }
        ServiceAccountsAction::Update { name, description } => {
            let updated = authority
                .update_service_account(&request_id(), &name, &description)
                .map_err(failed)?;
            render_json(&updated, globals, trace)?;
        }
        ServiceAccountsAction::Suspend { name } => {
            let changed = authority
                .set_suspended(&request_id(), &name, true)
                .map_err(failed)?;
            render_json(&changed, globals, trace)?;
        }
        ServiceAccountsAction::Resume { name } => {
            let changed = authority
                .set_suspended(&request_id(), &name, false)
                .map_err(failed)?;
            render_json(&changed, globals, trace)?;
        }
        ServiceAccountsAction::Delete { name } => {
            let deleted = authority
                .delete_service_account(&request_id(), &name)
                .map_err(failed)?;
            render_json(&deleted, globals, trace)?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

fn scopes(globals: &Globals, action: ScopesAction, trace: &Trace) -> Result<ExitCode, Failure> {
    let authority = authority(globals, trace)?;
    match action {
        ScopesAction::Get { name } => {
            render_json(&authority.scopes(&name).map_err(failed)?, globals, trace)?;
        }
        ScopesAction::Set {
            name,
            scopes,
            revoke_tokens,
        } => {
            let scopes = scopes_of(&scopes)?;
            let set = authority
                .set_scopes(&request_id(), &name, &scopes, revoke_tokens)
                .map_err(failed)?;
            render_json(&set, globals, trace)?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

/// The text a key file holds: the access key and its secret key, one per line.
fn key_file(access_key: &str, secret_key: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(format!(
        "access_key: {access_key}\nsecret_key: {secret_key}\n"
    ))
}

fn keys(
    globals: &Globals,
    action: KeysOfAccountAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let authority = authority(globals, trace)?;
    match action {
        KeysOfAccountAction::List { name } => {
            render_json(
                &authority.access_keys(&name).map_err(failed)?,
                globals,
                trace,
            )?;
        }
        KeysOfAccountAction::Create {
            name,
            secret_out,
            expires,
        } => {
            // The file first: a secret the Authority Plane answered has somewhere to go.
            let reserved = Reserved::claim(&rooted_file(globals, &secret_out))?;
            let created = authority
                .create_access_key(&request_id(), &name, expires.as_deref())
                .map_err(failed)?;
            if created.secret_key.is_empty() {
                return Err(Failure::internal(
                    "the Authority Plane answered no secret key: delete the key and make another",
                ));
            }
            reserved.fill(key_file(&created.key.access_key, &created.secret_key).as_bytes())?;
            trace.say(format!(
                "the secret key is written to {}",
                secret_out.display()
            ));
            render_json(&created.key, globals, trace)?;
        }
        KeysOfAccountAction::Delete { name, key } => {
            let deleted = authority
                .delete_access_key(&request_id(), &name, &key)
                .map_err(failed)?;
            render_json(&deleted, globals, trace)?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

fn tokens(globals: &Globals, action: TokensAction, trace: &Trace) -> Result<ExitCode, Failure> {
    let authority = authority(globals, trace)?;
    match action {
        TokensAction::List { account, status } => {
            let tokens = authority
                .tokens(account.as_deref(), status.as_deref())
                .map_err(failed)?;
            render_json(&tokens, globals, trace)?;
        }
        TokensAction::Revoke { jti } => {
            let revoked = authority
                .revoke_token(&request_id(), &jti)
                .map_err(failed)?;
            render_json(&revoked, globals, trace)?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

/// `authority token`: a token for the configured client, written to a new owner-only file.
fn token(
    globals: &Globals,
    scope: Option<String>,
    lifetime: Option<u64>,
    out: &Path,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    // The key file read as every command reads it: only its owner's, or one root mounts.
    let (access_key, secret_key) =
        crate::client_token::credentials(globals, &store)?.ok_or_else(|| {
            Failure::usage(
                "a token is obtained with the client's secret key: --secret-key-file or \
                 auth.client.secret_file",
            )
        })?;
    let url = crate::client_token::authority_endpoint(globals, &store)
        .ok_or_else(|| Failure::usage("the Authority Plane is reached at --authority-endpoint"))?;
    let tls = crate::client_token::authority_tls(globals, &store, trace)?;
    let reserved = Reserved::claim(&rooted_file(globals, out))?;
    let authority = permguard_control_client::authority::client(
        &url,
        &tls,
        crate::narrator::for_run(globals.verbose),
    )
    .map_err(Failure::usage)?;
    let answer = authority
        .issue_token(&TokenAsk {
            access_key,
            secret_key,
            scope: scope.map(|scope| scope.replace(',', " ")),
            lifetime,
        })
        .map_err(failed)?;
    reserved.fill(answer.access_token.as_bytes())?;
    render_json(
        &serde_json::json!({
            "token_file": out.display().to_string(),
            "expires_in": answer.expires_in,
            "scope": answer.scope,
        }),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}

/// `authority admin-key --volume <dir>`: a new key for `admin`, the server stopped.
fn admin_key(globals: &Globals, secret_out: &Path, trace: &Trace) -> Result<ExitCode, Failure> {
    use permguard_authority_plane::{accounts::Accounts, admin};
    use permguard_host::storage::Dir;

    let volume = volume_of(globals)?;
    let held = super::host::claim(&volume, trace)?;
    let plane_dir = volume
        .join(permguard_host::composition::PLANES)
        .join("authority");
    if !plane_dir.is_dir() {
        return Err(Failure::usage(format!(
            "{} holds no Authority Plane: start the server with the Authority Plane once",
            volume.display()
        )));
    }
    let dir = Dir::open(&plane_dir)
        .map_err(|error| Failure::unavailable(format!("{}: {error}", plane_dir.display())))?;
    let options = held.journal_options(permguard_host::storage::journal::Options::default());
    let (accounts, _) = Accounts::open(&dir, options)
        .map_err(|error| Failure::unavailable(format!("opening the accounts: {error}")))?;
    let out = rooted_file(globals, secret_out);
    let access_key = admin::offline_key(
        &accounts,
        &plane_dir,
        &out,
        permguard_host::authz::store::now(),
    )
    .map_err(Failure::unavailable)?;
    drop(held);
    render_json(
        &serde_json::json!({
            "account": "admin",
            "access_key": access_key,
            "secret_file": out.display().to_string(),
        }),
        globals,
        trace,
    )?;
    Ok(ExitCode::from(EXIT_READY))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scope_reads_its_operations_and_its_selector() {
        let scope = scope_of("decision.evaluate, event.submit@plane/data/*")
            .unwrap_or_else(|_| unreachable!("a scope"));
        assert_eq!(scope.operations, vec!["decision.evaluate", "event.submit"]);
        assert_eq!(scope.selector, "plane/data/*");
        assert!(scope_of("decision.evaluate").is_err());
        assert!(scope_of("@plane/data/*").is_err());
    }
}
