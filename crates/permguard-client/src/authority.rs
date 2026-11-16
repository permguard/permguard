// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane, as a client sees it (`2-security/7`): its service accounts, their scopes
//! and access keys, the tokens it issued, and the token endpoint; one facade over REST and gRPC,
//! the scheme of one URL deciding which (`https` or `grpcs`, `http` or `grpc` on a loopback).
//!
//! The answers are the same views whichever transport carried them, and a refusal the same
//! `{class, code, message}`. A secret key is answered once, by the call that made it, and never
//! printed by `Debug`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::authority_v1 as proto;
use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::grpc::GrpcChannel;
use crate::http::Client;
use crate::tls::TlsOptions;

/// The token endpoint's path.
pub const TOKEN_PATH: &str = "/authority/v1/token";

/// One scope: operations on a selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub operations: Vec<String>,
    pub selector: String,
}

/// One access key; never its secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessKey {
    pub access_key: String,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
    pub status: String,
}

/// One service account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub name: String,
    pub description: String,
    pub status: String,
    pub scopes: Vec<Scope>,
    pub keys: Vec<AccessKey>,
    pub administrator: bool,
    pub created_at: String,
    pub updated_at: String,
    pub revision: u64,
}

/// One token the Authority Plane issued; never the token itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Token {
    pub jti: String,
    pub subject: String,
    pub account: String,
    pub access_key: String,
    pub scopes: Vec<Scope>,
    pub issued_at: String,
    pub expires_at: String,
    pub status: String,
    pub status_list: String,
    pub index: u64,
}

/// An account's scopes, after a read or a change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scopes {
    pub name: String,
    pub scopes: Vec<Scope>,
    pub revision: u64,
    pub tokens_revoked: u64,
}

/// A key made: the secret once.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyCreated {
    pub key: AccessKey,
    pub secret_key: String,
}

impl std::fmt::Debug for KeyCreated {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyCreated")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// What an account's deletion answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Deleted {
    pub name: String,
    pub tokens_revoked: u64,
}

/// What an access key's deletion answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDeleted {
    pub access_key: String,
    pub tokens_revoked: u64,
}

/// A token, as the endpoint answers it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAnswer {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
}

impl std::fmt::Debug for TokenAnswer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenAnswer")
            .field("expires_in", &self.expires_in)
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

/// What a token is asked with.
#[derive(Clone, Default)]
pub struct TokenAsk {
    pub access_key: String,
    pub secret_key: Zeroizing<String>,
    /// Operations, space separated, narrowing the account's.
    pub scope: Option<String>,
    pub lifetime: Option<u64>,
}

impl std::fmt::Debug for TokenAsk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenAsk")
            .field("access_key", &self.access_key)
            .field("scope", &self.scope)
            .field("lifetime", &self.lifetime)
            .finish_non_exhaustive()
    }
}

/// Every call the Authority Plane answers.
pub trait Authority {
    /// The RFC 8414 metadata: the issuer, the edition and what it serves.
    fn metadata(&self) -> Result<serde_json::Value, Failure>;
    /// The `authority.tokens` key set.
    fn keys(&self) -> Result<serde_json::Value, Failure>;
    /// A token for an access key and its secret key.
    fn issue_token(&self, ask: &TokenAsk) -> Result<TokenAnswer, Failure>;
    fn service_accounts(&self) -> Result<Vec<ServiceAccount>, Failure>;
    fn service_account(&self, name: &str) -> Result<ServiceAccount, Failure>;
    fn create_service_account(
        &self,
        request_id: &str,
        name: &str,
        description: &str,
        scopes: &[Scope],
    ) -> Result<ServiceAccount, Failure>;
    fn update_service_account(
        &self,
        request_id: &str,
        name: &str,
        description: &str,
    ) -> Result<ServiceAccount, Failure>;
    fn delete_service_account(&self, request_id: &str, name: &str) -> Result<Deleted, Failure>;
    fn set_suspended(
        &self,
        request_id: &str,
        name: &str,
        suspended: bool,
    ) -> Result<ServiceAccount, Failure>;
    fn scopes(&self, name: &str) -> Result<Scopes, Failure>;
    fn set_scopes(
        &self,
        request_id: &str,
        name: &str,
        scopes: &[Scope],
        revoke_tokens: bool,
    ) -> Result<Scopes, Failure>;
    fn access_keys(&self, name: &str) -> Result<Vec<AccessKey>, Failure>;
    fn create_access_key(
        &self,
        request_id: &str,
        name: &str,
        expires_at: Option<&str>,
    ) -> Result<KeyCreated, Failure>;
    fn delete_access_key(
        &self,
        request_id: &str,
        name: &str,
        access_key: &str,
    ) -> Result<KeyDeleted, Failure>;
    fn tokens(&self, account: Option<&str>, status: Option<&str>) -> Result<Vec<Token>, Failure>;
    fn revoke_token(&self, request_id: &str, jti: &str) -> Result<Token, Failure>;
}

fn usage(detail: impl Into<String>) -> Failure {
    Failure {
        class: "validation".to_owned(),
        reason: permguard_core::codes::client::USAGE.to_owned(),
        detail: detail.into(),
        usage: true,
    }
}

/// The client of the Authority Plane at `url`: REST for `https`/`http`, gRPC for
/// `grpcs`/`grpc`. A bearer the options carry is sent on every call but the token endpoint's.
pub fn client(
    url: &str,
    tls: &TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn Authority + Send + Sync>, String> {
    let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;
    if endpoint.is_grpc() {
        return Ok(Box::new(GrpcAuthority(GrpcChannel::connect(
            url, tls, narrator,
        )?)));
    }
    let client = Client::new(
        std::time::Duration::from_secs(30),
        tls.clone(),
        endpoint.is_tls(),
    )
    .map_err(|error| error.to_string())?
    .with_narrator(narrator);
    // The token endpoint is reached without the bearer: its proof is the access key's.
    let mut bare = tls.clone();
    bare.token = None;
    Ok(Box::new(RestAuthority {
        client,
        bare,
        endpoint,
    }))
}

/// A path segment: refused when it would change the path.
fn segment(text: &str) -> Result<String, Failure> {
    if text.is_empty() || text.contains(['/', '?', '#', '%']) || text.chars().any(char::is_control)
    {
        return Err(usage(format!("`{text}` is not a name")));
    }
    Ok(crate::encode::value(text))
}

fn json(body: &impl Serialize) -> Result<String, Failure> {
    serde_json::to_string(body).map_err(|error| usage(error.to_string()))
}

#[derive(Deserialize)]
struct AccountsBody {
    accounts: Vec<ServiceAccount>,
}

#[derive(Deserialize)]
struct KeysBody {
    keys: Vec<AccessKey>,
}

#[derive(Deserialize)]
struct TokensBody {
    tokens: Vec<Token>,
}

struct RestAuthority {
    client: Client,
    /// The TLS options without the bearer: the token endpoint's.
    bare: TlsOptions,
    endpoint: Endpoint,
}

impl RestAuthority {
    fn call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<T, Failure> {
        crate::catalog::call(&self.client, &self.endpoint, method, path, body)
    }
}

/// The token request as RFC 6749 encodes it: the proof in Basic, the rest in the form.
fn token_form(ask: &TokenAsk) -> (String, String) {
    use base64::Engine as _;
    let form = crate::encode::value;
    let mut body = "grant_type=client_credentials".to_owned();
    if let Some(scope) = ask
        .scope
        .as_deref()
        .filter(|scope| !scope.trim().is_empty())
    {
        body.push_str(&format!("&scope={}", form(scope)));
    }
    if let Some(lifetime) = ask.lifetime {
        body.push_str(&format!("&requested_lifetime={lifetime}"));
    }
    let pair = Zeroizing::new(format!(
        "{}:{}",
        form(&ask.access_key),
        form(ask.secret_key.trim())
    ));
    (
        body,
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(pair.as_bytes())
        ),
    )
}

/// RFC 6749's refusal as a failure: the error and its description, never anything sent.
fn token_failure(status: u16, body: &[u8], access_key: &str) -> Failure {
    let parsed: Option<serde_json::Value> = serde_json::from_slice(body).ok();
    let error = parsed
        .as_ref()
        .and_then(|value| value["error"].as_str())
        .map_or_else(|| format!("http_{status}"), printable);
    let description = parsed
        .as_ref()
        .and_then(|value| value["error_description"].as_str())
        .map(printable)
        .unwrap_or_default();
    Failure {
        class: match status {
            401 => "unauthenticated",
            400 | 403 => "validation",
            429 => "exhausted",
            _ => "unavailable",
        }
        .to_owned(),
        detail: refused_token(&error, &description, access_key),
        reason: error,
        usage: false,
    }
}

/// At most 256 characters of `text`, without a control character.
fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).take(256).collect()
}

/// Why no token was issued, the error's code left to the failure's reason. `invalid_client`
/// never says which of its causes holds (`2-security/8` Token endpoint), so all are named.
fn refused_token(error: &str, description: &str, access_key: &str) -> String {
    if error == "invalid_client" {
        return format!(
            "the Authority Plane did not accept the access key {access_key}: its secret key does \
             not match, the key is unknown, expired or deleted, or its account is suspended"
        );
    }
    if description.is_empty() {
        "the Authority Plane issued no token".to_owned()
    } else {
        format!("the Authority Plane issued no token: {description}")
    }
}

impl Authority for RestAuthority {
    fn metadata(&self) -> Result<serde_json::Value, Failure> {
        self.call("GET", "/.well-known/oauth-authorization-server", None)
    }

    fn keys(&self) -> Result<serde_json::Value, Failure> {
        self.call("GET", "/authority/v1/keys", None)
    }

    fn issue_token(&self, ask: &TokenAsk) -> Result<TokenAnswer, Failure> {
        let (body, basic) = token_form(ask);
        // A secret key crosses verified TLS only.
        let client = Client::new(
            std::time::Duration::from_secs(30),
            self.bare.clone(),
            self.endpoint.is_tls(),
        )
        .and_then(|client| client.with_authorization(&basic, self.endpoint.is_tls()))
        .map_err(|error| usage(error.to_string()))?;
        let answered = client
            .request_raw(
                &self.endpoint,
                "POST",
                TOKEN_PATH,
                "application/x-www-form-urlencoded",
                Some(body.as_bytes()),
            )
            .map_err(|error| Failure {
                class: "unavailable".to_owned(),
                reason: error.reason().to_owned(),
                detail: error.to_string(),
                usage: false,
            })?;
        if answered.status != 200 {
            return Err(token_failure(
                answered.status,
                &answered.body,
                &ask.access_key,
            ));
        }
        serde_json::from_slice(&answered.body).map_err(|_| Failure {
            class: "unavailable".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: "the Authority Plane answered something that is not a token answer".to_owned(),
            usage: false,
        })
    }

    fn service_accounts(&self) -> Result<Vec<ServiceAccount>, Failure> {
        self.call::<AccountsBody>("GET", "/authority/v1/service-accounts", None)
            .map(|body| body.accounts)
    }

    fn service_account(&self, name: &str) -> Result<ServiceAccount, Failure> {
        self.call(
            "GET",
            &format!("/authority/v1/service-accounts/{}", segment(name)?),
            None,
        )
    }

    fn create_service_account(
        &self,
        request_id: &str,
        name: &str,
        description: &str,
        scopes: &[Scope],
    ) -> Result<ServiceAccount, Failure> {
        let body = json(&serde_json::json!({
            "request_id": request_id, "name": name, "description": description, "scopes": scopes,
        }))?;
        self.call("POST", "/authority/v1/service-accounts", Some(&body))
    }

    fn update_service_account(
        &self,
        request_id: &str,
        name: &str,
        description: &str,
    ) -> Result<ServiceAccount, Failure> {
        let body = json(&serde_json::json!({
            "request_id": request_id, "description": description,
        }))?;
        self.call(
            "PATCH",
            &format!("/authority/v1/service-accounts/{}", segment(name)?),
            Some(&body),
        )
    }

    fn delete_service_account(&self, request_id: &str, name: &str) -> Result<Deleted, Failure> {
        let body = json(&serde_json::json!({ "request_id": request_id }))?;
        self.call(
            "DELETE",
            &format!("/authority/v1/service-accounts/{}", segment(name)?),
            Some(&body),
        )
    }

    fn set_suspended(
        &self,
        request_id: &str,
        name: &str,
        suspended: bool,
    ) -> Result<ServiceAccount, Failure> {
        let body = json(&serde_json::json!({ "request_id": request_id }))?;
        let verb = if suspended { "suspend" } else { "resume" };
        self.call(
            "POST",
            &format!("/authority/v1/service-accounts/{}/{verb}", segment(name)?),
            Some(&body),
        )
    }

    fn scopes(&self, name: &str) -> Result<Scopes, Failure> {
        self.call(
            "GET",
            &format!("/authority/v1/service-accounts/{}/scopes", segment(name)?),
            None,
        )
    }

    fn set_scopes(
        &self,
        request_id: &str,
        name: &str,
        scopes: &[Scope],
        revoke_tokens: bool,
    ) -> Result<Scopes, Failure> {
        let body = json(&serde_json::json!({
            "request_id": request_id, "scopes": scopes, "revoke_tokens": revoke_tokens,
        }))?;
        self.call(
            "PUT",
            &format!("/authority/v1/service-accounts/{}/scopes", segment(name)?),
            Some(&body),
        )
    }

    fn access_keys(&self, name: &str) -> Result<Vec<AccessKey>, Failure> {
        self.call::<KeysBody>(
            "GET",
            &format!("/authority/v1/service-accounts/{}/keys", segment(name)?),
            None,
        )
        .map(|body| body.keys)
    }

    fn create_access_key(
        &self,
        request_id: &str,
        name: &str,
        expires_at: Option<&str>,
    ) -> Result<KeyCreated, Failure> {
        let body = json(&serde_json::json!({
            "request_id": request_id, "expires_at": expires_at,
        }))?;
        self.call(
            "POST",
            &format!("/authority/v1/service-accounts/{}/keys", segment(name)?),
            Some(&body),
        )
    }

    fn delete_access_key(
        &self,
        request_id: &str,
        name: &str,
        access_key: &str,
    ) -> Result<KeyDeleted, Failure> {
        let body = json(&serde_json::json!({ "request_id": request_id }))?;
        self.call(
            "DELETE",
            &format!(
                "/authority/v1/service-accounts/{}/keys/{}",
                segment(name)?,
                segment(access_key)?
            ),
            Some(&body),
        )
    }

    fn tokens(&self, account: Option<&str>, status: Option<&str>) -> Result<Vec<Token>, Failure> {
        let mut query = Vec::new();
        if let Some(account) = account {
            query.push(format!("account={}", crate::encode::value(account)));
        }
        if let Some(status) = status {
            query.push(format!("status={}", crate::encode::value(status)));
        }
        let path = if query.is_empty() {
            "/authority/v1/tokens".to_owned()
        } else {
            format!("/authority/v1/tokens?{}", query.join("&"))
        };
        self.call::<TokensBody>("GET", &path, None)
            .map(|body| body.tokens)
    }

    fn revoke_token(&self, request_id: &str, jti: &str) -> Result<Token, Failure> {
        let body = json(&serde_json::json!({ "request_id": request_id }))?;
        self.call(
            "POST",
            &format!("/authority/v1/tokens/{}/revoke", segment(jti)?),
            Some(&body),
        )
    }
}

struct GrpcAuthority(GrpcChannel);

fn scope_in(scope: proto::Scope) -> Scope {
    Scope {
        operations: scope.operations,
        selector: scope.selector,
    }
}

fn scope_out(scope: &Scope) -> proto::Scope {
    proto::Scope {
        operations: scope.operations.clone(),
        selector: scope.selector.clone(),
    }
}

fn key_in(key: proto::AccessKey) -> AccessKey {
    AccessKey {
        access_key: key.access_key,
        created_at: key.created_at,
        expires_at: key.expires_at,
        last_used_at: key.last_used_at,
        status: key.status,
    }
}

fn account_in(account: Option<proto::ServiceAccount>) -> Result<ServiceAccount, Failure> {
    let account = account.ok_or_else(|| Failure {
        class: "internal".to_owned(),
        reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
        detail: "the Authority Plane answered no account".to_owned(),
        usage: false,
    })?;
    Ok(ServiceAccount {
        name: account.name,
        description: account.description,
        status: account.status,
        scopes: account.scopes.into_iter().map(scope_in).collect(),
        keys: account.keys.into_iter().map(key_in).collect(),
        administrator: account.administrator,
        created_at: account.created_at,
        updated_at: account.updated_at,
        revision: account.revision,
    })
}

fn token_in(token: proto::TokenSummary) -> Token {
    Token {
        jti: token.jti,
        subject: token.subject,
        account: token.account,
        access_key: token.access_key,
        scopes: token.scopes.into_iter().map(scope_in).collect(),
        issued_at: token.issued_at,
        expires_at: token.expires_at,
        status: token.status,
        status_list: token.status_list,
        index: token.index,
    }
}

fn scopes_in(scopes: proto::ScopesResponse) -> Scopes {
    Scopes {
        name: scopes.name,
        scopes: scopes.scopes.into_iter().map(scope_in).collect(),
        revision: scopes.revision,
        tokens_revoked: scopes.tokens_revoked,
    }
}

fn decoded(what: &str, text: &str) -> Result<serde_json::Value, Failure> {
    serde_json::from_str(text).map_err(|error| Failure {
        class: "internal".to_owned(),
        reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
        detail: format!("the {what} the Authority Plane answered is not JSON: {error}"),
        usage: false,
    })
}

impl GrpcAuthority {
    fn tokens_client(
        &self,
    ) -> proto::token_service_client::TokenServiceClient<crate::grpc::AuthChannel> {
        proto::token_service_client::TokenServiceClient::new(self.0.channel())
    }

    fn accounts_client(
        &self,
    ) -> proto::service_account_service_client::ServiceAccountServiceClient<crate::grpc::AuthChannel>
    {
        proto::service_account_service_client::ServiceAccountServiceClient::new(self.0.channel())
    }

    fn account(
        &self,
        rpc: &str,
        future: impl std::future::Future<
            Output = Result<tonic::Response<proto::ServiceAccountResponse>, tonic::Status>,
        >,
    ) -> Result<ServiceAccount, Failure> {
        let answer = self.0.run(rpc, future).map_err(crate::grpc::failure_of)?;
        account_in(answer.account)
    }
}

impl Authority for GrpcAuthority {
    fn metadata(&self) -> Result<serde_json::Value, Failure> {
        let mut client = self.tokens_client();
        let answer = self
            .0
            .run(
                "GetMetadata",
                client.get_metadata(proto::GetMetadataRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        decoded("metadata", &answer.document_json)
    }

    fn keys(&self) -> Result<serde_json::Value, Failure> {
        let mut client = self.tokens_client();
        let answer = self
            .0
            .run("GetKeys", client.get_keys(proto::GetKeysRequest {}))
            .map_err(crate::grpc::failure_of)?;
        decoded("key set", &answer.jwks_json)
    }

    fn issue_token(&self, ask: &TokenAsk) -> Result<TokenAnswer, Failure> {
        let mut client = self.tokens_client();
        let answer = self
            .0
            .run(
                "IssueToken",
                client.issue_token(proto::IssueTokenRequest {
                    grant_type: "client_credentials".to_owned(),
                    client_id: ask.access_key.clone(),
                    client_secret: ask.secret_key.trim().to_owned(),
                    scope: ask.scope.clone().unwrap_or_default(),
                    requested_lifetime: ask.lifetime,
                }),
            )
            .map_err(|status| Failure {
                class: match status.code() {
                    tonic::Code::Unauthenticated => "unauthenticated",
                    tonic::Code::InvalidArgument => "validation",
                    tonic::Code::ResourceExhausted => "exhausted",
                    _ => "unavailable",
                }
                .to_owned(),
                reason: status
                    .message()
                    .split(':')
                    .next()
                    .map(printable)
                    .unwrap_or_default(),
                detail: {
                    let (error, description) = status
                        .message()
                        .split_once(':')
                        .unwrap_or((status.message(), ""));
                    refused_token(
                        &printable(error),
                        printable(description).trim(),
                        &ask.access_key,
                    )
                },
                usage: false,
            })?;
        Ok(TokenAnswer {
            access_token: answer.access_token,
            token_type: answer.token_type,
            expires_in: answer.expires_in,
            scope: answer.scope,
        })
    }

    fn service_accounts(&self) -> Result<Vec<ServiceAccount>, Failure> {
        let mut client = self.accounts_client();
        let answer = self
            .0
            .run(
                "ListServiceAccounts",
                client.list_service_accounts(proto::ListServiceAccountsRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        answer
            .accounts
            .into_iter()
            .map(|account| account_in(Some(account)))
            .collect()
    }

    fn service_account(&self, name: &str) -> Result<ServiceAccount, Failure> {
        let mut client = self.accounts_client();
        self.account(
            "GetServiceAccount",
            client.get_service_account(proto::GetServiceAccountRequest {
                name: name.to_owned(),
            }),
        )
    }

    fn create_service_account(
        &self,
        request_id: &str,
        name: &str,
        description: &str,
        scopes: &[Scope],
    ) -> Result<ServiceAccount, Failure> {
        let mut client = self.accounts_client();
        self.account(
            "CreateServiceAccount",
            client.create_service_account(proto::CreateServiceAccountRequest {
                request_id: request_id.to_owned(),
                name: name.to_owned(),
                description: description.to_owned(),
                scopes: scopes.iter().map(scope_out).collect(),
            }),
        )
    }

    fn update_service_account(
        &self,
        request_id: &str,
        name: &str,
        description: &str,
    ) -> Result<ServiceAccount, Failure> {
        let mut client = self.accounts_client();
        self.account(
            "UpdateServiceAccount",
            client.update_service_account(proto::UpdateServiceAccountRequest {
                request_id: request_id.to_owned(),
                name: name.to_owned(),
                description: description.to_owned(),
                expected_revision: None,
            }),
        )
    }

    fn delete_service_account(&self, request_id: &str, name: &str) -> Result<Deleted, Failure> {
        let mut client = self.accounts_client();
        let answer = self
            .0
            .run(
                "DeleteServiceAccount",
                client.delete_service_account(proto::DeleteServiceAccountRequest {
                    request_id: request_id.to_owned(),
                    name: name.to_owned(),
                    expected_revision: None,
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(Deleted {
            name: answer.name,
            tokens_revoked: answer.tokens_revoked,
        })
    }

    fn set_suspended(
        &self,
        request_id: &str,
        name: &str,
        suspended: bool,
    ) -> Result<ServiceAccount, Failure> {
        let mut client = self.accounts_client();
        let request = proto::ServiceAccountStatusRequest {
            request_id: request_id.to_owned(),
            name: name.to_owned(),
            expected_revision: None,
        };
        if suspended {
            self.account(
                "SuspendServiceAccount",
                client.suspend_service_account(request),
            )
        } else {
            self.account(
                "ResumeServiceAccount",
                client.resume_service_account(request),
            )
        }
    }

    fn scopes(&self, name: &str) -> Result<Scopes, Failure> {
        let mut client = self.accounts_client();
        self.0
            .run(
                "GetScopes",
                client.get_scopes(proto::GetScopesRequest {
                    name: name.to_owned(),
                }),
            )
            .map(scopes_in)
            .map_err(crate::grpc::failure_of)
    }

    fn set_scopes(
        &self,
        request_id: &str,
        name: &str,
        scopes: &[Scope],
        revoke_tokens: bool,
    ) -> Result<Scopes, Failure> {
        let mut client = self.accounts_client();
        self.0
            .run(
                "SetScopes",
                client.set_scopes(proto::SetScopesRequest {
                    request_id: request_id.to_owned(),
                    name: name.to_owned(),
                    scopes: scopes.iter().map(scope_out).collect(),
                    expected_revision: None,
                    revoke_tokens,
                }),
            )
            .map(scopes_in)
            .map_err(crate::grpc::failure_of)
    }

    fn access_keys(&self, name: &str) -> Result<Vec<AccessKey>, Failure> {
        let mut client = self.accounts_client();
        self.0
            .run(
                "ListAccessKeys",
                client.list_access_keys(proto::ListAccessKeysRequest {
                    name: name.to_owned(),
                }),
            )
            .map(|answer| answer.keys.into_iter().map(key_in).collect())
            .map_err(crate::grpc::failure_of)
    }

    fn create_access_key(
        &self,
        request_id: &str,
        name: &str,
        expires_at: Option<&str>,
    ) -> Result<KeyCreated, Failure> {
        let mut client = self.accounts_client();
        let answer = self
            .0
            .run(
                "CreateAccessKey",
                client.create_access_key(proto::CreateAccessKeyRequest {
                    request_id: request_id.to_owned(),
                    name: name.to_owned(),
                    expires_at: expires_at.map(str::to_owned),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        let key = answer.key.map(key_in).ok_or_else(|| Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: "the Authority Plane answered no key".to_owned(),
            usage: false,
        })?;
        Ok(KeyCreated {
            key,
            secret_key: answer.secret_key,
        })
    }

    fn delete_access_key(
        &self,
        request_id: &str,
        name: &str,
        access_key: &str,
    ) -> Result<KeyDeleted, Failure> {
        let mut client = self.accounts_client();
        let answer = self
            .0
            .run(
                "DeleteAccessKey",
                client.delete_access_key(proto::DeleteAccessKeyRequest {
                    request_id: request_id.to_owned(),
                    name: name.to_owned(),
                    access_key: access_key.to_owned(),
                    expected_revision: None,
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        Ok(KeyDeleted {
            access_key: answer.access_key,
            tokens_revoked: answer.tokens_revoked,
        })
    }

    fn tokens(&self, account: Option<&str>, status: Option<&str>) -> Result<Vec<Token>, Failure> {
        let mut client = self.tokens_client();
        self.0
            .run(
                "ListTokens",
                client.list_tokens(proto::ListTokensRequest {
                    account: account.unwrap_or_default().to_owned(),
                    status: status.unwrap_or_default().to_owned(),
                }),
            )
            .map(|answer| answer.tokens.into_iter().map(token_in).collect())
            .map_err(crate::grpc::failure_of)
    }

    fn revoke_token(&self, request_id: &str, jti: &str) -> Result<Token, Failure> {
        let mut client = self.tokens_client();
        let answer = self
            .0
            .run(
                "RevokeToken",
                client.revoke_token(proto::RevokeTokenRequest {
                    jti: jti.to_owned(),
                    request_id: request_id.to_owned(),
                }),
            )
            .map_err(crate::grpc::failure_of)?;
        answer.token.map(token_in).ok_or_else(|| Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: "the Authority Plane answered no token".to_owned(),
            usage: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_token_form_carries_the_proof_in_basic_and_never_in_the_body() {
        let (body, basic) = token_form(&TokenAsk {
            access_key: "pgak_AAAAAAAAAAAAAAAAAAAA".to_owned(),
            secret_key: Zeroizing::new("pgsk_secret".to_owned()),
            scope: Some("decision.evaluate event.submit".to_owned()),
            lifetime: Some(600),
        });
        assert!(body.contains("grant_type=client_credentials"));
        assert!(body.contains("scope=decision.evaluate"));
        assert!(body.contains("requested_lifetime=600"));
        assert!(!body.contains("pgsk_"), "the secret travels in the header");
        assert!(basic.starts_with("Basic "));
        assert!(segment("a/b").is_err());
        assert_eq!(segment("billing").ok().as_deref(), Some("billing"));
        let failure = token_failure(
            401,
            br#"{"error":"invalid_client","error_description":"x"}"#,
            "pgak_AAAAAAAAAAAAAAAAAAAA",
        );
        assert_eq!(failure.reason, "invalid_client");
        assert_eq!(failure.class, "unauthenticated");
        assert_eq!(
            failure.detail,
            "the Authority Plane did not accept the access key pgak_AAAAAAAAAAAAAAAAAAAA: its \
             secret key does not match, the key is unknown, expired or deleted, or its account \
             is suspended"
        );
        let failure = token_failure(
            400,
            br#"{"error":"invalid_scope","error_description":"`catalog.write` is not held"}"#,
            "pgak_AAAAAAAAAAAAAAAAAAAA",
        );
        assert_eq!(failure.reason, "invalid_scope");
        assert_eq!(
            failure.detail,
            "the Authority Plane issued no token: `catalog.write` is not held"
        );
    }
}
