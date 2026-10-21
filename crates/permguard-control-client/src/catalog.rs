// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The zone catalog, as a client sees it: zones and ledgers, addressed by
//! name **or** GUID, over whichever transport the endpoint named.
//!
//! Wherever a command refers to an existing zone or ledger it accepts the GUID **or** the name —
//! the server tells them apart by shape, and names shaped like GUIDs cannot be created, so the
//! resolution never guesses. `--zone` on every ledger command is that same rule.
//!
//! The commands are thin on purpose: they speak to the control plane's `/v1/zones` routes and print
//! what came back. All the semantics — uniqueness, emptiness before deletion, name rules — live on
//! the server, so the CLI can never disagree with another client about what is allowed.

use serde::{Deserialize, Serialize};

use crate::endpoint::Endpoint;
use crate::http::Client;

/// The state a ledger answered before states existed is.
fn active() -> String {
    "active".to_owned()
}

/// One zone, as the server answers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// The record's revision, what a rename or a delete names as expected (WP-7.3a).
    #[serde(default)]
    pub revision: u64,
}

/// One ledger, as the server answers it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ledger {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    /// The ledger's default ref — a reference into its git-like store, never a head copy.
    #[serde(default)]
    pub default_ref: String,
    pub created_at: u64,
    pub updated_at: u64,
    /// The record's revision, what a rename or a delete names as expected (WP-7.3a).
    #[serde(default)]
    pub revision: u64,
    /// `active` or `archived` (WP-7.3b): an archived ledger is read and takes no push.
    #[serde(default = "active")]
    pub state: String,
}

/// What the server says when it refuses: the shape every Permguard API shares.
#[derive(Debug, Deserialize)]
struct Refusal {
    class: String,
    code: String,
    message: String,
}

/// A call that did not produce what was asked for, and why.
#[derive(Debug)]
pub struct Failure {
    /// The closed category, exactly as the server named it — or the transport's own.
    pub class: String,
    /// The stable code: the server's, or the transport's.
    pub reason: String,
    /// The sentence.
    pub detail: String,
    /// Whether the mistake is in what was asked (a usage error) or in the world (a failure).
    pub usage: bool,
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail)
    }
}

/// Sends one catalog request and reads back either the payload or the refusal.
pub(crate) fn call<T: for<'de> Deserialize<'de>>(
    client: &Client,
    endpoint: &Endpoint,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<T, Failure> {
    let response = client
        .request(endpoint, method, path, body)
        .map_err(|error| Failure {
            class: "unavailable".to_owned(),
            reason: error.reason().to_owned(),
            detail: error.to_string(),
            usage: false,
        })?;

    if (200..300).contains(&response.status) {
        return serde_json::from_str(&response.body).map_err(|error| Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
            detail: format!("the answer to {method} {path} was unreadable: {error}"),
            usage: false,
        });
    }

    // A refusal carries its class, its code and a sentence; anything else gets the status as both.
    match serde_json::from_str::<Refusal>(&response.body) {
        Ok(refusal) => Err(Failure {
            // The class decides whose mistake it is: validation, conflicts and lookups are the
            // operator's to fix; unavailable and internal are the world's.
            usage: matches!(
                refusal.class.as_str(),
                "validation" | "conflict" | "not_found"
            ),
            class: refusal.class,
            reason: refusal.code,
            detail: refusal.message,
        }),
        // A denial at the listener's gate (TC-1): `{code, message}` and no class, as the wire
        // carries it; the operator's to fix, as over gRPC.
        Err(_) => match serde_json::from_str::<permguard_core::api::WireDenial>(&response.body) {
            Ok(denial) if matches!(response.status, 401 | 403) => Err(Failure {
                class: String::new(),
                reason: denial.code,
                detail: denial.message,
                usage: true,
            }),
            _ => Err(Failure {
                class: "internal".to_owned(),
                reason: permguard_core::codes::client::HTTP_STATUS.to_owned(),
                detail: format!("{method} {path} answered {}", response.status),
                usage: false,
            }),
        },
    }
}

/// A fresh request id, what a retry of the same change repeats (WP-7.3a): 16 random bytes in hex,
/// minted as the Host mints an operation's.
pub fn request_id() -> Result<String, Failure> {
    permguard_host::operations::journal::OperationId::mint()
        .map(|id| id.to_string())
        .ok_or_else(|| Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::ENCODE_FAILED.to_owned(),
            detail: "no randomness for a request id".to_owned(),
            usage: false,
        })
}

/// A create's or a rename's body (WP-7.3a): the name, a fresh request id and, for a rename, the
/// revision the record was read at.
fn name_body(name: &str, expected_revision: Option<u64>) -> Result<String, Failure> {
    #[derive(Serialize)]
    struct Body<'a> {
        name: &'a str,
        request_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_revision: Option<u64>,
    }

    serde_json::to_string(&Body {
        name,
        request_id: request_id()?,
        expected_revision,
    })
    .map_err(|error| Failure {
        class: "internal".to_owned(),
        reason: permguard_core::codes::client::ENCODE_FAILED.to_owned(),
        detail: error.to_string(),
        usage: false,
    })
}

pub fn create_zone(client: &Client, endpoint: &Endpoint, name: &str) -> Result<Zone, Failure> {
    call(
        client,
        endpoint,
        "POST",
        "/v1/zones",
        Some(&name_body(name, None)?),
    )
}

pub fn list_zones(
    client: &Client,
    endpoint: &Endpoint,
    page: Option<u32>,
    size: Option<u32>,
) -> Result<Vec<Zone>, Failure> {
    call(
        client,
        endpoint,
        "GET",
        &paged("/v1/zones", page, size),
        None,
    )
}

/// Appends the paging a caller asked for; nothing when they did not — the
/// pre-pagination request, byte for byte.
fn paged(path: &str, page: Option<u32>, size: Option<u32>) -> String {
    match (page, size) {
        (None, None) => path.to_owned(),
        (Some(page), None) => format!("{path}?page={page}"),
        (None, Some(size)) => format!("{path}?size={size}"),
        (Some(page), Some(size)) => format!("{path}?page={page}&size={size}"),
    }
}

pub fn get_zone(client: &Client, endpoint: &Endpoint, zone: &str) -> Result<Zone, Failure> {
    call(
        client,
        endpoint,
        "GET",
        &format!("/v1/zones/{}", crate::encode::value(zone)),
        None,
    )
}

pub fn rename_zone(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    name: &str,
    expected_revision: u64,
) -> Result<Zone, Failure> {
    call(
        client,
        endpoint,
        "PATCH",
        &format!("/v1/zones/{}", crate::encode::value(zone)),
        Some(&name_body(name, Some(expected_revision))?),
    )
}

/// A delete's query (WP-7.3a): a fresh request id and the revision the record was read at.
fn deletion(expected_revision: u64) -> Result<String, Failure> {
    Ok(format!(
        "request_id={}&expected_revision={expected_revision}",
        request_id()?
    ))
}

pub fn delete_zone(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    expected_revision: u64,
) -> Result<Zone, Failure> {
    call(
        client,
        endpoint,
        "DELETE",
        &format!(
            "/v1/zones/{}?{}",
            crate::encode::value(zone),
            deletion(expected_revision)?
        ),
        None,
    )
}

pub fn create_ledger(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    name: &str,
) -> Result<Ledger, Failure> {
    call(
        client,
        endpoint,
        "POST",
        &format!("/v1/zones/{}/ledgers", crate::encode::value(zone)),
        Some(&name_body(name, None)?),
    )
}

pub fn list_ledgers(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    page: Option<u32>,
    size: Option<u32>,
) -> Result<Vec<Ledger>, Failure> {
    call(
        client,
        endpoint,
        "GET",
        &paged(
            &format!("/v1/zones/{}/ledgers", crate::encode::value(zone)),
            page,
            size,
        ),
        None,
    )
}

pub fn get_ledger(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    ledger: &str,
) -> Result<Ledger, Failure> {
    call(
        client,
        endpoint,
        "GET",
        &format!(
            "/v1/zones/{}/ledgers/{}",
            crate::encode::value(zone),
            crate::encode::value(ledger)
        ),
        None,
    )
}

pub fn rename_ledger(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    ledger: &str,
    name: &str,
    expected_revision: u64,
) -> Result<Ledger, Failure> {
    call(
        client,
        endpoint,
        "PATCH",
        &format!(
            "/v1/zones/{}/ledgers/{}",
            crate::encode::value(zone),
            crate::encode::value(ledger)
        ),
        Some(&name_body(name, Some(expected_revision))?),
    )
}

/// Archives or restores a ledger (WP-7.3b): `verb` is `archive` or `restore`.
pub fn set_ledger_state(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    ledger: &str,
    verb: &str,
    expected_revision: u64,
) -> Result<Ledger, Failure> {
    #[derive(Serialize)]
    struct Body {
        request_id: String,
        expected_revision: u64,
    }

    let body = serde_json::to_string(&Body {
        request_id: request_id()?,
        expected_revision,
    })
    .map_err(|error| Failure {
        class: "internal".to_owned(),
        reason: permguard_core::codes::client::ENCODE_FAILED.to_owned(),
        detail: error.to_string(),
        usage: false,
    })?;
    call(
        client,
        endpoint,
        "POST",
        &format!(
            "/v1/zones/{}/ledgers/{}/{verb}",
            crate::encode::value(zone),
            crate::encode::value(ledger)
        ),
        Some(&body),
    )
}

pub fn delete_ledger(
    client: &Client,
    endpoint: &Endpoint,
    zone: &str,
    ledger: &str,
    expected_revision: u64,
) -> Result<Ledger, Failure> {
    call(
        client,
        endpoint,
        "DELETE",
        &format!(
            "/v1/zones/{}/ledgers/{}?{}",
            crate::encode::value(zone),
            crate::encode::value(ledger),
            deletion(expected_revision)?
        ),
        None,
    )
}

// --- one catalog, whichever transport answers it ------------------------------------------------

/// The catalog, as a caller asks it — the shape both transports satisfy, so
/// nothing above this line knows which door was used.
///
/// Reads first, because every consumer needs them: a mirror discovers what to
/// follow with `list_zones` and `list_ledgers`, and resolves a name to a GUID
/// with the two `get`s. The writes exist for the CLI, which is the only thing
/// that administers.
pub trait Catalog {
    /// Lists zones — all of them, or one page when the caller asks
    /// (`page` 0-based, `size` capped by the server).
    fn list_zones(&self, page: Option<u32>, size: Option<u32>) -> Result<Vec<Zone>, Failure>;
    fn get_zone(&self, zone: &str) -> Result<Zone, Failure>;
    /// Lists a zone's ledgers, whole or paged like [`Catalog::list_zones`].
    fn list_ledgers(
        &self,
        zone: &str,
        page: Option<u32>,
        size: Option<u32>,
    ) -> Result<Vec<Ledger>, Failure>;
    fn get_ledger(&self, zone: &str, ledger: &str) -> Result<Ledger, Failure>;

    /// The writes take a fresh request id each, and a change of a record the revision it was
    /// read at (WP-7.3a): another one is refused `revision_conflict`.
    fn create_zone(&self, name: &str) -> Result<Zone, Failure>;
    fn rename_zone(&self, zone: &str, name: &str, expected_revision: u64) -> Result<Zone, Failure>;
    fn delete_zone(&self, zone: &str, expected_revision: u64) -> Result<Zone, Failure>;
    fn create_ledger(&self, zone: &str, name: &str) -> Result<Ledger, Failure>;
    fn rename_ledger(
        &self,
        zone: &str,
        ledger: &str,
        name: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure>;
    fn delete_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure>;
    /// Archives a ledger (WP-7.3b): it is read and takes no push.
    fn archive_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure>;
    /// Restores an archived ledger: it takes pushes again.
    fn restore_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure>;
}

/// The catalog over HTTP.
pub struct HttpCatalog {
    client: Client,
    endpoint: Endpoint,
}

impl Catalog for HttpCatalog {
    fn list_zones(&self, page: Option<u32>, size: Option<u32>) -> Result<Vec<Zone>, Failure> {
        list_zones(&self.client, &self.endpoint, page, size)
    }

    fn get_zone(&self, zone: &str) -> Result<Zone, Failure> {
        get_zone(&self.client, &self.endpoint, zone)
    }

    fn list_ledgers(
        &self,
        zone: &str,
        page: Option<u32>,
        size: Option<u32>,
    ) -> Result<Vec<Ledger>, Failure> {
        list_ledgers(&self.client, &self.endpoint, zone, page, size)
    }

    fn get_ledger(&self, zone: &str, ledger: &str) -> Result<Ledger, Failure> {
        get_ledger(&self.client, &self.endpoint, zone, ledger)
    }

    fn create_zone(&self, name: &str) -> Result<Zone, Failure> {
        create_zone(&self.client, &self.endpoint, name)
    }

    fn rename_zone(&self, zone: &str, name: &str, expected_revision: u64) -> Result<Zone, Failure> {
        rename_zone(&self.client, &self.endpoint, zone, name, expected_revision)
    }

    fn delete_zone(&self, zone: &str, expected_revision: u64) -> Result<Zone, Failure> {
        delete_zone(&self.client, &self.endpoint, zone, expected_revision)
    }

    fn create_ledger(&self, zone: &str, name: &str) -> Result<Ledger, Failure> {
        create_ledger(&self.client, &self.endpoint, zone, name)
    }

    fn rename_ledger(
        &self,
        zone: &str,
        ledger: &str,
        name: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure> {
        rename_ledger(
            &self.client,
            &self.endpoint,
            zone,
            ledger,
            name,
            expected_revision,
        )
    }

    fn delete_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure> {
        delete_ledger(
            &self.client,
            &self.endpoint,
            zone,
            ledger,
            expected_revision,
        )
    }

    fn archive_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure> {
        set_ledger_state(
            &self.client,
            &self.endpoint,
            zone,
            ledger,
            "archive",
            expected_revision,
        )
    }

    fn restore_ledger(
        &self,
        zone: &str,
        ledger: &str,
        expected_revision: u64,
    ) -> Result<Ledger, Failure> {
        set_ledger_state(
            &self.client,
            &self.endpoint,
            zone,
            ledger,
            "restore",
            expected_revision,
        )
    }
}

/// Connects to a catalog: one URL, and the scheme decides the transport.
///
/// The timeout is the client's own — a catalog call is a question with an
/// answer, and a question that never returns is worse than one that fails.
pub fn client(
    url: &str,
    tls: &crate::tls::TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn Catalog>, String> {
    if url.starts_with("grpc://") || url.starts_with("grpcs://") {
        let channel = crate::grpc::GrpcChannel::connect(url, tls, narrator)?;
        return Ok(Box::new(crate::grpc::GrpcAdmin(channel)));
    }

    let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;
    let client = Client::new(
        std::time::Duration::from_secs(30),
        tls.clone(),
        endpoint.is_tls(),
    )
    .map_err(|error| error.to_string())?
    .with_narrator(narrator);

    Ok(Box::new(HttpCatalog { client, endpoint }))
}
