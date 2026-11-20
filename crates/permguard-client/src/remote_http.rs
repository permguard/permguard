// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The HTTP transport of the six NOTP verbs, plus the discovery check a
//! caller runs before it trusts a URL.
//!
//! Bodies are `application/vnd.permguard.notp.v1+cbor`; the negotiated batch
//! compression is remembered here and undone here, because it is an encoding
//! of the pipe and nothing above this file should know it happened.

use std::cell::RefCell;

use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    GetRefResponse, NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest,
    NegotiatePushResponse, UploadObjectsRequest, UploadObjectsResponse,
};
use permguard_objects::{compress, limits};
use serde::Deserialize;

use crate::endpoint::Endpoint;
use crate::http::Client;
use crate::narrate::Narrator;
use crate::remote::{RefAnswer, Remote};
use crate::tls::TlsOptions;

/// A remote reached over the control plane's HTTP surface.
pub struct HttpRemote {
    client: Client,
    endpoint: Endpoint,
    /// The URL's path prefix, for deployments behind one.
    prefix: String,
    /// Who is told about each exchange — the CLI prints, a server logs.
    narrator: Box<dyn Narrator>,
    /// The resolved (zone GUID, ledger GUID), set by `resolve` or pre-bound
    /// from the workspace config.
    ids: RefCell<Option<(String, String)>>,
    /// The refs and heads a re-home imported, as the ledger `resolve` read names them
    /// (BUG-0185).
    imported: RefCell<Vec<permguard_core::ImportedHead>>,
    /// The batch compression the last negotiation advertised — remembered
    /// here because compression is this transport's concern, invisible to
    /// the engine: batches leave compressed and arrive decompressed.
    compression: RefCell<Option<String>>,
    /// The last failure, with the class and code a string loses (BUG-0002, BUG-0087).
    failed: RefCell<Option<crate::failure::Failure>>,
}

#[derive(Debug, Deserialize)]
struct IdAnswer {
    id: String,
}

/// What a checkout reads of a ledger's record: its id, and the heads a re-home imported.
#[derive(Debug, Deserialize)]
struct LedgerAnswer {
    id: String,
    #[serde(default)]
    provenance: Option<permguard_core::Provenance>,
}

#[derive(Debug, Deserialize)]
struct Refusal {
    class: String,
    code: String,
    message: String,
}

impl HttpRemote {
    /// Connects to a server URL — `https://host[:port][/prefix]` (or http).
    pub fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn Narrator>,
    ) -> Result<Self, String> {
        let (base, prefix) = split_prefix(url)?;
        let endpoint = Endpoint::parse(&base).map_err(|error| error.to_string())?;
        let client = Client::new(
            std::time::Duration::from_secs(30),
            tls.clone(),
            endpoint.is_tls(),
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            endpoint,
            prefix,
            narrator,
            ids: RefCell::new(None),
            imported: RefCell::new(Vec::new()),
            compression: RefCell::new(None),
            failed: RefCell::new(None),
        })
    }

    /// The last failure this remote met, taken: its class and code, which the `String` the
    /// engine sees cannot carry.
    pub fn take_failure(&self) -> Option<crate::failure::Failure> {
        self.failed.borrow_mut().take()
    }

    /// Keeps `failure` for [`take_failure`](Self::take_failure) and answers its sentence.
    fn failed(&self, failure: crate::failure::Failure) -> String {
        let said = failure.detail.clone();
        *self.failed.borrow_mut() = Some(failure);
        said
    }

    /// A transport that could not reach the server: the world's, unless what was refused is the
    /// operator's to fix, a certificate or a scheme (DEC-0008 option A).
    fn unreachable(&self, error: &crate::http::Error) -> String {
        self.failed(error.failure())
    }

    /// One exchange, told to whoever is listening.
    fn narrate(&self, method: &str, path: &str, sent: usize, status: u16, received: usize) {
        self.narrator
            .exchange(method, path, sent, &status.to_string(), received);
    }

    /// Pre-binds the resolved GUIDs, for workspaces that already carry them.
    pub fn bind(&self, zone_id: &str, ledger_id: &str) {
        *self.ids.borrow_mut() = Some((zone_id.to_owned(), ledger_id.to_owned()));
    }

    /// Reads the discovery document — the proof this URL is a Permguard
    /// plane — before the remote is remembered.
    pub fn verify_discovery(&self) -> Result<(), String> {
        let body = self.get_json(&format!("{}/.well-known/server-configuration", self.prefix))?;
        crate::transport::control_plane_document(&body)
    }

    fn ledger_base(&self) -> Result<String, String> {
        let ids = self.ids.borrow();
        let (zone, ledger) = ids
            .as_ref()
            .ok_or_else(|| "the remote is not bound to a ledger yet".to_owned())?;
        Ok(format!(
            "{}/notp/v1/zones/{zone}/ledgers/{ledger}",
            self.prefix
        ))
    }

    fn get_json(&self, path: &str) -> Result<Vec<u8>, String> {
        let answer = self
            .client
            .request_raw(&self.endpoint, "GET", path, "application/json", None)
            .map_err(|error| self.unreachable(&error))?;
        self.narrate("GET", path, 0, answer.status, answer.body.len());
        if answer.status != 200 {
            return Err(self.failed(refusal(&answer.body, answer.status)));
        }
        Ok(answer.body)
    }

    fn post_cbor(&self, path: &str, body: &[u8]) -> Result<Vec<u8>, String> {
        let answer = self
            .client
            .request_raw(
                &self.endpoint,
                "POST",
                path,
                permguard_notp::MEDIA_TYPE,
                Some(body),
            )
            .map_err(|error| self.unreachable(&error))?;
        self.narrate("POST", path, body.len(), answer.status, answer.body.len());
        if answer.status != 200 {
            return Err(self.failed(refusal(&answer.body, answer.status)));
        }
        Ok(answer.body)
    }
}

impl HttpRemote {
    /// Keeps the advertised algorithm only when this build speaks it —
    /// anything else falls back to raw batches, which every server accepts.
    fn remember_compression(&self, advertised: Option<&str>) {
        *self.compression.borrow_mut() = advertised
            .filter(|algorithm| *algorithm == compress::DEFLATE)
            .map(str::to_owned);
    }
}

/// A refusal, as every other client of this crate reads one: the server's class, code and
/// sentence; a denial at a listener's gate, its code and no class (TC-1); anything else, the status
/// (BUG-0087).
fn refusal(body: &[u8], status: u16) -> crate::failure::Failure {
    if let Ok(refusal) = serde_json::from_slice::<Refusal>(body) {
        return crate::failure::Failure {
            usage: matches!(
                refusal.class.as_str(),
                "validation" | "conflict" | "not_found"
            ),
            class: refusal.class,
            reason: refusal.code,
            detail: refusal.message,
        };
    }
    match serde_json::from_slice::<permguard_core::api::WireDenial>(body) {
        Ok(denial) if matches!(status, 401 | 403) => crate::failure::Failure {
            class: String::new(),
            reason: denial.code,
            detail: denial.message,
            usage: true,
        },
        _ => crate::failure::Failure {
            class: "internal".to_owned(),
            reason: permguard_core::codes::client::HTTP_STATUS.to_owned(),
            detail: format!("the server answered {status}"),
            usage: false,
        },
    }
}

/// Splits `scheme://host[:port][/prefix]` into the endpoint and the prefix.
pub(crate) fn split_prefix(url: &str) -> Result<(String, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "a server is a URL: https://host[:port][/prefix]".to_owned())?;
    let scheme = scheme.to_ascii_lowercase();
    if !matches!(scheme.as_str(), "http" | "https") {
        return Err(format!(
            "the scheme `{scheme}` is not supported here: use http or https"
        ));
    }
    let (authority, prefix) = rest.split_once('/').unwrap_or((rest, ""));
    // The base is read through the one endpoint grammar (DEC-0017): its port, userinfo, query and
    // fragment, and its canonical form.
    let base = crate::Endpoint::parse(&format!("{scheme}://{authority}"))
        .map_err(|error| error.to_string())?
        .to_string();
    if prefix.contains(['?', '#']) {
        return Err(format!(
            "`{url}` carries a query or a fragment, and a server URL is https://host[:port][/prefix]"
        ));
    }
    // A path of `/` (or `//`) is no prefix, and a real one loses its trailing `/` (BUG-0021).
    let segments: Vec<&str> = prefix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let prefix = if segments.is_empty() {
        String::new()
    } else {
        format!("/{}", segments.join("/"))
    };
    Ok((base, prefix))
}

impl Remote for HttpRemote {
    fn resolve(&self, zone: &str, ledger: &str) -> Result<(String, String), String> {
        let zone_body = self.get_json(&format!("{}/catalog/v1/zones/{zone}", self.prefix))?;
        let zone_id = serde_json::from_slice::<IdAnswer>(&zone_body)
            .map_err(|error| format!("the zone answer does not parse: {error}"))?
            .id;
        let ledger_body = self.get_json(&format!(
            "{}/catalog/v1/zones/{zone_id}/ledgers/{ledger}",
            self.prefix
        ))?;
        let ledger = serde_json::from_slice::<LedgerAnswer>(&ledger_body)
            .map_err(|error| format!("the ledger answer does not parse: {error}"))?;
        let ledger_id = ledger.id;
        *self.imported.borrow_mut() = ledger
            .provenance
            .map(|provenance| provenance.heads)
            .unwrap_or_default();
        self.bind(&zone_id, &ledger_id);
        Ok((zone_id, ledger_id))
    }

    fn keyring(&self) -> Result<Vec<u8>, String> {
        self.get_json(&format!("{}/control-plane/v1/keys", self.prefix))
    }

    fn imported_head(&self, r#ref: &str) -> Result<Option<String>, String> {
        Ok(self
            .imported
            .borrow()
            .iter()
            .find(|named| named.r#ref == r#ref)
            .map(|named| named.head.clone()))
    }

    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String> {
        let path = format!("{}/refs/{ref}", self.ledger_base()?, ref = r#ref);
        let answer = self
            .client
            .request_raw(&self.endpoint, "GET", &path, "application/json", None)
            .map_err(|error| self.unreachable(&error))?;
        if answer.status == 404 {
            return Ok(None);
        }
        if answer.status != 200 {
            return Err(self.failed(refusal(&answer.body, answer.status)));
        }
        // A closed message: a label this client does not know is refused, never skipped.
        let answered = GetRefResponse::decode(&answer.body)
            .map_err(|error| format!("the ref answer does not parse: {error}"))?;
        Ok(Some(RefAnswer {
            head: answered.head.to_string(),
            counter: answered.counter,
            statement: answered.statement,
            ref_digest: answered.ref_digest.to_string(),
        }))
    }

    fn negotiate_push(
        &self,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String> {
        let body = self.post_cbor(
            &format!("{}/push/negotiate", self.ledger_base()?),
            &request.encode().map_err(|error| error.to_string())?,
        )?;
        let response = NegotiatePushResponse::decode(&body).map_err(|error| error.to_string())?;
        self.remember_compression(response.compression.as_deref());
        Ok(response)
    }

    fn upload(&self, request: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String> {
        let request = match &*self.compression.borrow() {
            Some(algorithm) => UploadObjectsRequest {
                objects: request
                    .objects
                    .iter()
                    .map(|o| compress::deflate(o))
                    .collect(),
                compression: Some(algorithm.clone()),
                transfer_id: request.transfer_id,
            },
            None => request.clone(),
        };
        let body = self.post_cbor(
            &format!("{}/objects", self.ledger_base()?),
            &request.encode().map_err(|error| error.to_string())?,
        )?;
        UploadObjectsResponse::decode(&body).map_err(|error| error.to_string())
    }

    fn commit_push(&self, request: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        let body = self.post_cbor(
            &format!("{}/push/commit", self.ledger_base()?),
            &request.encode().map_err(|error| error.to_string())?,
        )?;
        CommitPushResponse::decode(&body).map_err(|error| error.to_string())
    }

    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        let body = self.post_cbor(
            &format!("{}/pull/negotiate", self.ledger_base()?),
            &request.encode().map_err(|error| error.to_string())?,
        )?;
        let response = NegotiatePullResponse::decode(&body).map_err(|error| error.to_string())?;
        self.remember_compression(response.compression.as_deref());
        Ok(response)
    }

    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        let request = FetchObjectsRequest {
            digests: request.digests.clone(),
            accept_compression: self.compression.borrow().clone(),
            transfer_id: request.transfer_id,
        };
        let body = self.post_cbor(
            &format!("{}/objects/fetch", self.ledger_base()?),
            &request.encode().map_err(|error| error.to_string())?,
        )?;
        let mut response =
            FetchObjectsResponse::decode(&body).map_err(|error| error.to_string())?;
        if let Some(algorithm) = response.compression.take() {
            if algorithm != compress::DEFLATE {
                return Err(format!(
                    "the server compressed with `{algorithm}`, which was not asked for"
                ));
            }
            response.objects = response
                .objects
                .iter()
                .map(|bytes| compress::inflate(bytes, limits::MAX_OBJECT_BYTES))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("a fetched object does not decompress: {error}"))?;
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::split_prefix;
    use crate::transport::control_plane_document;

    /// BUG-0022: a remote is the control plane; another plane is refused by name.
    #[test]
    fn only_the_control_plane_is_a_remote() {
        assert!(control_plane_document(br#"{"plane":"control-plane"}"#).is_ok());
        let refused = control_plane_document(br#"{"plane":"data-plane"}"#).unwrap_err();
        assert!(refused.contains("`data-plane`"), "{refused}");
        assert!(control_plane_document(br#"{"other":1}"#).is_err());
    }

    /// BUG-0021, DEC-0017: `/` and `//` are no prefix, a real prefix loses its trailing `/`, and
    /// the base is the canonical endpoint.
    #[test]
    fn a_trailing_slash_is_no_prefix_and_a_prefix_is_normalised() {
        for (url, base, prefix) in [
            ("http://127.0.0.1:6443", "http://127.0.0.1:6443", ""),
            ("http://127.0.0.1:6443/", "http://127.0.0.1:6443", ""),
            ("http://127.0.0.1:6443//", "http://127.0.0.1:6443", ""),
            (
                "HTTPS://host:6443/permguard/",
                "https://host:6443",
                "/permguard",
            ),
            ("https://host/a//b/", "https://host", "/a/b"),
        ] {
            assert_eq!(
                split_prefix(url),
                Ok((base.to_owned(), prefix.to_owned())),
                "{url}"
            );
        }
        for url in [
            "http://host:99999/",
            "http://user@host/",
            "http://host/x?y=1",
            "grpc://host",
        ] {
            assert!(split_prefix(url).is_err(), "{url}");
        }
    }
}
