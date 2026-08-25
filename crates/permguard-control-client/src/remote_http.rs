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
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    UploadObjectsRequest, UploadObjectsResponse,
};
use permguard_objects::cbor::{self, Value};
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
    /// The batch compression the last negotiation advertised — remembered
    /// here because compression is this transport's concern, invisible to
    /// the engine: batches leave compressed and arrive decompressed.
    compression: RefCell<Option<String>>,
}

#[derive(Debug, Deserialize)]
struct IdAnswer {
    id: String,
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
            compression: RefCell::new(None),
        })
    }

    /// One finished exchange, told to whoever is listening.
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
        let value: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|error| format!("the discovery document does not parse: {error}"))?;
        if value
            .get("plane")
            .and_then(|plane| plane.as_str())
            .is_none()
        {
            return Err("this URL answers, but not with a Permguard plane".to_owned());
        }
        Ok(())
    }

    fn ledger_base(&self) -> Result<String, String> {
        let ids = self.ids.borrow();
        let (zone, ledger) = ids
            .as_ref()
            .ok_or_else(|| "the remote is not bound to a ledger yet".to_owned())?;
        Ok(format!("{}/v1/zones/{zone}/ledgers/{ledger}", self.prefix))
    }

    fn get_json(&self, path: &str) -> Result<Vec<u8>, String> {
        let answer = self
            .client
            .request_raw(&self.endpoint, "GET", path, "application/json", None)
            .map_err(|error| error.to_string())?;
        self.narrate("GET", path, 0, answer.status, answer.body.len());
        if answer.status != 200 {
            return Err(refusal(&answer.body, answer.status));
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
            .map_err(|error| error.to_string())?;
        self.narrate("POST", path, body.len(), answer.status, answer.body.len());
        if answer.status != 200 {
            return Err(refusal(&answer.body, answer.status));
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

fn refusal(body: &[u8], status: u16) -> String {
    match serde_json::from_slice::<Refusal>(body) {
        Ok(refusal) => format!("{} ({}/{})", refusal.message, refusal.class, refusal.code),
        Err(_) => format!("the server answered {status}"),
    }
}

/// Splits `scheme://host[:port][/prefix]` into the endpoint and the prefix.
fn split_prefix(url: &str) -> Result<(String, String), String> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| "a server is a URL: https://host[:port][/prefix]".to_owned())?;
    if !matches!(scheme, "http" | "https") {
        return Err(format!(
            "the scheme `{scheme}` is not supported here: use http or https"
        ));
    }
    match rest.split_once('/') {
        Some((authority, prefix)) => Ok((
            format!("{scheme}://{authority}"),
            format!("/{}", prefix.trim_end_matches('/')),
        )),
        None => Ok((url.to_owned(), String::new())),
    }
}

impl Remote for HttpRemote {
    fn resolve(&self, zone: &str, ledger: &str) -> Result<(String, String), String> {
        let zone_body = self.get_json(&format!("{}/v1/zones/{zone}", self.prefix))?;
        let zone_id = serde_json::from_slice::<IdAnswer>(&zone_body)
            .map_err(|error| format!("the zone answer does not parse: {error}"))?
            .id;
        let ledger_body = self.get_json(&format!(
            "{}/v1/zones/{zone_id}/ledgers/{ledger}",
            self.prefix
        ))?;
        let ledger_id = serde_json::from_slice::<IdAnswer>(&ledger_body)
            .map_err(|error| format!("the ledger answer does not parse: {error}"))?
            .id;
        self.bind(&zone_id, &ledger_id);
        Ok((zone_id, ledger_id))
    }

    fn keyring(&self) -> Result<Vec<u8>, String> {
        self.get_json(&format!("{}/control-plane/keys", self.prefix))
    }

    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String> {
        let path = format!("{}/refs/{ref}", self.ledger_base()?, ref = r#ref);
        let answer = self
            .client
            .request_raw(&self.endpoint, "GET", &path, "application/json", None)
            .map_err(|error| error.to_string())?;
        if answer.status == 404 {
            return Ok(None);
        }
        if answer.status != 200 {
            return Err(refusal(&answer.body, answer.status));
        }
        let value = cbor::decode_canonical(&answer.body)
            .map_err(|error| format!("the ref answer does not parse: {error}"))?;
        let Value::Map(pairs) = value else {
            return Err("the ref answer is not a map".to_owned());
        };
        let field = |key: i64| {
            pairs
                .iter()
                .find(|(k, _)| *k == Value::Int(key))
                .map(|(_, v)| v)
        };
        let head = match field(1) {
            Some(Value::Text(head)) => head.clone(),
            _ => return Err("the ref answer has no head".to_owned()),
        };
        let counter = match field(2) {
            Some(Value::Int(counter)) => *counter as u64,
            _ => return Err("the ref answer has no counter".to_owned()),
        };
        let statement = match field(3) {
            Some(Value::Bytes(statement)) => statement.clone(),
            _ => return Err("the ref answer has no statement".to_owned()),
        };
        Ok(Some(RefAnswer {
            head,
            counter,
            statement,
        }))
    }

    fn negotiate_push(
        &self,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String> {
        let body = self.post_cbor(
            &format!("{}/notp/push/negotiate", self.ledger_base()?),
            &request.encode(),
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
            },
            None => request.clone(),
        };
        let body = self.post_cbor(
            &format!("{}/notp/objects", self.ledger_base()?),
            &request.encode(),
        )?;
        UploadObjectsResponse::decode(&body).map_err(|error| error.to_string())
    }

    fn commit_push(&self, request: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        let body = self.post_cbor(
            &format!("{}/notp/push/commit", self.ledger_base()?),
            &request.encode(),
        )?;
        CommitPushResponse::decode(&body).map_err(|error| error.to_string())
    }

    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        let body = self.post_cbor(
            &format!("{}/notp/pull/negotiate", self.ledger_base()?),
            &request.encode(),
        )?;
        let response = NegotiatePullResponse::decode(&body).map_err(|error| error.to_string())?;
        self.remember_compression(response.compression.as_deref());
        Ok(response)
    }

    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        let request = FetchObjectsRequest {
            digests: request.digests.clone(),
            accept_compression: self.compression.borrow().clone(),
        };
        let body = self.post_cbor(
            &format!("{}/notp/objects/fetch", self.ledger_base()?),
            &request.encode(),
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
