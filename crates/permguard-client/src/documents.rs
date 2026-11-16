// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A plane's own documents, over either transport (owner decision of 2026-11-15).
//!
//! What a client reads to find its way around a plane: the plane's document, its health, its
//! streams, its keys, the Authority Plane's status lists, and each interface's configuration. One URL, and its
//! scheme is the transport, as everywhere here: REST reads the paths the contracts fix, gRPC calls
//! the methods the same contracts pair with them (`contracts/endpoints.csv`).
//!
//! A document gRPC carries as `document_json`, or as JSON bytes, is the REST document itself; the
//! three configurations it carries as fields are mapped back member for member, so a caller holds
//! the same JSON whichever transport carried it. The process registry is not here: it is REST on
//! the Server Host listener by contract, and names each plane's `grpc_endpoint`, which is the URL a
//! client speaking gRPC alone gives this module.

use std::collections::HashMap;

use serde_json::{Map, Value, json};

use crate::catalog::{Failure, call};
use crate::endpoint::Endpoint;
use crate::grpc::GrpcChannel;
use crate::http::Client;
use crate::tls::TlsOptions;
use crate::{authority_v1 as authority, pdp_v1 as data, v1 as control};
use permguard_core::domains::interface;

/// Which plane a URL reaches: each answers on its own gRPC services.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plane {
    Control,
    Data,
    Authority,
}

impl Plane {
    /// The plane a document's public name names: `control-plane`, `data-plane`, `authority-plane`.
    pub fn of_name(name: &str) -> Option<Self> {
        match name {
            "control-plane" => Some(Self::Control),
            "data-plane" => Some(Self::Data),
            "authority-plane" => Some(Self::Authority),
            _ => None,
        }
    }

    /// Its public name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Control => "control-plane",
            Self::Data => "data-plane",
            Self::Authority => "authority-plane",
        }
    }

    const fn keys_path(self) -> &'static str {
        match self {
            Self::Control => "/control-plane/v1/keys",
            Self::Data => "/data-plane/v1/keys",
            Self::Authority => "/authority/v1/keys",
        }
    }
}

/// An interface whose configuration a plane publishes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interface {
    /// `permguard.api.decisions.native.v1`, on the Control Plane.
    Decisions,
    /// `permguard.api.events.native.v1alpha1`, on the Control Plane.
    Events,
    /// `permguard.api.pdp.native.v1`, on the Data Plane.
    Pdp,
    /// `permguard.api.pdp.temporal.v1alpha1`, on the Data Plane.
    Temporal,
}

impl Interface {
    /// The interface an identifier names.
    pub fn of_id(id: &str) -> Option<Self> {
        match id {
            interface::DECISIONS_NATIVE_V1 => Some(Self::Decisions),
            interface::EVENTS_NATIVE_V1ALPHA1 => Some(Self::Events),
            interface::PDP_NATIVE_V1 => Some(Self::Pdp),
            interface::PDP_TEMPORAL_V1ALPHA1 => Some(Self::Temporal),
            _ => None,
        }
    }

    /// Its identifier.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Decisions => interface::DECISIONS_NATIVE_V1,
            Self::Events => interface::EVENTS_NATIVE_V1ALPHA1,
            Self::Pdp => interface::PDP_NATIVE_V1,
            Self::Temporal => interface::PDP_TEMPORAL_V1ALPHA1,
        }
    }

    /// The plane that publishes it.
    pub const fn plane(self) -> Plane {
        match self {
            Self::Decisions | Self::Events => Plane::Control,
            Self::Pdp | Self::Temporal => Plane::Data,
        }
    }

    const fn path(self) -> &'static str {
        match self {
            Self::Decisions => "/.well-known/permguard-decisions-native-v1-configuration",
            Self::Events => "/.well-known/permguard-events-native-v1alpha1-configuration",
            Self::Pdp => "/.well-known/permguard-pdp-v1-configuration",
            Self::Temporal => "/.well-known/permguard-pdp-temporal-v1alpha1-configuration",
        }
    }
}

/// A plane's documents, over the transport its URL names.
pub trait Documents {
    /// `GET /.well-known/server-configuration`, `<Plane>/GetServerConfiguration`.
    fn configuration(&self) -> Result<Value, Failure>;
    /// `GET /health`, `<Plane>/GetHealth`: whether it is live and ready, its phase, what is
    /// degraded and every component.
    fn health(&self) -> Result<Value, Failure>;
    /// `GET /streams/v1`, `<Plane>/GetStreams`: the Control and Data Planes only.
    fn streams(&self) -> Result<Value, Failure>;
    /// The plane's public key set: `GitLikeStore/GetKeyRing`, `DataPlane/GetKeys` or
    /// `TokenService/GetKeys`.
    fn keys(&self) -> Result<Value, Failure>;
    /// `GET /authority/v1/status-lists`, `TokenService/ListStatusLists`: the Authority Plane only.
    fn status_lists(&self) -> Result<Value, Failure>;
    /// An interface's own configuration document, on the plane that publishes it.
    fn interface(&self, interface: Interface) -> Result<Value, Failure>;
}

/// The documents of the `plane` at `url`: REST for `http`/`https`, gRPC for `grpc`/`grpcs`.
pub fn client(
    url: &str,
    plane: Plane,
    tls: &TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn Documents + Send + Sync>, String> {
    let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;
    if endpoint.is_grpc() {
        return Ok(Box::new(GrpcDocuments {
            channel: GrpcChannel::connect(url, tls, narrator)?,
            plane,
        }));
    }
    let client = Client::new(
        std::time::Duration::from_secs(30),
        tls.clone(),
        endpoint.is_tls(),
    )
    .map_err(|error| error.to_string())?
    .with_narrator(narrator);
    Ok(Box::new(RestDocuments {
        client,
        endpoint,
        plane,
    }))
}

fn usage(detail: String) -> Failure {
    Failure {
        class: "validation".to_owned(),
        reason: permguard_core::codes::client::USAGE.to_owned(),
        detail,
        usage: true,
    }
}

/// A read this plane does not publish: asked of the wrong plane, refused before anything is sent.
fn not_on(plane: Plane, what: &str) -> Failure {
    usage(format!("the {} publishes no {what}", plane.name()))
}

fn decoded(what: &str, bytes: &[u8]) -> Result<Value, Failure> {
    serde_json::from_slice(bytes).map_err(|error| Failure {
        class: "internal".to_owned(),
        reason: permguard_core::codes::client::DECODE_FAILED.to_owned(),
        detail: format!("the {what} the plane answered is not JSON: {error}"),
        usage: false,
    })
}

struct RestDocuments {
    client: Client,
    endpoint: Endpoint,
    plane: Plane,
}

impl RestDocuments {
    fn get(&self, path: &str) -> Result<Value, Failure> {
        call(&self.client, &self.endpoint, "GET", path, None)
    }
}

impl Documents for RestDocuments {
    fn configuration(&self) -> Result<Value, Failure> {
        self.get("/.well-known/server-configuration")
    }

    fn health(&self) -> Result<Value, Failure> {
        self.get("/health")
    }

    fn streams(&self) -> Result<Value, Failure> {
        if self.plane == Plane::Authority {
            return Err(not_on(self.plane, "streams"));
        }
        self.get("/streams/v1")
    }

    fn keys(&self) -> Result<Value, Failure> {
        self.get(self.plane.keys_path())
    }

    fn status_lists(&self) -> Result<Value, Failure> {
        if self.plane != Plane::Authority {
            return Err(not_on(self.plane, "status lists"));
        }
        self.get("/authority/v1/status-lists")
    }

    fn interface(&self, interface: Interface) -> Result<Value, Failure> {
        if interface.plane() != self.plane {
            return Err(not_on(self.plane, interface.id()));
        }
        self.get(interface.path())
    }
}

struct GrpcDocuments {
    channel: GrpcChannel,
    plane: Plane,
}

impl GrpcDocuments {
    fn run<T, F>(&self, rpc: &str, future: F) -> Result<T, Failure>
    where
        F: std::future::Future<Output = Result<tonic::Response<T>, tonic::Status>>,
    {
        self.channel
            .run(rpc, future)
            .map_err(crate::grpc::failure_of)
    }
}

impl Documents for GrpcDocuments {
    fn configuration(&self) -> Result<Value, Failure> {
        let channel = self.channel.channel();
        let document = match self.plane {
            Plane::Control => {
                self.run(
                    "GetServerConfiguration",
                    control::control_plane_client::ControlPlaneClient::new(channel)
                        .get_server_configuration(control::GetServerConfigurationRequest {}),
                )?
                .document_json
            }
            Plane::Data => {
                self.run(
                    "GetServerConfiguration",
                    data::data_plane_client::DataPlaneClient::new(channel)
                        .get_server_configuration(data::GetServerConfigurationRequest {}),
                )?
                .document_json
            }
            Plane::Authority => {
                self.run(
                    "GetServerConfiguration",
                    authority::authority_plane_client::AuthorityPlaneClient::new(channel)
                        .get_server_configuration(authority::GetServerConfigurationRequest {}),
                )?
                .document_json
            }
        };
        decoded("document", document.as_bytes())
    }

    fn health(&self) -> Result<Value, Failure> {
        let channel = self.channel.channel();
        Ok(match self.plane {
            Plane::Control => {
                let answer = self.run(
                    "GetHealth",
                    control::control_plane_client::ControlPlaneClient::new(channel)
                        .get_health(control::GetHealthRequest {}),
                )?;
                health_document(
                    answer.live,
                    answer.ready,
                    answer.state,
                    answer
                        .degraded
                        .into_iter()
                        .map(|held| (held.capability, held.reason))
                        .collect(),
                    answer
                        .components
                        .into_iter()
                        .map(|held| HealthComponent {
                            component: held.component,
                            kind: held.kind,
                            state: held.state,
                            required: held.required,
                            stalled_since: held.stalled_since,
                            last_success: held.last_success,
                            next_attempt: held.next_attempt,
                            reason: held.reason,
                        })
                        .collect(),
                )
            }
            Plane::Data => {
                let answer = self.run(
                    "GetHealth",
                    data::data_plane_client::DataPlaneClient::new(channel)
                        .get_health(data::GetHealthRequest {}),
                )?;
                health_document(
                    answer.live,
                    answer.ready,
                    answer.state,
                    answer
                        .degraded
                        .into_iter()
                        .map(|held| (held.capability, held.reason))
                        .collect(),
                    answer
                        .components
                        .into_iter()
                        .map(|held| HealthComponent {
                            component: held.component,
                            kind: held.kind,
                            state: held.state,
                            required: held.required,
                            stalled_since: held.stalled_since,
                            last_success: held.last_success,
                            next_attempt: held.next_attempt,
                            reason: held.reason,
                        })
                        .collect(),
                )
            }
            Plane::Authority => {
                let answer = self.run(
                    "GetHealth",
                    authority::authority_plane_client::AuthorityPlaneClient::new(channel)
                        .get_health(authority::GetHealthRequest {}),
                )?;
                health_document(
                    answer.live,
                    answer.ready,
                    answer.state,
                    answer
                        .degraded
                        .into_iter()
                        .map(|held| (held.capability, held.reason))
                        .collect(),
                    answer
                        .components
                        .into_iter()
                        .map(|held| HealthComponent {
                            component: held.component,
                            kind: held.kind,
                            state: held.state,
                            required: held.required,
                            stalled_since: held.stalled_since,
                            last_success: held.last_success,
                            next_attempt: held.next_attempt,
                            reason: held.reason,
                        })
                        .collect(),
                )
            }
        })
    }

    fn streams(&self) -> Result<Value, Failure> {
        let channel = self.channel.channel();
        let document = match self.plane {
            Plane::Control => {
                self.run(
                    "GetStreams",
                    control::control_plane_client::ControlPlaneClient::new(channel)
                        .get_streams(control::GetStreamsRequest {}),
                )?
                .document_json
            }
            Plane::Data => {
                self.run(
                    "GetStreams",
                    data::data_plane_client::DataPlaneClient::new(channel)
                        .get_streams(data::GetStreamsRequest {}),
                )?
                .document_json
            }
            Plane::Authority => return Err(not_on(self.plane, "streams")),
        };
        decoded("streams document", document.as_bytes())
    }

    fn keys(&self) -> Result<Value, Failure> {
        let channel = self.channel.channel();
        match self.plane {
            Plane::Control => decoded(
                "key set",
                &self
                    .run(
                        "GetKeyRing",
                        control::git_like_store_client::GitLikeStoreClient::new(channel)
                            .get_key_ring(control::GetKeyRingRequest {}),
                    )?
                    .jwks,
            ),
            Plane::Data => decoded(
                "key set",
                &self
                    .run(
                        "GetKeys",
                        data::data_plane_client::DataPlaneClient::new(channel)
                            .get_keys(data::GetKeysRequest {}),
                    )?
                    .jwks,
            ),
            Plane::Authority => decoded(
                "key set",
                self.run(
                    "GetKeys",
                    authority::token_service_client::TokenServiceClient::new(channel)
                        .get_keys(authority::GetKeysRequest {}),
                )?
                .jwks_json
                .as_bytes(),
            ),
        }
    }

    fn status_lists(&self) -> Result<Value, Failure> {
        if self.plane != Plane::Authority {
            return Err(not_on(self.plane, "status lists"));
        }
        let lists = self
            .run(
                "ListStatusLists",
                authority::token_service_client::TokenServiceClient::new(self.channel.channel())
                    .list_status_lists(authority::ListStatusListsRequest {}),
            )?
            .lists;
        Ok(json!({ "lists": lists }))
    }

    fn interface(&self, interface: Interface) -> Result<Value, Failure> {
        if interface.plane() != self.plane {
            return Err(not_on(self.plane, interface.id()));
        }
        let channel = self.channel.channel();
        match interface {
            Interface::Decisions => decoded(
                "decisions configuration",
                self.run(
                    "GetConfiguration",
                    control::decision_log_client::DecisionLogClient::new(channel)
                        .get_configuration(control::GetDecisionConfigurationRequest {}),
                )?
                .document_json
                .as_bytes(),
            ),
            Interface::Events => Ok(events_document(self.run(
                "GetEventConfiguration",
                control::event_log_client::EventLogClient::new(channel)
                    .get_event_configuration(control::GetEventConfigurationRequest {}),
            )?)),
            Interface::Pdp => Ok(pdp_document(self.run(
                "GetConfiguration",
                data::policy_decision_point_client::PolicyDecisionPointClient::new(channel)
                    .get_configuration(data::GetConfigurationRequest {}),
            )?)),
            Interface::Temporal => Ok(temporal_document(
                self.run(
                    "GetTemporalConfiguration",
                    data::temporal_policy_decision_point_client::TemporalPolicyDecisionPointClient::new(
                        channel,
                    )
                    .get_temporal_configuration(data::GetTemporalConfigurationRequest {}),
                )?,
            )),
        }
    }
}

/// One component of a plane's health, as the three planes' `GetHealth` carry it alike.
struct HealthComponent {
    component: String,
    kind: String,
    state: String,
    required: bool,
    stalled_since: Option<String>,
    last_success: Option<String>,
    next_attempt: Option<String>,
    reason: Option<String>,
}

/// `<Plane>/GetHealth`, member for member the REST `/health`: `degraded` only when something is,
/// a component's optional members only when it has them.
fn health_document(
    live: bool,
    ready: bool,
    state: String,
    degraded: Vec<(String, String)>,
    components: Vec<HealthComponent>,
) -> Value {
    let mut document = Map::new();
    document.insert("live".to_owned(), json!(live));
    document.insert("ready".to_owned(), json!(ready));
    document.insert("state".to_owned(), json!(state));
    if !degraded.is_empty() {
        document.insert(
            "degraded".to_owned(),
            Value::Array(
                degraded
                    .into_iter()
                    .map(|(capability, reason)| json!({ "capability": capability, "reason": reason }))
                    .collect(),
            ),
        );
    }
    document.insert(
        "components".to_owned(),
        Value::Array(
            components
                .into_iter()
                .map(|held| {
                    let mut component = Map::new();
                    component.insert("component".to_owned(), json!(held.component));
                    component.insert("kind".to_owned(), json!(held.kind));
                    component.insert("state".to_owned(), json!(held.state));
                    component.insert("required".to_owned(), json!(held.required));
                    for (name, value) in [
                        ("stalled_since", held.stalled_since),
                        ("last_success", held.last_success),
                        ("next_attempt", held.next_attempt),
                        ("reason", held.reason),
                    ] {
                        if let Some(value) = value {
                            component.insert(name.to_owned(), json!(value));
                        }
                    }
                    Value::Object(component)
                })
                .collect(),
        ),
    );
    Value::Object(document)
}

/// The common header every interface document carries (WP-7.4a); the sunset only when deprecated.
fn header(
    document: &mut Map<String, Value>,
    version: String,
    component: String,
    state: String,
    stage: String,
    sunset: Option<String>,
) {
    document.insert("version".to_owned(), json!(version));
    document.insert("component".to_owned(), json!(component));
    document.insert("state".to_owned(), json!(state));
    document.insert("stage".to_owned(), json!(stage));
    if let Some(sunset) = sunset {
        document.insert("sunset".to_owned(), json!(sunset));
    }
}

/// The ceilings by name, as the REST document's `limits` object.
fn limits(limits: HashMap<String, u64>) -> Value {
    Value::Object(
        limits
            .into_iter()
            .map(|(name, value)| (name, json!(value)))
            .collect(),
    )
}

fn store_scope(scope: Option<data::StoreScope>) -> Value {
    let scope = scope.unwrap_or_default();
    json!({
        "in": scope.r#in,
        "zone": scope.zone,
        "ledger": scope.ledger,
        "profile": scope.profile,
    })
}

/// `EventLog/GetEventConfiguration`, member for member the REST document.
pub fn events_document(answer: control::GetEventConfigurationResponse) -> Value {
    let endpoints = answer.endpoints.unwrap_or_default();
    let offsets = answer.offsets.unwrap_or_default();
    let mut document = Map::new();
    document.insert("interface".to_owned(), json!(answer.r#interface));
    document.insert("store".to_owned(), json!(answer.store));
    document.insert(
        "endpoints".to_owned(),
        json!({ "records": endpoints.records, "record": endpoints.record }),
    );
    document.insert("event_types".to_owned(), json!(answer.event_types));
    document.insert("capabilities".to_owned(), json!(answer.capabilities));
    document.insert(
        "offsets".to_owned(),
        json!({ "api": offsets.api, "format": offsets.format, "editable": offsets.editable }),
    );
    document.insert(
        "producer_classes".to_owned(),
        json!(answer.producer_classes),
    );
    document.insert("filters".to_owned(), json!(answer.filters));
    document.insert("limits".to_owned(), limits(answer.limits));
    header(
        &mut document,
        answer.version,
        answer.component,
        answer.state,
        answer.stage,
        answer.sunset,
    );
    Value::Object(document)
}

/// `PolicyDecisionPoint/GetConfiguration`, member for member the REST document.
pub fn pdp_document(answer: data::GetConfigurationResponse) -> Value {
    let endpoints = answer.endpoints.unwrap_or_default();
    let signing = answer.response_signing.unwrap_or_default();
    let mut document = Map::new();
    document.insert("interface".to_owned(), json!(answer.r#interface));
    document.insert("pdp".to_owned(), json!(answer.pdp));
    document.insert(
        "endpoints".to_owned(),
        json!({ "evaluation": endpoints.evaluation, "evaluations": endpoints.evaluations }),
    );
    document.insert("capabilities".to_owned(), json!(answer.capabilities));
    document.insert("store_scope".to_owned(), store_scope(answer.store_scope));
    document.insert("limits".to_owned(), limits(answer.limits));
    // `optional` carries its lifetime and skew; `disabled` its state alone, as REST tags it.
    document.insert(
        "response_signing".to_owned(),
        if signing.state == "optional" {
            json!({
                "state": signing.state,
                "validity_seconds": signing.validity_seconds,
                "clock_skew_seconds": signing.clock_skew_seconds,
            })
        } else {
            json!({ "state": signing.state })
        },
    );
    header(
        &mut document,
        answer.version,
        answer.component,
        answer.state,
        answer.stage,
        answer.sunset,
    );
    Value::Object(document)
}

/// `TemporalPolicyDecisionPoint/GetTemporalConfiguration`, member for member the REST document.
pub fn temporal_document(answer: data::GetTemporalConfigurationResponse) -> Value {
    let endpoints = answer.endpoints.unwrap_or_default();
    let mut document = Map::new();
    document.insert("interface".to_owned(), json!(answer.r#interface));
    document.insert("pdp".to_owned(), json!(answer.pdp));
    document.insert(
        "endpoints".to_owned(),
        json!({ "submission": endpoints.submission }),
    );
    document.insert("event_types".to_owned(), json!(answer.event_types));
    document.insert("capabilities".to_owned(), json!(answer.capabilities));
    document.insert("store_scope".to_owned(), store_scope(answer.store_scope));
    document.insert("limits".to_owned(), limits(answer.limits));
    header(
        &mut document,
        answer.version,
        answer.component,
        answer.state,
        answer.stage,
        answer.sunset,
    );
    Value::Object(document)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plane_and_an_interface_are_named_by_what_the_documents_say() {
        for plane in [Plane::Control, Plane::Data, Plane::Authority] {
            assert_eq!(Plane::of_name(plane.name()), Some(plane));
        }
        assert_eq!(Plane::of_name("host"), None);
        for interface in [
            Interface::Decisions,
            Interface::Events,
            Interface::Pdp,
            Interface::Temporal,
        ] {
            assert_eq!(Interface::of_id(interface.id()), Some(interface));
        }
        assert_eq!(Interface::of_id(interface::PDP_V1_LEGACY), None);
        assert_eq!(Interface::Pdp.plane(), Plane::Data);
        assert_eq!(Interface::Events.plane(), Plane::Control);
    }

    #[test]
    fn the_events_configuration_maps_back_member_for_member() {
        let document = events_document(control::GetEventConfigurationResponse {
            r#interface: interface::EVENTS_NATIVE_V1ALPHA1.to_owned(),
            store: "s-1".to_owned(),
            endpoints: Some(control::EventEndpoints {
                records: "http://c/records".to_owned(),
                record: "http://c/records/{event_id}".to_owned(),
            }),
            event_types: vec!["permguard.dogwood.event.v1".to_owned()],
            capabilities: vec!["read".to_owned()],
            offsets: Some(control::EventOffsets {
                api: "opaque".to_owned(),
                format: "base64url".to_owned(),
                editable: false,
            }),
            version: "0.1.32".to_owned(),
            component: "control-plane".to_owned(),
            state: "serving".to_owned(),
            stage: "preview".to_owned(),
            sunset: None,
            limits: [("max_records".to_owned(), 1000)].into_iter().collect(),
            producer_classes: vec!["data-plane".to_owned()],
            filters: vec!["kind".to_owned()],
        });
        assert_eq!(
            document,
            json!({
                "interface": interface::EVENTS_NATIVE_V1ALPHA1,
                "store": "s-1",
                "endpoints": {"records": "http://c/records", "record": "http://c/records/{event_id}"},
                "event_types": ["permguard.dogwood.event.v1"],
                "capabilities": ["read"],
                "offsets": {"api": "opaque", "format": "base64url", "editable": false},
                "producer_classes": ["data-plane"],
                "filters": ["kind"],
                "limits": {"max_records": 1000},
                "version": "0.1.32",
                "component": "control-plane",
                "state": "serving",
                "stage": "preview",
            })
        );
    }

    #[test]
    fn the_pdp_configuration_maps_back_its_signing_as_rest_tags_it() {
        let answer = |signing: data::ResponseSigning, sunset: Option<&str>| {
            pdp_document(data::GetConfigurationResponse {
                r#interface: interface::PDP_NATIVE_V1.to_owned(),
                pdp: "p-1".to_owned(),
                endpoints: Some(data::Endpoints {
                    evaluation: "http://d/eval".to_owned(),
                    evaluations: "http://d/evals".to_owned(),
                }),
                capabilities: vec![],
                store_scope: Some(data::StoreScope {
                    r#in: "path".to_owned(),
                    zone: "z".to_owned(),
                    ledger: "l".to_owned(),
                    profile: "default".to_owned(),
                }),
                version: "0.1.32".to_owned(),
                component: "data-plane".to_owned(),
                state: "serving".to_owned(),
                stage: "deprecated".to_owned(),
                sunset: sunset.map(str::to_owned),
                limits: [("max_evaluations".to_owned(), 64)].into_iter().collect(),
                response_signing: Some(signing),
            })
        };
        let optional = answer(
            data::ResponseSigning {
                state: "optional".to_owned(),
                validity_seconds: 300,
                clock_skew_seconds: 30,
            },
            Some("2027-06-30T00:00:00Z"),
        );
        assert_eq!(
            optional["response_signing"],
            json!({"state": "optional", "validity_seconds": 300, "clock_skew_seconds": 30})
        );
        assert_eq!(optional["sunset"], "2027-06-30T00:00:00Z");
        assert_eq!(
            optional["store_scope"],
            json!({"in": "path", "zone": "z", "ledger": "l", "profile": "default"})
        );
        let disabled = answer(
            data::ResponseSigning {
                state: "disabled".to_owned(),
                ..data::ResponseSigning::default()
            },
            None,
        );
        assert_eq!(disabled["response_signing"], json!({"state": "disabled"}));
        assert!(disabled.get("sunset").is_none(), "no sunset, no member");
    }

    #[test]
    fn a_health_maps_back_as_rest_answers_it() {
        let healthy = health_document(
            true,
            true,
            "serving".to_owned(),
            Vec::new(),
            vec![HealthComponent {
                component: "decisions".to_owned(),
                kind: "service".to_owned(),
                state: "serving".to_owned(),
                required: true,
                stalled_since: None,
                last_success: Some("2026-11-15T00:00:00Z".to_owned()),
                next_attempt: None,
                reason: None,
            }],
        );
        assert_eq!(
            healthy,
            json!({
                "live": true,
                "ready": true,
                "state": "serving",
                "components": [{
                    "component": "decisions",
                    "kind": "service",
                    "state": "serving",
                    "required": true,
                    "last_success": "2026-11-15T00:00:00Z",
                }],
            }),
            "nothing degraded, no `degraded`; a component's absent members absent"
        );
        let degraded = health_document(
            true,
            false,
            "ready".to_owned(),
            vec![("shipping".to_owned(), "stalled".to_owned())],
            Vec::new(),
        );
        assert_eq!(
            degraded["degraded"],
            json!([{"capability": "shipping", "reason": "stalled"}])
        );
    }

    #[test]
    fn the_temporal_configuration_maps_back_member_for_member() {
        let document = temporal_document(data::GetTemporalConfigurationResponse {
            r#interface: interface::PDP_TEMPORAL_V1ALPHA1.to_owned(),
            pdp: "p-1".to_owned(),
            endpoints: Some(data::TemporalEndpoints {
                submission: "http://d/submit".to_owned(),
            }),
            event_types: vec!["permguard.dogwood.event.v1".to_owned()],
            capabilities: vec![],
            store_scope: None,
            version: "0.1.32".to_owned(),
            component: "data-plane".to_owned(),
            state: "serving".to_owned(),
            stage: "preview".to_owned(),
            sunset: None,
            limits: HashMap::new(),
        });
        assert_eq!(
            document["endpoints"],
            json!({"submission": "http://d/submit"})
        );
        assert_eq!(document["limits"], json!({}));
        assert_eq!(
            document["store_scope"],
            json!({"in": "", "zone": "", "ledger": "", "profile": ""})
        );
    }
}
