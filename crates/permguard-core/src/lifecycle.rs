// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The component lifecycle (P2): one state machine for the Host, every Plane and every service.
//!
//! ```text
//! Bootstrap ─▶ Load ─▶ Initialize ─▶ Ready ─▶ Serving ─▶ Draining ─▶ Stopped
//!     └──────────┴──────────┴───────────┴──────────┴──▶ Failed { component, phase, reason }
//! ```
//!
//! [`Lifecycle`] is the registry every component reports into and every surface reads from: the
//! Host's own phase, each configured Plane's — listed even before it binds anything, never omitted —
//! and each background service's state. Readiness is derived from it, never set by hand: the
//! process is ready when the Host is Ready or Serving and every required Plane is too, and a
//! remote dependency never touches liveness.
//!
//! | Kind    | States                                                                 |
//! | ------- | ---------------------------------------------------------------------- |
//! | Host    | the phases, in order                                                   |
//! | Plane   | the phases; Bootstrap until the Host is Ready, then its own progress   |
//! | Service | `disabled`, `running`, `backoff`, `draining`, `failed`                 |

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use serde::Serialize;

/// A phase of the Host or a Plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Phase {
    Bootstrap,
    Load,
    Initialize,
    Ready,
    Serving,
    Draining,
    Stopped,
    Failed,
}

impl Phase {
    /// The phase as every surface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Load => "load",
            Self::Initialize => "initialize",
            Self::Ready => "ready",
            Self::Serving => "serving",
            Self::Draining => "draining",
            Self::Stopped => "stopped",
            Self::Failed => "failed",
        }
    }

    /// Whether a component in this phase accepts work: Ready and Serving only.
    pub fn accepts_work(self) -> bool {
        matches!(self, Self::Ready | Self::Serving)
    }
}

/// The state of a background service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ServiceState {
    Disabled,
    Running,
    Backoff,
    Draining,
    Failed,
}

impl ServiceState {
    /// The state as every surface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Running => "running",
            Self::Backoff => "backoff",
            Self::Draining => "draining",
            Self::Failed => "failed",
        }
    }
}

/// What a component is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    Host,
    Plane,
    Service,
}

impl Kind {
    /// The kind as every surface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Plane => "plane",
            Self::Service => "service",
        }
    }
}

/// A component's state: a phase for the Host and the Planes, a service state for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Phase(Phase),
    Service(ServiceState),
}

impl State {
    /// The state as every surface spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Phase(phase) => phase.as_str(),
            Self::Service(state) => state.as_str(),
        }
    }
}

/// One component, as discovery and health report it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub kind: Kind,
    pub state: State,
    /// Whether it gates readiness: the Host always, a Plane unless the deployment made it optional.
    pub required: bool,
    /// Since when it has been unable to progress for a remote reason, when it is.
    pub stalled_since: Option<SystemTime>,
    pub last_success: Option<SystemTime>,
    pub next_attempt: Option<SystemTime>,
    /// Why it is where it is: the failure, the backoff, what it waits for.
    pub reason: Option<String>,
    /// Capabilities of this component that are unavailable while it serves.
    pub degraded: Vec<Degraded>,
}

/// A capability that is unavailable, named so unrelated readiness is untouched.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Degraded {
    pub capability: String,
    pub reason: String,
}

/// One component as a health body carries it: `components[]` of `GET /health` and `GetHealth`.
///
/// The instants are RFC 3339 at second precision, absent when the component has none to report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ComponentReport {
    pub component: String,
    pub kind: &'static str,
    pub state: &'static str,
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stalled_since: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_success: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_attempt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ComponentReport {
    /// How `component` reads on the wire.
    pub fn of(component: &Component) -> Self {
        Self {
            component: component.name.clone(),
            kind: component.kind.as_str(),
            state: component.state.as_str(),
            required: component.required,
            stalled_since: component.stalled_since.map(rfc3339),
            last_success: component.last_success.map(rfc3339),
            next_attempt: component.next_attempt.map(rfc3339),
            reason: component.reason.clone(),
        }
    }
}

/// `when` as RFC 3339, at second precision.
fn rfc3339(when: SystemTime) -> String {
    let seconds = match when.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(since) => i64::try_from(since.as_secs()).unwrap_or(i64::MAX),
        Err(before) => -i64::try_from(before.duration().as_secs()).unwrap_or(i64::MAX),
    };
    crate::time::to_rfc3339(seconds)
}

/// What a health body says beyond `live` and `ready`: the reporting component's phase, what it
/// serves without, and every component the process hosts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Report {
    pub state: &'static str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub degraded: Vec<Degraded>,
    pub components: Vec<ComponentReport>,
}

/// The registry of every component's state, shared by everything that reports or reads it.
#[derive(Debug, Clone, Default)]
pub struct Lifecycle {
    components: Arc<Mutex<Registry>>,
}

#[derive(Debug, Default)]
struct Registry {
    components: BTreeMap<String, Component>,
    /// What each Plane still waits for before it may leave Load, by requirement, with the reason.
    waits: BTreeMap<String, BTreeMap<String, String>>,
    /// The Planes whose start the Host finished: only these move on by themselves once nothing is
    /// awaited.
    settled: std::collections::BTreeSet<String>,
}

/// The name the Host reports under.
pub const HOST: &str = "host";

impl Lifecycle {
    /// An empty registry: the Host is reported in Bootstrap from the start.
    pub fn new() -> Self {
        let lifecycle = Self::default();
        lifecycle.enter(HOST, Kind::Host, true, Phase::Bootstrap);
        lifecycle
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.components
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Lists `name` in `phase`, creating it when new; a stall clears once it progresses.
    pub fn enter(&self, name: &str, kind: Kind, required: bool, phase: Phase) {
        Self::enter_in(&mut self.lock(), name, kind, required, phase);
    }

    fn enter_in(registry: &mut Registry, name: &str, kind: Kind, required: bool, phase: Phase) {
        let component = registry
            .components
            .entry(name.to_owned())
            .or_insert_with(|| Component {
                name: name.to_owned(),
                kind,
                state: State::Phase(phase),
                required,
                stalled_since: None,
                last_success: None,
                next_attempt: None,
                reason: None,
                degraded: Vec::new(),
            });
        // Failed is terminal: nothing moves a failed component on.
        if component.state == State::Phase(Phase::Failed) {
            return;
        }
        component.required = required;
        if component.state != State::Phase(phase) {
            component.stalled_since = None;
            component.reason = None;
        }
        component.state = State::Phase(phase);
    }

    /// Moves an already listed component to `phase`, keeping its kind and requirement.
    pub fn advance(&self, name: &str, phase: Phase) {
        Self::advance_in(&mut self.lock(), name, phase);
    }

    fn advance_in(registry: &mut Registry, name: &str, phase: Phase) {
        let Some((kind, required)) = registry
            .components
            .get(name)
            .map(|component| (component.kind, component.required))
        else {
            return;
        };
        Self::enter_in(registry, name, kind, required, phase);
    }

    /// Records that Plane `name` cannot leave Load until `requirement` is satisfied, stalled since
    /// `now` for `reason`.
    ///
    /// A Plane that already accepts work does not go back: the phases only move forward, so the
    /// requirement it lost is reported as degraded instead, and the paths that need it refuse on
    /// their own.
    pub fn wait(&self, name: &str, requirement: &str, reason: impl Into<String>, now: SystemTime) {
        let reason = reason.into();
        let mut registry = self.lock();
        let Some(component) = registry.components.get_mut(name) else {
            return;
        };
        match component.state {
            State::Phase(phase) if phase.accepts_work() => {
                component
                    .degraded
                    .retain(|degraded| degraded.capability != requirement);
                component.degraded.push(Degraded {
                    capability: requirement.to_owned(),
                    reason,
                });
            }
            State::Phase(Phase::Bootstrap | Phase::Load | Phase::Initialize) => {
                component.stalled_since.get_or_insert(now);
                component.reason = Some(reason.clone());
                registry
                    .waits
                    .entry(name.to_owned())
                    .or_default()
                    .insert(requirement.to_owned(), reason);
            }
            _ => {}
        }
    }

    /// Names `capability` of component `name` as unavailable for `reason`, without touching its
    /// phase or readiness: what serves keeps serving, and the paths that need the capability
    /// refuse on their own. Replaces an earlier reason for the same capability.
    pub fn degrade(&self, name: &str, capability: &str, reason: impl Into<String>) {
        let mut registry = self.lock();
        if let Some(component) = registry.components.get_mut(name) {
            component
                .degraded
                .retain(|degraded| degraded.capability != capability);
            component.degraded.push(Degraded {
                capability: capability.to_owned(),
                reason: reason.into(),
            });
        }
    }

    /// Withdraws a [`Lifecycle::degrade`]: `capability` of `name` is available again.
    pub fn restore(&self, name: &str, capability: &str) {
        let mut registry = self.lock();
        if let Some(component) = registry.components.get_mut(name) {
            component
                .degraded
                .retain(|degraded| degraded.capability != capability);
        }
    }

    /// Records that `requirement` of Plane `name` is satisfied; a settled Plane that waits for
    /// nothing else moves on to Ready, or to Serving when the Host already serves.
    pub fn satisfy(&self, name: &str, requirement: &str) {
        let mut registry = self.lock();
        if let Some(component) = registry.components.get_mut(name) {
            component
                .degraded
                .retain(|degraded| degraded.capability != requirement);
        }
        let waits = registry.waits.entry(name.to_owned()).or_default();
        waits.remove(requirement);
        match waits.values().next_back().cloned() {
            // Still stalled, on what is left.
            Some(reason) => {
                if let Some(component) = registry.components.get_mut(name) {
                    component.reason = Some(reason);
                }
            }
            None => Self::promote(&mut registry, name),
        }
    }

    /// What Plane `name` still waits for before it may leave Load.
    pub fn awaiting(&self, name: &str) -> Vec<String> {
        self.lock()
            .waits
            .get(name)
            .map(|waits| waits.keys().cloned().collect())
            .unwrap_or_default()
    }

    /// Moves Plane `name` from Load to Initialize, its listeners about to bind, unless it still
    /// waits for a requirement: then it stays in Load, and its bound domain routes refuse with
    /// that phase.
    pub fn initialize(&self, name: &str) {
        let mut registry = self.lock();
        let waiting = registry
            .waits
            .get(name)
            .is_some_and(|waits| !waits.is_empty());
        if !waiting
            && registry
                .components
                .get(name)
                .map(|component| component.state)
                == Some(State::Phase(Phase::Load))
        {
            Self::advance_in(&mut registry, name, Phase::Initialize);
        }
    }

    /// Records that the Host finished starting Plane `name`: Ready now when it waits for nothing,
    /// otherwise as soon as its last requirement is satisfied.
    pub fn settle(&self, name: &str) {
        let mut registry = self.lock();
        registry.settled.insert(name.to_owned());
        Self::promote(&mut registry, name);
    }

    fn promote(registry: &mut Registry, name: &str) {
        if !registry.settled.contains(name)
            || registry
                .waits
                .get(name)
                .is_some_and(|waits| !waits.is_empty())
        {
            return;
        }
        let Some(State::Phase(phase)) = registry
            .components
            .get(name)
            .map(|component| component.state)
        else {
            return;
        };
        if !matches!(phase, Phase::Load | Phase::Initialize) {
            return;
        }
        let serving = registry.components.get(HOST).map(|host| host.state)
            == Some(State::Phase(Phase::Serving));
        Self::advance_in(registry, name, Phase::Initialize);
        Self::advance_in(
            registry,
            name,
            if serving {
                Phase::Serving
            } else {
                Phase::Ready
            },
        );
    }

    /// The Host serves: it moves to Serving, and so does every Plane already Ready.
    pub fn serve(&self) {
        let mut registry = self.lock();
        Self::advance_in(&mut registry, HOST, Phase::Serving);
        let ready: Vec<String> = registry
            .components
            .values()
            .filter(|component| {
                component.kind == Kind::Plane && component.state == State::Phase(Phase::Ready)
            })
            .map(|component| component.name.clone())
            .collect();
        for plane in ready {
            Self::advance_in(&mut registry, &plane, Phase::Serving);
        }
    }

    /// Fails `name` in the phase it was in, with `reason`.
    pub fn fail(&self, name: &str, reason: impl Into<String>) {
        let mut registry = self.lock();
        if let Some(component) = registry.components.get_mut(name) {
            let was = component.state.as_str();
            component.reason = Some(format!("in {was}: {}", reason.into()));
            component.state = match component.kind {
                Kind::Service => State::Service(ServiceState::Failed),
                _ => State::Phase(Phase::Failed),
            };
        }
    }

    /// Reports a service's state, with its last success and next attempt.
    pub fn service(
        &self,
        name: &str,
        state: ServiceState,
        last_success: Option<SystemTime>,
        next_attempt: Option<SystemTime>,
        reason: Option<String>,
    ) {
        let mut registry = self.lock();
        let component = registry
            .components
            .entry(name.to_owned())
            .or_insert_with(|| Component {
                name: name.to_owned(),
                kind: Kind::Service,
                state: State::Service(state),
                required: false,
                stalled_since: None,
                last_success: None,
                next_attempt: None,
                reason: None,
                degraded: Vec::new(),
            });
        // A service that shares a name with the Host or a Plane never overwrites its phase.
        if component.kind != Kind::Service {
            return;
        }
        if state == ServiceState::Backoff {
            // Since now, the moment it reported the backoff: never since the attempt still to come.
            component.stalled_since.get_or_insert_with(SystemTime::now);
        } else {
            component.stalled_since = None;
        }
        component.state = State::Service(state);
        if last_success.is_some() {
            component.last_success = last_success;
        }
        component.next_attempt = next_attempt;
        component.reason = reason;
    }

    /// One component.
    pub fn component(&self, name: &str) -> Option<Component> {
        self.lock().components.get(name).cloned()
    }

    /// A component's phase; `None` for a service or an unknown name.
    pub fn phase(&self, name: &str) -> Option<Phase> {
        match self.lock().components.get(name)?.state {
            State::Phase(phase) => Some(phase),
            State::Service(_) => None,
        }
    }

    /// Every component: the Host first, then the Planes, then the services, each by name.
    pub fn components(&self) -> Vec<Component> {
        let mut all: Vec<Component> = self.lock().components.values().cloned().collect();
        all.sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));
        all
    }

    /// The health report as component `name` gives it: its own state and degraded list, and every
    /// component. An unknown `name` reports `bootstrap`, which is where an unlisted component is.
    pub fn report(&self, name: &str) -> Report {
        let registry = self.lock();
        let (state, degraded) = registry
            .components
            .get(name)
            .map(|component| (component.state.as_str(), component.degraded.clone()))
            .unwrap_or((Phase::Bootstrap.as_str(), Vec::new()));
        let mut components: Vec<&Component> = registry.components.values().collect();
        components.sort_by(|left, right| (left.kind, &left.name).cmp(&(right.kind, &right.name)));
        Report {
            state,
            degraded,
            components: components.into_iter().map(ComponentReport::of).collect(),
        }
    }

    /// Whether the process accepts work: the Host and every required Plane are Ready or Serving.
    pub fn ready(&self) -> bool {
        self.lock()
            .components
            .values()
            .filter(|component| component.kind != Kind::Service && component.required)
            .all(|component| matches!(component.state, State::Phase(phase) if phase.accepts_work()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn readiness_waits_for_the_host_and_every_required_plane() {
        let lifecycle = Lifecycle::new();
        assert!(!lifecycle.ready(), "the Host starts in bootstrap");
        lifecycle.enter("data", Kind::Plane, true, Phase::Bootstrap);
        lifecycle.enter("control", Kind::Plane, false, Phase::Bootstrap);
        lifecycle.advance(HOST, Phase::Ready);
        assert!(!lifecycle.ready(), "a required plane is still in bootstrap");
        lifecycle.advance("data", Phase::Load);
        assert!(!lifecycle.ready(), "and then in load");
        lifecycle.advance("data", Phase::Serving);
        assert!(
            lifecycle.ready(),
            "an optional plane does not gate readiness"
        );
        lifecycle.fail("control", "its store did not open");
        assert!(lifecycle.ready(), "nor does it when it fails");
        assert_eq!(lifecycle.phase("control"), Some(Phase::Failed));
        lifecycle.advance(HOST, Phase::Draining);
        assert!(!lifecycle.ready(), "draining is not ready");
    }

    #[test]
    fn failed_is_terminal_and_names_the_phase() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter("data", Kind::Plane, true, Phase::Load);
        lifecycle.fail("data", "a ledger did not verify");
        lifecycle.advance("data", Phase::Ready);
        let data = lifecycle.component("data").expect("listed");
        assert_eq!(data.state, State::Phase(Phase::Failed));
        assert_eq!(
            data.reason.as_deref(),
            Some("in load: a ledger did not verify")
        );
    }

    #[test]
    fn a_stall_is_kept_from_its_first_report_and_cleared_by_progress() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter("data", Kind::Plane, true, Phase::Load);
        let first = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(10);
        lifecycle.wait(
            "data",
            "mirrors:http://cp",
            "the coordinator is unreachable",
            first,
        );
        lifecycle.wait(
            "data",
            "mirrors:http://cp",
            "still unreachable",
            first + std::time::Duration::from_secs(5),
        );
        let data = lifecycle.component("data").expect("listed");
        assert_eq!(
            data.stalled_since,
            Some(first),
            "the first report, not the latest"
        );
        assert_eq!(data.reason.as_deref(), Some("still unreachable"));
        lifecycle.satisfy("data", "mirrors:http://cp");
        lifecycle.settle("data");
        let data = lifecycle.component("data").expect("listed");
        assert_eq!(data.stalled_since, None);
        assert_eq!(data.reason, None);
        assert_eq!(data.state, State::Phase(Phase::Ready));
    }

    #[test]
    fn a_plane_waiting_for_a_requirement_stays_in_load_until_it_is_satisfied() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter("data", Kind::Plane, true, Phase::Bootstrap);
        lifecycle.advance(HOST, Phase::Ready);
        lifecycle.advance("data", Phase::Load);
        let since = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(7);
        lifecycle.wait(
            "data",
            "mirrors:https://cp",
            "the coordinator is unreachable",
            since,
        );
        lifecycle.initialize("data");
        lifecycle.settle("data");
        lifecycle.serve();
        let data = lifecycle.component("data").expect("listed");
        assert_eq!(data.state, State::Phase(Phase::Load), "still waiting");
        assert_eq!(data.stalled_since, Some(since));
        assert_eq!(
            data.reason.as_deref(),
            Some("the coordinator is unreachable")
        );
        assert_eq!(lifecycle.awaiting("data"), vec!["mirrors:https://cp"]);
        assert!(
            !lifecycle.ready(),
            "a required plane in load gates readiness"
        );

        lifecycle.satisfy("data", "mirrors:https://cp");
        let data = lifecycle.component("data").expect("listed");
        assert_eq!(
            data.state,
            State::Phase(Phase::Serving),
            "the Host already serves"
        );
        assert_eq!(data.stalled_since, None);
        assert!(lifecycle.ready());
    }

    #[test]
    fn a_plane_is_promoted_only_once_the_host_settled_it() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter("data", Kind::Plane, true, Phase::Load);
        lifecycle.wait("data", "ledgers", "none mirrored", SystemTime::now());
        lifecycle.satisfy("data", "ledgers");
        assert_eq!(
            lifecycle.phase("data"),
            Some(Phase::Load),
            "its start is not finished"
        );
        lifecycle.initialize("data");
        assert_eq!(lifecycle.phase("data"), Some(Phase::Initialize));
        lifecycle.settle("data");
        assert_eq!(
            lifecycle.phase("data"),
            Some(Phase::Ready),
            "the Host does not serve yet"
        );
        lifecycle.serve();
        assert_eq!(lifecycle.phase(HOST), Some(Phase::Serving));
        assert_eq!(lifecycle.phase("data"), Some(Phase::Serving));
    }

    #[test]
    fn a_requirement_lost_after_ready_degrades_and_never_goes_back() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter("data", Kind::Plane, true, Phase::Load);
        lifecycle.settle("data");
        lifecycle.serve();
        lifecycle.wait(
            "data",
            "ledgers",
            "older than expire_after",
            SystemTime::now(),
        );
        let data = lifecycle.component("data").expect("listed");
        assert_eq!(data.state, State::Phase(Phase::Serving));
        assert_eq!(
            data.degraded,
            vec![Degraded {
                capability: "ledgers".into(),
                reason: "older than expire_after".into()
            }]
        );
        assert!(lifecycle.awaiting("data").is_empty());
        lifecycle.satisfy("data", "ledgers");
        assert!(
            lifecycle
                .component("data")
                .expect("listed")
                .degraded
                .is_empty()
        );
    }

    #[test]
    fn a_failed_plane_is_never_promoted() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter("data", Kind::Plane, false, Phase::Load);
        lifecycle.fail("data", "its store did not open");
        lifecycle.settle("data");
        lifecycle.serve();
        assert_eq!(lifecycle.phase("data"), Some(Phase::Failed));
    }

    #[test]
    fn a_report_carries_the_reporting_component_and_every_other() {
        let lifecycle = Lifecycle::new();
        lifecycle.enter("data", Kind::Plane, true, Phase::Load);
        let since = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(86_400);
        lifecycle.wait("data", "mirrors", "unreachable", since);
        lifecycle.service(
            "sync",
            ServiceState::Backoff,
            None,
            Some(since),
            Some("retrying".into()),
        );
        let report = lifecycle.report("data");
        assert_eq!(report.state, "load");
        assert!(report.degraded.is_empty());
        let names: Vec<(&str, &str)> = report
            .components
            .iter()
            .map(|component| (component.component.as_str(), component.state))
            .collect();
        assert_eq!(
            names,
            vec![("host", "bootstrap"), ("data", "load"), ("sync", "backoff")]
        );
        assert_eq!(
            report.components[1].stalled_since.as_deref(),
            Some("1970-01-02T00:00:00Z")
        );
        assert_eq!(report.components[1].reason.as_deref(), Some("unreachable"));
        assert_eq!(
            report.components[2].next_attempt.as_deref(),
            Some("1970-01-02T00:00:00Z")
        );
        let json = serde_json::to_value(&report).expect("serializes");
        assert!(json.get("degraded").is_none(), "absent when empty");
        assert!(json["components"][0].get("stalled_since").is_none());
        assert_eq!(lifecycle.report("nobody").state, "bootstrap");
    }

    #[test]
    fn services_report_their_own_states_and_never_gate_readiness() {
        let lifecycle = Lifecycle::new();
        lifecycle.advance(HOST, Phase::Serving);
        let now = SystemTime::now();
        let next = now + std::time::Duration::from_secs(30);
        lifecycle.service(
            "mirrors",
            ServiceState::Backoff,
            None,
            Some(next),
            Some("unreachable".into()),
        );
        assert!(lifecycle.ready());
        let mirrors = lifecycle.component("mirrors").expect("listed");
        assert_eq!(mirrors.state.as_str(), "backoff");
        let stalled = mirrors
            .stalled_since
            .expect("stalled since it reported the backoff");
        assert!(
            stalled >= now && stalled <= SystemTime::now() && stalled < next,
            "since the report, never since the attempt still to come"
        );
        assert_eq!(mirrors.next_attempt, Some(next));
        lifecycle.service("mirrors", ServiceState::Running, Some(now), None, None);
        let mirrors = lifecycle.component("mirrors").expect("listed");
        assert_eq!(mirrors.stalled_since, None);
        assert_eq!(mirrors.last_success, Some(now));
        let names: Vec<String> = lifecycle.components().into_iter().map(|c| c.name).collect();
        assert_eq!(names, vec!["host", "mirrors"], "the Host first");
    }
}
