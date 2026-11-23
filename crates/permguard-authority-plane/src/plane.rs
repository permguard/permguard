// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane as a Plane of the Host: what it declares, how it composes its facade from
//! the handles the Host registered, and the pass that keeps its lists signed. Its routes, on both
//! transports, are `permguard-authority-plane-server`'s.
//!
//! | Declared                           | Handle                           | Used by                     |
//! | ---------------------------------- | -------------------------------- | --------------------------- |
//! | signs `AccessTokenV1`              | `Signer<AccessTokenV1>`          | the token endpoint, the keys |
//! | signs `StatusListTokenV1`          | `Signer<StatusListTokenV1>`      | the status lists            |
//! | audit schema [`AuthorityAudit`]    | `AuditHandle<AuthorityAudit>`    | tokens issued and refused   |
//! | mutates `authority.accounts`, `authority.tokens` | `MutationHandle`   | every change                |
//! | feeds the token trust              | `AuthorityTrust`                 | this Host's verification    |

use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Result;
use permguard_core::planes::discovery::{PlaneId, plane_http_base};
use permguard_core::planes::settings::{
    SETTING_AUTHORITY_AUDIENCE, SETTING_AUTHORITY_GRPC_ADDR, SETTING_AUTHORITY_URL,
};
use permguard_core::{BoxFuture, PlaneContext, PlaneTask};
use permguard_host::composition::{AccessTokenV1, Declaration, StatusListTokenV1};

use crate::authority::{Authority, AuthorityAudit, Parts};
use crate::{accounts, admin, tokens};

/// How often the lists are signed again and handed to this Host: well within their `ttl`.
const FEED_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
/// How often the lists whose tokens all expired are retired.
const RETIRE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);
/// The single job the retirement of expired lists is (WP-28.2).
const RETIRE_JOB: &str = "authority/retire-lists";

/// The facade, composed once from the Host's handles and shared by whatever serves it and by the
/// plane's pass: `None` when the plane is dormant or could not compose, as the log says why.
#[derive(Default)]
pub struct Composition {
    authority: OnceLock<Option<Arc<Authority>>>,
}

impl Composition {
    /// The facade under `context`, composed at the first call.
    pub fn authority(&self, context: &PlaneContext<'_>) -> Option<Arc<Authority>> {
        self.authority.get_or_init(|| compose(context)).clone()
    }
}

/// The issuer the Authority Plane signs as: `authority.url`, or where its HTTP listener is
/// advertised.
pub fn issuer_of(config: &permguard_core::Config) -> Option<String> {
    config
        .setting(SETTING_AUTHORITY_URL)
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .or_else(|| plane_http_base(config, PlaneId::Authority))
        .map(|url| permguard_host::authz::authority::normalized(&url))
}

/// Whether the Authority Plane has a listener of its own: without one it is dormant, as every
/// Plane is that is given no address, and serves and signs nothing.
fn listening(config: &permguard_core::Config) -> bool {
    plane_http_base(config, PlaneId::Authority).is_some()
        || config
            .setting(SETTING_AUTHORITY_GRPC_ADDR)
            .is_some_and(|address| !address.trim().is_empty())
}

/// The stores of the Authority Plane on a backend that is not a volume (iteration 03, WP-28.1):
/// what the composition hands it, found among the context's extensions.
pub struct AuthorityStores {
    pub accounts: Arc<dyn accounts::AccountStore>,
    pub tokens: Arc<dyn tokens::TokenStore>,
    pub marks: Arc<dyn crate::marks::MarkStore>,
    /// The database the three are kept in: what a start completes of the tokens reads the
    /// accounts and writes the tokens in one of its units, so an instance that changes them
    /// meanwhile has the unit run again rather than its change read as gone (WP-28.2).
    pub database: permguard_postgres::Database,
}

fn compose(context: &PlaneContext<'_>) -> Option<Arc<Authority>> {
    let config = context.config();
    if !listening(config) {
        tracing::info!(
            event.name = "authority.dormant",
            component = crate::COMPONENT,
            "the Authority Plane has no listener: it issues nothing in this process"
        );
        return None;
    }
    let fail = |what: &str, error: &dyn std::fmt::Display| {
        tracing::error!(
            event.name = "authority.unserved",
            component = crate::COMPONENT,
            error = %error,
            "the Authority Plane serves nothing: {what}"
        );
    };
    let Some(registration) = crate::handles::registration(context) else {
        fail("no Host registered it", &"no registration");
        return None;
    };
    let Some(issuer) = issuer_of(config) else {
        fail(
            "it has no issuer",
            &"set authority.url, or give the Authority Plane an HTTP listener",
        );
        return None;
    };
    // On a shared backend the composition hands the stores over; on files they are this Plane's
    // directory of the volume. Either way the administrator's first secret and an offline mark
    // are files of this instance, beside its configuration (decision X105).
    let shared = context.extension::<AuthorityStores>();
    let (dir, options) = match (&shared, registration.state_dir()) {
        (None, Ok(Some(found))) => found,
        (Some(_), _) => match permguard_host::storage::Dir::create_root(
            &config.working_dir().join("planes").join(crate::PLANE),
        ) {
            Ok(dir) => (dir, permguard_host::storage::journal::Options::default()),
            Err(error) => {
                fail("its directory does not open", &error);
                return None;
            }
        },
        (None, Ok(None)) => {
            fail("the Host composes no volume", &"no volume");
            return None;
        }
        (None, Err(error)) => {
            fail("its directory does not open", &error);
            return None;
        }
    };
    // One subsystem: an account's change and the tokens it ends are one step (decision E26).
    let accounts_mutations = registration
        .mutations(accounts::DOMAIN)
        .ok()
        .flatten()
        .map(|handle| handle.in_subsystem(crate::PLANE));
    let token_mutations = registration
        .mutations(tokens::DOMAIN)
        .ok()
        .flatten()
        .map(|handle| handle.in_subsystem(crate::PLANE));
    let (accounts, registry): (Arc<dyn accounts::AccountStore>, Arc<dyn tokens::TokenStore>) =
        match &shared {
            Some(stores) => (Arc::clone(&stores.accounts), Arc::clone(&stores.tokens)),
            None => {
                let accounts = match accounts::files::FileAccounts::open(&dir, options) {
                    Ok((opened, _)) => opened,
                    Err(error) => {
                        fail("its accounts do not open", &error);
                        return None;
                    }
                };
                let registry = match tokens::files::FileTokens::open(&dir, options) {
                    Ok((opened, _)) => opened,
                    Err(error) => {
                        fail("its tokens do not open", &error);
                        return None;
                    }
                };
                (accounts as _, registry as _)
            }
        };
    // A change a crash left open is committed or failed before anything reads the state.
    if let Some(handle) = &accounts_mutations
        && let Err(error) = handle.recover(&accounts::Recovering(&*accounts))
    {
        fail(
            "the account changes a crash left open do not resolve",
            &error,
        );
        return None;
    }
    if let Some(handle) = &token_mutations
        && let Err(error) = handle.recover(&tokens::Recovering(&*registry))
    {
        fail(
            "the token revocations a crash left open do not resolve",
            &error,
        );
        return None;
    }
    let time = Arc::new(permguard_host::time::TimeGuard::system(
        config.time_max_clock_skew(),
    ));
    // What a change of an account left to do of its tokens is done before anything is served.
    let now = time.now_secs();
    let completing = || crate::completion::complete_tokens(&*accounts, &*registry, now);
    let completion = match &shared {
        Some(stores) => stores
            .database
            // A statement the database failed, one it could not serialize among them, is the
            // unit's failure, so the unit is run again; only the completion's own refusal is one.
            .transaction(|unit| {
                completing().map_err(|refusal| match unit.failure() {
                    Some(failed) => permguard_postgres::Failure::Db(failed),
                    None => permguard_postgres::Failure::Refused(refusal),
                })
            })
            .map_err(|error| error.to_string())
            .and_then(|completed| completed),
        None => completing(),
    };
    let completed = match completion {
        Ok(completed) if completed.is_empty() => None,
        Ok(completed) => {
            tracing::warn!(
                event.name = "authority.tokens_completed",
                component = crate::COMPONENT,
                invalidated = completed.invalidated,
                suspended = completed.suspended,
                "tokens a change of their account had left as they were now are as it says"
            );
            Some(completed)
        }
        Err(error) => {
            fail(
                "the tokens a change of their account left to revoke are not completed",
                &error,
            );
            return None;
        }
    };
    match admin::ensure(&*accounts, dir.path(), time.now_secs()) {
        Ok(Some(access_key)) => tracing::warn!(
            event.name = "authority.admin_created",
            component = crate::COMPONENT,
            access_key = %access_key,
            file = %dir.path().join(admin::KEY_FILE).display(),
            "the administrator `admin` is made: its first secret key is in the file named, \
             readable by its owner alone; move it somewhere safe and delete the file"
        ),
        Ok(None) => {}
        Err(error) => {
            fail("the administrator could not be made", &error);
            return None;
        }
    }
    let offline = admin::take_offline_mark(dir.path());
    let signer = |what: &str| {
        tracing::warn!(
            event.name = "authority.unsigned",
            component = crate::COMPONENT,
            "no authority.tokens ring is composed: the Authority Plane issues no {what}"
        );
    };
    let token_signer = registration.signer::<AccessTokenV1>().ok().flatten();
    if token_signer.is_none() {
        signer("token");
    }
    let list_signer = registration.signer::<StatusListTokenV1>().ok().flatten();
    let audit = registration.audit::<AuthorityAudit>().ok().flatten();
    let authority = match Authority::new(Parts {
        accounts,
        registry,
        tokens: token_signer,
        lists: list_signer,
        issuer: issuer.clone(),
        audience: config
            .setting(SETTING_AUTHORITY_AUDIENCE)
            .map(str::trim)
            .filter(|audience| !audience.is_empty())
            .unwrap_or(permguard_host::authz::authority::DEFAULT_AUDIENCE)
            .to_owned(),
        profile: config.assurance().profile(),
        authorization: registration.authorization(),
        mutations: accounts_mutations,
        audit: audit.clone(),
        trust: registration.authority_trust(),
        time,
        marks: match &shared {
            Some(stores) => Some(Arc::clone(&stores.marks)),
            None => permguard_host::storage::Dir::open(dir.path())
                .ok()
                .map(|dir| {
                    Arc::new(crate::marks::files::FileMarks::new(dir))
                        as Arc<dyn crate::marks::MarkStore>
                }),
        },
    }) {
        Ok(authority) => Arc::new(authority),
        Err(error) => {
            fail("its status lists do not read", &error);
            return None;
        }
    };
    authority.feed_trust();
    // What the start changed of the tokens is in the trail, beside the log line.
    if let (Some(completed), Some(audit)) = (completed, audit.clone()) {
        tokio::spawn(async move {
            let facts = [
                (
                    "invalidated",
                    permguard_core::Fact::Uint(completed.invalidated as u64),
                ),
                (
                    "suspended",
                    permguard_core::Fact::Uint(completed.suspended as u64),
                ),
            ];
            let event = permguard_core::AuditEvent::new(
                permguard_host::audit::AUDIT_TOKENS_COMPLETED,
                permguard_core::Subject::System(crate::completion::BY),
            )
            .on("tokens")
            .with_facts(&facts);
            let _ = audit.record_event(&event).await;
        });
    }
    if let (Some(access_key), Some(audit)) = (offline, audit) {
        tokio::spawn(async move {
            let facts = [("access_key", permguard_core::Fact::Text(&access_key))];
            let event = permguard_core::AuditEvent::new(
                permguard_host::audit::AUDIT_ADMIN_KEY_OFFLINE,
                permguard_core::Subject::System("offline"),
            )
            .on("sa:admin")
            .with_facts(&facts);
            let _ = audit.record_event(&event).await;
        });
    }
    tracing::info!(
        event.name = "authority.serving",
        component = crate::COMPONENT,
        issuer = %issuer,
        accounts = authority.accounts().count().unwrap_or_default(),
        "the Authority Plane issues tokens"
    );
    Some(authority)
}

/// What the Authority Plane declares to the Host: the two artifacts it signs, its audit schema,
/// the two domains it mutates, and the token trust it feeds.
pub fn declaration(_config: &permguard_core::Config) -> Declaration {
    Declaration::new(crate::PLANE)
        .signs::<AccessTokenV1>()
        .signs::<StatusListTokenV1>()
        .audits::<AuthorityAudit>()
        .mutates(accounts::DOMAIN)
        .mutates(tokens::DOMAIN)
        .feeds_token_trust()
}

/// Whether the Authority Plane, though selected, has nothing to serve under `config`.
pub fn dormant(config: &permguard_core::Config) -> bool {
    !listening(config)
}

/// What the Authority Plane requires of a configuration before the process starts: an issuer, and
/// TLS for every secret key outside `development`.
pub fn startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::planes::settings::{
        SETTING_AUTHORITY_HTTP_TLS_CERT, SETTING_AUTHORITY_HTTP_TLS_TERMINATED_UPSTREAM,
    };

    if issuer_of(config).is_none() {
        anyhow::bail!(
            "the Authority Plane has no issuer: set authority.url, or give it an HTTP listener \
             (authorityPlane.public.http)"
        );
    }
    // A secret key crosses only TLS outside `development` (`2-security/8` Profiles).
    let profile = config.assurance().profile();
    let tls = config.setting(SETTING_AUTHORITY_HTTP_TLS_CERT).is_some()
        || config.public_tls().is_some()
        || config
            .setting(SETTING_AUTHORITY_HTTP_TLS_TERMINATED_UPSTREAM)
            .is_some_and(|value| value.trim() == "true")
        || config.public_tls_terminated_upstream();
    if profile != AssuranceProfile::Development && !tls {
        anyhow::bail!(
            "the `{}` profile sends a secret key over TLS only: give the Authority Plane TLS \
             material (authorityPlane.public.http.tls or public.tls)",
            profile.as_str()
        );
    }
    Ok(())
}

/// The Authority Plane's background work: the pass that keeps its lists signed.
pub fn services(composition: &Arc<Composition>) -> Vec<Box<dyn PlaneTask>> {
    vec![Box::new(ListsService {
        composition: Arc::clone(composition),
        task: Mutex::new(None),
    })]
}

/// The pass that keeps the lists signed within their `ttl`, hands them to this Host, and retires
/// the lists whose tokens all expired.
struct ListsService {
    composition: Arc<Composition>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl PlaneTask for ListsService {
    fn name(&self) -> &'static str {
        "authority-lists"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some(authority) = self.composition.authority(context) else {
                return Ok(());
            };
            // The retirement of expired lists is one instance's at a time (WP-28.2); what every
            // instance verifies with is fed by each.
            let jobs = context
                .extension::<permguard_host::jobs::Jobs>()
                .map_or_else(permguard_host::jobs::Jobs::on_volume, |jobs| {
                    permguard_host::jobs::Jobs::clone(&jobs)
                });
            let task = tokio::spawn(async move {
                let mut retired_at = std::time::Instant::now();
                loop {
                    tokio::time::sleep(FEED_EVERY).await;
                    let (feeding, jobs) = (Arc::clone(&authority), jobs.clone());
                    let retire = retired_at.elapsed() >= RETIRE_EVERY;
                    if retire {
                        retired_at = std::time::Instant::now();
                    }
                    let _ = tokio::task::spawn_blocking(move || {
                        if retire {
                            jobs.run(RETIRE_JOB, RETIRE_EVERY, &mut || {
                                let retired = feeding.retire_expired();
                                if let Err(refusal) = &retired {
                                    tracing::warn!(
                                        event.name = "authority.retire_failed",
                                        component = crate::COMPONENT,
                                        refusal = ?refusal,
                                        "the expired status lists could not be retired"
                                    );
                                }
                                retired.is_ok()
                            });
                        }
                        feeding.feed_trust();
                    })
                    .await;
                }
            });
            *self
                .task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(task) = self
                .task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                task.abort();
            }
            Ok(())
        })
    }
}
