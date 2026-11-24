// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `postgresql-s3` backend as a build selects it (iteration 03, WP-28.1): one database and
//! one bucket a process, opened from the configuration, and every store of the Host over them.
//!
//! The runtime links neither: a build hands it [`connect`] and [`shared`], as it hands it the
//! KMS custody, and the runtime composes the Host from the [`Shared`] they answer. A Plane's
//! server reads the [`Connected`] the Host was given and composes its own stores over it.
//!
//! | Step     | What it does                                                                         |
//! | -------- | ------------------------------------------------------------------------------------ |
//! | database | TLS verified against the CA named, or the system's roots; the schema brought to this build's |
//! | bucket   | TLS likewise; the store must refuse a replacement before it is used (decision X112) |
//! | secrets  | the database's password and the bucket's keys resolved from the secret store, by reference |

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use zeroize::Zeroizing;

use permguard_core::Config;
use permguard_core::secrets::{SecretRef, SecretStore};
use permguard_host::backend::Shared;
use permguard_postgres::Database;

use crate::{Bucket, Encryption, Put};

/// How long a connection to the database is waited for.
const DATABASE_WAIT: Duration = Duration::from_secs(10);
/// How long one request to the bucket may take.
const BUCKET_TIMEOUT: Duration = Duration::from_secs(30);

/// The scope the Host's clock mark is kept under.
pub(crate) const CLOCK_MARK: &str = "host";

/// The name a stream consumer's runs are kept under: its descriptor's `plane/type/version`.
pub(crate) fn consumer(plane: &str, stream_type: &str, version: &str) -> String {
    format!("{plane}/{stream_type}/{version}")
}

/// The one database and the one bucket of a process.
#[derive(Debug, Clone)]
pub struct Connected {
    pub database: Database,
    pub bucket: Bucket,
}

/// The roots a server is verified against: the CA bundle at `ca`, or the system's.
fn roots(ca: Option<&std::path::Path>, what: &str) -> Result<Arc<rustls::RootCertStore>> {
    use rustls::pki_types::pem::PemObject as _;

    let mut roots = rustls::RootCertStore::empty();
    match ca {
        Some(path) => {
            let pem = std::fs::read(path)
                .with_context(|| format!("reading the {what} CA at {}", path.display()))?;
            for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
                let certificate = certificate
                    .map_err(|error| anyhow::anyhow!("reading the {what} CA: {error:?}"))?;
                roots
                    .add(certificate)
                    .with_context(|| format!("adding the {what} CA"))?;
            }
        }
        None => {
            for certificate in rustls_native_certs::load_native_certs().certs {
                let _ = roots.add(certificate);
            }
        }
    }
    if roots.is_empty() {
        bail!("no root verifies the {what}: name its CA");
    }
    Ok(Arc::new(roots))
}

/// The text a secret reference resolves to.
fn resolved(
    secrets: Option<&dyn SecretStore>,
    reference: &SecretRef,
    what: &str,
) -> Result<Zeroizing<String>> {
    let secrets = secrets.with_context(|| {
        format!(
            "the {what} is resolved from the secret store, and this build resolved none: set \
             `operations.secrets.provider`"
        )
    })?;
    let secret = secrets
        .resolve(reference)
        .with_context(|| format!("resolving the {what} `{}`", reference.name()))?;
    Ok(Zeroizing::new(
        std::str::from_utf8(secret.expose())
            .with_context(|| format!("the {what} is text"))?
            .trim()
            .to_owned(),
    ))
}

/// Opens the backend `config` names and makes every store over it: what a build registers as
/// its shared backend.
pub fn open(config: &Config, secrets: Option<&dyn SecretStore>) -> Result<Shared> {
    shared(&connect(config, secrets)?)
}

/// Opens the database and the bucket `config` names, the schema brought to this build's and the
/// bucket proven to refuse a replacement. Refused, before anything is written, when either is
/// unreachable, misconfigured, or a store that would overwrite in silence.
pub fn connect(config: &Config, secrets: Option<&dyn SecretStore>) -> Result<Connected> {
    let connection = config.storage_connection();
    let named = |value: &Option<String>, what: &str| {
        value
            .clone()
            .with_context(|| format!("the `postgresql-s3` backend names no {what}"))
    };
    let database = Database::connect(permguard_postgres::Config {
        host: named(&connection.postgresql_host, "database host")?,
        port: connection.postgresql_port(),
        database: named(&connection.postgresql_database, "database")?,
        user: named(&connection.postgresql_user, "database user")?,
        password: connection
            .postgresql_password_ref
            .as_ref()
            .map(|reference| resolved(secrets, reference, "database password"))
            .transpose()?
            .map(|password| password.as_str().to_owned()),
        schema: connection.postgresql_schema.clone(),
        tls: if connection.postgresql_tls {
            permguard_postgres::Tls::Verified(roots(
                config.storage_postgresql_ca().as_deref(),
                "database",
            )?)
        } else {
            permguard_postgres::Tls::Disabled
        },
        pool: connection.postgresql_pool(),
        wait: DATABASE_WAIT,
    })
    .context("connecting to the database")?;
    let version = permguard_postgres::schema::migrate(&database)
        .context("bringing the database's schema to this build's")?;
    tracing::info!(
        event.name = "storage.database_ready",
        component = "host",
        schema = version,
        "the database is at this build's schema"
    );

    let endpoint = named(&connection.s3_endpoint, "bucket endpoint")?;
    let (scheme, address) = endpoint
        .split_once("://")
        .with_context(|| format!("`{endpoint}` is no endpoint: `https://host:port`"))?;
    let address = address.trim_end_matches('/');
    let (host, port) = match address.rsplit_once(':') {
        Some((host, port)) => (
            host.to_owned(),
            port.parse::<u16>()
                .with_context(|| format!("`{endpoint}` names no port"))?,
        ),
        None => (address.to_owned(), if scheme == "https" { 443 } else { 80 }),
    };
    let tls = match scheme {
        "https" => crate::Tls::Verified(roots(config.storage_s3_ca().as_deref(), "bucket")?),
        "http" => crate::Tls::Disabled,
        other => bail!("`{other}` is no scheme of an object store: `https://host:port`"),
    };
    let encryption = match connection.s3_encryption.as_str() {
        "managed" => Some(Encryption::Managed),
        "none" => None,
        other => Some(Encryption::Kms(
            other
                .strip_prefix("kms:")
                .with_context(|| format!("`{other}` is no encryption of a bucket"))?
                .to_owned(),
        )),
    };
    let bucket = Bucket::connect(crate::Config {
        host,
        port,
        tls,
        region: named(&connection.s3_region, "bucket region")?,
        bucket: named(&connection.s3_bucket, "bucket")?,
        prefix: connection.s3_prefix.clone().unwrap_or_default(),
        access_key: named(&connection.s3_access_key, "bucket access key")?,
        secret: resolved(
            secrets,
            connection
                .s3_secret_ref
                .as_ref()
                .context("the `postgresql-s3` backend names no bucket secret")?,
            "bucket secret",
        )?,
        session_token: connection
            .s3_session_token_ref
            .as_ref()
            .map(|reference| resolved(secrets, reference, "bucket session token"))
            .transpose()?,
        encryption,
        timeout: BUCKET_TIMEOUT,
    })
    .context("reaching the bucket")?;
    refuses_a_replacement(&bucket)?;
    Ok(Connected { database, bucket })
}

/// Whether the bucket refuses to replace what a key holds (decision X112): a ledger's objects,
/// an archive and a batch are published once, and a store that ignores `If-None-Match` would
/// overwrite them in silence. A probe key is published twice, and the second must be refused.
fn refuses_a_replacement(bucket: &Bucket) -> Result<()> {
    let mut random = [0_u8; 16];
    getrandom(&mut random)?;
    let key = format!(
        "probes/{}",
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    bucket
        .put_new(&key, b"probe")
        .context("publishing a probe to the bucket")?;
    let second = bucket
        .put_new(&key, b"replacement")
        .context("publishing a probe to the bucket again");
    let removed = bucket.delete(&key);
    if second? != Put::Exists {
        bail!(
            "the bucket replaced what a key held: a store that ignores `If-None-Match` would \
             overwrite a ledger's objects in silence, and is not used"
        );
    }
    removed.context("removing the probe from the bucket")?;
    Ok(())
}

/// The channel the hints of the watches travel on between instances.
const HINTS: &str = "permguard_hints";

/// The hints of one instance to the others, over the database's notifications (iteration 03,
/// WP-28.4, decision E9): a hint published on one instance reaches a watch another holds. A
/// notification is sent when the unit of work it is made in commits, and not at all when it is
/// undone.
struct PostgresRelay {
    database: Database,
    /// This instance: what it sent itself is not delivered twice.
    origin: String,
}

impl permguard_host::membership::watch::Relay for PostgresRelay {
    fn send(
        &self,
        task_type: permguard_host::membership::record::TaskType,
        resource: &permguard_core::authz::Resource,
        hint: &permguard_host::membership::record::WatchHint,
    ) {
        let payload = hint_payload(&self.origin, task_type, resource, hint);
        let sent = self.database.write(|unit| {
            unit.execute("SELECT pg_notify($1, $2)", &[&HINTS, &payload])
                .map(|_| ())
        });
        if let Err(error) = sent {
            tracing::warn!(
                event.name = "host.membership.hint_unrelayed",
                component = "host",
                error = %error,
                "a hint did not reach the other instances: their members run their ordinary round"
            );
        }
    }

    fn listen(
        &self,
        hub: std::sync::Weak<permguard_host::membership::watch::Hub>,
    ) -> Box<dyn std::any::Any + Send + Sync> {
        let origin = self.origin.clone();
        let heard = move |payload: &str| {
            if let Some((task_type, resource, hint)) = hint_of(payload, &origin)
                && let Some(hub) = hub.upgrade()
            {
                hub.deliver(task_type, &resource, &hint);
            }
        };
        let lost = |error: &permguard_postgres::DbError| {
            tracing::warn!(
                event.name = "host.membership.hints_unheard",
                component = "host",
                error = %error,
                "the other instances' hints are not heard: listening again"
            );
        };
        match self.database.listen(HINTS, Box::new(heard), Box::new(lost)) {
            Ok(listening) => Box::new(listening),
            Err(error) => {
                tracing::warn!(
                    event.name = "host.membership.hints_unheard",
                    component = "host",
                    error = %error,
                    "the other instances' hints are not heard: members run their ordinary round"
                );
                Box::new(())
            }
        }
    }
}

/// What a hint travels as between instances: JSON, with the instance that sent it.
fn hint_payload(
    origin: &str,
    task_type: permguard_host::membership::record::TaskType,
    resource: &permguard_core::authz::Resource,
    hint: &permguard_host::membership::record::WatchHint,
) -> String {
    serde_json::json!({
        "origin": origin,
        "task": task_type.as_str(),
        "resource": resource.to_string(),
        "key": hint.key,
        "head": hint.head,
        "counter": hint.counter,
    })
    .to_string()
}

/// The hint `payload` carries, unless this instance, `origin`, sent it or it does not read.
fn hint_of(
    payload: &str,
    origin: &str,
) -> Option<(
    permguard_host::membership::record::TaskType,
    permguard_core::authz::Resource,
    permguard_host::membership::record::WatchHint,
)> {
    use permguard_host::membership::record::{TaskType, WatchHint};

    let hint = serde_json::from_str::<serde_json::Value>(payload).ok()?;
    if hint["origin"].as_str() == Some(origin) {
        return None;
    }
    Some((
        TaskType::ALL
            .into_iter()
            .find(|task| Some(task.as_str()) == hint["task"].as_str())?,
        permguard_core::authz::Resource::parse(hint["resource"].as_str()?).ok()?,
        WatchHint {
            key: hint["key"].as_str()?.to_owned(),
            head: hint["head"].as_str()?.to_owned(),
            counter: hint["counter"].as_u64()?,
        },
    ))
}

/// This instance, as the leases it holds name it: drawn once a process.
fn holder() -> Result<String> {
    let mut drawn = [0_u8; 16];
    getrandom(&mut drawn)?;
    Ok(drawn.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn getrandom(bytes: &mut [u8]) -> Result<()> {
    use ring::rand::SecureRandom as _;
    ring::rand::SystemRandom::new()
        .fill(bytes)
        .map_err(|_| anyhow::anyhow!("the system's random source refused"))
}

/// Every store of the Host over `connected`.
pub fn shared(connected: &Connected) -> Result<Shared> {
    use permguard_postgres as pg;

    let database = connected.database.clone();
    let deployment = pg::deployment::home(&database).context("reading the deployment's id")?;
    if deployment.importing {
        bail!(
            "the import of a volume began on this database and did not complete: no start serves \
             what it left; empty the database's schema and the bucket's prefix, then import again"
        );
    }
    let home = deployment.id;
    let delivered = database.clone();
    let mutations = database.clone();
    Ok(Shared {
        backend: permguard_core::volume::Backend::PostgresqlS3.as_str(),
        home,
        clock_mark: Arc::new(pg::time::PostgresClockMark::new(
            Arc::new(database.clone()),
            CLOCK_MARK,
        )),
        identity: Arc::new(pg::identity::PostgresIdentity::new(database.clone())),
        identity_slots: Arc::new(pg::slots::PostgresSlots::new(
            database.clone(),
            permguard_host::keys::ring::HOST_IDENTITY,
        )),
        rings: Arc::new(PostgresRings::new(database.clone())),
        members: Arc::new(pg::members::PostgresMembers::new(database.clone())),
        seen: Arc::new(pg::peers::PostgresSeen::new(database.clone())),
        witnesses: Arc::new(pg::witnesses::PostgresWitnesses::new(database.clone())),
        delivered: Box::new(move |sealer| {
            Arc::new(pg::delivered::PostgresDeliveredKeys::new(
                delivered.clone(),
                sealer,
            ))
        }),
        versions: Arc::new(pg::witnesses::PostgresVersionWitnesses::new(
            database.clone(),
        )),
        held: Arc::new(pg::held::PostgresHeld::new(database.clone())),
        bootstrap: Arc::new(pg::bootstrap::PostgresBootstrap::new(database.clone())),
        holds: Arc::new(pg::holds::PostgresHolds::new(database.clone())),
        plans: Arc::new(pg::replay::PostgresReplay::new(database.clone())),
        trails: Arc::new(
            pg::audit::PostgresTrails::new(database.clone())
                .with_objects(Arc::new(connected.bucket.clone())),
        ),
        audit_cursor_root: {
            let database = database.clone();
            Box::new(move |sealer| {
                use permguard_control_plane::decisions::cursorkey::CursorRoots as _;
                permguard_control_plane::decisions::cursorkey::postgres::PostgresCursorRoots::new(
                    database.clone(),
                    sealer,
                    permguard_host::audit::QUERY_CURSORS,
                )
                .roots()
                .map(|roots| roots.issuing)
                .map_err(|error| error.to_string())
            })
        },
        ready: {
            let (database, bucket) = (database.clone(), connected.bucket.clone());
            Arc::new(move || {
                database
                    .ready()
                    .map_err(|error| format!("PostgreSQL: {error}"))?;
                bucket.ready().map_err(|error| format!("S3: {error}"))
            })
        },
        catalog: Arc::new(pg::catalog::PostgresCatalog::new(database.clone())),
        mutations: Box::new(move |projection| {
            Arc::new(pg::mutations::PostgresMutations::new(
                mutations.clone(),
                projection,
            ))
        }),
        handles: vec![
            Arc::new(connected.clone()),
            // The task sessions every instance holds, for the clone alarm (WP-28.4).
            Arc::new(permguard_host::membership::task::SharedSessions(Arc::new(
                pg::sessions::PostgresSessions::new(database.clone()),
            ))),
            // The hints this instance publishes reach the watches the others hold (WP-28.4).
            Arc::new(permguard_host::membership::watch::Relayed(Arc::new(
                PostgresRelay {
                    database: database.clone(),
                    origin: holder()?,
                },
            ))),
            // The single jobs of this instance, each run by the holder of its lease (WP-28.2).
            Arc::new(permguard_host::jobs::Jobs(Arc::new(
                pg::jobs::PostgresJobs::new(database.clone(), holder()?),
            ))),
            Arc::new(consumer_runs(connected)),
            Arc::new(permguard_control_plane::plane::ZoneStores {
                ledgers: Arc::new(crate::control_plane::PostgresLedgers::new(
                    database.clone(),
                    connected.bucket.clone(),
                )),
                archives: Arc::new(crate::control_plane::PostgresArchives::new(
                    database.clone(),
                    connected.bucket.clone(),
                )),
            }),
            Arc::new(evidence(&database)),
            Arc::new(permguard_authority_plane::plane::AuthorityStores {
                accounts: Arc::new(
                    permguard_authority_plane::accounts::postgres::PostgresAccounts::new(
                        database.clone(),
                    ),
                ),
                tokens: Arc::new(
                    permguard_authority_plane::tokens::postgres::PostgresTokens::new(
                        database.clone(),
                    ),
                ),
                marks: Arc::new(
                    permguard_authority_plane::tokens::postgres::PostgresMarks::new(
                        database.clone(),
                    ),
                ),
                database: database.clone(),
            }),
        ],
    })
}

/// What the offline verification of the trails reads (decision X101): the Host's trails, their
/// settled days in the bucket, and the records of `host.operations`, whose keys sign their
/// checkpoints. Opened apart from [`shared`], so the database is read as it is: no deployment is
/// minted in one that holds none.
pub fn audit(
    connected: &Connected,
) -> (
    Arc<dyn permguard_host::audit::store::Trails>,
    Arc<dyn permguard_host::keys::ring::store::RingStore>,
) {
    (
        Arc::new(
            permguard_postgres::audit::PostgresTrails::new(connected.database.clone())
                .with_objects(Arc::new(connected.bucket.clone())),
        ),
        Arc::new(permguard_postgres::ring::PostgresRing::new(
            connected.database.clone(),
            permguard_host::keys::ring::HOST_OPERATIONS,
        )),
    )
}

/// Rotates the cursor root of the evidence store `store`, `decisions` or `events` (decision
/// X110): the issuing root becomes the previous, and the next ask mints another. Answers whether
/// the store held a root to rotate. An instance reads the roots at its start, so the servers are
/// stopped while it runs.
pub fn rotate_cursor_root(connected: &Connected, store: &str) -> Result<bool> {
    use permguard_control_plane::plane::{DECISIONS_API, EVENTS_API};

    if store != DECISIONS_API && store != EVENTS_API {
        bail!("`{store}` is no evidence store: `{DECISIONS_API}` or `{EVENTS_API}`");
    }
    permguard_control_plane::decisions::cursorkey::postgres::rotate(&connected.database, store)
}

/// The runs of each stream consumer, kept under its descriptor's `plane/type/version`.
fn consumer_runs(connected: &Connected) -> permguard_stream::engine::consumer::store::ConsumerRuns {
    let connected = connected.clone();
    permguard_stream::engine::consumer::store::ConsumerRuns(Box::new(move |descriptor| {
        Arc::new(crate::streams::PostgresRuns::new(
            connected.database.clone(),
            connected.bucket.clone(),
            &consumer(
                &descriptor.plane,
                &descriptor.stream_type,
                &descriptor.version.to_string(),
            ),
        ))
    }))
}

/// Where a Host's rings are kept in one database: a ring's records and the slots of its private
/// keys, each under the ring's name (iteration 03, WP-28.1).
#[derive(Debug, Clone)]
struct PostgresRings {
    database: Database,
}

impl PostgresRings {
    /// The rings of `database`, whose schema is this build's.
    fn new(database: Database) -> Self {
        Self { database }
    }
}

impl permguard_host::keys::registry::Home for PostgresRings {
    fn stores(
        &self,
        ring: &'static str,
        legacy: Option<&std::path::Path>,
    ) -> Result<permguard_host::keys::registry::Stores, permguard_host::keys::registry::OpenError>
    {
        // A ring written before the registry is a directory of a volume: it reaches this
        // backend by the import of that volume, never by a start that would leave it behind.
        if let Some(legacy) = legacy.filter(|legacy| legacy.exists()) {
            return Err(permguard_host::keys::registry::OpenError::Migration(
                format!(
                    "`{ring}` is still at {} on files: import the volume before a start on this \
                 backend",
                    legacy.display()
                ),
            ));
        }
        Ok(permguard_host::keys::registry::Stores {
            ring: Arc::new(permguard_postgres::ring::PostgresRing::new(
                self.database.clone(),
                ring,
            )),
            slots: Arc::new(permguard_postgres::slots::PostgresSlots::new(
                self.database.clone(),
                ring,
            )),
        })
    }
}

/// The Control Plane's evidence over `database`: the cursor roots of each evidence store, a row
/// each, sealed.
fn evidence(database: &Database) -> permguard_control_plane::plane::SharedEvidence {
    let database = database.clone();
    permguard_control_plane::plane::SharedEvidence {
        cursor_roots: Box::new(move |sealer, store| {
            Arc::new(
                permguard_control_plane::decisions::cursorkey::postgres::PostgresCursorRoots::new(
                    database.clone(),
                    sealer,
                    store,
                ),
            )
        }),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_host::membership::record::{TaskType, WatchHint};

    /// A hint read back as it was sent, by another instance; the one that sent it reads nothing.
    #[test]
    fn a_hint_travels_whole_to_the_other_instances() {
        let resource =
            permguard_core::authz::Resource::parse("plane/control/zone/z1").expect("a resource");
        let hint = WatchHint {
            key: "ledger/l1".to_owned(),
            head: "sha256:ab".to_owned(),
            counter: 7,
        };
        let payload = hint_payload("one", TaskType::PolicyMirror, &resource, &hint);
        assert_eq!(
            hint_of(&payload, "other"),
            Some((TaskType::PolicyMirror, resource, hint))
        );
        assert_eq!(hint_of(&payload, "one"), None);
        assert_eq!(hint_of("not json", "other"), None);
    }
}
