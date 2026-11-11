// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane's key set and status lists, fetched by a Host that verifies its tokens
//! from another process (`2-security/8` Keys and lists on a Plane): one task, never a request.
//!
//! | Rule        | Here                                                                                       |
//! | ----------- | ------------------------------------------------------------------------------------------ |
//! | key set     | `<url>/authority/v1/keys` every 5 minutes, and when a token names an unknown `kid`, at most once a minute |
//! | lists       | `<url>/authority/v1/status-lists`, then each list, every half of the shortest `ttl`, between 15 and 30 seconds |
//! | verified    | every list a signed `statuslist+jwt`, checked under the held key set and the issuer before it is held |
//! | transport   | HTTPS with the system's authorities and `authority.tls.ca`; HTTP only under `development`; no redirect; 5 s to connect, 15 s in all |
//! | size        | a key set over 256 KiB, a list over 1 MiB, refused                                         |
//! | failure     | counted, retried from 5 s, doubling up to the cadence; what is held serves until a list's `exp` |
//! | reported    | every 15 s: `degraded: token-status` on the Host while a held list has expired, and the metrics below |

use std::sync::Arc;
use std::time::Duration;

use permguard_core::metrics::labels;
use permguard_host::authz::AuthorityTrust;
use permguard_host::authz::access_tokens::Trust as _;

/// How often the key set is fetched.
pub const KEYS_EVERY: Duration = Duration::from_secs(300);
/// The bounds the lists' cadence is held within.
pub const LISTS_AT_LEAST: Duration = Duration::from_secs(15);
pub const LISTS_AT_MOST: Duration = Duration::from_secs(30);
/// The first retry after a failed fetch.
pub const FIRST_RETRY: Duration = Duration::from_secs(5);
/// How long a connection may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a whole fetch may take, connection included.
pub const FETCH_TIMEOUT: Duration = Duration::from_secs(15);
/// How often the lists' standing is reported.
pub const WATCH: Duration = Duration::from_secs(15);
/// The most bytes a key set or an index takes.
pub const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

/// Where the Authority Plane's documents are under its URL.
pub const KEYS_PATH: &str = "/authority/v1/keys";
pub const LISTS_PATH: &str = "/authority/v1/status-lists";

/// The age of the oldest list held.
pub const LIST_AGE: permguard_core::Metric = permguard_core::Metric::gauge(
    "permguard_token_status_list_age_seconds",
    "Seconds since the oldest status list this Host holds was issued; 0 when it holds none.",
);

/// The lists held past their `exp`.
pub const LISTS_EXPIRED: permguard_core::Metric = permguard_core::Metric::gauge(
    "permguard_token_status_lists_expired",
    "Status lists held past their exp: every token they name is refused.",
);

/// Fetches that failed.
pub const REFRESH_FAILURES: permguard_core::Metric = permguard_core::Metric::counter(
    "permguard_authority_refresh_failures_total",
    "Fetches of the Authority Plane's key set or status lists that failed; what is held serves meanwhile.",
);

/// The list tokens refused, by reason.
pub const LISTS_REFUSED: permguard_core::Metric = permguard_core::Metric::counter(
    "permguard_token_status_list_rejected_total",
    "Status list tokens this Host refused, by reason: signature, rollback, expired, size.",
);

/// Where the Authority Plane is.
#[derive(Debug, Clone)]
pub struct Source {
    /// `authority.url`, without a trailing slash.
    pub url: String,
    /// `authority.tls.ca`, beside the system's authorities.
    pub ca: Option<std::path::PathBuf>,
    pub allow_http: bool,
}

/// Where the standing is reported.
#[derive(Clone)]
pub struct Observing {
    pub health: permguard_core::server::Health,
    pub metrics: permguard_core::Metrics,
    pub time: Arc<permguard_host::time::TimeGuard>,
}

/// The running tasks; dropping them stops them.
pub struct Refreshing(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Refreshing {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Starts the fetch of `source` into `trust`, and the report of what it holds.
pub fn drive(
    trust: Arc<AuthorityTrust>,
    source: Source,
    observing: Observing,
) -> anyhow::Result<Refreshing> {
    let tls = connector(source.ca.as_deref()).map_err(anyhow::Error::msg)?;
    let fetching = tokio::spawn(run(
        Arc::clone(&trust),
        source,
        tls,
        observing.metrics.clone(),
        Arc::clone(&observing.time),
    ));
    let reporting = tokio::spawn(async move {
        let mut interval = tokio::time::interval(WATCH);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            report(&trust, &observing);
        }
    });
    Ok(Refreshing(vec![fetching, reporting]))
}

/// Reports the held lists once: the metrics, and `degraded: token-status` on the Host while a
/// held list has expired.
pub fn report(trust: &AuthorityTrust, observing: &Observing) {
    let standing = trust.standing(observing.time.now_secs());
    observing
        .metrics
        .set(&LIST_AGE, &[], standing.oldest_age.unwrap_or(0) as f64);
    observing
        .metrics
        .set(&LISTS_EXPIRED, &[], standing.expired.len() as f64);
    for (reason, count) in trust.take_refused() {
        observing
            .metrics
            .add(&LISTS_REFUSED, &[(labels::REASON, reason)], count as f64);
    }
    let lifecycle = observing.health.lifecycle();
    if standing.expired.is_empty() {
        lifecycle.restore(
            permguard_core::lifecycle::HOST,
            permguard_host::authz::authority::CAPABILITY,
        );
    } else {
        lifecycle.degrade(
            permguard_core::lifecycle::HOST,
            permguard_host::authz::authority::CAPABILITY,
            format!(
                "{} status list(s) of the Authority Plane expired: every token they name is \
                 refused until a fresh one is fetched",
                standing.expired.len()
            ),
        );
    }
}

async fn run(
    trust: Arc<AuthorityTrust>,
    source: Source,
    tls: tokio_rustls::TlsConnector,
    metrics: permguard_core::Metrics,
    time: Arc<permguard_host::time::TimeGuard>,
) {
    let mut keys_due = std::time::Instant::now();
    let mut retry = FIRST_RETRY;
    loop {
        let outcome = async {
            if trust.anchor().is_none()
                || trust.take_keys_wanted()
                || std::time::Instant::now() >= keys_due
            {
                fetch_keys(&trust, &source, &tls).await?;
                keys_due = std::time::Instant::now() + KEYS_EVERY;
            }
            fetch_lists(&trust, &source, &tls, time.now_secs()).await
        }
        .await;
        let pause = match outcome {
            Ok(cadence) => {
                retry = FIRST_RETRY;
                cadence
            }
            Err(reason) => {
                tracing::warn!(
                    event.name = "authz.authority_refresh_failed",
                    component = "server",
                    url = %source.url,
                    reason = %reason,
                    "the Authority Plane's keys or lists could not be fetched: what is held serves"
                );
                metrics.count(&REFRESH_FAILURES, &[]);
                let pause = retry;
                retry = (retry * 2).min(LISTS_AT_MOST);
                pause
            }
        };
        // A token naming a key the set lacks wakes the next round early, within a second.
        let until = std::time::Instant::now() + pause;
        while std::time::Instant::now() < until {
            tokio::time::sleep(Duration::from_secs(1)).await;
            if trust.anchor().is_some() && trust.take_keys_wanted() {
                keys_due = std::time::Instant::now();
                break;
            }
        }
    }
}

/// Fetches the key set and holds it.
async fn fetch_keys(
    trust: &AuthorityTrust,
    source: &Source,
    tls: &tokio_rustls::TlsConnector,
) -> Result<(), String> {
    let url = format!("{}{KEYS_PATH}", source.url);
    let document = get(&url, tls, source.allow_http, MAX_DOCUMENT_BYTES).await?;
    let jwks: serde_json::Value = serde_json::from_slice(&document)
        .map_err(|error| format!("the key set at {url} is not JSON: {error}"))?;
    let held = trust
        .accept_keys(&jwks)
        .map_err(|reason| format!("the key set at {url}: {reason}"))?;
    tracing::debug!(
        event.name = "authz.authority_keys",
        component = "server",
        keys = held,
        "the Authority Plane's key set is held"
    );
    Ok(())
}

/// Fetches the index, then every list it names, and holds each one that verifies. Answers when
/// the next round is due: half the shortest `ttl` held, within the bounds.
async fn fetch_lists(
    trust: &AuthorityTrust,
    source: &Source,
    tls: &tokio_rustls::TlsConnector,
    now: u64,
) -> Result<Duration, String> {
    let url = format!("{}{LISTS_PATH}", source.url);
    let document = get(&url, tls, source.allow_http, MAX_DOCUMENT_BYTES).await?;
    let index: serde_json::Value = serde_json::from_slice(&document)
        .map_err(|error| format!("the list index at {url} is not JSON: {error}"))?;
    let ids: Vec<String> = index
        .get("lists")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("the list index at {url} names no lists"))?
        .iter()
        .filter_map(|id| id.as_str().map(str::to_owned))
        .filter(|id| is_list_id(id))
        .take(permguard_host::authz::status_lists::MAX_LISTS)
        .collect();
    let mut shortest = LISTS_AT_MOST;
    for id in &ids {
        let list_url = format!("{url}/{id}");
        let token = get(
            &list_url,
            tls,
            source.allow_http,
            permguard_host::authz::status_lists::MAX_LIST_TOKEN_BYTES,
        )
        .await?;
        let token =
            String::from_utf8(token).map_err(|_| format!("the list at {list_url} is not text"))?;
        match trust.accept_list(token.trim(), now) {
            Ok(_) => {}
            Err(refusal) => {
                tracing::warn!(
                    event.name = "authz.status_list_refused",
                    component = "server",
                    list = %id,
                    reason = refusal.signal(),
                    detail = %refusal,
                    "a status list of the Authority Plane was refused: the one held stays in use"
                );
            }
        }
    }
    trust.keep_named(&ids);
    for list in trust.standing(now).aging {
        tracing::debug!(
            event.name = "authz.status_list_aging",
            component = "server",
            list = %list,
            "a status list is past half its lifetime"
        );
    }
    // Half the shortest `ttl` the Authority Plane states, held within the bounds.
    if let Some(ttl) = trust.shortest_ttl() {
        shortest = shortest.min(Duration::from_secs(ttl / 2));
    }
    Ok(shortest.clamp(LISTS_AT_LEAST, LISTS_AT_MOST))
}

/// A list id as the Authority Plane names one: a UUID's text, no path in it.
fn is_list_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

fn connector(ca: Option<&std::path::Path>) -> Result<tokio_rustls::TlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(certificate);
    }
    if let Some(path) = ca {
        use rustls::pki_types::pem::PemObject as _;
        let pem =
            std::fs::read(path).map_err(|error| format!("reading {}: {error}", path.display()))?;
        for certificate in rustls::pki_types::CertificateDer::pem_slice_iter(&pem) {
            let certificate =
                certificate.map_err(|error| format!("reading {}: {error:?}", path.display()))?;
            roots
                .add(certificate)
                .map_err(|error| format!("adding {}: {error}", path.display()))?;
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| format!("the TLS versions: {error}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(tokio_rustls::TlsConnector::from(Arc::new(config)))
}

/// One `GET`, bounded: HTTPS unless `allow_http`, no redirect followed, 200 only, at most `max`
/// bytes.
async fn get(
    url: &str,
    tls: &tokio_rustls::TlsConnector,
    allow_http: bool,
    max: usize,
) -> Result<Vec<u8>, String> {
    permguard_core::authz::check_service_url(url, allow_http)?;
    permguard_core::egress::check(permguard_core::egress::Target::Authority)
        .map_err(|refused| refused.to_string())?;
    let uri: http::Uri = url
        .parse()
        .map_err(|error| format!("`{url}` is not a URL: {error}"))?;
    let secure = uri.scheme_str() == Some("https");
    let host = uri.host().ok_or_else(|| format!("`{url}` names no host"))?;
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let authority = uri.authority().map_or_else(
        || host.to_owned(),
        |authority| authority.as_str().to_owned(),
    );
    let path = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str)
        .to_owned();
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(path)
        .header(http::header::HOST, authority)
        .header(
            http::header::USER_AGENT,
            concat!("permguard/", env!("CARGO_PKG_VERSION")),
        )
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|error| error.to_string())?;
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let exchange = async {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect((host.as_str(), port)),
        )
        .await
        .map_err(|_| {
            format!(
                "connecting to {url}: no answer within {}s",
                CONNECT_TIMEOUT.as_secs()
            )
        })?
        .map_err(|error| format!("connecting to {url}: {error}"))?;
        let response = if secure {
            let name = rustls::pki_types::ServerName::try_from(host.clone())
                .map_err(|error| format!("the host name of {url}: {error}"))?;
            let stream = tls
                .connect(name, tcp)
                .await
                .map_err(|error| format!("the TLS handshake with {url}: {error}"))?;
            send(hyper_util::rt::TokioIo::new(stream), request).await?
        } else {
            send(hyper_util::rt::TokioIo::new(tcp), request).await?
        };
        let status = response.status();
        if status.is_redirection() {
            return Err(format!(
                "{url} answered {status}: redirects are not followed; configure the final URL"
            ));
        }
        if status != http::StatusCode::OK {
            return Err(format!("{url} answered {status}"));
        }
        use http_body_util::BodyExt as _;
        let bytes = http_body_util::Limited::new(response.into_body(), max)
            .collect()
            .await
            .map_err(|error| format!("reading {url}: {error}"))?
            .to_bytes();
        Ok(bytes.to_vec())
    };
    tokio::time::timeout(FETCH_TIMEOUT, exchange)
        .await
        .map_err(|_| {
            format!(
                "{url}: no complete answer within {}s",
                FETCH_TIMEOUT.as_secs()
            )
        })?
}

async fn send<S>(
    stream: S,
    request: http::Request<http_body_util::Empty<bytes::Bytes>>,
) -> Result<http::Response<hyper::body::Incoming>, String>
where
    S: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(stream)
        .await
        .map_err(|error| format!("the connection: {error}"))?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    sender
        .send_request(request)
        .await
        .map_err(|error| format!("the request: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_list_id_names_no_path() {
        assert!(is_list_id("0198f2aa-0000-7000-8000-000000000003"));
        for refused in ["", "../keys", "a/b", "a?b", &"a".repeat(65)] {
            assert!(!is_list_id(refused), "{refused}");
        }
    }
}
