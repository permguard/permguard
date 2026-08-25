// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The smallest HTTP client that can ask a Permguard plane what it is.
//!
//! Deliberately not a dependency: one `GET` against an endpoint an operator typed, over a
//! connection that is closed immediately afterwards. What matters is not the feature set but that
//! every way it can fail is a value the caller can act on — a report has to say *why* a plane did
//! not answer, and "connection refused" and "timed out" send an operator to different places.
//!
//! # TLS is the same request over a different stream
//!
//! An `https://` endpoint gets a handshake and then the identical exchange. The handshake is
//! completed before the request is written, so a certificate that is refused is reported as a
//! handshake failure rather than as a strange read error halfway through a response.
//!
//! # Every wait is bounded
//!
//! Connect, write and read each carry the deadline. A stated timeout that only covers reading is
//! worse than no timeout: an endpoint that accepts nothing and answers nothing — a dropped packet, a
//! firewall that blackholes — would hang for as long as the operating system feels like retrying,
//! which is measured in minutes.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use rustls::{ClientConfig, ClientConnection, StreamOwned};

use crate::endpoint::Endpoint;
use crate::tls::{self, TlsOptions};

/// What an endpoint answered, bytes untouched.
pub struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// What an endpoint answered.
pub struct Response {
    /// The HTTP status code.
    pub status: u16,
    /// The response body.
    pub body: String,
}

/// Every way asking an endpoint can fail.
///
/// Each variant carries a stable [`reason`](Error::reason) code as well as a sentence for a person.
/// The sentence is free to be reworded; the code is an interface, and a runbook that branches on
/// "the service is not running" versus "the service is not answering" reads the code.
#[derive(Debug)]
pub enum Error {
    /// The client side of TLS is misconfigured.
    Tls { source: tls::Error },
    /// The endpoint refused the handshake, or is not who it says it is.
    Handshake { address: String, detail: String },
    /// The endpoint demands a client certificate, and none was presented.
    ClientCertificateRequired { address: String },
    /// The endpoint has no host, or no name that resolves.
    Resolve { address: String, source: io::Error },
    /// Nothing is listening: the port refused the connection.
    Refused { address: String },
    /// The endpoint neither answered nor refused within the deadline.
    Timeout { address: String, after: Duration },
    /// The connection could not be established, for some other reason.
    Connect { address: String, source: io::Error },
    /// The connection was established and then failed.
    Transport { source: io::Error },
    /// Something answered with TLS where plain HTTP was asked for.
    PlaintextToTls { endpoint: String },
    /// Something answered, but not with HTTP.
    Malformed { endpoint: String, detail: String },
}

impl Error {
    /// The stable code for this failure.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Tls { source } => source.reason(),
            Self::Handshake { .. } => "tls_handshake_failed",
            Self::ClientCertificateRequired { .. } => "tls_client_certificate_required",
            Self::Resolve { .. } => "resolve_failed",
            Self::Refused { .. } => "connection_refused",
            Self::Timeout { .. } => "timeout",
            Self::Connect { .. } => "connect_failed",
            Self::Transport { .. } => "transport_failed",
            Self::PlaintextToTls { .. } => "tls_expected",
            Self::Malformed { .. } => "malformed_response",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls { source } => write!(f, "{source}"),
            Self::Handshake { address, detail } => {
                write!(f, "the TLS handshake with `{address}` failed: {detail}")
            }
            Self::ClientCertificateRequired { address } => write!(
                f,
                "`{address}` requires a client certificate: pass --tls-cert-file and --tls-key-file"
            ),
            Self::Resolve { address, source } => write!(f, "resolving `{address}`: {source}"),
            Self::Refused { address } => {
                write!(f, "nothing is listening on `{address}`: connection refused")
            }
            Self::Timeout { address, after } => write!(
                f,
                "`{address}` did not answer within {}s",
                after.as_secs_f32()
            ),
            Self::Connect { address, source } => write!(f, "connecting to `{address}`: {source}"),
            Self::Transport { source } => write!(f, "the connection failed: {source}"),
            Self::PlaintextToTls { endpoint } => write!(
                f,
                "`{endpoint}` answered with TLS, not plain HTTP: reach it as https:// instead"
            ),
            Self::Malformed { endpoint, detail } => {
                write!(f, "`{endpoint}` did not answer with HTTP: {detail}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// What a request is made with: the deadline, and the TLS material if any is needed.
pub struct Client {
    timeout: Duration,
    tls: TlsOptions,
    /// Built once, because reading the material and parsing it is per-process work, not per-request.
    config: Option<Arc<ClientConfig>>,
    /// Told once per JSON exchange. Silent unless a caller asks — the CLI's
    /// `-v` — so every surface riding this client narrates the same way
    /// instead of each command growing (or forgetting) its own.
    narrator: Box<dyn crate::narrate::Narrator>,
}

impl Client {
    /// Prepares a client, reading TLS material only if a TLS endpoint will actually be reached.
    ///
    /// Material is read eagerly, before any request: a missing certificate file is a mistake in what
    /// the operator typed, and reporting it as one failed endpoint among several would bury it.
    pub fn new(timeout: Duration, tls: TlsOptions, needs_tls: bool) -> Result<Self, Error> {
        let config = if needs_tls {
            Some(
                tls.client_config()
                    .map_err(|source| Error::Tls { source })?,
            )
        } else {
            None
        };

        Ok(Self {
            timeout,
            tls,
            config,
            narrator: Box::new(crate::narrate::Silent),
        })
    }

    /// The same client, narrating each exchange to `narrator`.
    pub fn with_narrator(mut self, narrator: Box<dyn crate::narrate::Narrator>) -> Self {
        self.narrator = narrator;

        self
    }

    /// Asks one endpoint for one path, and closes the connection.
    pub fn get(&self, endpoint: &Endpoint, path: &str) -> Result<Response, Error> {
        self.request(endpoint, "GET", path, None)
    }

    /// Sends one request with a method and, when there is one, a JSON body.
    ///
    /// Still the smallest client that can do the job: one exchange, `Connection: close`, every wait
    /// bounded. The body is always JSON because that is the only thing these APIs speak.
    pub fn request(
        &self,
        endpoint: &Endpoint,
        method: &str,
        path: &str,
        body: Option<&str>,
    ) -> Result<Response, Error> {
        let address = endpoint.authority();
        let tcp = connect(&address, self.timeout)?;

        tcp.set_write_timeout(Some(self.timeout))
            .map_err(|source| Error::Transport { source })?;
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(|source| Error::Transport { source })?;

        let mut stream = self.wrap(endpoint, &address, tcp)?;
        let request = match body {
            Some(body) => format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                endpoint.host_header(),
                body.len()
            ),
            None => format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nConnection: close\r\n\r\n",
                endpoint.host_header()
            ),
        };

        stream
            .write_all(request.as_bytes())
            .map_err(|source| transport_error(&address, self.timeout, source))?;

        let mut response = Vec::new();

        // Bounded, so a server that streams forever costs a refusal and not
        // this process's memory: `Connection: close` means "read to the end",
        // and the end is the server's to place — this is the ceiling on where.
        stream
            .take(crate::MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .map_err(|source| transport_error(&address, self.timeout, source))?;

        if response.len() as u64 > crate::MAX_RESPONSE_BYTES {
            return Err(Error::Malformed {
                endpoint: endpoint.to_string(),
                detail: format!(
                    "its answer exceeds {} bytes, which nothing this protocol carries does",
                    crate::MAX_RESPONSE_BYTES
                ),
            });
        }
        let parsed = parse(endpoint, &response)?;
        self.narrator.exchange(
            method,
            path,
            body.map_or(0, str::len),
            &parsed.status.to_string(),
            parsed.body.len(),
        );

        Ok(parsed)
    }

    /// Sends one request with an arbitrary content type and a binary body,
    /// answering the raw bytes — what the CBOR-speaking NOTP endpoints need.
    /// The same smallest-client discipline: one exchange, `Connection:
    /// close`, every wait bounded.
    pub fn request_raw(
        &self,
        endpoint: &Endpoint,
        method: &str,
        path: &str,
        content_type: &str,
        body: Option<&[u8]>,
    ) -> Result<RawResponse, Error> {
        let address = endpoint.authority();
        let tcp = connect(&address, self.timeout)?;
        tcp.set_write_timeout(Some(self.timeout))
            .map_err(|source| Error::Transport { source })?;
        tcp.set_read_timeout(Some(self.timeout))
            .map_err(|source| Error::Transport { source })?;

        let mut stream = self.wrap(endpoint, &address, tcp)?;
        let head = match body {
            Some(body) => format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                endpoint.host_header(),
                body.len()
            ),
            None => format!(
                "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
                endpoint.host_header()
            ),
        };
        stream
            .write_all(head.as_bytes())
            .map_err(|source| transport_error(&address, self.timeout, source))?;
        if let Some(body) = body {
            stream
                .write_all(body)
                .map_err(|source| transport_error(&address, self.timeout, source))?;
        }
        let mut response = Vec::new();
        // Bounded, so a server that streams forever costs a refusal and not
        // this process's memory: `Connection: close` means "read to the end",
        // and the end is the server's to place — this is the ceiling on where.
        stream
            .take(crate::MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut response)
            .map_err(|source| transport_error(&address, self.timeout, source))?;
        if response.len() as u64 > crate::MAX_RESPONSE_BYTES {
            return Err(Error::Malformed {
                endpoint: endpoint.to_string(),
                detail: format!(
                    "its answer exceeds {} bytes, which nothing this protocol carries does",
                    crate::MAX_RESPONSE_BYTES
                ),
            });
        }

        parse_raw(endpoint, &response)
    }

    /// Hands back the stream the request is written to: the socket, or TLS over it.
    fn wrap(
        &self,
        endpoint: &Endpoint,
        address: &str,
        mut tcp: TcpStream,
    ) -> Result<Box<dyn ReadWrite>, Error> {
        if !endpoint.is_tls() {
            return Ok(Box::new(tcp));
        }

        let Some(config) = self.config.as_ref() else {
            // Unreachable in practice: the client is built knowing whether TLS will be needed.
            return Err(Error::Tls {
                source: tls::Error::Config {
                    detail: "this client was built without TLS".to_owned(),
                },
            });
        };
        let name = tls::server_name(self.tls.name_for(endpoint.host()))
            .map_err(|source| Error::Tls { source })?;
        let mut connection =
            ClientConnection::new(Arc::clone(config), name).map_err(|error| Error::Handshake {
                address: address.to_owned(),
                detail: error.to_string(),
            })?;

        // The handshake is completed here rather than lazily on first write, so that a refused
        // certificate is reported as a refused certificate.
        connection
            .complete_io(&mut tcp)
            .map_err(|error| handshake_error(address, self.timeout, error))?;

        Ok(Box::new(StreamOwned::new(connection, tcp)))
    }
}

/// A stream a request can be written to and a response read from.
trait ReadWrite: Read + Write {}

impl<T: Read + Write> ReadWrite for T {}

/// Connects within the deadline, trying every address the name resolves to.
///
/// A host with several addresses — a name with both an A and a AAAA record, most commonly — is a
/// host where the first address can be the unreachable one. Giving up there would report a plane as
/// down while it is answering perfectly well on its other address.
fn connect(address: &str, timeout: Duration) -> Result<TcpStream, Error> {
    let resolved: Vec<SocketAddr> = address
        .to_socket_addrs()
        .map_err(|source| Error::Resolve {
            address: address.to_owned(),
            source,
        })?
        .collect();

    if resolved.is_empty() {
        return Err(Error::Resolve {
            address: address.to_owned(),
            source: io::Error::new(io::ErrorKind::NotFound, "the name resolved to no address"),
        });
    }

    let mut last = None;

    for candidate in &resolved {
        match TcpStream::connect_timeout(candidate, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last = Some(error),
        }
    }

    Err(match last {
        Some(error) if error.kind() == io::ErrorKind::ConnectionRefused => Error::Refused {
            address: address.to_owned(),
        },
        Some(error) if is_timeout(&error) => Error::Timeout {
            address: address.to_owned(),
            after: timeout,
        },
        Some(source) => Error::Connect {
            address: address.to_owned(),
            source,
        },
        // Unreachable: `resolved` is not empty, so the loop ran at least once.
        None => Error::Resolve {
            address: address.to_owned(),
            source: io::Error::new(io::ErrorKind::NotFound, "the name resolved to no address"),
        },
    })
}

/// A handshake that failed. A deadline that expired during it is still a timeout.
fn handshake_error(address: &str, timeout: Duration, error: io::Error) -> Error {
    if is_timeout(&error) {
        return Error::Timeout {
            address: address.to_owned(),
            after: timeout,
        };
    }

    Error::Handshake {
        address: address.to_owned(),
        // The interesting part of a rustls failure is the alert, which is in the source chain.
        detail: match error.get_ref() {
            Some(source) => source.to_string(),
            None => error.to_string(),
        },
    }
}

/// A read or write that failed.
///
/// A deadline that expired is a timeout, and a TLS alert is a TLS failure — which is not pedantry:
/// under TLS 1.3 a client finishes its handshake before the server has judged its certificate, so
/// the rejection of a client identity arrives here, on the first read, rather than during the
/// handshake. Reporting it as a transport failure would describe the most common mutual-TLS
/// misconfiguration there is as a network problem.
fn transport_error(address: &str, timeout: Duration, source: io::Error) -> Error {
    if is_timeout(&source) {
        return Error::Timeout {
            address: address.to_owned(),
            after: timeout,
        };
    }

    if let Some(alert) = source
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        if matches!(
            alert,
            rustls::Error::AlertReceived(rustls::AlertDescription::CertificateRequired)
        ) {
            return Error::ClientCertificateRequired {
                address: address.to_owned(),
            };
        }

        return Error::Handshake {
            address: address.to_owned(),
            detail: alert.to_string(),
        };
    }

    Error::Transport { source }
}

/// Whether an error is a deadline that expired.
///
/// Both kinds mean that on a socket carrying a timeout, and which one arrives is the platform's
/// choice rather than ours.
fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

/// Reads the status line and the body out of a response.
///
/// The bytes are decoded leniently on purpose: what is needed from them is a status line and a JSON
/// body, both ASCII, and a response that is not text at all has a better explanation than a decoding
/// error — see the TLS check below.
/// Parses a response without ever treating the body as text.
fn parse_raw(endpoint: &Endpoint, response: &[u8]) -> Result<RawResponse, Error> {
    let malformed = |detail: &str| Error::Malformed {
        endpoint: endpoint.to_string(),
        detail: detail.to_owned(),
    };
    if response.is_empty() {
        return Err(malformed("it closed the connection without answering"));
    }
    let split = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| malformed("the response has no header section"))?;
    let head = String::from_utf8_lossy(&response[..split]);
    let mut body = response[split + 4..].to_vec();
    let status = head
        .lines()
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| malformed("its status line is unreadable"))?;
    // Minimal chunked decoding, for servers that answer that way.
    let chunked = head.lines().any(|line| {
        line.to_ascii_lowercase().starts_with("transfer-encoding:")
            && line.to_ascii_lowercase().contains("chunked")
    });
    if chunked {
        body = dechunk(&body).ok_or_else(|| malformed("its chunked body is unreadable"))?;
    }
    Ok(RawResponse { status, body })
}

/// Decodes a chunked body; `None` when it is not one.
fn dechunk(body: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    loop {
        let line_end = body[at..].windows(2).position(|w| w == b"\r\n")? + at;
        let size = usize::from_str_radix(
            std::str::from_utf8(&body[at..line_end])
                .ok()?
                .trim()
                .split(';')
                .next()?,
            16,
        )
        .ok()?;
        at = line_end + 2;
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(body.get(at..at + size)?);
        at += size + 2;
    }
}

fn parse(endpoint: &Endpoint, response: &[u8]) -> Result<Response, Error> {
    let malformed = |detail: &str| Error::Malformed {
        endpoint: endpoint.to_string(),
        detail: detail.to_owned(),
    };

    if response.is_empty() {
        return Err(malformed("it closed the connection without answering"));
    }

    // A TLS record: a content type in 20..=24, then the protocol version. An endpoint serving TLS
    // that was asked for plain HTTP answers a handshake or an alert, and "malformed response" sends
    // the operator looking for a broken server instead of a missing `s`.
    if matches!(response.first(), Some(0x14..=0x18)) && response.get(1) == Some(&0x03) {
        return Err(Error::PlaintextToTls {
            endpoint: endpoint.to_string(),
        });
    }

    let response = String::from_utf8_lossy(response);

    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or_else(|| malformed("the response has no header section"))?;
    let status_line = head.lines().next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| malformed(&format!("its status line reads `{status_line}`")))?;

    Ok(Response {
        status,
        body: body.to_owned(),
    })
}
