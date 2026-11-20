// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One URL, and the scheme decides the transport: `http`/`https` ride the
//! HTTP surface, `grpc`/`grpcs` the gRPC one. Same server, same facade
//! behind it — everything above this file is blind to which door was used.

// An import one transport alone uses is idle in a build that carries the other alone.
#![cfg_attr(not(all(feature = "http", feature = "grpc")), allow(unused_imports))]

use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    UploadObjectsRequest, UploadObjectsResponse,
};

#[cfg(feature = "grpc")]
use crate::grpc::GrpcRemote;
use crate::remote::{RefAnswer, Remote};
#[cfg(feature = "http")]
use crate::remote_http::HttpRemote;
use crate::tls::TlsOptions;

/// everything downstream blind to it — the same [`Remote`] contract either way.
pub enum AnyRemote {
    #[cfg(feature = "http")]
    Http(HttpRemote),
    #[cfg(feature = "grpc")]
    Grpc(GrpcRemote),
}

impl AnyRemote {
    /// Connects by scheme: `http`/`https` ride the HTTP surface, `grpc`/`grpcs`
    /// the gRPC one. Same server, same facade — one URL says which door.
    pub fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn crate::narrate::Narrator>,
    ) -> Result<Self, String> {
        if crate::transport::is_grpc(url) {
            #[cfg(feature = "grpc")]
            return GrpcRemote::connect(url, tls, narrator).map(Self::Grpc);
            #[cfg(not(feature = "grpc"))]
            return Err(crate::transport::no_grpc(url));
        }
        #[cfg(feature = "http")]
        return HttpRemote::connect(url, tls, narrator).map(Self::Http);
        #[cfg(not(feature = "http"))]
        return Err(crate::transport::no_http(url));
    }

    pub fn bind(&self, zone_id: &str, ledger_id: &str) {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.bind(zone_id, ledger_id),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.bind(zone_id, ledger_id),
        }
    }

    pub fn verify_discovery(&self) -> Result<(), String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.verify_discovery(),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.verify_discovery(),
        }
    }

    /// The last failure this remote met, taken, with the class and code the engine's `String`
    /// cannot carry: what a command reports a remote's refusal or absence with (BUG-0002).
    pub fn take_failure(&self) -> Option<crate::failure::Failure> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.take_failure(),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.take_failure(),
        }
    }
}

impl Remote for AnyRemote {
    fn resolve(&self, zone: &str, ledger: &str) -> Result<(String, String), String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.resolve(zone, ledger),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.resolve(zone, ledger),
        }
    }

    fn keyring(&self) -> Result<Vec<u8>, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.keyring(),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.keyring(),
        }
    }

    fn get_ref(&self, r#ref: &str) -> Result<Option<RefAnswer>, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.get_ref(r#ref),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.get_ref(r#ref),
        }
    }

    fn negotiate_push(
        &self,
        request: &NegotiatePushRequest,
    ) -> Result<NegotiatePushResponse, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.negotiate_push(request),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.negotiate_push(request),
        }
    }

    fn upload(&self, request: &UploadObjectsRequest) -> Result<UploadObjectsResponse, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.upload(request),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.upload(request),
        }
    }

    fn imported_head(&self, r#ref: &str) -> Result<Option<String>, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.imported_head(r#ref),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.imported_head(r#ref),
        }
    }

    fn commit_push(&self, request: &CommitPushRequest) -> Result<CommitPushResponse, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.commit_push(request),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.commit_push(request),
        }
    }

    fn negotiate_pull(
        &self,
        request: &NegotiatePullRequest,
    ) -> Result<NegotiatePullResponse, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.negotiate_pull(request),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.negotiate_pull(request),
        }
    }

    fn fetch(&self, request: &FetchObjectsRequest) -> Result<FetchObjectsResponse, String> {
        match self {
            #[cfg(feature = "http")]
            Self::Http(remote) => remote.fetch(request),
            #[cfg(feature = "grpc")]
            Self::Grpc(remote) => remote.fetch(request),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::narrate::Silent;

    fn scratch() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permguard-connect-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");

        dir
    }

    fn ca_file() -> std::path::PathBuf {
        let key = rcgen::KeyPair::generate().expect("a key generates");
        let cert = rcgen::CertificateParams::new(vec!["localhost".to_owned()])
            .expect("params build")
            .self_signed(&key)
            .expect("the certificate signs");
        let path = scratch().join("ca.pem");
        std::fs::write(&path, cert.pem()).expect("the certificate writes");

        path
    }

    fn connect(url: &str) -> Result<AnyRemote, String> {
        AnyRemote::connect(url, &TlsOptions::default(), Box::new(Silent))
    }

    fn connect_insecure(url: &str) -> Result<AnyRemote, String> {
        AnyRemote::connect(
            url,
            &TlsOptions {
                skip_verify: true,
                ..TlsOptions::default()
            },
            Box::new(Silent),
        )
    }

    fn connect_with_ca(url: &str) -> Result<AnyRemote, String> {
        AnyRemote::connect(
            url,
            &TlsOptions {
                ca_file: Some(ca_file()),
                ..TlsOptions::default()
            },
            Box::new(Silent),
        )
    }

    #[test]
    fn the_scheme_picks_the_transport() {
        // Connecting is lazy on both sides: what is asserted here is the
        // dispatch, not that anything answers.
        assert!(matches!(
            connect("http://127.0.0.1:6443"),
            Ok(AnyRemote::Http(_))
        ));
        assert!(matches!(
            connect_insecure("https://control.example.com"),
            Ok(AnyRemote::Http(_))
        ));
        assert!(matches!(
            connect("grpc://127.0.0.1:6443"),
            Ok(AnyRemote::Grpc(_))
        ));
        let grpcs = connect_with_ca("grpcs://localhost:6443");
        assert!(matches!(grpcs, Ok(AnyRemote::Grpc(_))), "{:?}", grpcs.err());
    }

    #[test]
    fn what_is_refused_and_why() {
        for (url, expected) in [
            ("127.0.0.1:6443", "a URL"),
            ("ftp://host", "not supported here"),
            ("grpc://host/with/path", "carries a path"),
        ] {
            let error = match connect(url) {
                Err(error) => error,
                Ok(_) => panic!("{url} must be refused"),
            };
            assert!(error.contains(expected), "for {url}: {error}");
        }
    }
}
