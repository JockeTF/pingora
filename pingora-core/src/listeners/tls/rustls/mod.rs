// Copyright 2026 Cloudflare, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use crate::listeners::TlsAcceptCallbacks;
use crate::protocols::tls::{server::handshake, server::handshake_with_callback, TlsStream};
use log::debug;
use pingora_error::ErrorType::InternalError;
use pingora_error::{Error, OrErr, Result};
use pingora_rustls::cert_resolvers::ResolvesServerCert;
use pingora_rustls::load_certs_and_key_files;
use pingora_rustls::ClientCertVerifier;
use pingora_rustls::{version, TlsAcceptor as RusTlsAcceptor};
use pingora_rustls::{ConfigBuilder, ServerConfig, WantsServerCert};

use crate::protocols::{ALPN, IO};

/// The TLS settings of a listening endpoint
pub struct TlsSettings {
    alpn_protocols: Option<Vec<Vec<u8>>>,
    cert_key_path: Option<(String, String)>,
    cert_resolver: Option<Arc<dyn ResolvesServerCert>>,
    client_cert_verifier: Option<Arc<dyn ClientCertVerifier>>,
}

pub struct Acceptor {
    pub acceptor: RusTlsAcceptor,
    callbacks: Option<TlsAcceptCallbacks>,
}

impl TlsSettings {
    /// Create a Rustls acceptor based on the current setting for certificates,
    /// keys, and protocols.
    pub(crate) fn build(self) -> Result<Acceptor> {
        // rustls 0.23+ requires an explicit CryptoProvider.
        pingora_rustls::install_default_crypto_provider();

        let mut config = if let Some((ref cert_path, ref key_path)) = self.cert_key_path {
            self.build_with_cert_key_files(cert_path, key_path)?
        } else if let Some(ref cert_resolver) = self.cert_resolver {
            self.build_with_cert_resolver(cert_resolver.clone())
        } else {
            return Err(Error::explain(
                InternalError,
                "Neither cert/key path pair nor certificate resolver available.",
            ));
        };

        if let Some(alpn_protocols) = self.alpn_protocols {
            config.alpn_protocols = alpn_protocols;
        }

        Ok(Acceptor {
            acceptor: RusTlsAcceptor::from(Arc::new(config)),
            callbacks: None,
        })
    }

    fn server_config_builder(&self) -> ConfigBuilder<ServerConfig, WantsServerCert> {
        let versions = [&version::TLS12, &version::TLS13];
        let builder = ServerConfig::builder_with_protocol_versions(&versions);

        if let Some(ref verifier) = self.client_cert_verifier {
            builder.with_client_cert_verifier(verifier.clone())
        } else {
            builder.with_no_client_auth()
        }
    }

    fn build_with_cert_key_files(&self, cert_path: &str, key_path: &str) -> Result<ServerConfig> {
        let cert_key =
            load_certs_and_key_files(cert_path, key_path).explain_err(InternalError, |e| {
                format!(
                    "Failed to load provided certificates \"{}\" or key \"{}\" error {}.",
                    cert_path, key_path, e
                )
            })?;

        let Some((certs, key)) = cert_key else {
            return Err(Error::explain(
                InternalError,
                format!(
                    "Certificate \"{}\" or key \"{}\" did not contain expected data.",
                    cert_path, key_path
                ),
            ));
        };

        // TODO: Add custom CA support
        self.server_config_builder()
            .with_single_cert(certs, key)
            .explain_err(InternalError, |e| {
                format!("Failed to create server listener config: {e}")
            })
    }

    fn build_with_cert_resolver(&self, cert_resolver: Arc<dyn ResolvesServerCert>) -> ServerConfig {
        // TODO: Add custom CA support
        self.server_config_builder()
            .with_cert_resolver(cert_resolver)
    }

    /// Enable HTTP/2 support for this endpoint, which is default off.
    /// This effectively sets the ALPN to prefer HTTP/2 with HTTP/1.1 allowed
    pub fn enable_h2(&mut self) {
        self.set_alpn(ALPN::H2H1);
    }

    pub fn set_alpn(&mut self, alpn: ALPN) {
        self.alpn_protocols = Some(alpn.to_wire_protocols());
    }

    /// Configure mTLS by providing a rustls client certificate verifier.
    pub fn set_client_cert_verifier(&mut self, verifier: Arc<dyn ClientCertVerifier>) {
        self.client_cert_verifier = Some(verifier);
    }

    pub fn intermediate(cert_path: &str, key_path: &str) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_key_path: Some((cert_path.to_string(), key_path.to_string())),
            cert_resolver: None,
            client_cert_verifier: None,
        })
    }

    pub fn resolver(cert_resolver: Arc<dyn ResolvesServerCert>) -> Result<Self>
    where
        Self: Sized,
    {
        Ok(TlsSettings {
            alpn_protocols: None,
            cert_key_path: None,
            cert_resolver: Some(cert_resolver),
            client_cert_verifier: None,
        })
    }

    pub fn with_callbacks() -> Result<Self>
    where
        Self: Sized,
    {
        Error::e_explain(
            InternalError,
            "Certificate callbacks are not supported when using rustls.",
        )
    }
}

impl Acceptor {
    pub async fn tls_handshake<S: IO>(&self, stream: S) -> Result<TlsStream<S>> {
        debug!("new tls session");
        // TODO: be able to offload this handshake in a thread pool
        if let Some(cb) = self.callbacks.as_ref() {
            handshake_with_callback(self, stream, cb).await
        } else {
            handshake(self, stream).await
        }
    }
}
