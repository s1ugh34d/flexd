//! TLS and QUIC configuration construction.
//!
//! flexd uses [rustls](https://docs.rs/rustls) exclusively — there is no
//! OpenSSL dependency. This module turns the parsed
//! [`SslSettings`](crate::config::SslSettings) (or explicit cert/key paths, for
//! ACME-issued certificates) into the acceptors the server needs:
//!
//! - [`build_tls_acceptor`](crate::tls::build_tls_acceptor) — a `tokio_rustls`
//!   acceptor for static certs, advertising `h2` and `http/1.1` via ALPN.
//! - [`build_tls_acceptor_acme`](crate::tls::build_tls_acceptor_acme) — like the
//!   above but with a challenge-aware certificate resolver that also serves
//!   TLS-ALPN-01 validation certs.
//! - [`build_quinn_server_config`](crate::tls::build_quinn_server_config) /
//!   [`build_quinn_server_config_from_paths`](crate::tls::build_quinn_server_config_from_paths)
//!   — a QUIC server config advertising `h3` for HTTP/3 listeners.
//!
//! Only TLS 1.2 and 1.3 are ever negotiated; the configuration validator
//! rejects older versions before these functions run.

use crate::config::SslSettings;
use anyhow::{Context, Result};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

/// Load a PEM certificate chain from `cert_path`.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, fails to parse as PEM, or
/// contains no certificates.
pub fn load_certificate(cert_path: &str) -> Result<Vec<CertificateDer<'static>>> {
    let file = File::open(cert_path)
        .with_context(|| format!("Failed to open certificate: {}", cert_path))?;
    let mut reader = BufReader::new(file);

    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to parse certificate: {}", cert_path))?;

    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", cert_path);
    }

    Ok(certs)
}

/// Load a private key from `key_path`, trying PKCS#8 first and then RSA.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or holds no usable private key.
pub fn load_private_key(key_path: &str) -> Result<PrivateKeyDer<'static>> {
    let file = File::open(key_path)
        .with_context(|| format!("Failed to open private key: {}", key_path))?;
    let mut reader = BufReader::new(file);

    let keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to parse PKCS8 key: {}", key_path));

    if let Ok(keys) = keys {
        if let Some(key) = keys.into_iter().next() {
            return Ok(key.into());
        }
    }

    let mut reader = BufReader::new(File::open(key_path)?);
    let keys = rustls_pemfile::rsa_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to parse RSA key: {}", key_path))?;

    if let Some(key) = keys.into_iter().next() {
        return Ok(key.into());
    }

    anyhow::bail!("No private keys found in {}", key_path)
}

/// Build a `tokio_rustls` acceptor from static-certificate [`SslSettings`].
///
/// The acceptor advertises `h2` and `http/1.1` via ALPN and negotiates only
/// the configured TLS versions (defaulting to 1.3 and 1.2).
///
/// # Errors
///
/// Returns an error if `certificate`/`certificate_key` are unset or unreadable,
/// or if rustls rejects the cert/key pair.
pub fn build_tls_acceptor(ssl: &SslSettings) -> Result<tokio_rustls::TlsAcceptor> {
    let cert_path = ssl
        .certificate
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TLS certificate path not configured"))?;
    let key_path = ssl
        .certificate_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TLS private key path not configured"))?;

    let certs = load_certificate(cert_path)?;
    let key = load_private_key(key_path)?;

    let mut versions = vec![];
    for proto in &ssl.protocols {
        match proto.to_uppercase().as_str() {
            "TLSV1.2" => versions.push(&rustls::version::TLS12),
            "TLSV1.3" => versions.push(&rustls::version::TLS13),
            _ => {}
        }
    }

    if versions.is_empty() {
        versions.push(&rustls::version::TLS13);
        versions.push(&rustls::version::TLS12);
    }

    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| "Failed to build TLS server config")?;

    // Advertise h2 + http/1.1 so ALPN negotiation works for HTTP/2
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Parse the configured TLS protocol versions, defaulting to TLS1.3+TLS1.2.
fn tls_versions(protocols: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut versions = vec![];
    for proto in protocols {
        match proto.to_uppercase().as_str() {
            "TLSV1.2" => versions.push(&rustls::version::TLS12),
            "TLSV1.3" => versions.push(&rustls::version::TLS13),
            _ => {}
        }
    }
    if versions.is_empty() {
        versions.push(&rustls::version::TLS13);
        versions.push(&rustls::version::TLS12);
    }
    versions
}

/// Build a TLS acceptor for an `acme.enabled` block. The default cert is the
/// ACME-issued chain at `cert_path`/`key_path`; an [`crate::acme::AcmeResolver`]
/// additionally serves TLS-ALPN-01 challenge certs from `store`. The acceptor
/// advertises `acme-tls/1` alongside h2/http1.1 so the CA's validation handshake
/// (C52) negotiates it.
pub fn build_tls_acceptor_acme(
    cert_path: &str,
    key_path: &str,
    protocols: &[String],
    store: crate::acme::ChallengeStore,
) -> Result<tokio_rustls::TlsAcceptor> {
    let default = crate::acme::load_certified_key(cert_path, key_path)?;
    let resolver = Arc::new(crate::acme::AcmeResolver::new(default, store));

    let versions = tls_versions(protocols);
    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&versions)
        .with_no_client_auth()
        .with_cert_resolver(resolver);

    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        b"acme-tls/1".to_vec(),
    ];

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// QUIC server config from explicit cert/key paths (used for ACME-issued certs,
/// where `SslSettings.certificate` is absent).
///
/// # Errors
///
/// Returns an error if the cert/key cannot be loaded or the QUIC crypto config
/// cannot be built.
pub fn build_quinn_server_config_from_paths(
    cert_path: &str,
    key_path: &str,
) -> Result<quinn::ServerConfig> {
    build_quinn_from_paths(cert_path, key_path)
}

/// Build a QUIC (HTTP/3) server config from [`SslSettings`].
///
/// The config advertises the `h3` ALPN protocol and caps concurrent streams.
///
/// # Errors
///
/// Returns an error if `certificate`/`certificate_key` are unset or the QUIC
/// crypto config cannot be built.
pub fn build_quinn_server_config(ssl: &SslSettings) -> Result<quinn::ServerConfig> {
    let cert_path = ssl
        .certificate
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TLS certificate path not configured for QUIC"))?;
    let key_path = ssl
        .certificate_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("TLS private key path not configured for QUIC"))?;
    build_quinn_from_paths(cert_path, key_path)
}

fn build_quinn_from_paths(cert_path: &str, key_path: &str) -> Result<quinn::ServerConfig> {
    let cert = load_certificate(cert_path)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("No certificate found"))?;
    let key = load_private_key(key_path)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .with_context(|| "Failed to build QUIC TLS config")?;

    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?,
    ));

    let transport_config = Arc::get_mut(&mut server_config.transport)
        .ok_or_else(|| anyhow::anyhow!("Failed to get mutable transport config"))?;

    transport_config.max_concurrent_uni_streams(100u32.into());
    transport_config.max_concurrent_bidi_streams(100u32.into());

    Ok(server_config)
}
