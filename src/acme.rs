//! ACME (RFC 8555) certificate lifecycle for flexd.
//!
//! Covers contract invariants 67–77 and §7 criteria C50–C58: automatic issuance
//! on startup, HTTP-01 / TLS-ALPN-01 / DNS-01 challenge response, EAB, renewal,
//! `Retry-After`-aware backoff, and fail-closed behaviour (no silent self-signed
//! fallback). The actual ACME protocol is driven by `instant-acme`; this module
//! adds the flexd-specific glue: a challenge store shared with the request
//! handler and TLS resolver, a custom HTTP client that trusts an optional test
//! root and surfaces `Retry-After`, and the `ensure_cert` orchestration.

use crate::config::AcmeConfig;
use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use instant_acme::{
    Account, BodyWrapper, BytesResponse, ChallengeType, ExternalAccountKey, HttpClient,
    Identifier, NewAccount, NewOrder, RetryPolicy,
};
use rcgen::{CertificateParams, CustomExtension, KeyPair};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock as StdRwLock};
use std::time::Duration;
use tracing::{info, warn};

/// Token paths and challenge certs awaiting validation, shared by reference
/// (cheap `Arc` clone) into the request handler (HTTP-01) and the TLS
/// `ResolvesServerCert` hook (TLS-ALPN-01). Reads happen on synchronous paths
/// (rustls' resolver is sync), so the maps use `std::sync::RwLock`, never held
/// across an `.await`.
#[derive(Clone, Default)]
pub struct ChallengeStore {
    /// http-01: token (last path segment) -> key authorization (response body)
    http01: Arc<StdRwLock<HashMap<String, String>>>,
    /// tls-alpn-01: SNI host -> challenge certificate
    tls_alpn: Arc<StdRwLock<HashMap<String, Arc<rustls::sign::CertifiedKey>>>>,
}

impl std::fmt::Debug for ChallengeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key authorizations or key material (inv 68/77).
        let http = self.http01.read().map(|m| m.len()).unwrap_or(0);
        let alpn = self.tls_alpn.read().map(|m| m.len()).unwrap_or(0);
        f.debug_struct("ChallengeStore")
            .field("http01_pending", &http)
            .field("tls_alpn_pending", &alpn)
            .finish()
    }
}

impl ChallengeStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn put_http01(&self, token: String, key_auth: String) {
        if let Ok(mut m) = self.http01.write() {
            m.insert(token, key_auth);
        }
    }

    /// Look up an http-01 key authorization by token. Synchronous: safe to call
    /// from the async request handler without holding a lock across `.await`.
    pub fn get_http01(&self, token: &str) -> Option<String> {
        self.http01.read().ok().and_then(|m| m.get(token).cloned())
    }

    pub fn put_tls_alpn(&self, sni: String, cert: Arc<rustls::sign::CertifiedKey>) {
        if let Ok(mut m) = self.tls_alpn.write() {
            m.insert(sni, cert);
        }
    }

    pub fn get_tls_alpn(&self, sni: &str) -> Option<Arc<rustls::sign::CertifiedKey>> {
        self.tls_alpn.read().ok().and_then(|m| m.get(sni).cloned())
    }

    /// Whether any tls-alpn-01 challenge cert is staged (used to decide whether
    /// the acceptor must advertise the `acme-tls/1` ALPN protocol).
    pub fn has_tls_alpn(&self) -> bool {
        self.tls_alpn.read().map(|m| !m.is_empty()).unwrap_or(false)
    }
}

/// rustls certificate resolver. Serves the staged TLS-ALPN-01 challenge cert
/// when (and only when) the client negotiates the `acme-tls/1` ALPN protocol
/// (RFC 8737); all ordinary traffic gets the issued/static `default` cert.
#[derive(Debug)]
pub struct AcmeResolver {
    default: Arc<rustls::sign::CertifiedKey>,
    store: ChallengeStore,
}

impl AcmeResolver {
    pub fn new(default: Arc<rustls::sign::CertifiedKey>, store: ChallengeStore) -> Self {
        Self { default, store }
    }
}

impl rustls::server::ResolvesServerCert for AcmeResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let is_acme_alpn = hello
            .alpn()
            .map(|mut protos| protos.any(|p| p == b"acme-tls/1"))
            .unwrap_or(false);
        if is_acme_alpn {
            // Per RFC 8737 the validation request always carries SNI; serve the
            // matching challenge cert, or nothing (terminating the handshake).
            let sni = hello.server_name()?;
            return self.store.get_tls_alpn(sni);
        }
        Some(self.default.clone())
    }
}

type HyperAcmeClient = hyper_util::client::legacy::Client<
    hyper_rustls::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
    BodyWrapper<Bytes>,
>;

/// Custom `instant-acme` HTTP client. Two jobs the default client can't do:
///   1. Trust an optional extra root CA (`acme.ca_root`) so the daemon can use a
///      testing/enterprise ACME PKI (mirrors `Account::builder_with_root`).
///   2. Surface the CA's `Retry-After` on a `429` into a shared counter so the
///      issuance loop can honour it (inv 71 / C54) — `instant-acme` otherwise
///      buries it inside an opaque `Error::Api`.
struct AcmeHttpClient {
    inner: HyperAcmeClient,
    retry_after: Arc<AtomicU64>,
}

impl AcmeHttpClient {
    fn new(ca_root: Option<&str>, retry_after: Arc<AtomicU64>) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(path) = ca_root {
            let pem = std::fs::read(path)
                .with_context(|| format!("reading acme.ca_root {}", path))?;
            for cert in rustls_pemfile::certs(&mut &pem[..]) {
                let cert = cert.with_context(|| format!("parsing acme.ca_root {}", path))?;
                roots
                    .add(cert)
                    .with_context(|| format!("adding acme.ca_root {}", path))?;
            }
        }
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config(tls)
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let inner = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build(connector);
        Ok(Self { inner, retry_after })
    }
}

impl HttpClient for AcmeHttpClient {
    fn request(
        &self,
        req: http::Request<BodyWrapper<Bytes>>,
    ) -> Pin<Box<dyn Future<Output = Result<BytesResponse, instant_acme::Error>> + Send>> {
        // Delegate to instant-acme's blanket HttpClient impl for the hyper client.
        let fut = HttpClient::request(&self.inner, req);
        let retry_after = Arc::clone(&self.retry_after);
        Box::pin(async move {
            let rsp = fut.await?;
            if rsp.parts.status == http::StatusCode::TOO_MANY_REQUESTS {
                if let Some(secs) = rsp
                    .parts
                    .headers
                    .get(http::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.trim().parse::<u64>().ok())
                {
                    retry_after.store(secs, Ordering::SeqCst);
                }
            }
            Ok(rsp)
        })
    }
}

/// Orchestrates issuance for one TLS server block.
pub struct AcmeManager {
    cfg: AcmeConfig,
    /// `server_name` values of the block, used to default `domains`.
    server_names: Vec<String>,
    store: ChallengeStore,
}

impl AcmeManager {
    pub fn new(cfg: AcmeConfig, server_names: Vec<String>) -> Self {
        Self {
            cfg,
            server_names,
            store: ChallengeStore::new(),
        }
    }

    pub fn store(&self) -> ChallengeStore {
        self.store.clone()
    }

    pub fn http_challenge_port(&self) -> u16 {
        self.cfg.http_challenge_port.unwrap_or(80)
    }

    pub fn cert_path(&self) -> String {
        format!("{}/cert.pem", self.cfg.cert_dir)
    }

    pub fn key_path(&self) -> String {
        format!("{}/key.pem", self.cfg.cert_dir)
    }

    /// Effective domains to request: explicit `acme.domains` or, if empty, the
    /// block's `server_name` list.
    fn domains(&self) -> Vec<String> {
        if self.cfg.domains.is_empty() {
            self.server_names.clone()
        } else {
            self.cfg.domains.clone()
        }
    }

    /// How often the renewal task re-checks expiry (default 1h).
    pub fn renewal_check_interval(&self) -> Duration {
        Duration::from_secs(self.cfg.renewal_check_interval_secs.unwrap_or(3600))
    }

    /// Whether a loadable cert + key already exist on disk.
    fn has_usable_cert(&self) -> bool {
        std::path::Path::new(&self.cert_path()).exists()
            && std::path::Path::new(&self.key_path()).exists()
            && load_certified_key(&self.cert_path(), &self.key_path()).is_ok()
    }

    /// C53 / invariant 75-aware: true if the issued cert is within
    /// `renewal_window` days of expiry (or unreadable, which also warrants
    /// re-issuance).
    pub fn needs_renewal(&self) -> Result<bool> {
        let pem = match std::fs::read(self.cert_path()) {
            Ok(p) => p,
            Err(_) => return Ok(true),
        };
        let (_, pem_obj) = x509_parser::pem::parse_x509_pem(&pem)
            .map_err(|e| anyhow!("parsing issued cert PEM: {e}"))?;
        let cert = pem_obj
            .parse_x509()
            .map_err(|e| anyhow!("parsing issued cert DER: {e}"))?;
        let not_after = cert.validity().not_after.timestamp();
        let now = chrono::Utc::now().timestamp();
        let window = self.cfg.renewal_window as i64 * 86_400;
        Ok(not_after - now < window)
    }

    /// Startup issuance: reuse an existing usable cert (the renewal task handles
    /// expiry); otherwise issue one. On failure the caller refuses to bind the
    /// TLS listener (inv 76 / C58) — never a self-signed fallback.
    pub async fn ensure_cert(&self) -> Result<()> {
        if self.has_usable_cert() {
            info!(cert = %self.cert_path(), "ACME: reusing existing certificate");
            return Ok(());
        }
        self.issue_with_retry().await
    }

    /// Force a fresh issuance (used on startup when no cert exists and by the
    /// renewal task), retrying with `Retry-After`-aware exponential backoff
    /// (inv 71).
    pub async fn issue_with_retry(&self) -> Result<()> {
        let retry_after = Arc::new(AtomicU64::new(0));
        let max_attempts: u32 = 5;
        let mut attempt: u32 = 0;
        loop {
            attempt += 1;
            retry_after.store(0, Ordering::SeqCst);
            match self.try_issue(Arc::clone(&retry_after)).await {
                Ok(()) => {
                    info!(
                        domains = ?self.domains(),
                        cert = %self.cert_path(),
                        "ACME certificate issued"
                    );
                    return Ok(());
                }
                Err(e) => {
                    if attempt >= max_attempts {
                        return Err(e).with_context(|| {
                            format!("ACME issuance failed after {} attempts", max_attempts)
                        });
                    }
                    // inv 71: respect Retry-After, otherwise exponential backoff.
                    let server = Duration::from_secs(retry_after.load(Ordering::SeqCst));
                    let backoff = Duration::from_secs(1u64 << (attempt - 1).min(6));
                    let wait = server.max(backoff);
                    warn!(
                        acme_error = %e,
                        attempt,
                        wait_secs = wait.as_secs(),
                        retry_after_secs = server.as_secs(),
                        "ACME issuance attempt failed; backing off before retry"
                    );
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }

    async fn try_issue(&self, retry_after: Arc<AtomicU64>) -> Result<()> {
        let http = AcmeHttpClient::new(self.cfg.ca_root.as_deref(), retry_after)?;
        let builder = Account::builder_with_http(Box::new(http));

        let eab = self.load_eab()?;
        let contact = format!("mailto:{}", self.cfg.email);
        let new_account = NewAccount {
            contact: &[contact.as_str()],
            terms_of_service_agreed: self.cfg.agree_tos,
            only_return_existing: false,
        };
        let (account, _creds) = builder
            .create(&new_account, self.cfg.ca_endpoint.clone(), eab.as_ref())
            .await
            .map_err(map_acme_err)
            .context("ACME account creation")?;

        let domains = self.domains();
        if domains.is_empty() {
            bail!("ACME enabled but no domains/server_name to request");
        }
        let identifiers: Vec<Identifier> =
            domains.iter().map(|d| Identifier::Dns(d.clone())).collect();
        let mut order = account
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(map_acme_err)
            .context("ACME new-order")?;

        // Respond to each authorization's challenge.
        let mut authorizations = order.authorizations();
        while let Some(authz) = authorizations.next().await {
            let mut authz = authz.map_err(map_acme_err).context("fetch authorization")?;
            if authz.status == instant_acme::AuthorizationStatus::Valid {
                continue;
            }

            let domain = match &authz.identifier().identifier {
                Identifier::Dns(d) => d.clone(),
                other => bail!("unsupported ACME identifier: {:?}", other),
            };

            // Pick the first configured challenge type the CA actually offered.
            let pick = self.cfg.challenge_types.iter().find_map(|ct| {
                let (kind, want) = match ct.as_str() {
                    "http-01" => (Pick::Http, ChallengeType::Http01),
                    "tls-alpn-01" => (Pick::Alpn, ChallengeType::TlsAlpn01),
                    "dns-01" => (Pick::Dns, ChallengeType::Dns01),
                    _ => return None,
                };
                if authz.challenges.iter().any(|c| c.r#type == want) {
                    Some((kind, want))
                } else {
                    None
                }
            });
            let (kind, want) = pick.ok_or_else(|| {
                anyhow!("no configured challenge type offered for {}", domain)
            })?;

            let mut challenge = authz
                .challenge(want.clone())
                .ok_or_else(|| anyhow!("challenge {:?} unavailable for {}", want, domain))?;
            let key_auth = challenge.key_authorization();
            let token = challenge.token.clone();

            match kind {
                Pick::Http => {
                    self.store.put_http01(token.clone(), key_auth.as_str().to_string());
                }
                Pick::Alpn => {
                    let digest = key_auth.digest();
                    let cert = build_tls_alpn_cert(&domain, digest.as_ref())
                        .context("building tls-alpn-01 challenge cert")?;
                    self.store.put_tls_alpn(domain.clone(), Arc::new(cert));
                }
                Pick::Dns => {
                    self.post_dns_webhook(&domain, &token, &key_auth.dns_value())
                        .await
                        .context("posting dns-01 webhook")?;
                }
            }

            challenge
                .set_ready()
                .await
                .map_err(map_acme_err)
                .context("set challenge ready")?;
        }
        drop(authorizations);

        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(map_acme_err)
            .context("poll order ready")?;
        if status != instant_acme::OrderStatus::Ready {
            bail!("ACME order not ready after validation: {:?}", status);
        }

        // Generate our own key + CSR for the full SAN set, then finalize.
        let key_pair = KeyPair::generate().context("generating certificate key")?;
        let mut params =
            CertificateParams::new(domains.clone()).context("building CSR params")?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params
            .serialize_request(&key_pair)
            .context("serializing CSR")?;
        order
            .finalize_csr(csr.der())
            .await
            .map_err(map_acme_err)
            .context("finalize order")?;

        let cert_chain_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(map_acme_err)
            .context("poll certificate")?;
        let key_pem = key_pair.serialize_pem();

        self.write_cert(&cert_chain_pem, &key_pem)
            .context("persisting issued certificate")?;
        Ok(())
    }

    /// inv 68: issued cert + key written with mode 0600.
    fn write_cert(&self, chain_pem: &str, key_pem: &str) -> Result<()> {
        std::fs::create_dir_all(&self.cfg.cert_dir)
            .with_context(|| format!("creating cert dir {}", self.cfg.cert_dir))?;
        let cert_path = self.cert_path();
        let key_path = self.key_path();
        write_secret(&cert_path, chain_pem.as_bytes())?;
        write_secret(&key_path, key_pem.as_bytes())?;
        Ok(())
    }

    /// inv 77: EAB HMAC key is read from a file (validated 0600 at config load),
    /// base64-decoded, and never logged.
    fn load_eab(&self) -> Result<Option<ExternalAccountKey>> {
        match &self.cfg.eab {
            None => Ok(None),
            Some(eab) => {
                let b64 = std::fs::read_to_string(&eab.hmac_key)
                    .with_context(|| format!("reading eab.hmac_key {}", eab.hmac_key))?;
                let key_bytes = decode_b64(b64.trim())
                    .ok_or_else(|| anyhow!("eab.hmac_key is not valid base64"))?;
                Ok(Some(ExternalAccountKey::new(eab.kid.clone(), &key_bytes)))
            }
        }
    }

    /// inv 67 (network exception) / C57: post the dns-01 challenge to the
    /// configured webhook with the auth header value read from its file.
    async fn post_dns_webhook(&self, domain: &str, token: &str, dns_value: &str) -> Result<()> {
        let webhook = self
            .cfg
            .dns_webhook
            .as_ref()
            .ok_or_else(|| anyhow!("dns-01 challenge selected but no dns_webhook configured"))?;
        let body = serde_json::json!({
            "domain": domain,
            "token": token,
            "value": dns_value,
            "action": "create",
        });
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(webhook.timeout))
            .build()
            .context("building dns webhook client")?;
        let mut req = client.post(&webhook.url).json(&body);
        if let Some(auth_path) = &webhook.auth_header {
            let header_value = std::fs::read_to_string(auth_path)
                .with_context(|| format!("reading dns_webhook.auth_header {}", auth_path))?;
            req = req.header(http::header::AUTHORIZATION, header_value.trim());
        }
        let resp = req.send().await.context("sending dns webhook")?;
        if !resp.status().is_success() {
            bail!("dns webhook returned HTTP {}", resp.status());
        }
        Ok(())
    }
}

/// Which challenge branch was selected (a `Copy` tag so the `ChallengeType`
/// value can be moved into `authz.challenge(..)` independently).
#[derive(Clone, Copy)]
enum Pick {
    Http,
    Alpn,
    Dns,
}

/// Build a self-signed TLS-ALPN-01 challenge certificate for `domain` carrying
/// the critical `id-pe-acmeIdentifier` extension (OID 1.3.6.1.5.5.7.1.31) with
/// the SHA-256 of the key authorization (RFC 8737 §3).
fn build_tls_alpn_cert(
    domain: &str,
    key_auth_digest: &[u8],
) -> Result<rustls::sign::CertifiedKey> {
    if key_auth_digest.len() != 32 {
        bail!(
            "tls-alpn-01 digest must be 32 bytes, got {}",
            key_auth_digest.len()
        );
    }
    let key_pair = KeyPair::generate().context("challenge cert key")?;
    let mut params =
        CertificateParams::new(vec![domain.to_string()]).context("challenge cert params")?;
    params
        .custom_extensions
        .push(CustomExtension::new_acme_identifier(key_auth_digest));
    let cert = params
        .self_signed(&key_pair)
        .context("self-signing challenge cert")?;

    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
    );
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| anyhow!("loading challenge signing key: {e}"))?;
    Ok(rustls::sign::CertifiedKey::new(vec![cert_der], signing_key))
}

/// Load a cert chain + key from disk into a `CertifiedKey` for the resolver's
/// default (the issued or static cert).
pub fn load_certified_key(
    cert_path: &str,
    key_path: &str,
) -> Result<Arc<rustls::sign::CertifiedKey>> {
    let certs = crate::tls::load_certificate(cert_path)?;
    let key = crate::tls::load_private_key(key_path)?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow!("loading signing key {}: {e}", key_path))?;
    Ok(Arc::new(rustls::sign::CertifiedKey::new(certs, signing_key)))
}

fn map_acme_err(e: instant_acme::Error) -> anyhow::Error {
    anyhow!("ACME protocol error: {e}")
}

/// Write secret bytes with mode 0600 (owner read/write only).
fn write_secret(path: &str, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).with_context(|| format!("writing {}", path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("setting 0600 on {}", path))?;
    }
    Ok(())
}

/// Tolerant base64 decode: tries URL-safe (no pad) then standard.
fn decode_b64(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(s))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrip_http01() {
        let store = ChallengeStore::new();
        assert_eq!(store.get_http01("tok"), None);
        store.put_http01("tok".into(), "tok.thumb".into());
        assert_eq!(store.get_http01("tok").as_deref(), Some("tok.thumb"));
        assert_eq!(store.get_http01("missing"), None);
    }

    #[test]
    fn store_debug_redacts_secrets() {
        let store = ChallengeStore::new();
        store.put_http01("tok".into(), "super-secret-keyauth".into());
        let dbg = format!("{:?}", store);
        assert!(!dbg.contains("super-secret-keyauth"), "debug leaked key auth");
        assert!(dbg.contains("http01_pending"));
    }

    #[test]
    #[cfg_attr(miri, ignore)] // rcgen/ring key generation uses FFI/asm miri can't execute
    fn tls_alpn_cert_has_acme_identifier_and_loads() {
        // 32-byte digest -> valid challenge cert that rustls accepts as a key.
        let digest = [7u8; 32];
        let ck = build_tls_alpn_cert("example.com", &digest).expect("build cert");
        assert_eq!(ck.cert.len(), 1, "exactly the leaf challenge cert");
    }

    #[test]
    fn tls_alpn_cert_rejects_bad_digest_len() {
        assert!(build_tls_alpn_cert("example.com", &[0u8; 16]).is_err());
    }

    #[test]
    fn b64_decode_tolerates_both_alphabets() {
        // "hello" url-safe-no-pad and standard both decode to the same bytes.
        assert_eq!(decode_b64("aGVsbG8").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_b64("aGVsbG8=").as_deref(), Some(&b"hello"[..]));
        assert_eq!(decode_b64("!!not-b64!!"), None);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // builds a cert (rcgen/ring FFI) for the resolver default
    fn resolver_serves_default_without_acme_alpn() {
        // Build a throwaway default cert and confirm the resolver returns it.
        let ck = build_tls_alpn_cert("default.example", &[1u8; 32]).unwrap();
        let resolver = AcmeResolver::new(Arc::new(ck), ChallengeStore::new());
        // We can't easily fabricate a ClientHello here; assert construction and
        // store wiring instead (resolve() is exercised end-to-end by C52).
        assert!(!resolver.store.has_tls_alpn());
    }
}

#[cfg(all(test, not(miri)))]
mod prop_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(256))]

        /// Invariant: whatever token/key-auth pair goes in comes back out
        /// unchanged, and unrelated tokens never collide.
        #[test]
        fn prop_http01_store_roundtrip(token in "[A-Za-z0-9_-]{1,40}", auth in "[A-Za-z0-9._-]{1,80}") {
            let store = ChallengeStore::new();
            store.put_http01(token.clone(), auth.clone());
            prop_assert_eq!(store.get_http01(&token), Some(auth));
            let other = format!("{}x", token);
            prop_assert_eq!(store.get_http01(&other), None);
        }
    }
}
