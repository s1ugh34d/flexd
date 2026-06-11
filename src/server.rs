use crate::config::{Config, HttpBlock, ListenDirective, MailBlock, StreamBlock, TimeoutSettings};
use crate::handler::HandlerService;
use crate::logging::AccessLogger;
use crate::security;
use crate::security::rate_limit::ResetTracker;
use crate::tls;
use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{RwLock, broadcast};
use tracing::{error, info, warn};

/// C30: Wrapper that rejects connections containing bare LF (RFC 9112 §2.2).
/// Buffers the first read, checks for bare \n not preceded by \r, sends 400 if found.
struct BareLfGuard<S> {
    inner: S,
    prefix: Vec<u8>,
    prefix_pos: usize,
    /// When true, all reads return 0 bytes (connection rejected)
    rejected: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> BareLfGuard<S> {
    fn new(inner: S, prefix: Vec<u8>, rejected: bool) -> Self {
        Self { inner, prefix, prefix_pos: 0, rejected }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BareLfGuard<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, rbuf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.rejected {
            return Poll::Ready(Ok(())); // EOF — connection rejected
        }
        // Drain prefix buffer first
        if self.prefix_pos < self.prefix.len() {
            let remaining = &self.prefix[self.prefix_pos..];
            let to_copy = remaining.len().min(rbuf.remaining());
            rbuf.put_slice(&remaining[..to_copy]);
            self.prefix_pos += to_copy;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, rbuf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BareLfGuard<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Check whether a raw HTTP request prefix contains bare LF (not preceded by CR)
fn has_bare_lf(buf: &[u8]) -> bool {
    // Only inspect up to the end of headers (first blank line)
    let header_end = buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|p| p + 4)
        .unwrap_or(buf.len());
    let header_section = &buf[..header_end];
    for i in 0..header_section.len() {
        if header_section[i] == b'\n' && (i == 0 || header_section[i - 1] != b'\r') {
            return true;
        }
    }
    false
}

/// Resolve a listen directive to a socket address (default 0.0.0.0).
fn listen_addr(listen: &ListenDirective) -> SocketAddr {
    let ip: IpAddr = listen
        .address
        .as_deref()
        .and_then(|a| a.parse().ok())
        .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    SocketAddr::new(ip, listen.port)
}

/// Default per-connection HTTP/2 reset budget when `http2_max_reset_rate` is
/// not configured: generous for legitimate clients, fatal for Rapid Reset
/// floods (Invariant 20).
fn default_reset_rate() -> crate::config::ResetRateLimit {
    crate::config::ResetRateLimit { count: 100, window_seconds: 10 }
}

pub struct Server {
    config: Arc<RwLock<Config>>,
    shutdown_tx: broadcast::Sender<()>,
    reload_tx: broadcast::Sender<()>,
    /// Addresses actually bound (port 0 resolved); for ops and tests.
    bound: Arc<StdMutex<Vec<SocketAddr>>>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (reload_tx, _) = broadcast::channel(1);

        Self {
            config: Arc::new(RwLock::new(config)),
            shutdown_tx,
            reload_tx,
            bound: Arc::new(StdMutex::new(Vec::new())),
        }
    }

    /// Addresses of listeners bound so far (TCP; resolved after `run` starts).
    pub fn bound_addrs(&self) -> Vec<SocketAddr> {
        self.bound.lock().map(|v| v.clone()).unwrap_or_default()
    }

    fn record_bound(&self, listener: &TcpListener) {
        if let (Ok(addr), Ok(mut bound)) = (listener.local_addr(), self.bound.lock()) {
            bound.push(addr);
        }
    }

    pub async fn run(&self) -> Result<()> {
        let config_snapshot = {
            let guard = self.config.read().await;
            guard.clone()
        };
        let timeouts: TimeoutSettings =
            config_snapshot.global.timeouts.clone().unwrap_or_default();

        if let Some(ref pid_file) = config_snapshot.global.pid_file {
            if let Some(parent) = std::path::Path::new(pid_file).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = std::fs::write(pid_file, std::process::id().to_string());
        }

        let mut join_set = tokio::task::JoinSet::<Result<()>>::new();

        // One ACME manager (+ shared challenge store) per acme.enabled block,
        // keyed by http_block index.
        let mut acme_managers: std::collections::HashMap<usize, Arc<crate::acme::AcmeManager>> =
            std::collections::HashMap::new();
        for (idx, http_block) in config_snapshot.http.iter().enumerate() {
            if let Some(acme) = http_block.ssl.as_ref().and_then(|s| s.acme.as_ref()) {
                if acme.enabled {
                    acme_managers.insert(
                        idx,
                        Arc::new(crate::acme::AcmeManager::new(
                            acme.clone(),
                            http_block.server_name.clone(),
                        )),
                    );
                }
            }
        }

        // Bind every listener socket now, while still privileged. ACME-TLS
        // listeners are *bound* here but not served until issuance succeeds
        // (invariant 76 / C58) — deferring the bind itself used to fail for
        // privileged ports once the daemon had dropped to `user`.
        let mut bound_now: Vec<(TcpListener, String, usize)> = Vec::new();
        let mut deferred_acme_tls: Vec<(TcpListener, String, usize)> = Vec::new();
        // Pre-bound UDP sockets for QUIC listeners, keyed by block.
        let mut quic_sockets: Vec<(std::net::UdpSocket, usize)> = Vec::new();

        for (idx, http_block) in config_snapshot.http.iter().enumerate() {
            let is_acme = acme_managers.contains_key(&idx);
            for listen in &http_block.listen {
                let addr = listen_addr(listen);
                match listen.protocol.as_str() {
                    "tcp" | "http" => {
                        let tcp_listener = TcpListener::bind(addr)
                            .await
                            .with_context(|| format!("Failed to bind to {}", addr))?;
                        self.record_bound(&tcp_listener);
                        info!("Listening on {} ({})", addr, listen.protocol);
                        bound_now.push((tcp_listener, listen.protocol.clone(), idx));
                    }
                    "tls" | "https" => {
                        let tcp_listener = TcpListener::bind(addr)
                            .await
                            .with_context(|| format!("Failed to bind to {}", addr))?;
                        self.record_bound(&tcp_listener);
                        if is_acme {
                            info!("Bound {} ({}); serving deferred until ACME issuance", addr, listen.protocol);
                            deferred_acme_tls.push((tcp_listener, listen.protocol.clone(), idx));
                        } else {
                            info!("Listening on {} ({})", addr, listen.protocol);
                            bound_now.push((tcp_listener, listen.protocol.clone(), idx));
                        }
                    }
                    "quic" | "h3" | "http3" => {
                        let socket = std::net::UdpSocket::bind(addr)
                            .with_context(|| format!("Failed to bind QUIC socket on {}", addr))?;
                        info!("QUIC/HTTP3 socket bound on {}", addr);
                        quic_sockets.push((socket, idx));
                    }
                    other => {
                        warn!("Unknown listen protocol: {}", other);
                    }
                }
            }
        }

        // Bind stream (TCP proxy) listeners
        let mut stream_listeners: Vec<(TcpListener, StreamBlock)> = Vec::new();
        for stream_block in &config_snapshot.stream {
            let addr = listen_addr(&stream_block.listen);
            let tcp_listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("Failed to bind stream listener on {}", addr))?;
            self.record_bound(&tcp_listener);
            info!("Stream proxy listening on {}", addr);
            stream_listeners.push((tcp_listener, stream_block.clone()));
        }

        // Bind mail (SMTP/IMAP) listeners
        let mut mail_listeners: Vec<(TcpListener, MailBlock)> = Vec::new();
        if let Some(ref mail_block) = config_snapshot.mail {
            warn!(
                "mail listener enabled: flexd mail support is a protocol stub \
                 (EHLO/NOOP/QUIT only) and does NOT relay messages"
            );
            for listen in &mail_block.listen {
                let addr = listen_addr(listen);
                let tcp_listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("Failed to bind mail listener on {}", addr))?;
                self.record_bound(&tcp_listener);
                info!("Mail ({}) listening on {}", mail_block.protocol, addr);
                mail_listeners.push((tcp_listener, mail_block.clone()));
            }
        }

        // All sockets are bound — drop privileges before serving anything.
        if let Some(ref user) = config_snapshot.global.user {
            security::privilege::drop_privileges(user)
                .with_context(|| "Failed to drop privileges")?;
        }

        for (tcp_listener, stream_block) in stream_listeners {
            let shutdown_rx = self.shutdown_tx.subscribe();
            join_set.spawn(async move {
                Self::accept_stream_loop(tcp_listener, stream_block, shutdown_rx).await
            });
        }

        for (tcp_listener, mail_block) in mail_listeners {
            let shutdown_rx = self.shutdown_tx.subscribe();
            join_set.spawn(async move {
                Self::accept_mail_loop(tcp_listener, mail_block, shutdown_rx).await
            });
        }

        // Spawn accept loops for non-ACME listeners. Plain HTTP loops must be
        // accepting before issuance so the CA can fetch HTTP-01 tokens.
        for (tcp_listener, protocol, idx) in bound_now {
            let Some(http_block) = config_snapshot.http.get(idx).cloned() else { continue };
            let shutdown_rx = self.shutdown_tx.subscribe();
            let reload_rx = self.reload_tx.subscribe();
            let config = Arc::clone(&self.config);
            let is_tls = protocol == "tls" || protocol == "https";
            let acme = acme_managers.get(&idx).cloned();
            let timeouts = timeouts.clone();

            join_set.spawn(async move {
                Self::accept_loop(
                    tcp_listener,
                    http_block,
                    idx,
                    is_tls,
                    config,
                    acme,
                    timeouts,
                    shutdown_rx,
                    reload_rx,
                )
                .await
            });
        }

        // QUIC/HTTP3 for non-ACME blocks (static cert) — serve now.
        let mut deferred_quic: Vec<(std::net::UdpSocket, usize)> = Vec::new();
        for (socket, idx) in quic_sockets {
            let Some(http_block) = config_snapshot.http.get(idx) else { continue };
            if !http_block.http3 {
                continue;
            }
            if acme_managers.contains_key(&idx) {
                deferred_quic.push((socket, idx));
                continue;
            }
            if http_block.ssl.is_none() {
                warn!("QUIC listener for http[{}] has no ssl block; skipping", idx);
                continue;
            }
            let shutdown_rx = self.shutdown_tx.subscribe();
            let reload_rx = self.reload_tx.subscribe();
            let config = Arc::clone(&self.config);
            let http_block = http_block.clone();
            let timeouts = timeouts.clone();
            join_set.spawn(async move {
                Self::accept_quic_loop(
                    socket, http_block, idx, config, None, timeouts, shutdown_rx, reload_rx,
                )
                .await
            });
        }

        // ACME issuance. Serve the pre-bound TLS (and ACME HTTP/3) listeners
        // only on success; abort startup on failure — invariant 76 / C58
        // forbids any self-signed fallback.
        for (idx, manager) in &acme_managers {
            if let Err(e) = manager.ensure_cert().await {
                error!("ACME issuance failed for http[{}]: {:#}", idx, e);
                anyhow::bail!(
                    "ACME issuance failed and no self-signed fallback is permitted \
                     (invariant 76): {:#}",
                    e
                );
            }

            let mut i = 0;
            while i < deferred_acme_tls.len() {
                if deferred_acme_tls[i].2 != *idx {
                    i += 1;
                    continue;
                }
                let (tcp_listener, protocol, block_idx) = deferred_acme_tls.remove(i);
                let Some(http_block) = config_snapshot.http.get(block_idx).cloned() else {
                    continue;
                };
                info!(
                    "Serving {} ({}) [ACME]",
                    tcp_listener.local_addr().map(|a| a.to_string()).unwrap_or_default(),
                    protocol
                );
                let shutdown_rx = self.shutdown_tx.subscribe();
                let reload_rx = self.reload_tx.subscribe();
                let config = Arc::clone(&self.config);
                let acme = Some(Arc::clone(manager));
                let timeouts = timeouts.clone();
                join_set.spawn(async move {
                    Self::accept_loop(
                        tcp_listener,
                        http_block,
                        block_idx,
                        true,
                        config,
                        acme,
                        timeouts,
                        shutdown_rx,
                        reload_rx,
                    )
                    .await
                });
            }

            // ACME HTTP/3 (issued cert) if the block enables http3.
            let mut q = 0;
            while q < deferred_quic.len() {
                if deferred_quic[q].1 != *idx {
                    q += 1;
                    continue;
                }
                let (socket, block_idx) = deferred_quic.remove(q);
                let Some(http_block) = config_snapshot.http.get(block_idx).cloned() else {
                    continue;
                };
                let shutdown_rx = self.shutdown_tx.subscribe();
                let reload_rx = self.reload_tx.subscribe();
                let config = Arc::clone(&self.config);
                let acme = Some(Arc::clone(manager));
                let timeouts = timeouts.clone();
                join_set.spawn(async move {
                    Self::accept_quic_loop(
                        socket, http_block, block_idx, config, acme, timeouts, shutdown_rx,
                        reload_rx,
                    )
                    .await
                });
            }

            // Background renewal (C53).
            let renewal_manager = Arc::clone(manager);
            let renewal_shutdown = self.shutdown_tx.subscribe();
            let renewal_reload = self.reload_tx.clone();
            join_set.spawn(async move {
                Self::acme_renewal_loop(renewal_manager, renewal_reload, renewal_shutdown).await
            });
        }

        let signal_handle = tokio::spawn(Self::signal_handler(
            self.shutdown_tx.clone(),
            self.reload_tx.clone(),
            Arc::clone(&self.config),
        ));

        while let Some(res) = join_set.join_next().await {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error!("Listener task exited with error: {:?}", e);
                }
                Err(e) => {
                    error!("Listener task panicked: {:?}", e);
                }
            }
        }

        signal_handle.abort();

        info!("All listeners stopped");
        Ok(())
    }

    fn build_logger(path: &str) -> Arc<AccessLogger> {
        Arc::new(AccessLogger::new(path).unwrap_or_else(|_| {
            let _ = std::fs::create_dir_all("./logs");
            AccessLogger::new("./logs/access.log").expect("Failed to create fallback access log")
        }))
    }

    #[allow(clippy::too_many_arguments)]
    async fn accept_loop(
        tcp_listener: TcpListener,
        http_block: HttpBlock,
        block_idx: usize,
        is_tls: bool,
        config: Arc<RwLock<Config>>,
        acme: Option<Arc<crate::acme::AcmeManager>>,
        mut timeouts: TimeoutSettings,
        mut shutdown_rx: broadcast::Receiver<()>,
        mut reload_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let mut current_http_block = Arc::new(http_block);
        let acme_store = acme.as_ref().map(|m| m.store());
        let mut tls_acceptor: Option<tokio_rustls::TlsAcceptor> = None;

        if is_tls {
            if let Some(ref ssl) = current_http_block.ssl {
                tls_acceptor = match acme {
                    Some(ref mgr) => tls::build_tls_acceptor_acme(
                        &mgr.cert_path(),
                        &mgr.key_path(),
                        &ssl.protocols,
                        mgr.store(),
                    )
                    .ok(),
                    None => tls::build_tls_acceptor(ssl).ok(),
                };
            }
        }

        let mut access_logger = Self::build_logger(&current_http_block.access_log);
        let mut handler = Arc::new(HandlerService::new(
            Arc::clone(&current_http_block),
            Arc::clone(&access_logger),
            acme_store.clone(),
            is_tls,
            &timeouts,
        ));

        loop {
            tokio::select! {
                biased;

                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping accept loop");
                    break;
                }

                _ = reload_rx.recv() => {
                    info!("Configuration reload triggered for http[{}]", block_idx);

                    let new_config = {
                        let guard = config.read().await;
                        guard.clone()
                    };

                    // Refresh this listener's own block (by index), not http[0].
                    if let Some(new_block) = new_config.http.get(block_idx) {
                        let new_block = Arc::new(new_block.clone());
                        timeouts = new_config.global.timeouts.clone().unwrap_or_default();
                        access_logger = Self::build_logger(&new_block.access_log);

                        current_http_block = new_block;
                        handler = Arc::new(HandlerService::new(
                            Arc::clone(&current_http_block),
                            Arc::clone(&access_logger),
                            acme_store.clone(),
                            is_tls,
                            &timeouts,
                        ));

                        if is_tls {
                            if let Some(ref ssl) = current_http_block.ssl {
                                // ACME blocks keep serving the issued cert + the
                                // TLS-ALPN resolver across reloads; renewal swaps
                                // the cert on disk via a background task.
                                tls_acceptor = match acme {
                                    Some(ref mgr) => tls::build_tls_acceptor_acme(
                                        &mgr.cert_path(),
                                        &mgr.key_path(),
                                        &ssl.protocols,
                                        mgr.store(),
                                    )
                                    .ok(),
                                    None => tls::build_tls_acceptor(ssl).ok(),
                                };
                            }
                        }

                        info!("Configuration reloaded atomically for http[{}]", block_idx);
                    } else {
                        warn!(
                            "Reloaded config has no http[{}]; keeping previous configuration",
                            block_idx
                        );
                    }
                }

                accept_result = tcp_listener.accept() => {
                    match accept_result {
                        Ok((stream, remote_addr)) => {
                            if security::limits::check_memory_pressure(
                                security::limits::MEMORY_PRESSURE_THRESHOLD,
                            ) {
                                warn!("Memory pressure detected, rejecting connection from {}", remote_addr);
                                tokio::spawn(Self::send_503(stream));
                                continue;
                            }

                            if !security::limits::acquire_connection() {
                                warn!("Connection limit reached, rejecting from {}", remote_addr);
                                tokio::spawn(Self::send_503(stream));
                                continue;
                            }

                            let handler = Arc::clone(&handler);
                            let tls_acceptor = tls_acceptor.clone();
                            let reset_rate = current_http_block
                                .http2_max_reset_rate
                                .clone()
                                .unwrap_or_else(default_reset_rate);
                            let conn_timeouts = timeouts.clone();

                            tokio::spawn(async move {
                                let _guard = ConnectionGuard;

                                let serve_result = if let Some(acceptor) = tls_acceptor {
                                    // Bound the TLS handshake so half-open
                                    // handshakes can't pin connections.
                                    match tokio::time::timeout(
                                        Duration::from_secs(10),
                                        acceptor.accept(stream),
                                    ).await {
                                        Ok(Ok(tls_stream)) => {
                                            // C2: detect h2 via ALPN
                                            let is_h2 = tls_stream
                                                .get_ref()
                                                .1
                                                .alpn_protocol()
                                                == Some(b"h2");
                                            if is_h2 {
                                                Self::serve_http2(
                                                    handler, tls_stream, remote_addr,
                                                    reset_rate, &conn_timeouts,
                                                ).await
                                            } else {
                                                Self::serve_http1(
                                                    handler, tls_stream, remote_addr,
                                                    &conn_timeouts,
                                                ).await
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            warn!("TLS handshake failed from {}: {}", remote_addr, e);
                                            Ok(())
                                        }
                                        Err(_) => {
                                            warn!("TLS handshake timed out from {}", remote_addr);
                                            Ok(())
                                        }
                                    }
                                } else {
                                    // C30: peek at first 4KB, reject bare LF before hyper sees it
                                    Self::serve_http1_with_bare_lf_check(
                                        handler, stream, remote_addr, &conn_timeouts,
                                    ).await
                                };

                                if let Err(e) = serve_result {
                                    warn!("Connection error from {}: {}", remote_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            error!("Accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn send_503(stream: tokio::net::TcpStream) {
        let response = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header(http::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from("503 Service Unavailable\n")));

        if let Ok(response) = response {
            let io = hyper_util::rt::TokioIo::new(stream);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, service_fn(move |_req: Request<Incoming>| {
                    let resp = response.clone();
                    async move { Ok::<_, anyhow::Error>(resp) }
                }))
                .await;
        }
    }

    /// C30: Read a peek buffer from a plain TCP stream, reject if bare LF found.
    async fn serve_http1_with_bare_lf_check(
        handler: Arc<HandlerService>,
        mut stream: tokio::net::TcpStream,
        remote_addr: SocketAddr,
        timeouts: &TimeoutSettings,
    ) -> anyhow::Result<()> {
        use tokio::io::AsyncReadExt;
        let mut peek_buf = vec![0u8; 4096];
        let n = match tokio::time::timeout(
            Duration::from_secs(5),
            stream.read(&mut peek_buf),
        ).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Ok(()), // idle timeout during peek
        };

        if n == 0 {
            return Ok(()); // EOF
        }

        if has_bare_lf(&peek_buf[..n]) {
            // C30: Send 400 and close
            let _ = tokio::io::AsyncWriteExt::write_all(
                &mut stream,
                b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            ).await;
            return Ok(());
        }

        let guard = BareLfGuard::new(stream, peek_buf[..n].to_vec(), false);
        Self::serve_http1(handler, guard, remote_addr, timeouts).await
    }

    async fn serve_http1<S>(
        handler: Arc<HandlerService>,
        stream: S,
        remote_addr: SocketAddr,
        timeouts: &TimeoutSettings,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(stream);

        let service = service_fn(move |req: Request<Incoming>| {
            let handler = Arc::clone(&handler);
            async move {
                let resp = handler.handle(req, remote_addr).await;
                Ok::<_, anyhow::Error>(resp)
            }
        });

        let mut builder = hyper::server::conn::http1::Builder::new();
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            // Slowloris defense: the full header section must arrive within
            // the request timeout.
            .header_read_timeout(Duration::from_secs(timeouts.request));

        builder
            .serve_connection(io, service)
            .with_upgrades()
            .await?;

        Ok(())
    }

    async fn serve_http2<S>(
        handler: Arc<HandlerService>,
        stream: S,
        remote_addr: SocketAddr,
        reset_rate: crate::config::ResetRateLimit,
        timeouts: &TimeoutSettings,
    ) -> anyhow::Result<()>
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    {
        let io = hyper_util::rt::TokioIo::new(stream);

        // Invariant 20: per-connection RST_STREAM tracking. hyper doesn't
        // surface RST frames, but a request future dropped before producing a
        // response is a stream the peer abandoned/reset; count those.
        let tracker = Arc::new(ResetTracker::new(
            reset_rate.count,
            Duration::from_secs(reset_rate.window_seconds),
        ));
        let kill = Arc::new(tokio::sync::Notify::new());

        let service = {
            let tracker = Arc::clone(&tracker);
            let kill = Arc::clone(&kill);
            service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler);
                let mut guard = StreamDropGuard {
                    tracker: Arc::clone(&tracker),
                    kill: Arc::clone(&kill),
                    completed: false,
                };
                async move {
                    let resp = handler.handle(req, remote_addr).await;
                    guard.completed = true;
                    drop(guard);
                    Ok::<_, anyhow::Error>(resp)
                }
            })
        };

        let mut builder =
            hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new());
        builder
            .timer(hyper_util::rt::TokioTimer::new())
            // C19: bounded concurrent streams per HTTP/2 connection
            .max_concurrent_streams(128)
            // h2's own Rapid Reset backstop (CVE-2023-44487): too many
            // pending-accept resets ⇒ GOAWAY.
            .max_pending_accept_reset_streams(reset_rate.count)
            .keep_alive_interval(Some(Duration::from_secs(20)))
            .keep_alive_timeout(Duration::from_secs(timeouts.keepalive));

        let conn = builder.serve_connection(io, service);
        tokio::pin!(conn);

        tokio::select! {
            result = conn.as_mut() => result?,
            _ = kill.notified() => {
                // Invariant 20: reset rate exceeded — terminate the connection.
                warn!(
                    "HTTP/2 stream reset rate exceeded by {}; terminating connection",
                    remote_addr
                );
                conn.as_mut().graceful_shutdown();
                let _ = conn.as_mut().await;
            }
        }

        Ok(())
    }

    // C12: TCP stream proxy loop with round-robin + connect failover.
    async fn accept_stream_loop(
        tcp_listener: TcpListener,
        stream_block: StreamBlock,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let balancer = Arc::new(crate::balance::Balancer::for_upstream(&stream_block.upstream));
        let upstream = Arc::new(stream_block.upstream.clone());

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal, stopping stream proxy");
                    break;
                }
                accept = tcp_listener.accept() => {
                    match accept {
                        Ok((mut client_stream, addr)) => {
                            let balancer = Arc::clone(&balancer);
                            let upstream = Arc::clone(&upstream);
                            tokio::spawn(async move {
                                for idx in balancer.candidates(&upstream, addr.ip()) {
                                    let Some(server) = upstream.servers.get(idx) else { continue };
                                    match tokio::time::timeout(
                                        Duration::from_secs(10),
                                        tokio::net::TcpStream::connect(&server.address),
                                    ).await {
                                        Ok(Ok(mut server_stream)) => {
                                            let _inflight = balancer.track(&upstream, idx);
                                            let _ = tokio::io::copy_bidirectional(
                                                &mut client_stream,
                                                &mut server_stream,
                                            ).await;
                                            return;
                                        }
                                        _ => {
                                            warn!(
                                                "Stream proxy upstream {} unreachable; trying next",
                                                server.address
                                            );
                                        }
                                    }
                                }
                                warn!("Stream proxy: no upstream reachable for {}", addr);
                            });
                        }
                        Err(e) => {
                            error!("Stream proxy accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // C43: SMTP/mail listener with line-length enforcement
    async fn accept_mail_loop(
        tcp_listener: TcpListener,
        mail_block: MailBlock,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let max_line = mail_block.max_line_length.unwrap_or(4096);

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal, stopping mail listener");
                    break;
                }
                accept = tcp_listener.accept() => {
                    match accept {
                        Ok((stream, addr)) => {
                            info!("Mail connection from {}", addr);
                            tokio::spawn(async move {
                                Self::handle_mail_session(stream, max_line).await;
                            });
                        }
                        Err(e) => {
                            error!("Mail accept error: {}", e);
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_mail_session(stream: tokio::net::TcpStream, max_line_len: usize) {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut buf_reader = BufReader::new(reader);

        // Send SMTP greeting banner
        if writer.write_all(b"220 flexd ESMTP\r\n").await.is_err() {
            return;
        }

        let mut line = String::new();
        loop {
            line.clear();
            match buf_reader.read_line(&mut line).await {
                Ok(0) => break, // EOF
                Ok(n) if n > max_line_len => {
                    // C43: line too long — terminate session
                    let _ = writer.write_all(b"500 5.5.6 Command line too long\r\n").await;
                    break;
                }
                Ok(_) => {
                    let cmd = line.trim().to_uppercase();
                    if cmd.starts_with("QUIT") {
                        let _ = writer.write_all(b"221 2.0.0 Bye\r\n").await;
                        break;
                    } else if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                        let _ = writer.write_all(b"250 flexd\r\n").await;
                    } else if cmd.starts_with("NOOP") {
                        let _ = writer.write_all(b"250 2.0.0 OK\r\n").await;
                    } else {
                        // Honest stub: flexd does not implement mail relay.
                        // Answering "250 OK" to MAIL/RCPT/DATA would make
                        // senders believe messages were accepted and silently
                        // lose them.
                        let _ = writer
                            .write_all(b"502 5.5.1 Command not implemented (flexd mail stub)\r\n")
                            .await;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn accept_quic_loop(
        socket: std::net::UdpSocket,
        http_block: HttpBlock,
        block_idx: usize,
        config: Arc<RwLock<Config>>,
        acme: Option<Arc<crate::acme::AcmeManager>>,
        timeouts: TimeoutSettings,
        mut shutdown_rx: broadcast::Receiver<()>,
        mut reload_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let local_addr = socket.local_addr().ok();
        let ssl = http_block
            .ssl
            .clone()
            .ok_or_else(|| anyhow::anyhow!("QUIC listener requires an ssl block"))?;

        let quic_config = match acme {
            Some(ref mgr) => {
                tls::build_quinn_server_config_from_paths(&mgr.cert_path(), &mgr.key_path())
            }
            None => tls::build_quinn_server_config(&ssl),
        }
        .with_context(|| format!("Failed to build QUIC config for {:?}", local_addr))?;

        socket
            .set_nonblocking(true)
            .with_context(|| "Failed to set QUIC socket non-blocking")?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(quic_config),
            socket,
            quinn::default_runtime()
                .ok_or_else(|| anyhow::anyhow!("no async runtime for QUIC endpoint"))?,
        )
        .with_context(|| format!("Failed to create QUIC endpoint on {:?}", local_addr))?;

        info!("QUIC listener serving on {:?}", local_addr);

        // Per-block logger/handler (previously hardcoded ./logs/access.log
        // and http[0]); rebuilt on reload like the TCP loops.
        let mut current_block = Arc::new(http_block);
        let mut access_logger = Self::build_logger(&current_block.access_log);
        let mut handler = Arc::new(HandlerService::new(
            Arc::clone(&current_block),
            Arc::clone(&access_logger),
            None,
            true, // QUIC is always TLS
            &timeouts,
        ));

        loop {
            tokio::select! {
                biased;

                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping QUIC accept loop");
                    break;
                }

                _ = reload_rx.recv() => {
                    let new_config = {
                        let guard = config.read().await;
                        guard.clone()
                    };
                    if let Some(new_block) = new_config.http.get(block_idx) {
                        current_block = Arc::new(new_block.clone());
                        access_logger = Self::build_logger(&current_block.access_log);
                        let new_timeouts = new_config.global.timeouts.clone().unwrap_or_default();
                        handler = Arc::new(HandlerService::new(
                            Arc::clone(&current_block),
                            Arc::clone(&access_logger),
                            None,
                            true,
                            &new_timeouts,
                        ));
                        info!("QUIC configuration reloaded for http[{}]", block_idx);
                    }
                }

                connecting = endpoint.accept() => {
                    let Some(connecting) = connecting else {
                        continue;
                    };

                    if security::limits::check_memory_pressure(
                        security::limits::MEMORY_PRESSURE_THRESHOLD,
                    ) {
                        warn!("Memory pressure, rejecting QUIC connection");
                        continue;
                    }

                    if !security::limits::acquire_connection() {
                        warn!("QUIC connection limit reached");
                        continue;
                    }

                    let handler = Arc::clone(&handler);

                    let max_body = current_block.max_body_size.unwrap_or(10 * 1024 * 1024);
                    // Invariant 21 / 31: bound the HTTP/3 field section size.
                    let max_field = current_block
                        .http3_max_dynamic_table_size
                        .unwrap_or(65536) as u64;

                    tokio::spawn(async move {
                        let _guard = ConnectionGuard;

                        match connecting.await {
                            Ok(connection) => {
                                let remote = connection.remote_address();
                                if let Err(e) = Self::serve_http3(
                                    handler, connection, remote, max_body, max_field,
                                )
                                .await
                                {
                                    warn!("HTTP/3 connection error from {}: {}", remote, e);
                                }
                            }
                            Err(e) => {
                                warn!("QUIC connection failed: {}", e);
                            }
                        }
                    });
                }
            }
        }

        endpoint.close(0u32.into(), b"shutdown");
        Ok(())
    }

    /// Drive a single HTTP/3 connection: accept request streams, route each
    /// through the shared `HandlerService`, and write the response back.
    /// (C3, invariants 21/31/35/36/37 — request bodies are bounded by `max_body`
    /// and header blocks by `max_field`; quinn caps concurrent streams.)
    async fn serve_http3(
        handler: Arc<HandlerService>,
        connection: quinn::Connection,
        remote: SocketAddr,
        max_body: usize,
        max_field: u64,
    ) -> anyhow::Result<()> {
        use bytes::Buf;

        let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
            h3::server::builder()
                .max_field_section_size(max_field)
                .build(h3_quinn::Connection::new(connection))
                .await?;

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let (req, mut stream) = match resolver.resolve_request().await {
                        Ok(rs) => rs,
                        Err(e) => {
                            warn!("HTTP/3 request resolution failed from {}: {}", remote, e);
                            continue;
                        }
                    };

                    let handler = Arc::clone(&handler);
                    tokio::spawn(async move {
                        // Collect the request body, enforcing the body-size cap
                        // (invariant 16) so a peer cannot exhaust memory.
                        let mut body = bytes::BytesMut::new();
                        let mut overflow = false;
                        loop {
                            match stream.recv_data().await {
                                Ok(Some(mut chunk)) => {
                                    while chunk.has_remaining() {
                                        let bytes = chunk.chunk();
                                        body.extend_from_slice(bytes);
                                        let adv = bytes.len();
                                        chunk.advance(adv);
                                        if body.len() > max_body {
                                            overflow = true;
                                            break;
                                        }
                                    }
                                    if overflow {
                                        break;
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => return,
                            }
                        }

                        let resp = if overflow {
                            let mut resp = Response::new(Full::new(Bytes::from(
                                "413 Payload Too Large\n",
                            )));
                            *resp.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                            resp
                        } else {
                            handler.handle_h3(req, body.freeze(), remote).await
                        };

                        let (parts, full_body) = resp.into_parts();
                        let body_bytes = match full_body.collect().await {
                            Ok(c) => c.to_bytes(),
                            Err(_) => Bytes::new(),
                        };
                        let head = Response::from_parts(parts, ());

                        if stream.send_response(head).await.is_err() {
                            return;
                        }
                        if !body_bytes.is_empty() {
                            let _ = stream.send_data(body_bytes).await;
                        }
                        let _ = stream.finish().await;
                    });
                }
                Ok(None) => break, // connection closed cleanly
                Err(e) => {
                    warn!("HTTP/3 accept error from {}: {}", remote, e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// C53 — background certificate renewal. Periodically checks whether the
    /// issued cert is within `renewal_window` days of expiry and, if so,
    /// re-issues and signals a reload so accept loops hot-swap the new cert
    /// without dropping active connections.
    async fn acme_renewal_loop(
        manager: Arc<crate::acme::AcmeManager>,
        reload_tx: broadcast::Sender<()>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let interval = manager.renewal_check_interval();
        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => break,
                _ = tokio::time::sleep(interval) => {
                    match manager.needs_renewal() {
                        Ok(true) => {
                            info!("ACME cert within renewal window; renewing");
                            match manager.issue_with_retry().await {
                                Ok(()) => {
                                    // Hot-swap: accept loops rebuild their acceptor
                                    // from the (now-updated) cert files on reload.
                                    let _ = reload_tx.send(());
                                    info!("ACME cert renewed and reload signalled");
                                }
                                Err(e) => warn!(acme_error = %format!("{:#}", e), "ACME renewal failed; will retry"),
                            }
                        }
                        Ok(false) => {}
                        Err(e) => warn!(acme_error = %format!("{:#}", e), "ACME renewal check failed"),
                    }
                }
            }
        }
        Ok(())
    }

    async fn signal_handler(
        shutdown_tx: broadcast::Sender<()>,
        reload_tx: broadcast::Sender<()>,
        config: Arc<RwLock<Config>>,
    ) {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(_) => return,
        };
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(_) => return,
        };

        loop {
            tokio::select! {
                _ = sigterm.recv() => {
                    info!("Received SIGTERM, initiating graceful shutdown");
                    let _ = shutdown_tx.send(());
                    break;
                }

                _ = sigint.recv() => {
                    info!("Received SIGINT, initiating graceful shutdown");
                    let _ = shutdown_tx.send(());
                    break;
                }

                _ = sighup.recv() => {
                    info!("Received SIGHUP, reloading configuration");

                    let current_config = {
                        let guard = config.read().await;
                        guard.clone()
                    };

                    if let Some(pid_file) = &current_config.global.pid_file {
                        let config_path = pid_file.replace(".pid", ".conf");
                        match Config::load(std::path::Path::new(&config_path)) {
                            Ok(new_config) => {
                                info!("New configuration loaded and validated");
                                {
                                    let mut guard = config.write().await;
                                    *guard = new_config;
                                }
                                let _ = reload_tx.send(());
                                info!("Configuration swapped atomically");
                            }
                            Err(e) => {
                                error!("Configuration reload failed: {}", e);
                            }
                        }
                    } else {
                        warn!("SIGHUP received but no pid_file configured, cannot determine config path");
                    }
                }
            }
        }
    }

    pub fn shutdown_tx(&self) -> broadcast::Sender<()> {
        self.shutdown_tx.clone()
    }

    pub fn reload_tx(&self) -> broadcast::Sender<()> {
        self.reload_tx.clone()
    }
}

struct ConnectionGuard;

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        security::limits::release_connection();
    }
}

/// Records a dropped (never-completed) HTTP/2 request future as a peer stream
/// reset and trips the connection kill switch past the configured rate
/// (Invariant 20).
struct StreamDropGuard {
    tracker: Arc<ResetTracker>,
    kill: Arc<tokio::sync::Notify>,
    completed: bool,
}

impl Drop for StreamDropGuard {
    fn drop(&mut self) {
        if !self.completed && self.tracker.record_reset() {
            self.kill.notify_waiters();
        }
    }
}
