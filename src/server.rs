use crate::config::{Config, HttpBlock, MailBlock, StreamBlock};
use crate::handler::HandlerService;
use crate::logging::AccessLogger;
use crate::security;
use crate::tls;
use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
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
        if header_section[i] == b'\n' {
            if i == 0 || header_section[i - 1] != b'\r' {
                return true;
            }
        }
    }
    false
}

pub struct Server {
    config: Arc<RwLock<Config>>,
    shutdown_tx: broadcast::Sender<()>,
    reload_tx: broadcast::Sender<()>,
}

impl Server {
    pub fn new(config: Config) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (reload_tx, _) = broadcast::channel(1);

        Self {
            config: Arc::new(RwLock::new(config)),
            shutdown_tx,
            reload_tx,
        }
    }

    pub async fn run(&self) -> Result<()> {
        let config_snapshot = {
            let guard = self.config.read().await;
            guard.clone()
        };

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

        // Bind HTTP listeners. Plain + static-TLS bind immediately; ACME-TLS
        // listeners are deferred until issuance succeeds (invariant 76 / C58).
        let mut bound_now: Vec<(TcpListener, HttpBlock, String, usize)> = Vec::new();
        let mut deferred_acme_tls: Vec<(SocketAddr, HttpBlock, String, usize)> = Vec::new();
        let mut bound_any = false;

        for (idx, http_block) in config_snapshot.http.iter().enumerate() {
            let is_acme = acme_managers.contains_key(&idx);
            for listen in &http_block.listen {
                let addr: SocketAddr = ([0, 0, 0, 0], listen.port).into();
                match listen.protocol.as_str() {
                    "tcp" | "http" => {
                        let tcp_listener = TcpListener::bind(addr)
                            .await
                            .with_context(|| format!("Failed to bind to {}", addr))?;
                        info!("Listening on {} ({})", addr, listen.protocol);
                        bound_any = true;
                        bound_now.push((
                            tcp_listener,
                            http_block.clone(),
                            listen.protocol.clone(),
                            idx,
                        ));
                    }
                    "tls" | "https" => {
                        if is_acme {
                            deferred_acme_tls.push((
                                addr,
                                http_block.clone(),
                                listen.protocol.clone(),
                                idx,
                            ));
                        } else {
                            let tcp_listener = TcpListener::bind(addr)
                                .await
                                .with_context(|| format!("Failed to bind to {}", addr))?;
                            info!("Listening on {} ({})", addr, listen.protocol);
                            bound_any = true;
                            bound_now.push((
                                tcp_listener,
                                http_block.clone(),
                                listen.protocol.clone(),
                                idx,
                            ));
                        }
                    }
                    "quic" | "h3" | "http3" => {
                        info!(
                            "QUIC/HTTP3 listener on port {} (spawned separately)",
                            listen.port
                        );
                    }
                    other => {
                        warn!("Unknown listen protocol: {}", other);
                    }
                }
            }
        }

        // Bind stream (TCP proxy) listeners
        for stream_block in &config_snapshot.stream {
            let addr: SocketAddr = ([0, 0, 0, 0], stream_block.listen.port).into();
            let tcp_listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("Failed to bind stream listener on {}", addr))?;
            info!("Stream proxy listening on {}", addr);

            let shutdown_rx = self.shutdown_tx.subscribe();
            let block = stream_block.clone();
            join_set.spawn(async move {
                Self::accept_stream_loop(tcp_listener, block, shutdown_rx).await
            });
        }

        // Bind mail (SMTP/IMAP) listeners
        if let Some(ref mail_block) = config_snapshot.mail {
            for listen in &mail_block.listen {
                let addr: SocketAddr = ([0, 0, 0, 0], listen.port).into();
                let tcp_listener = TcpListener::bind(addr)
                    .await
                    .with_context(|| format!("Failed to bind mail listener on {}", addr))?;
                info!("Mail ({}) listening on {}", mail_block.protocol, addr);

                let shutdown_rx = self.shutdown_tx.subscribe();
                let block = mail_block.clone();
                join_set.spawn(async move {
                    Self::accept_mail_loop(tcp_listener, block, shutdown_rx).await
                });
            }
        }

        if bound_any {
            if let Some(ref user) = config_snapshot.global.user {
                security::privilege::drop_privileges(user)
                    .with_context(|| "Failed to drop privileges")?;
            }
        }

        // Spawn accept loops for already-bound listeners. Plain HTTP loops must
        // be accepting before issuance so the CA can fetch HTTP-01 tokens.
        for (tcp_listener, http_block, protocol, idx) in bound_now {
            let shutdown_rx = self.shutdown_tx.subscribe();
            let reload_rx = self.reload_tx.subscribe();
            let config = Arc::clone(&self.config);
            let is_tls = protocol == "tls" || protocol == "https";
            let acme = acme_managers.get(&idx).cloned();

            join_set.spawn(async move {
                Self::accept_loop(
                    tcp_listener,
                    http_block,
                    is_tls,
                    config,
                    acme,
                    shutdown_rx,
                    reload_rx,
                )
                .await
            });
        }

        // QUIC/HTTP3 for non-ACME blocks (static cert) — bind now.
        for (idx, http_block) in config_snapshot.http.iter().enumerate() {
            if !http_block.http3 || acme_managers.contains_key(&idx) {
                continue;
            }
            if let Some(ref ssl) = http_block.ssl {
                for listen in &http_block.listen {
                    if matches!(listen.protocol.as_str(), "quic" | "h3" | "http3") {
                        let shutdown_rx = self.shutdown_tx.subscribe();
                        let reload_rx = self.reload_tx.subscribe();
                        let config = Arc::clone(&self.config);
                        let port = listen.port;
                        let ssl = ssl.clone();
                        join_set.spawn(async move {
                            Self::accept_quic_loop(port, ssl, config, None, shutdown_rx, reload_rx)
                                .await
                        });
                    }
                }
            }
        }

        // ACME issuance. Bind the deferred TLS (and ACME HTTP/3) listeners only
        // on success; abort startup on failure — invariant 76 / C58 forbids any
        // self-signed fallback.
        for (idx, manager) in &acme_managers {
            if let Err(e) = manager.ensure_cert().await {
                error!("ACME issuance failed for http[{}]: {:#}", idx, e);
                anyhow::bail!(
                    "ACME issuance failed and no self-signed fallback is permitted \
                     (invariant 76): {:#}",
                    e
                );
            }

            for (addr, http_block, protocol, _l) in
                deferred_acme_tls.iter().filter(|(_, _, _, l)| l == idx)
            {
                let tcp_listener = TcpListener::bind(*addr)
                    .await
                    .with_context(|| format!("Failed to bind ACME TLS listener on {}", addr))?;
                info!("Listening on {} ({}) [ACME]", addr, protocol);
                let shutdown_rx = self.shutdown_tx.subscribe();
                let reload_rx = self.reload_tx.subscribe();
                let config = Arc::clone(&self.config);
                let acme = Some(Arc::clone(manager));
                let http_block = http_block.clone();
                join_set.spawn(async move {
                    Self::accept_loop(
                        tcp_listener, http_block, true, config, acme, shutdown_rx, reload_rx,
                    )
                    .await
                });
            }

            // ACME HTTP/3 (issued cert) if the block enables http3.
            if let Some(http_block) = config_snapshot.http.get(*idx) {
                if http_block.http3 {
                    if let Some(ssl) = http_block.ssl.clone() {
                        for listen in &http_block.listen {
                            if matches!(listen.protocol.as_str(), "quic" | "h3" | "http3") {
                                let shutdown_rx = self.shutdown_tx.subscribe();
                                let reload_rx = self.reload_tx.subscribe();
                                let config = Arc::clone(&self.config);
                                let port = listen.port;
                                let ssl = ssl.clone();
                                let acme = Some(Arc::clone(manager));
                                join_set.spawn(async move {
                                    Self::accept_quic_loop(
                                        port, ssl, config, acme, shutdown_rx, reload_rx,
                                    )
                                    .await
                                });
                            }
                        }
                    }
                }
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

    async fn accept_loop(
        tcp_listener: TcpListener,
        http_block: HttpBlock,
        is_tls: bool,
        config: Arc<RwLock<Config>>,
        acme: Option<Arc<crate::acme::AcmeManager>>,
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

        let access_logger = Arc::new(
            AccessLogger::new(&current_http_block.access_log)
                .unwrap_or_else(|_| {
                    let _ = std::fs::create_dir_all("./logs");
                    AccessLogger::new("./logs/access.log")
                        .expect("Failed to create fallback access log")
                }),
        );

        let mut handler = Arc::new(HandlerService::with_acme(
            Arc::clone(&config),
            Arc::clone(&current_http_block),
            Arc::clone(&access_logger),
            acme_store.clone(),
        ));

        loop {
            tokio::select! {
                biased;

                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received, stopping accept loop");
                    break;
                }

                _ = reload_rx.recv() => {
                    info!("Configuration reload triggered");

                    let new_config = {
                        let guard = config.read().await;
                        guard.clone()
                    };

                    if let Some(new_block) = new_config.http.first() {
                        let new_block = Arc::new(new_block.clone());
                        let new_logger = Arc::new(
                            AccessLogger::new(&new_block.access_log)
                                .unwrap_or_else(|_| {
                                    let _ = std::fs::create_dir_all("./logs");
                                    AccessLogger::new("./logs/access.log")
                                        .expect("Failed to create fallback access log")
                                }),
                        );

                        current_http_block = new_block;
                        handler = Arc::new(HandlerService::with_acme(
                            Arc::clone(&config),
                            Arc::clone(&current_http_block),
                            Arc::clone(&new_logger),
                            acme_store.clone(),
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

                        info!("Configuration reloaded atomically");
                    }
                }

                accept_result = tcp_listener.accept() => {
                    match accept_result {
                        Ok((stream, remote_addr)) => {
                            if security::limits::check_memory_pressure(0.05) {
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

                            let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                tokio::spawn(async move {
                                    let _guard = ConnectionGuard;

                                    let serve_result = if let Some(acceptor) = tls_acceptor {
                                        match acceptor.accept(stream).await {
                                            Ok(tls_stream) => {
                                                // C2: detect h2 via ALPN
                                                let is_h2 = tls_stream
                                                    .get_ref()
                                                    .1
                                                    .alpn_protocol()
                                                    == Some(b"h2");
                                                if is_h2 {
                                                    Self::serve_http2(handler, tls_stream, remote_addr).await
                                                } else {
                                                    Self::serve_http1(handler, tls_stream, remote_addr).await
                                                }
                                            }
                                            Err(e) => {
                                                warn!("TLS handshake failed from {}: {}", remote_addr, e);
                                                Ok(())
                                            }
                                        }
                                    } else {
                                        // C30: peek at first 4KB, reject bare LF before hyper sees it
                                        Self::serve_http1_with_bare_lf_check(handler, stream, remote_addr).await
                                    };

                                    if let Err(e) = serve_result {
                                        warn!("Connection error from {}: {}", remote_addr, e);
                                    }
                                })
                            }));

                            if connection_result.is_err() {
                                error!("Handler panicked for connection from {}", remote_addr);
                                security::limits::release_connection();
                            }
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
        Self::serve_http1(handler, guard, remote_addr).await
    }

    async fn serve_http1<S>(
        handler: Arc<HandlerService>,
        stream: S,
        remote_addr: SocketAddr,
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

        hyper::server::conn::http1::Builder::new()
            .serve_connection(io, service)
            .with_upgrades()
            .await?;

        Ok(())
    }

    async fn serve_http2<S>(
        handler: Arc<HandlerService>,
        stream: S,
        remote_addr: SocketAddr,
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

        // C19: enforce 128 concurrent stream limit per HTTP/2 connection
        hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
            .max_concurrent_streams(128)
            .serve_connection(io, service)
            .await?;

        Ok(())
    }

    // C12: TCP stream proxy loop
    async fn accept_stream_loop(
        tcp_listener: TcpListener,
        stream_block: StreamBlock,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let upstream_addr = stream_block
            .upstream
            .servers
            .first()
            .map(|s| s.address.clone())
            .unwrap_or_default();

        loop {
            tokio::select! {
                biased;
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal, stopping stream proxy");
                    break;
                }
                accept = tcp_listener.accept() => {
                    match accept {
                        Ok((client_stream, addr)) => {
                            info!("Stream proxy connection from {}", addr);
                            let upstream = upstream_addr.clone();
                            tokio::spawn(async move {
                                match tokio::net::TcpStream::connect(&upstream).await {
                                    Ok(server_stream) => {
                                        let (mut cr, mut cw) = tokio::io::split(client_stream);
                                        let (mut sr, mut sw) = tokio::io::split(server_stream);
                                        let _ = tokio::join!(
                                            tokio::io::copy(&mut cr, &mut sw),
                                            tokio::io::copy(&mut sr, &mut cw),
                                        );
                                    }
                                    Err(e) => warn!("Stream proxy upstream connect failed: {}", e),
                                }
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
                    } else {
                        let _ = writer.write_all(b"250 OK\r\n").await;
                    }
                    if writer.flush().await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }

    async fn accept_quic_loop(
        port: u16,
        ssl: crate::config::SslSettings,
        config: Arc<RwLock<Config>>,
        acme: Option<Arc<crate::acme::AcmeManager>>,
        mut shutdown_rx: broadcast::Receiver<()>,
        mut _reload_rx: broadcast::Receiver<()>,
    ) -> Result<()> {
        let quic_config = match acme {
            Some(ref mgr) => {
                tls::build_quinn_server_config_from_paths(&mgr.cert_path(), &mgr.key_path())
            }
            None => tls::build_quinn_server_config(&ssl),
        }
        .with_context(|| format!("Failed to build QUIC config for port {}", port))?;

        let endpoint = quinn::Endpoint::server(
            quic_config,
            SocketAddr::new(std::net::Ipv4Addr::UNSPECIFIED.into(), port),
        )
        .with_context(|| format!("Failed to bind QUIC endpoint on port {}", port))?;

        info!("QUIC listener on port {}", port);

        let access_logger = Arc::new(
            AccessLogger::new("./logs/access.log")
                .unwrap_or_else(|_| {
                    let _ = std::fs::create_dir_all("./logs");
                    AccessLogger::new("./logs/access.log")
                        .expect("Failed to create fallback access log")
                }),
        );

        let http_block = {
            let guard = config.read().await;
            guard.http.first().cloned()
        };

        if let Some(http_block) = http_block {
            let http_block = Arc::new(http_block);
            let handler = Arc::new(HandlerService::new(
                Arc::clone(&config),
                Arc::clone(&http_block),
                Arc::clone(&access_logger),
            ));

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("Shutdown signal received, stopping QUIC accept loop");
                        break;
                    }

                    connecting = endpoint.accept() => {
                        let Some(connecting) = connecting else {
                            continue;
                        };

                        if security::limits::check_memory_pressure(0.05) {
                            warn!("Memory pressure, rejecting QUIC connection");
                            continue;
                        }

                        if !security::limits::acquire_connection() {
                            warn!("QUIC connection limit reached");
                            continue;
                        }

                        let handler = Arc::clone(&handler);

                        let max_body = http_block.max_body_size.unwrap_or(1024 * 1024);
                        // Invariant 21 / 31: bound the HTTP/3 field section size.
                        let max_field = http_block
                            .http3_max_dynamic_table_size
                            .unwrap_or(65536) as u64;

                        let connection_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
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
                            })
                        }));

                        if connection_result.is_err() {
                            error!("QUIC handler panicked");
                            security::limits::release_connection();
                        }
                    }
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
                            Response::builder()
                                .status(StatusCode::PAYLOAD_TOO_LARGE)
                                .body(Full::new(Bytes::from("413 Payload Too Large\n")))
                                .unwrap()
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
    /// without dropping active connections. (Body implemented in Phase 6.)
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
