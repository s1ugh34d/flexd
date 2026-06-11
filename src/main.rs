//! flexd command-line entry point.
//!
//! This binary is deliberately thin: it parses arguments, installs the rustls
//! crypto provider and the tracing subscriber, loads and validates the
//! configuration, and hands off to [`flexd::server::Server`]. All real logic
//! lives in the [`flexd`] library so it can be tested without a socket.
//!
//! ```text
//! flexd --config flexd.conf --test   # validate config and exit
//! flexd --config flexd.conf          # run
//! ```

use anyhow::Result;
use clap::Parser;
use flexd::config::Config;
use flexd::server::Server;
use std::path::PathBuf;
use tracing::info;

/// Parsed command-line arguments.
#[derive(Parser, Debug)]
#[command(name = "flexd")]
#[command(about = "flexd - hardened web server", long_about = None)]
struct Args {
    /// Path to the configuration file. Defaults to `./flexd.conf`.
    #[arg(long, help = "Path to configuration file")]
    config: Option<PathBuf>,

    /// Validate the configuration and exit without serving.
    #[arg(long, help = "Test configuration and exit")]
    test: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install rustls crypto provider before any TLS operations
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config_path = args.config.unwrap_or_else(|| PathBuf::from("./flexd.conf"));

    info!("Loading configuration from {}", config_path.display());

    let config = Config::load(&config_path)?;

    if args.test {
        info!("Configuration validated successfully");
        println!("configuration OK");
        return Ok(());
    }

    info!("Starting flexd server");

    let server = Server::new(config);
    server.run().await?;

    info!("Server stopped");
    Ok(())
}
