use anyhow::Result;
use clap::Parser;
use flexd::config::Config;
use flexd::server::Server;
use std::path::PathBuf;
use tracing::info;

#[derive(Parser, Debug)]
#[command(name = "flexd")]
#[command(about = "flexd - hardened web server", long_about = None)]
struct Args {
    #[arg(long, help = "Path to configuration file")]
    config: Option<PathBuf>,

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
