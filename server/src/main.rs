use std::error::Error;
use std::fs::File;
use std::sync::Arc;

use clap::Parser;
use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::hostkey::read_host_key;
use common::cipher::hostkey::rsa_sha2_512::RsaSha512;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use env_logger::Target;
use rat_server::cli;
use rat_server::layers::aggregation::AggregationLayer;
use tokio::net::TcpListener;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = cli::Arguments::parse();

    colog::default_builder()
        .filter_level(arguments.log_level.to_level_filter())
        .filter_module("rustyline", log::LevelFilter::Info)
        .target(Target::Pipe(Box::new(File::create(arguments.log_file)?)))
        .format_source_path(true)
        .init();

    let (ukey, rkey) = read_host_key(&arguments.host_key_file).await?;
    let listener = TcpListener::bind(("0.0.0.0", arguments.port)).await?;

    let agg = Arc::new(AggregationLayer::<ChaCha20Poly1305>::new(
        listener, ukey, rkey, 100,
    ));
    agg.listen_loop::<Curve25519Sha256, RsaSha512>().await;

    Ok(())
}
