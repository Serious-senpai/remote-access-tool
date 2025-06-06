mod cli;
mod layers;

use std::error::Error;
use std::fs::File;

use clap::Parser;
use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
use common::cipher::hostkey::read_host_key;
use common::cipher::hostkey::rsa_sha2_512::RsaSha512;
use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
use env_logger::Target;
use tokio::net::TcpListener;

use layers::events::EventLayer;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = cli::Arguments::parse();

    let mut log = colog::default_builder();
    log.filter_level(arguments.log_level.to_level_filter());
    log.filter_module("rustyline", log::LevelFilter::Info);
    log.target(Target::Pipe(Box::new(File::create(arguments.log_file)?)));
    log.init();

    let (ukey, rkey) = read_host_key(&arguments.host_key_file).await?;
    let listener = TcpListener::bind(("0.0.0.0", arguments.port)).await?;

    let event = EventLayer::<ChaCha20Poly1305>::new(listener, ukey, rkey, 100);
    event
        .listen_loop::<Curve25519Sha256, RsaSha512>(arguments.timeout)
        .await?;

    Ok(())
}
