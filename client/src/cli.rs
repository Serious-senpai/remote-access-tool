use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    long_about = "Remote Access Tool (RAT) client component",
    propagate_version = true,
    version
)]
pub struct Arguments {
    /// The address of the server to connect to
    pub address: String,
}
