use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    long_about = "Remote Access Tool (RAT) server component",
    propagate_version = true,
    version
)]
pub struct Arguments {
    /// Path to the host key file
    #[arg(short = 'k', long)]
    pub host_key_file: PathBuf,

    /// The port to bind to
    #[arg(short = 'p', long, default_value_t = 22)]
    pub port: u16,

    /// Path to the log file
    #[arg(short = 'l', long, default_value = "/var/log/rat.log")]
    pub log_file: PathBuf,
}
