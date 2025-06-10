use std::path::PathBuf;

use clap::{crate_description, crate_version, Parser};
use common::cli::LogLevel;

#[derive(Debug, Parser)]
#[command(
    long_about = crate_description!(),
    propagate_version = true,
    version = crate_version!(),
)]
pub struct Arguments {
    /// Path to the host key file
    #[arg(short = 'k', long)]
    pub host_key_file: PathBuf,

    /// The port to bind to
    #[arg(short = 'p', long, default_value_t = 22)]
    pub port: u16,

    /// Path to the log file
    #[arg(short = 'l', long, default_value = "/dev/stdout")]
    pub log_file: PathBuf,

    /// Log level
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,
}
