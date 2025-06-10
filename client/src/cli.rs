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
    /// The address of the server to connect to
    pub address: String,

    /// Log level
    #[arg(long, value_enum, default_value_t = LogLevel::Info)]
    pub log_level: LogLevel,

    /// Path to the host key file to authenticate as the admin
    #[arg(long)]
    pub admin: Option<PathBuf>,
}
