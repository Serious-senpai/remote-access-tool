use std::path::PathBuf;

use clap::{Parser, Subcommand};

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

#[derive(Debug, Parser)]
#[command(
    disable_help_flag = true,
    // disable_help_subcommand = true,
    name = "server>",
    long_about = "Remote Access Tool (RAT) server component",
    no_binary_name = true
)]
pub struct Internal {
    #[command(subcommand)]
    pub command: InternalCommand,
}

#[derive(Debug, Subcommand)]
pub enum InternalCommand {
    /// Manage connected clients
    Clients {
        #[command(subcommand)]
        command: InternalClientsCommand,
    },

    /// Shut down the server
    Exit,
}

#[derive(Debug, Subcommand)]
pub enum InternalClientsCommand {
    /// List connected clients
    List,

    /// Disconnect a client
    Disconnect {
        /// The ID of the client to disconnect
        id: u32,
    },
}
