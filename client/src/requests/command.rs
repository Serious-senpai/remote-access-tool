use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use common::cipher::encryption::Cipher;

use crate::broadcast::BroadcastLayer;
use crate::requests::handlers::cd::CdHandler;
use crate::requests::handlers::clear::ClearHandler;
use crate::requests::handlers::client::disconnect::ClientDisconnectHandler;
use crate::requests::handlers::client::ls::ClientLsHandler;
use crate::requests::handlers::download::DownloadHandler;
use crate::requests::handlers::exit::ExitHandler;
use crate::requests::handlers::kill::KillHandler;
use crate::requests::handlers::ls::LsHandler;
use crate::requests::handlers::mkdir::MkdirHandler;
use crate::requests::handlers::ps::PsHandler;
use crate::requests::handlers::pwd::PwdHandler;
use crate::requests::handlers::rm::RmHandler;
use crate::requests::handlers::target::TargetHandler;
use crate::requests::handlers::{Handler, HandlerResult};

struct CommandTree<C>
where
    C: Cipher,
{
    children: HashMap<&'static str, Arc<CommandTree<C>>>,
    handler: Option<Arc<dyn Handler<C>>>,
}

impl<C> CommandTree<C>
where
    C: Cipher,
{
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            handler: None,
        }
    }

    fn with_handler<H>(handler: H) -> Self
    where
        H: Handler<C> + 'static,
    {
        Self {
            children: HashMap::new(),
            handler: Some(Arc::new(handler)),
        }
    }

    fn add_child(&mut self, name: &'static str, child: Self) {
        self.children.insert(name, Arc::new(child));
    }
}

/// Stateless command builder for the internal CLI.
#[derive(Clone)]
pub struct CommandBuilder<C>
where
    C: Cipher + 'static,
{
    _root: Arc<CommandTree<C>>,
}

impl<C> CommandBuilder<C>
where
    C: Cipher + 'static,
{
    pub fn new() -> Self {
        let mut root = CommandTree::new();

        let mut client = CommandTree::new();
        client.add_child("ls", CommandTree::with_handler(ClientLsHandler));
        client.add_child(
            "disconnect",
            CommandTree::with_handler(ClientDisconnectHandler),
        );
        root.add_child("client", client);

        // NOTE: Sort these according to lexicography order (just to keep source code consistent)
        root.add_child("cd", CommandTree::with_handler(CdHandler));
        root.add_child("clear", CommandTree::with_handler(ClearHandler));
        root.add_child("download", CommandTree::with_handler(DownloadHandler));
        root.add_child("exit", CommandTree::with_handler(ExitHandler));
        root.add_child("ls", CommandTree::with_handler(LsHandler));
        root.add_child("mkdir", CommandTree::with_handler(MkdirHandler));
        root.add_child("ps", CommandTree::with_handler(PsHandler));
        root.add_child("kill", CommandTree::with_handler(KillHandler));
        root.add_child("rm", CommandTree::with_handler(RmHandler));
        root.add_child("pwd", CommandTree::with_handler(PwdHandler));
        root.add_child("target", CommandTree::with_handler(TargetHandler));

        Self {
            _root: Arc::new(root),
        }
    }

    pub fn prompt(&self, target: &Option<SocketAddr>) -> String {
        match target {
            Some(target) => format!("server:{}>", target),
            None => "server>".to_string(),
        }
    }

    pub fn build_command(&self, target: &Option<SocketAddr>) -> clap::Command {
        let addr = || {
            let arg = clap::Arg::new("addr")
                .short('a')
                .long("addr")
                .help("The address of the client to change directory for")
                .value_parser(clap::value_parser!(SocketAddr));

            match target {
                Some(target) => arg.default_value(target.to_string()).required(false),
                None => arg.required(true),
            }
        };

        // NOTE: Sort the subcommands according to their order in the help menu
        clap::Command::new(self.prompt(target))
            .disable_help_flag(true)
            .about(clap::crate_description!())
            .long_about(clap::crate_description!())
            .no_binary_name(true)
            .subcommand_required(true)
            .subcommand(
                clap::Command::new("client")
                    .about("Manage connected clients")
                    .subcommand_required(true)
                    .subcommand(clap::Command::new("ls").about("List connected clients"))
                    .subcommand(
                        clap::Command::new("disconnect")
                            .about("Disconnect a client")
                            .arg(addr()),
                    ),
            )
            .subcommand(
                clap::Command::new("clear")
                    .about("Clear the screen")
            )
            .subcommand(
                clap::Command::new("cd")
                    .about("Change the working directory on the client side")
                    .arg(addr())
                    .arg(
                        clap::Arg::new("path")
                            .help("The new working directory path")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf)),
                    ),
            )
            .subcommand(
                clap::Command::new("ls")
                    .about("List information about a directory on the client side")
                    .arg(addr())
                    .arg(
                        clap::Arg::new("path")
                            .help("The path to the directory to list")
                            .required(false)
                            .value_parser(clap::value_parser!(PathBuf))
                            .default_value("."),
                    ),
            )
            .subcommand(
                clap::Command::new("pwd")
                    .about("Print working directory on the client side")
                    .arg(addr()),
            )
            .subcommand(
                clap::Command::new("rm")
                    .about("Remove directories or files on the client side")
                    .arg(addr())
                    .arg(
                        clap::Arg::new("recursive")
                        .action(clap::ArgAction::SetTrue)
                            .help("Whether to remove directories recursively")
                            .short('r')
                            .long("recursive")
                            .required(false)
                    )
                    .arg(
                        clap::Arg::new("paths")
                            .action(clap::ArgAction::Append)
                            .help("The path to the directories or files to remove")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf)),
                    ),
            )
            .subcommand(
                clap::Command::new("mkdir")
                    .about("Create new directories if they do not exist on the client side")
                    .arg(addr())
                    .arg(
                        clap::Arg::new("parent")
                            .action(clap::ArgAction::SetTrue)
                            .help("Whether to create parent directories if they do not exist")
                            .short('p')
                            .long("parent")
                            .required(false)
                    )
                    .arg(
                        clap::Arg::new("paths")
                            .action(clap::ArgAction::Append)
                            .help("The path to the new directories to create")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf)),
                    ),
            )
            .subcommand(
                clap::Command::new("download")
                    .about("Download a file from the client")
                    .arg(addr())
                    .arg(
                        clap::Arg::new("max")
                            .help("Maximum download speed (KiB/s). Use 0 for unlimited.")
                            .short('m')
                            .long("max")
                            .default_value("2048")
                            .required(false)
                            .value_parser(clap::value_parser!(u64)),
                    )
                    .arg(
                        clap::Arg::new("src")
                            .help("The path to the file on the client side")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf)),
                    )
                    .arg(
                        clap::Arg::new("dest")
                            .help("The path to save the file on the server side")
                            .required(true)
                            .value_parser(clap::value_parser!(PathBuf)),
                    ),
            )
            .subcommand(
                clap::Command::new("ps")
                    .about("View running processes on the client side")
                    .arg(addr()),
            )
            .subcommand(
                clap::Command::new("kill")
                    .about("Kill a process on the client side")
                    .arg(addr())
                    .arg(
                        clap::Arg::new("pid")
                            .help("The PID of the process to kill")
                            .required(true)
                            .value_parser(clap::value_parser!(u64)),
                    )
                    .arg(
                        clap::Arg::new("signal")
                            .help("The signal to send to the process as an int32. See https://docs.rs/nix/0.30.1/nix/sys/signal/enum.Signal.html for details")
                            .short('s')
                            .long("signal")
                            .default_value("9")
                            .value_parser(clap::value_parser!(i32)),
                    ),
            )
            .subcommand(
                clap::Command::new("target")
                    .about("Set the default target address for commands")
                    .arg(
                        clap::Arg::new("addr")
                            .help("Set or clear default target address for other commands.")
                            .value_parser(clap::value_parser!(SocketAddr))
                            .required(false),
                    ),
            )
            .subcommand(clap::Command::new("exit").about("Shut down the server"))
    }

    pub async fn execute(
        &self,
        broadcast: Arc<BroadcastLayer<C>>,
        request_id: u32,
        mut matches: clap::ArgMatches,
    ) -> HandlerResult {
        let mut tree = self._root.clone();
        let mut qualified_name = vec![];
        while let Some((name, m)) = matches.subcommand() {
            qualified_name.push(name.to_string());
            match tree.children.get(name) {
                Some(t) => {
                    tree = t.clone();
                    matches = m.clone();
                }
                None => {
                    eprintln!(
                        "Command tree unexpectedly stopped at {:?} (current matches = {:?})",
                        name, matches
                    );
                    return HandlerResult::noop();
                }
            }
        }

        match &tree.handler {
            Some(handler) => {
                let local_addr = broadcast.local_addr();
                handler
                    .run(broadcast, request_id, local_addr, matches)
                    .await
            }
            None => {
                eprintln!(
                    "Missing command handler. Try `help {}`.",
                    qualified_name.join(" ")
                );

                HandlerResult::noop()
            }
        }
    }
}
