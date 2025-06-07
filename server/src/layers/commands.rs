use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use common::cipher::encryption::Cipher;
use tokio::sync::{mpsc, RwLock};

use super::events::EventLayer;
use super::handlers::cd::CdHandler;
use super::handlers::client::disconnect::ClientDisconnectHandler;
use super::handlers::client::ls::ClientLsHandler;
use super::handlers::download::DownloadHandler;
use super::handlers::exit::ExitHandler;
use super::handlers::ls::LsHandler;
use super::handlers::pwd::PwdHandler;
use super::handlers::target::TargetHandler;
use super::handlers::{Handler, SetTarget};

struct CommandTree<C>
where
    C: Cipher + 'static,
{
    children: HashMap<&'static str, Arc<CommandTree<C>>>,
    handler: Option<Arc<dyn Handler<C>>>,
}

impl<C> CommandTree<C>
where
    C: Cipher + 'static,
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

    fn add_child(&mut self, name: &'static str, child: CommandTree<C>) {
        self.children.insert(name, Arc::new(child));
    }
}

pub struct CommandBuilder<C>
where
    C: Cipher + 'static,
{
    pub target: Option<SocketAddr>,
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

        root.add_child("cd", CommandTree::with_handler(CdHandler));
        root.add_child("download", CommandTree::with_handler(DownloadHandler));
        root.add_child("exit", CommandTree::with_handler(ExitHandler));
        root.add_child("ls", CommandTree::with_handler(LsHandler));
        root.add_child("pwd", CommandTree::with_handler(PwdHandler));
        root.add_child("target", CommandTree::with_handler(TargetHandler));

        CommandBuilder {
            target: None,
            _root: Arc::new(root),
        }
    }

    pub fn prompt(&self) -> String {
        match self.target {
            Some(target) => format!("server:{}>", target),
            None => "server>".to_string(),
        }
    }

    pub fn build_command(&self) -> clap::Command {
        let addr = || {
            let arg = clap::Arg::new("addr")
                .short('a')
                .long("addr")
                .help("The address of the client to change directory for")
                .value_parser(clap::value_parser!(SocketAddr));

            match self.target {
                Some(target) => arg.default_value(target.to_string()).required(false),
                None => arg.required(true),
            }
        };

        clap::Command::new(self.prompt())
            .disable_help_flag(true)
            .about(clap::crate_description!())
            .long_about(clap::crate_description!())
            .no_binary_name(true)
            .subcommand(
                clap::Command::new("client")
                    .about("Manage connected clients")
                    .subcommand(clap::Command::new("ls").about("List connected clients"))
                    .subcommand(
                        clap::Command::new("disconnect")
                            .about("Disconnect a client")
                            .arg(addr()),
                    ),
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
                clap::Command::new("download")
                    .about("Download a file from the client")
                    .arg(addr())
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
        &mut self,
        ptr: Arc<EventLayer<C>>,
        clients: &RwLock<HashMap<SocketAddr, mpsc::UnboundedSender<Vec<u8>>>>,
        request_id: u32,
        mut matches: clap::ArgMatches,
    ) -> bool {
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
                    return false;
                }
            }
        }

        match &tree.handler {
            Some(handler) => {
                let packed = handler.run(ptr, clients, request_id, matches).await;

                if let SetTarget::Update(target) = packed.set_target {
                    self.target = target;
                }

                packed.exit
            }
            None => {
                eprintln!(
                    "Missing command handler. Try `help {}`",
                    qualified_name.join(" ")
                );
                false
            }
        }
    }
}
