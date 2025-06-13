use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use common::cipher::encryption::Cipher;
use common::payloads::custom::request::{Request, RequestType};
use common::payloads::custom::response::{Response, ResponseType};
use common::payloads::PayloadFormat;
use common::utils::{format_bytes, format_time, strip, wait_for, ConsoleTable};

use crate::broadcast::BroadcastLayer;
use crate::requests::handlers::{Handler, HandlerResult};

pub struct PsHandler;

#[async_trait]
impl<C> Handler<C> for PsHandler
where
    C: Cipher + 'static,
{
    async fn run(
        &self,
        broadcast: Arc<BroadcastLayer<C>>,
        request_id: u32,
        local_addr: SocketAddr,
        matches: clap::ArgMatches,
    ) -> HandlerResult {
        let addr = *matches.get_one::<SocketAddr>("addr").unwrap();

        let mut receiver = broadcast.subscribe();
        match broadcast
            .send(&Request::new(request_id, local_addr, addr, RequestType::Ps))
            .await
        {
            Ok(_) => {
                let response = wait_for(&mut receiver, async |packet| {
                    if let Ok(response) = Response::from_packet(&packet).await {
                        if response.request_id() == request_id {
                            return Some(response);
                        }
                    }

                    None
                })
                .await;
                match response.rtype() {
                    ResponseType::Ps { processes } => {
                        let mut table = ConsoleTable::new([
                            "PID".to_string(),
                            "Name".to_string(),
                            "CPU".to_string(),
                            "Mem".to_string(),
                            "Command".to_string(),
                            "Run time".to_string(),
                        ]);
                        for process in processes {
                            table.add_row([
                                process.pid.to_string(),
                                process.name.clone(),
                                format!("{:.2}%", process.cpu_usage),
                                format_bytes(process.memory),
                                strip(process.cmd.clone(), 50),
                                format_time(process.run_time),
                            ]);
                        }

                        println!("Total number of processes: {}", processes.len());
                        table.print();
                    }
                    ResponseType::Error { message } => {
                        eprintln!("{}", message);
                    }
                    rtype => {
                        eprintln!("Unexpected response type: {:?}", rtype);
                    }
                }
            }
            Err(e) => {
                eprintln!("Failed to send payload: {}", e);
                return HandlerResult::noop();
            }
        };

        HandlerResult::noop()
    }
}
