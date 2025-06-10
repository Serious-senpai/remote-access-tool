pub mod command;
pub mod handlers;

use std::sync::Arc;

use command::CommandBuilder;
use common::cipher::encryption::Cipher;
use common::payloads::custom::cancel::Cancel;
use rustyline::DefaultEditor;
use tokio::signal;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

use crate::broadcast::BroadcastLayer;
use crate::requests::handlers::SetTarget;

pub async fn interactive_loop<C>(ptr: Arc<BroadcastLayer<C>>)
where
    C: Cipher + 'static,
{
    let mut request_id = 0;
    let mut target = None;
    let command_builder = CommandBuilder::new();

    match DefaultEditor::new() {
        Ok(mut editor) => {
            loop {
                let prompt = format!("\n{}", command_builder.prompt(&target));
                let task = spawn_blocking(move || {
                    let mut e = editor;
                    let line = e.readline(&prompt);
                    (e, line)
                });

                let line = match task.await {
                    Ok((e, line)) => {
                        editor = e;
                        match line {
                            Ok(l) => l,
                            Err(e) => {
                                eprintln!("{}", e);
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("{}", e);
                        break;
                    }
                };

                if line.trim().is_empty() {
                    continue;
                }

                let tokens = match shlex::split(&line) {
                    Some(tokens) => tokens,
                    None => {
                        eprintln!("Invalid command syntax");
                        continue;
                    }
                };

                let _ = editor.add_history_entry(&line);
                let matches = match command_builder
                    .build_command(&target)
                    .try_get_matches_from(tokens)
                {
                    Ok(matches) => matches,
                    Err(e) => {
                        let _ = e.print();
                        continue;
                    }
                };

                // Even though `SSH<C>` read/write are atomic, aborting a running task
                // does not follow common sense...
                // Place a lock here to avoid dirty write (very rare, but not impossible)
                let abortable = Arc::new(Mutex::new(()));
                let abortable_cloned = abortable.clone();

                let c_ptr = ptr.clone();
                let signal_handler = tokio::spawn(async move {
                    let _ = signal::ctrl_c().await;
                    let _ = abortable_cloned.lock().await;
                    if let Err(e) = c_ptr
                        .send(&Cancel::new(request_id, c_ptr.local_addr()))
                        .await
                    {
                        eprintln!("Unable to create cancel request: {}", e);
                    }
                });

                let packed = command_builder
                    .execute(ptr.clone(), request_id, matches)
                    .await;

                let _ = abortable.lock().await;
                signal_handler.abort();

                if packed.exit {
                    break;
                }

                if let SetTarget::Update(t) = packed.set_target {
                    target = t;
                }

                request_id = request_id.wrapping_add(1);
            }
        }
        Err(e) => {
            eprintln!("Unable to start interactive mode: {}", e);
        }
    }

    ptr.exit().await;
}
