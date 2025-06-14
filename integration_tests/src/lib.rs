#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::process::Stdio;
    use std::sync::Arc;

    use common::cipher::encryption::chacha20_poly1305::ChaCha20Poly1305;
    use common::cipher::hostkey::read_host_key;
    use common::cipher::hostkey::rsa_sha2_512::RsaSha512;
    use common::cipher::kex::curve25519_sha256::Curve25519Sha256;
    use common::payloads::PayloadFormat;
    use common::payloads::custom::query::{Query, QueryType};
    use common::payloads::custom::response::{Response, ResponseType};
    use common::utils::wait_for;
    use rat_client::broadcast::BroadcastLayer as ClientBroadcastLayer;
    use rat_client::requests::command::CommandBuilder;
    use rat_client::{kex, responses};
    use rat_server::layers::aggregation::AggregationLayer;
    use tokio::fs::File;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};
    use tokio::process;

    async fn fallocate(path: &PathBuf, bytes: u64) {
        let mut file = File::create(path).await.unwrap();
        let buffer = vec![0u8; bytes as usize];
        file.write_all(&buffer).await.unwrap();
        file.flush().await.unwrap();
    }

    async fn create_host_key(path: &PathBuf) {
        let mut process = process::Command::new("bash")
            .arg("-c")
            .arg(format!(
                "yes | ssh-keygen -t rsa -f {} -N \"\"",
                path.to_string_lossy()
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();

        let status = process.wait().await.unwrap();
        assert!(status.success());
    }

    async fn start_server(
        addr: impl ToSocketAddrs,
        path: &PathBuf,
    ) -> Arc<AggregationLayer<ChaCha20Poly1305>> {
        let (ukey, rkey) = read_host_key(path).await.unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();

        let agg = Arc::new(AggregationLayer::<ChaCha20Poly1305>::new(
            listener, ukey, rkey, 100,
        ));
        tokio::spawn(agg.clone().listen_loop::<Curve25519Sha256, RsaSha512>());
        agg
    }

    async fn start_normal_client(
        addr: impl ToSocketAddrs,
    ) -> Arc<ClientBroadcastLayer<ChaCha20Poly1305>> {
        let stream = TcpStream::connect(addr).await.unwrap();
        let ssh = kex::key_exchange::<ChaCha20Poly1305, Curve25519Sha256, RsaSha512>(stream)
            .await
            .unwrap();

        let base = Arc::new(ClientBroadcastLayer::new(ssh, 100));
        tokio::spawn(base.clone().listen_loop());
        tokio::spawn(responses::listen_loop(base.clone()));

        base
    }

    async fn start_admin_client(
        addr: impl ToSocketAddrs,
        path: &PathBuf,
    ) -> Arc<ClientBroadcastLayer<ChaCha20Poly1305>> {
        let stream = TcpStream::connect(addr).await.unwrap();
        let ssh = kex::key_exchange::<ChaCha20Poly1305, Curve25519Sha256, RsaSha512>(stream)
            .await
            .unwrap();

        let base = Arc::new(ClientBroadcastLayer::new(ssh, 100));
        tokio::spawn(base.clone().listen_loop());

        let (_, rkey) = read_host_key(path).await.unwrap();
        let payload = Query::new(
            0,
            QueryType::Authenticate {
                rkey: rkey.to_bytes().unwrap().to_vec(),
            },
        );

        let mut receiver = base.subscribe();
        base.send(&payload).await.unwrap();
        let result = wait_for(&mut receiver, async |packet| {
            if let Ok(response) = Response::from_packet(&packet).await {
                return match response.rtype() {
                    ResponseType::Success => Some(true),
                    _ => Some(false),
                };
            }

            None
        })
        .await;

        assert!(result);
        // tokio::spawn(requests::interactive_loop(base.clone()));
        base
    }

    #[tokio::test]
    async fn test_client_ls() {
        let host_key_path = ["/tmp", "host-client-ls"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2222), &host_key_path).await;
        let client = start_normal_client(("localhost", 2222)).await;
        let admin = start_admin_client(("localhost", 2222), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from(["client", "ls"]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 0, matches).await;

        let packet = receiver.try_recv().unwrap();
        // Cannot test for Ping/Pong because it is handled internally in the broadcast layer.

        let response = Response::from_packet(&packet).await.unwrap();
        if let ResponseType::ClientLs { clients } = response.rtype() {
            assert_eq!(clients.len(), 2);
            assert!(clients.iter().any(|c| c.addr == client.local_addr()));
            assert!(clients.iter().any(|c| c.addr == admin.local_addr()));
        } else {
            panic!("Expected ClientList response");
        }
    }

    #[tokio::test]
    async fn test_pwd_command() {
        let host_key_path = ["/tmp", "host-pwd"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2223), &host_key_path).await;
        let client = start_normal_client(("localhost", 2223)).await;
        let admin = start_admin_client(("localhost", 2223), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "pwd",
            "-a",
            &client.local_addr().to_string(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 1, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Pwd { .. }));
    }

    #[tokio::test]
    async fn test_ps_command() {
        let host_key_path = ["/tmp", "host-ps"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2224), &host_key_path).await;
        let client = start_normal_client(("localhost", 2224)).await;
        let admin = start_admin_client(("localhost", 2224), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "ps",
            "-a",
            &client.local_addr().to_string(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 2, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Ps { .. }));
    }

    #[tokio::test]
    async fn test_ls_command() {
        let host_key_path = ["/tmp", "host-ls"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2225), &host_key_path).await;
        let client = start_normal_client(("localhost", 2225)).await;
        let admin = start_admin_client(("localhost", 2225), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "ls",
            "-a",
            &client.local_addr().to_string(),
            "/tmp",
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 3, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Ls { .. }));
    }

    #[tokio::test]
    async fn test_cd_command() {
        let host_key_path = ["/tmp", "host-cd"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2226), &host_key_path).await;
        let client = start_normal_client(("localhost", 2226)).await;
        let admin = start_admin_client(("localhost", 2226), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "cd",
            "-a",
            &client.local_addr().to_string(),
            "/tmp",
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 4, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Success));
    }

    #[tokio::test]
    async fn test_mkdir_command() {
        let host_key_path = ["/tmp", "host-mkdir"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2227), &host_key_path).await;
        let client = start_normal_client(("localhost", 2227)).await;
        let admin = start_admin_client(("localhost", 2227), &host_key_path).await;

        // Remove directory if it exists
        let test_dir = PathBuf::from("/tmp/test_mkdir_dir");
        let _ = tokio::fs::remove_dir_all(&test_dir).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "mkdir",
            "-a",
            &client.local_addr().to_string(),
            test_dir.to_str().unwrap(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 5, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Success));
    }

    #[tokio::test]
    async fn test_mkdir_with_parent_command() {
        let host_key_path = ["/tmp", "host-mkdir-parent"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2228), &host_key_path).await;
        let client = start_normal_client(("localhost", 2228)).await;
        let admin = start_admin_client(("localhost", 2228), &host_key_path).await;

        // Remove directory if it exists
        let test_dir = PathBuf::from("/tmp/test_mkdir_parent/nested/dir");
        let _ = tokio::fs::remove_dir_all("/tmp/test_mkdir_parent").await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "mkdir",
            "-a",
            &client.local_addr().to_string(),
            "-p",
            test_dir.to_str().unwrap(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 6, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Success));
    }

    #[tokio::test]
    async fn test_rm_file_command() {
        let host_key_path = ["/tmp", "host-rm-file"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2229), &host_key_path).await;
        let client = start_normal_client(("localhost", 2229)).await;
        let admin = start_admin_client(("localhost", 2229), &host_key_path).await;

        // Create a test file
        let test_file = PathBuf::from("/tmp/test_rm_file.txt");
        fallocate(&test_file, 100).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "rm",
            "-a",
            &client.local_addr().to_string(),
            test_file.to_str().unwrap(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 7, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Success));
    }

    #[tokio::test]
    async fn test_rm_directory_recursive_command() {
        let host_key_path = ["/tmp", "host-rm-dir"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2230), &host_key_path).await;
        let client = start_normal_client(("localhost", 2230)).await;
        let admin = start_admin_client(("localhost", 2230), &host_key_path).await;

        // Create a test directory with a file inside
        let test_dir = PathBuf::from("/tmp/test_rm_dir");
        let test_file = test_dir.join("file.txt");
        tokio::fs::create_dir_all(&test_dir).await.unwrap();
        fallocate(&test_file, 50).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "rm",
            "-a",
            &client.local_addr().to_string(),
            "-r",
            test_dir.to_str().unwrap(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 8, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Success));
    }

    #[tokio::test]
    async fn test_rm_nonexistent_file_command() {
        let host_key_path = ["/tmp", "host-rm-nonexistent"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2231), &host_key_path).await;
        let client = start_normal_client(("localhost", 2231)).await;
        let admin = start_admin_client(("localhost", 2231), &host_key_path).await;

        // Ensure the file doesn't exist
        let test_file = PathBuf::from("/tmp/nonexistent_file.txt");
        let _ = tokio::fs::remove_file(&test_file).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "rm",
            "-a",
            &client.local_addr().to_string(),
            test_file.to_str().unwrap(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 9, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Error { .. }));
    }

    #[tokio::test]
    async fn test_download_command() {
        let host_key_path = ["/tmp", "host-download"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2232), &host_key_path).await;
        let client = start_normal_client(("localhost", 2232)).await;
        let admin = start_admin_client(("localhost", 2232), &host_key_path).await;

        // Create a source file
        let src_file = PathBuf::from("/tmp/download_source.txt");
        let dest_file = PathBuf::from("/tmp/download_dest.txt");
        fallocate(&src_file, 1024).await;

        // Remove destination file if it exists
        let _ = tokio::fs::remove_file(&dest_file).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "download",
            "-a",
            &client.local_addr().to_string(),
            "-m",
            "0", // Unlimited speed
            src_file.to_str().unwrap(),
            dest_file.to_str().unwrap(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 10, matches).await;

        // Should receive multiple download chunk responses
        let mut chunks_received = 0;
        while let Ok(packet) = receiver.try_recv() {
            if let Ok(response) = Response::from_packet(&packet).await {
                match response.rtype() {
                    ResponseType::DownloadChunk { .. } => {
                        chunks_received += 1;
                    }
                    ResponseType::Success => {
                        break;
                    }
                    ResponseType::Error { .. } => {
                        panic!("Download failed");
                    }
                    _ => {}
                }
            }
        }

        assert!(chunks_received > 0);
    }

    #[tokio::test]
    async fn test_download_nonexistent_file_command() {
        let host_key_path = ["/tmp", "host-download-nonexistent"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2233), &host_key_path).await;
        let client = start_normal_client(("localhost", 2233)).await;
        let admin = start_admin_client(("localhost", 2233), &host_key_path).await;

        let src_file = PathBuf::from("/tmp/nonexistent_download_source.txt");
        let dest_file = PathBuf::from("/tmp/download_dest_fail.txt");

        // Ensure source doesn't exist and remove destination
        let _ = tokio::fs::remove_file(&src_file).await;
        let _ = tokio::fs::remove_file(&dest_file).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "download",
            "-a",
            &client.local_addr().to_string(),
            src_file.to_str().unwrap(),
            dest_file.to_str().unwrap(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 11, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Error { .. }));
    }

    #[tokio::test]
    async fn test_kill_command() {
        let host_key_path = ["/tmp", "host-kill"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2234), &host_key_path).await;
        let client = start_normal_client(("localhost", 2234)).await;
        let admin = start_admin_client(("localhost", 2234), &host_key_path).await;

        // Use PID 1 (init process) with signal 0 (test if process exists)
        // This should succeed without actually killing anything
        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "kill",
            "-a",
            &client.local_addr().to_string(),
            "-s",
            "0", // Signal 0 just tests if process exists
            "1", // PID 1 (init)
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 12, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(
            response.rtype(),
            ResponseType::Success | ResponseType::Error { .. }
        ));
    }

    #[tokio::test]
    async fn test_kill_nonexistent_process_command() {
        let host_key_path = ["/tmp", "host-kill-nonexistent"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2235), &host_key_path).await;
        let client = start_normal_client(("localhost", 2235)).await;
        let admin = start_admin_client(("localhost", 2235), &host_key_path).await;

        // Use a very high PID that likely doesn't exist
        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "kill",
            "-a",
            &client.local_addr().to_string(),
            "999999999", // Very high PID that shouldn't exist
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 13, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Error { .. }));
    }

    #[tokio::test]
    async fn test_target_command() {
        let host_key_path = ["/tmp", "host-target"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2236), &host_key_path).await;
        let client = start_normal_client(("localhost", 2236)).await;
        let admin = start_admin_client(("localhost", 2236), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd
            .build_command(&None)
            .get_matches_from(["target", &client.local_addr().to_string()]);

        // This command should not send any packets, just update internal state
        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 14, matches).await;

        // Should not receive any packets since target command is local-only
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_clear_command() {
        let host_key_path = ["/tmp", "host-clear"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2237), &host_key_path).await;
        let _client = start_normal_client(("localhost", 2237)).await;
        let admin = start_admin_client(("localhost", 2237), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from(["clear"]);

        // This command should not send any packets, just clear the screen
        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 15, matches).await;

        // Should not receive any packets since clear command is local-only
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn test_client_disconnect_command() {
        let host_key_path = ["/tmp", "host-client-disconnect"].iter().collect();
        create_host_key(&host_key_path).await;

        start_server(("127.0.0.1", 2238), &host_key_path).await;
        let client = start_normal_client(("localhost", 2238)).await;
        let admin = start_admin_client(("localhost", 2238), &host_key_path).await;

        let cmd = CommandBuilder::new();
        let matches = cmd.build_command(&None).get_matches_from([
            "client",
            "disconnect",
            "-a",
            &client.local_addr().to_string(),
        ]);

        let mut receiver = admin.subscribe();
        cmd.execute(admin.clone(), 16, matches).await;

        let packet = receiver.try_recv().unwrap();
        let response = Response::from_packet(&packet).await.unwrap();
        assert!(matches!(response.rtype(), ResponseType::Success));
    }
}
