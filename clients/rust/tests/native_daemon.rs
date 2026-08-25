use lattice_client::{kind, Client};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn rust_client_interoperates_with_the_c_daemon_over_one_multiplexed_socket() {
    let Some(daemon_bin) = std::env::var_os("LATTICED_BIN") else {
        eprintln!("skipping native daemon integration; set LATTICED_BIN after building daemon");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let socket =
        std::env::temp_dir().join(format!("latticed-{}-{unique}.sock", std::process::id()));
    let _ = std::fs::remove_file(&socket);
    let mut daemon = Command::new(daemon_bin)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("start C daemon");

    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(socket.exists(), "daemon did not create its Unix socket");
        let client = Client::connect(&socket).expect("connect Rust client");
        let ping = client
            .request_async(kind::PING, b"native")
            .expect("queue ping");
        let stats = client.request_async(kind::STATS, &[]).expect("queue stats");
        assert_eq!(
            ping.recv_timeout(Duration::from_secs(2))
                .expect("ping channel")
                .expect("ping result")
                .payload,
            b"native"
        );
        let stats = stats
            .recv_timeout(Duration::from_secs(2))
            .expect("stats channel")
            .expect("stats result");
        assert_eq!(stats.kind, kind::STATS_RESPONSE);
        assert!(String::from_utf8(stats.payload)
            .expect("stats utf8")
            .contains("ltp/1"));

        // A declared frame larger than the protocol maximum is dropped before
        // the daemon allocates its payload buffer.
        let mut raw = UnixStream::connect(&socket).expect("connect raw client");
        raw.write_all(b"LTP1").expect("magic");
        raw.write_all(&[1, kind::PING, 0, 0])
            .expect("header fields");
        raw.write_all(&1_u64.to_be_bytes()).expect("request id");
        raw.write_all(&((1024 * 1024 + 1) as u32).to_be_bytes())
            .expect("oversized length");
        raw.flush().expect("flush malformed frame");
        raw.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let mut one = [0_u8; 1];
        assert_eq!(raw.read(&mut one).expect("daemon close"), 0);
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);
    result
}

#[test]
fn rust_client_multiplexes_one_thousand_frames_over_one_c_daemon_connection() {
    let Some(daemon_bin) = std::env::var_os("LATTICED_BIN") else {
        eprintln!("skipping native daemon integration; set LATTICED_BIN after building daemon");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let socket = std::env::temp_dir().join(format!(
        "latticed-load-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let mut daemon = Command::new(daemon_bin)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("start C daemon");

    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(socket.exists(), "daemon did not create its Unix socket");
        let client = Client::connect(&socket).expect("connect one Rust client");
        let mut replies = Vec::with_capacity(1_000);
        for sequence in 0_u32..1_000 {
            replies.push((
                sequence,
                client
                    .request_async(kind::PING, &sequence.to_be_bytes())
                    .expect("queue multiplexed ping"),
            ));
        }
        for (sequence, reply) in replies {
            let frame = reply
                .recv_timeout(Duration::from_secs(5))
                .expect("ping channel")
                .expect("ping response");
            assert_eq!(frame.kind, kind::PONG);
            assert_eq!(frame.payload, sequence.to_be_bytes());
        }

        // The daemon's metrics are also a protocol-level assertion that all
        // 1,001 frames above (including STATS) used this single connection.
        let stats = client.stats().expect("read daemon stats");
        assert!(stats.contains("\"accepted\":1"), "stats: {stats}");
        assert!(stats.contains("\"active\":1"), "stats: {stats}");
        assert!(stats.contains("\"rejected\":0"), "stats: {stats}");
        assert!(stats.contains("\"frames\":1001"), "stats: {stats}");
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);
    result
}

#[test]
fn c_daemon_survives_a_peer_closing_before_its_response_is_written() {
    let Some(daemon_bin) = std::env::var_os("LATTICED_BIN") else {
        eprintln!("skipping native daemon integration; set LATTICED_BIN after building daemon");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let socket = std::env::temp_dir().join(format!(
        "latticed-sigpipe-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let mut daemon = Command::new(daemon_bin)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("start C daemon");

    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(socket.exists(), "daemon did not create its Unix socket");
        let mut abandoned = UnixStream::connect(&socket).expect("connect abandoned peer");
        let ping = lattice_client::Frame {
            kind: kind::PING,
            request_id: 1,
            payload: b"discarded".to_vec(),
        };
        abandoned
            .write_all(&ping.encode().expect("encode ping"))
            .expect("write ping");
        abandoned.shutdown(Shutdown::Both).expect("close peer");
        drop(abandoned);

        // The daemon may observe the close before or after reading the frame;
        // in both cases another client must still be served afterwards.
        std::thread::sleep(Duration::from_millis(25));
        let client = Client::connect(&socket).expect("daemon stayed alive");
        assert_eq!(
            client.ping(b"still-alive").expect("ping after close"),
            b"still-alive"
        );
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);
    result
}

#[test]
fn c_daemon_reports_capacity_rejections_without_disrupting_active_clients() {
    let Some(daemon_bin) = std::env::var_os("LATTICED_BIN") else {
        eprintln!("skipping native daemon integration; set LATTICED_BIN after building daemon");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let socket = std::env::temp_dir().join(format!(
        "latticed-capacity-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let mut daemon = Command::new(daemon_bin)
        .args(["--socket"])
        .arg(&socket)
        .args(["--max-clients", "1", "--max-buffered-bytes", "4194304"])
        .spawn()
        .expect("start C daemon");

    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let client = Client::connect(&socket).expect("connect active client");
        let rejected = UnixStream::connect(&socket).expect("connect over-capacity peer");
        // accept() is asynchronous, so let the daemon account for the peer.
        std::thread::sleep(Duration::from_millis(25));
        drop(rejected);
        assert_eq!(
            client.ping(b"active").expect("active client ping"),
            b"active"
        );
        let stats = client.stats().expect("read capacity stats");
        assert!(stats.contains("\"accepted\":1"), "stats: {stats}");
        assert!(stats.contains("\"active\":1"), "stats: {stats}");
        assert!(stats.contains("\"rejected\":1"), "stats: {stats}");
        assert!(
            stats.contains("\"max_buffered_bytes\":4194304"),
            "stats: {stats}"
        );
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);
    result
}

#[test]
fn c_daemon_enforces_a_global_buffer_budget_without_dropping_existing_clients() {
    let Some(daemon_bin) = std::env::var_os("LATTICED_BIN") else {
        eprintln!("skipping native daemon integration; set LATTICED_BIN after building daemon");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let socket = std::env::temp_dir().join(format!(
        "latticed-buffer-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let mut daemon = Command::new(daemon_bin)
        .args(["--socket"])
        .arg(&socket)
        .args(["--max-buffered-bytes", "4194304"])
        .spawn()
        .expect("start C daemon");

    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let established = Client::connect(&socket).expect("connect established client");
        let max_frame = vec![7_u8; 1024 * 1024];
        assert_eq!(
            established
                .ping(&max_frame)
                .expect("fill first client buffers"),
            max_frame
        );

        let constrained = Client::connect(&socket).expect("connect constrained client");
        match constrained.request_async(kind::PING, &vec![8_u8; 1024 * 1024]) {
            Ok(rejected) => assert!(
                rejected
                    .recv_timeout(Duration::from_secs(3))
                    .expect("second response channel")
                    .is_err(),
                "global buffer exhaustion must close only the new peer"
            ),
            Err(error) => assert!(
                matches!(
                    error.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::ConnectionAborted
                        | std::io::ErrorKind::NotConnected
                ),
                "unexpected write error: {error}"
            ),
        }

        assert_eq!(
            established
                .ping(b"established-still-alive")
                .expect("existing client ping"),
            b"established-still-alive"
        );
        let stats = established.stats().expect("read buffer stats");
        assert!(
            stats.contains("\"max_buffered_bytes\":4194304"),
            "stats: {stats}"
        );
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);
    result
}

#[test]
fn rust_load_command_measures_a_single_multiplexed_c_connection() {
    let (Some(daemon_bin), Some(client_bin)) = (
        std::env::var_os("LATTICED_BIN"),
        std::env::var_os("CARGO_BIN_EXE_lattice"),
    ) else {
        eprintln!("skipping load command integration; native binaries unavailable");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let socket = std::env::temp_dir().join(format!(
        "latticed-cli-load-{}-{unique}.sock",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&socket);
    let mut daemon = Command::new(daemon_bin)
        .arg("--socket")
        .arg(&socket)
        .spawn()
        .expect("start C daemon");

    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = Command::new(client_bin)
            .args([
                "--socket",
                socket.to_str().expect("socket UTF-8"),
                "load",
                "--requests",
                "1000",
                "--concurrency",
                "256",
                "--payload-bytes",
                "16",
            ])
            .output()
            .expect("run Rust load command");
        assert!(
            output.status.success(),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let measured = String::from_utf8(output.stdout).expect("load output utf8");
        assert!(measured.contains("\"requests\":1000"), "output: {measured}");
        assert!(measured.contains("\"connections\":1"), "output: {measured}");

        // The stats request is the second accepted connection, proving `load`
        // did not open a socket for every batch or request.
        let inspector = Client::connect(&socket).expect("connect inspector");
        let stats = inspector.stats().expect("read daemon stats");
        assert!(stats.contains("\"accepted\":2"), "stats: {stats}");
        assert!(stats.contains("\"frames\":1001"), "stats: {stats}");
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);
    result
}

#[test]
fn c_daemon_accepts_a_tor_style_config_file_and_validates_it_before_starting() {
    let Some(daemon_bin) = std::env::var_os("LATTICED_BIN") else {
        eprintln!("skipping config integration; set LATTICED_BIN after building daemon");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("latticed-config-{}-{unique}", std::process::id()));
    let socket = base.with_extension("sock");
    let config = base.with_extension("conf");
    std::fs::write(
        &config,
        format!(
            "# torrc-style local daemon configuration\nSocket {}\nMaxClients 7\nMaxBufferedBytes 4194304\n",
            socket.display()
        ),
    )
    .expect("write daemon config");
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600))
        .expect("secure config");

    let verified = Command::new(&daemon_bin)
        .args(["--config"])
        .arg(&config)
        .arg("--verify-config")
        .output()
        .expect("verify config");
    assert!(
        verified.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&verified.stderr)
    );

    let mut daemon = Command::new(daemon_bin)
        .arg("--config")
        .arg(&config)
        .spawn()
        .expect("start configured daemon");
    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            socket.exists(),
            "configured daemon did not create its socket"
        );
        let client = Client::connect(&socket).expect("connect configured daemon");
        let stats = client.stats().expect("read configured daemon stats");
        assert!(stats.contains("\"max_clients\":7"), "stats: {stats}");
        assert!(
            stats.contains("\"max_buffered_bytes\":4194304"),
            "stats: {stats}"
        );
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    let _ = std::fs::remove_file(socket);
    let _ = std::fs::remove_file(config);
    result
}

#[test]
fn c_daemon_signs_only_after_rust_client_authenticates_the_session() {
    let Some(daemon_bin) = std::env::var_os("LATTICED_BIN") else {
        eprintln!("skipping native signer integration; set LATTICED_BIN after building daemon");
        return;
    };
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let base = std::env::temp_dir().join(format!("latticed-sign-{}-{unique}", std::process::id()));
    let socket = base.with_extension("sock");
    let key = base.with_extension("key");
    let token_file = base.with_extension("token");
    let public_key = base.with_extension("pub");
    let payload_file = base.with_extension("payload");
    let signature_file = base.with_extension("sig");
    let token = b"native-session-token-with-entropy-012345";
    let payload = b"capability-bound action";
    std::fs::write(&token_file, token).expect("write session token");
    std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))
        .expect("secure session token");
    let generated = Command::new("openssl")
        .args(["genpkey", "-algorithm", "ED25519", "-out"])
        .arg(&key)
        .status()
        .expect("run openssl for ephemeral test key");
    assert!(
        generated.success(),
        "openssl could not generate Ed25519 key"
    );
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600))
        .expect("secure private key");
    let mut daemon = Command::new(daemon_bin)
        .args(["--socket"])
        .arg(&socket)
        .args(["--key-file"])
        .arg(&key)
        .args(["--session-token-file"])
        .arg(&token_file)
        .spawn()
        .expect("start signer daemon");

    let result = (|| {
        for _ in 0..100 {
            if socket.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let client = Client::connect(&socket).expect("connect Rust client");
        assert!(
            client.sign(payload).is_err(),
            "daemon must deny signing before authentication"
        );
        client
            .authenticate(token)
            .expect("authenticate Rust session");
        let signature = client.sign(payload).expect("sign through C daemon");
        assert_eq!(signature.len(), 64);
        std::fs::write(&payload_file, payload).expect("write payload");
        std::fs::write(&signature_file, &signature).expect("write signature");
        assert!(Command::new("openssl")
            .args(["pkey", "-in"])
            .arg(&key)
            .args(["-pubout", "-out"])
            .arg(&public_key)
            .status()
            .expect("export public key")
            .success());
        assert!(Command::new("openssl")
            .args(["pkeyutl", "-verify", "-pubin", "-inkey"])
            .arg(&public_key)
            .args(["-rawin", "-in"])
            .arg(&payload_file)
            .args(["-sigfile"])
            .arg(&signature_file)
            .status()
            .expect("verify C daemon signature")
            .success());
    })();
    let _ = daemon.kill();
    let _ = daemon.wait();
    for path in [
        &socket,
        &key,
        &token_file,
        &public_key,
        &payload_file,
        &signature_file,
    ] {
        let _ = std::fs::remove_file(path);
    }
    result
}
