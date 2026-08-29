use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chrono::{Duration, Utc};
use lattice_client::{kind, Client, ClientOptions, HARD_MAX_PENDING_BYTES, MAX_FRAME_BYTES};
use rand::RngCore;
use serde::Serialize;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::process::ExitCode;
use std::time::Instant;
use uuid::Uuid;

fn usage(program: &str) {
    eprintln!(
        "Usage: {program} [--socket <path>] [--session-token-file <path>] <command>\n\n\
Commands:\n\
  profile enroll|renew|status|connect|disconnect\n\
                                      Manage signed LNP/1 VPN profiles\n\
  open <lattice://service/path>       Validate a deep link and open HTTPS\n\
  run --agent <id> --profile <uuid> -- <command...>\n\
                                      Run in a verified Linux network namespace\n\
  status                              Read daemon health and capacity counters\n\
  ping [payload]                      Verify LTP/1 connectivity\n\
  sign <payload>                      Sign through an authenticated daemon\n\
  load [--requests <n>] [--concurrency <n>] [--payload-bytes <n>]\n\
                                      Run one multiplexed local load stream\n\n\
The socket is read from --socket, LATTICE_SOCKET, or LATTICE_DAEMON_SOCKET.\n\
Use `latticed --config /etc/lattice/latticed.conf` to start the daemon."
    );
}

fn main() -> ExitCode {
    let raw_args: Vec<String> = env::args().collect();
    if let Some(code) = dispatch_network_command(&raw_args) {
        return code;
    }
    let mut args = raw_args.into_iter();
    let program = args.next().unwrap_or_else(|| "lattice".to_owned());
    let mut socket = None;
    let mut token_file = None;
    let mut command = None;
    let mut payload = None;
    let mut load_requests = 10_000_usize;
    let mut load_concurrency = 256_usize;
    let mut load_payload_bytes = 0_usize;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => {
                usage(&program);
                return ExitCode::SUCCESS;
            }
            "--version" => {
                println!("lattice {}", env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            "--socket" => socket = args.next(),
            "--session-token-file" => token_file = args.next(),
            "ping" | "sign" if command.is_none() => {
                command = Some(argument);
                payload = args.next();
                break;
            }
            "status" | "stats" if command.is_none() => {
                command = Some("status".to_owned());
                break;
            }
            "load" if command.is_none() => {
                command = Some(argument);
                while let Some(load_argument) = args.next() {
                    let target = match load_argument.as_str() {
                        "--requests" => &mut load_requests,
                        "--concurrency" => &mut load_concurrency,
                        "--payload-bytes" => &mut load_payload_bytes,
                        _ => {
                            usage(&program);
                            return ExitCode::from(2);
                        }
                    };
                    let Some(value) = args.next() else {
                        usage(&program);
                        return ExitCode::from(2);
                    };
                    match value.parse::<usize>() {
                        Ok(parsed) => *target = parsed,
                        Err(_) => {
                            usage(&program);
                            return ExitCode::from(2);
                        }
                    }
                }
                break;
            }
            _ => {
                usage(&program);
                return ExitCode::from(2);
            }
        }
    }
    let socket = socket
        .or_else(|| env::var("LATTICE_SOCKET").ok())
        .or_else(|| env::var("LATTICE_DAEMON_SOCKET").ok());
    let (Some(socket), Some(command)) = (socket, command) else {
        usage(&program);
        return ExitCode::from(2);
    };
    let result = (|| {
        if command == "load" {
            return run_load(&socket, load_requests, load_concurrency, load_payload_bytes);
        }
        let client = Client::connect(&socket)?;
        match command.as_str() {
            "ping" => {
                let response = client.ping(payload.as_deref().unwrap_or_default().as_bytes())?;
                println!("{}", String::from_utf8_lossy(&response));
            }
            "status" => println!("{}", client.stats()?),
            "sign" => {
                let token_file = token_file
                    .or_else(|| env::var("LATTICE_SESSION_TOKEN_FILE").ok())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "sign requires --session-token-file",
                        )
                    })?;
                let mut token = fs::read(token_file)?;
                while matches!(token.last(), Some(b'\n' | b'\r')) {
                    token.pop();
                }
                if token.is_empty() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "empty session token",
                    ));
                }
                client.authenticate(&token)?;
                let signature = client.sign(payload.as_deref().unwrap_or_default().as_bytes())?;
                let mut hex = String::with_capacity(signature.len() * 2);
                for byte in signature {
                    write!(&mut hex, "{byte:02x}").expect("write to String");
                }
                println!("{hex}");
            }
            "load" => unreachable!("load is handled before opening a default client"),
            _ => unreachable!("command parser restricts values"),
        }
        Ok::<(), std::io::Error>(())
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("lattice: {error}");
            ExitCode::from(1)
        }
    }
}

fn dispatch_network_command(args: &[String]) -> Option<ExitCode> {
    let command = args.get(1)?.as_str();
    if command == "run" {
        return Some(dispatch_agent_run(args));
    }
    let (binary, forwarded): (&str, Vec<String>) = match command {
        "profile" => {
            let subcommand = args.get(2).map(String::as_str).unwrap_or("");
            let mapped = match subcommand {
                "enroll" => "profile-enroll",
                "renew" => "profile-renew",
                "status" => "profile-status",
                "connect" => "profile-connect",
                "disconnect" => "profile-disconnect",
                _ => {
                    eprintln!(
                        "lattice profile requires enroll, renew, status, connect, or disconnect"
                    );
                    return Some(ExitCode::from(2));
                }
            };
            let mut forwarded = vec![mapped.to_owned()];
            forwarded.extend_from_slice(&args[3..]);
            ("lattice-netd", forwarded)
        }
        "open" => {
            let mut forwarded = vec!["open-uri".to_owned()];
            forwarded.extend_from_slice(&args[2..]);
            ("lattice-netd", forwarded)
        }
        _ => return None,
    };
    let override_name = format!("{}_BIN", binary.replace('-', "_").to_ascii_uppercase());
    let executable = env::var(&override_name)
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            env::current_exe()
                .ok()?
                .parent()
                .map(|directory| directory.join(binary))
        })
        .unwrap_or_else(|| binary.into());
    match std::process::Command::new(executable)
        .args(forwarded)
        .status()
    {
        Ok(status) if status.success() => Some(ExitCode::SUCCESS),
        Ok(status) => Some(ExitCode::from(
            status.code().unwrap_or(1).clamp(1, 255) as u8
        )),
        Err(error) => {
            eprintln!("lattice: could not start {binary}: {error}");
            Some(ExitCode::from(1))
        }
    }
}

#[derive(Serialize)]
struct AgentLeasePayload {
    agent_id: String,
    profile_id: Uuid,
    namespace_id: String,
    issued_at: chrono::DateTime<Utc>,
    expires_at: chrono::DateTime<Utc>,
    nonce_b64: String,
}

#[derive(Serialize)]
struct AgentLease {
    payload: AgentLeasePayload,
    signature_b64: String,
}

fn dispatch_agent_run(args: &[String]) -> ExitCode {
    let separator = match args.iter().position(|arg| arg == "--") {
        Some(index) if index + 1 < args.len() => index,
        _ => {
            eprintln!("lattice run requires --agent <id> --profile <uuid> -- <command...>");
            return ExitCode::from(2);
        }
    };
    let mut agent_id = None;
    let mut profile_id = None;
    let mut socket = None;
    let mut token_file = None;
    let mut index = 2;
    while index < separator {
        let target = match args[index].as_str() {
            "--agent" => &mut agent_id,
            "--profile" => &mut profile_id,
            "--socket" => &mut socket,
            "--session-token-file" => &mut token_file,
            unexpected => {
                eprintln!("lattice run: unsupported option {unexpected}");
                return ExitCode::from(2);
            }
        };
        index += 1;
        if index >= separator {
            eprintln!("lattice run: missing option value");
            return ExitCode::from(2);
        }
        *target = Some(args[index].clone());
        index += 1;
    }
    let Some(agent_id) = agent_id else {
        eprintln!("lattice run: --agent is required");
        return ExitCode::from(2);
    };
    if agent_id.is_empty()
        || agent_id.len() > 128
        || !agent_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        eprintln!("lattice run: agent id must be canonical lowercase ASCII");
        return ExitCode::from(2);
    }
    let profile_id = match profile_id.and_then(|value| value.parse::<Uuid>().ok()) {
        Some(value) => value,
        None => {
            eprintln!("lattice run: --profile must be a UUID");
            return ExitCode::from(2);
        }
    };
    let socket = socket
        .or_else(|| env::var("LATTICE_SOCKET").ok())
        .or_else(|| env::var("LATTICE_DAEMON_SOCKET").ok());
    let token_file = token_file.or_else(|| env::var("LATTICE_SESSION_TOKEN_FILE").ok());
    let (Some(socket), Some(token_file)) = (socket, token_file) else {
        eprintln!("lattice run: authenticated latticed socket and session token are required");
        return ExitCode::from(2);
    };
    let result = (|| -> io::Result<std::process::ExitStatus> {
        let client = Client::connect(socket)?;
        let mut token = fs::read(token_file)?;
        while matches!(token.last(), Some(b'\n' | b'\r')) {
            token.pop();
        }
        if token.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty session token",
            ));
        }
        client.authenticate(&token)?;
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let namespace_id = format!(
            "lattice-{}-{}",
            &profile_id.simple().to_string()[..8],
            std::process::id()
        );
        let issued_at = Utc::now();
        let payload = AgentLeasePayload {
            agent_id,
            profile_id,
            namespace_id: namespace_id.clone(),
            issued_at,
            expires_at: issued_at + Duration::minutes(4),
            nonce_b64: STANDARD.encode(nonce),
        };
        let payload_bytes = serde_json::to_vec(&payload).map_err(io::Error::other)?;
        let signature = client.sign(&payload_bytes)?;
        let lease = AgentLease {
            payload,
            signature_b64: STANDARD.encode(signature),
        };
        let lease_path = env::temp_dir().join(format!("{namespace_id}.lease.json"));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        {
            use std::io::Write;
            let mut file = options.open(&lease_path)?;
            file.write_all(&serde_json::to_vec(&lease).map_err(io::Error::other)?)?;
            file.sync_all()?;
        }
        let netd = sibling_binary("lattice-netd");
        let mut command = std::process::Command::new(netd);
        command
            .arg("run-agent")
            .arg("--profile-id")
            .arg(profile_id.to_string())
            .arg("--namespace-id")
            .arg(namespace_id)
            .arg("--agent-lease")
            .arg(&lease_path)
            .arg("--")
            .args(&args[separator + 1..]);
        let status = command.status();
        let _ = fs::remove_file(&lease_path);
        status
    })();
    match result {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status.code().unwrap_or(1).clamp(1, 255) as u8),
        Err(error) => {
            eprintln!("lattice run: {error}");
            ExitCode::from(1)
        }
    }
}

fn sibling_binary(name: &str) -> std::path::PathBuf {
    let override_name = format!("{}_BIN", name.replace('-', "_").to_ascii_uppercase());
    env::var(&override_name)
        .ok()
        .map(std::path::PathBuf::from)
        .or_else(|| {
            env::current_exe()
                .ok()?
                .parent()
                .map(|directory| directory.join(name))
        })
        .unwrap_or_else(|| name.into())
}

fn run_load(
    socket: &str,
    requests: usize,
    concurrency: usize,
    payload_bytes: usize,
) -> io::Result<()> {
    if requests == 0 || concurrency == 0 || concurrency > 65_536 || payload_bytes > MAX_FRAME_BYTES
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load requests/concurrency/payload-bytes outside safe bounds",
        ));
    }
    let pending_response_bytes = concurrency
        .checked_mul(payload_bytes)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "load pending response byte budget overflow",
            )
        })?
        .max(1);
    if pending_response_bytes > HARD_MAX_PENDING_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "load pending response byte budget exceeds the LTP client ceiling",
        ));
    }
    let client = Client::connect_with_options(
        socket,
        ClientOptions {
            max_pending: concurrency,
            max_pending_bytes: pending_response_bytes,
        },
    )?;
    let payload = vec![0_u8; payload_bytes];
    let started = Instant::now();
    let mut issued = 0_usize;
    while issued < requests {
        let batch_size = (requests - issued).min(concurrency);
        let mut batch = Vec::with_capacity(batch_size);
        for _ in 0..batch_size {
            batch.push(client.request_async(kind::PING, &payload)?);
        }
        for response in batch {
            let frame = response.recv().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "LTP response reader stopped during load",
                )
            })??;
            if frame.kind != kind::PONG || frame.payload != payload {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid PING response during load",
                ));
            }
        }
        issued += batch_size;
    }
    let elapsed = started.elapsed();
    let elapsed_ms = elapsed.as_secs_f64() * 1_000.0;
    let rps = requests as f64 / elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    println!(
        "{{\"requests\":{requests},\"concurrency\":{concurrency},\"payload_bytes\":{payload_bytes},\"elapsed_ms\":{elapsed_ms:.3},\"rps\":{rps:.2},\"connections\":1}}"
    );
    Ok(())
}
