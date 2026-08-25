use lattice_client::{kind, Client, ClientOptions, HARD_MAX_PENDING_BYTES, MAX_FRAME_BYTES};
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::process::ExitCode;
use std::time::Instant;

fn usage(program: &str) {
    eprintln!(
        "Usage: {program} [--socket <path>] [--session-token-file <path>] <command>\n\n\
Commands:\n\
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
    let mut args = env::args();
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
