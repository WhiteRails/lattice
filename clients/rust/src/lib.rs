//! Multiplexed client for the local Lattice daemon protocol (LTP/1).
//! It is dependency-free so agent runtimes can use it in constrained hosts.

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

pub const MAGIC: &[u8; 4] = b"LTP1";
pub const VERSION: u8 = 1;
pub const HEADER_BYTES: usize = 20;
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_PENDING: usize = 4096;
pub const DEFAULT_MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;
pub const HARD_MAX_PENDING: usize = 65_536;
pub const HARD_MAX_PENDING_BYTES: usize = 1024 * 1024 * 1024;

pub mod kind {
    pub const PING: u8 = 1;
    pub const STATS: u8 = 2;
    pub const AUTH: u8 = 3;
    pub const SIGN: u8 = 4;
    pub const PONG: u8 = 129;
    pub const STATS_RESPONSE: u8 = 130;
    pub const CHALLENGE: u8 = 131;
    pub const AUTHENTICATED: u8 = 132;
    pub const SIGNATURE: u8 = 133;
    pub const ERROR: u8 = 255;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub request_id: u64,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn encode(&self) -> io::Result<Vec<u8>> {
        if self.payload.len() > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "frame exceeds LTP/1 limit",
            ));
        }
        let mut encoded = Vec::with_capacity(HEADER_BYTES + self.payload.len());
        encoded.extend_from_slice(MAGIC);
        encoded.push(VERSION);
        encoded.push(self.kind);
        encoded.extend_from_slice(&[0, 0]); // flags, reserved in v1
        encoded.extend_from_slice(&self.request_id.to_be_bytes());
        encoded.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        encoded.extend_from_slice(&self.payload);
        Ok(encoded)
    }

    pub fn read_from(reader: &mut impl Read) -> io::Result<Self> {
        let mut header = [0_u8; HEADER_BYTES];
        reader.read_exact(&mut header)?;
        if &header[..4] != MAGIC || header[4] != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported LTP frame",
            ));
        }
        let payload_len =
            u32::from_be_bytes(header[16..20].try_into().expect("fixed header")) as usize;
        if payload_len > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer frame exceeds LTP/1 limit",
            ));
        }
        let mut payload = vec![0_u8; payload_len];
        reader.read_exact(&mut payload)?;
        Ok(Frame {
            kind: header[5],
            request_id: u64::from_be_bytes(header[8..16].try_into().expect("fixed header")),
            payload,
        })
    }
}

struct ClientInner {
    writer: Mutex<UnixStream>,
    next_request_id: AtomicU64,
    pending: Mutex<PendingState>,
    max_pending: usize,
    max_pending_bytes: usize,
}

struct PendingRequest {
    sender: mpsc::Sender<io::Result<Frame>>,
    reserved_bytes: usize,
}

struct PendingState {
    requests: HashMap<u64, PendingRequest>,
    reserved_bytes: usize,
}

#[derive(Clone)]
pub struct Client {
    inner: Arc<ClientInner>,
    control: Arc<Mutex<mpsc::Receiver<Frame>>>,
}

#[derive(Debug, Clone, Copy)]
pub struct ClientOptions {
    pub max_pending: usize,
    /// Maximum bytes that queued response receivers may retain. The client
    /// reserves the protocol-specific maximum before writing a request.
    pub max_pending_bytes: usize,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            max_pending: DEFAULT_MAX_PENDING,
            max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
        }
    }
}

impl Client {
    pub fn connect(socket_path: impl AsRef<Path>) -> io::Result<Self> {
        Self::connect_with_options(socket_path, ClientOptions::default())
    }

    pub fn connect_with_options(
        socket_path: impl AsRef<Path>,
        options: ClientOptions,
    ) -> io::Result<Self> {
        if options.max_pending == 0 || options.max_pending > HARD_MAX_PENDING {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("max_pending must be between 1 and {HARD_MAX_PENDING}"),
            ));
        }
        if options.max_pending_bytes == 0 || options.max_pending_bytes > HARD_MAX_PENDING_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("max_pending_bytes must be between 1 and {HARD_MAX_PENDING_BYTES}"),
            ));
        }
        let stream = UnixStream::connect(socket_path)?;
        let reader = stream.try_clone()?;
        let inner = Arc::new(ClientInner {
            writer: Mutex::new(stream),
            next_request_id: AtomicU64::new(1),
            pending: Mutex::new(PendingState {
                requests: HashMap::new(),
                reserved_bytes: 0,
            }),
            max_pending: options.max_pending,
            max_pending_bytes: options.max_pending_bytes,
        });
        // The daemon issues one challenge per connection. A compromised local
        // peer must not turn unsolicited control frames into an unbounded
        // heap queue before authenticate() reads that challenge.
        let (control_sender, control_receiver) = mpsc::sync_channel(1);
        let pending = Arc::clone(&inner);
        std::thread::Builder::new()
            .name("lattice-client-reader".to_owned())
            .spawn(move || read_responses(reader, pending, control_sender))
            .map_err(|error| io::Error::other(format!("failed to start LTP reader: {error}")))?;
        Ok(Self {
            inner,
            control: Arc::new(Mutex::new(control_receiver)),
        })
    }

    /// Queues one request on the persistent socket. Responses can arrive out of
    /// order and are delivered through the returned receiver by request ID.
    pub fn request_async(
        &self,
        kind: u8,
        payload: &[u8],
    ) -> io::Result<mpsc::Receiver<io::Result<Frame>>> {
        let request_id = self.inner.next_request_id.fetch_add(1, Ordering::Relaxed);
        if request_id == u64::MAX {
            return Err(io::Error::other("request id exhausted"));
        }
        let request = Frame {
            kind,
            request_id,
            payload: payload.to_vec(),
        };
        let encoded = request.encode()?;
        let reserved_bytes = maximum_response_bytes(kind, payload.len());
        let (sender, receiver) = mpsc::channel();
        {
            let mut pending = self
                .inner
                .pending
                .lock()
                .map_err(|_| io::Error::other("pending request table poisoned"))?;
            if pending.requests.len() >= self.inner.max_pending {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "LTP client backpressure limit reached",
                ));
            }
            if reserved_bytes
                > self
                    .inner
                    .max_pending_bytes
                    .saturating_sub(pending.reserved_bytes)
            {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "LTP client pending response byte budget reached",
                ));
            }
            pending.reserved_bytes += reserved_bytes;
            pending.requests.insert(
                request_id,
                PendingRequest {
                    sender,
                    reserved_bytes,
                },
            );
        }
        let write_result = (|| {
            let mut writer = self
                .inner
                .writer
                .lock()
                .map_err(|_| io::Error::other("LTP writer poisoned"))?;
            writer.write_all(&encoded)?;
            writer.flush()
        })();
        if let Err(error) = write_result {
            if let Ok(mut pending) = self.inner.pending.lock() {
                if let Some(request) = pending.requests.remove(&request_id) {
                    pending.reserved_bytes = pending
                        .reserved_bytes
                        .saturating_sub(request.reserved_bytes);
                }
            }
            return Err(error);
        }
        Ok(receiver)
    }

    pub fn request(&self, kind: u8, payload: &[u8]) -> io::Result<Frame> {
        let response = self.request_async(kind, payload)?.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "LTP response reader stopped",
            )
        })??;
        if response.kind == kind::ERROR {
            return Err(io::Error::other(
                String::from_utf8_lossy(&response.payload).into_owned(),
            ));
        }
        Ok(response)
    }

    pub fn ping(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let response = self.request(kind::PING, payload)?;
        if response.kind != kind::PONG {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "expected PONG"));
        }
        Ok(response.payload)
    }

    pub fn stats(&self) -> io::Result<String> {
        let response = self.request(kind::STATS, &[])?;
        if response.kind != kind::STATS_RESPONSE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "expected STATS response",
            ));
        }
        String::from_utf8(response.payload)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "stats is not UTF-8"))
    }

    /// Completes the daemon's per-connection challenge before requesting an
    /// Ed25519 signature. The session token is never placed in an LTP frame.
    pub fn authenticate(&self, session_token: &[u8]) -> io::Result<()> {
        let challenge = self
            .control
            .lock()
            .map_err(|_| io::Error::other("LTP control channel poisoned"))?
            .recv_timeout(std::time::Duration::from_secs(5))
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "daemon did not issue an authentication challenge",
                )
            })?;
        if challenge.kind != kind::CHALLENGE
            || challenge.request_id != 0
            || challenge.payload.len() != 32
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid daemon authentication challenge",
            ));
        }
        let mut mac = Hmac::<Sha256>::new_from_slice(session_token)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid session token"))?;
        mac.update(&challenge.payload);
        let response = self.request(kind::AUTH, &mac.finalize().into_bytes())?;
        if response.kind != kind::AUTHENTICATED || !response.payload.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "daemon rejected authentication",
            ));
        }
        Ok(())
    }

    pub fn sign(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        let response = self.request(kind::SIGN, payload)?;
        if response.kind != kind::SIGNATURE || response.payload.len() != 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Ed25519 signature response",
            ));
        }
        Ok(response.payload)
    }
}

fn maximum_response_bytes(kind: u8, payload_len: usize) -> usize {
    match kind {
        kind::PING => payload_len,
        kind::STATS => 256,
        kind::AUTH => 0,
        kind::SIGN => 64,
        // Unsupported commands are small errors in the reference daemon, but
        // reserve a full protocol frame for an implementation we do not know.
        _ => MAX_FRAME_BYTES,
    }
}

fn read_responses(
    mut reader: UnixStream,
    inner: Arc<ClientInner>,
    control: mpsc::SyncSender<Frame>,
) {
    loop {
        match Frame::read_from(&mut reader) {
            Ok(response) => {
                if response.request_id == 0 {
                    // Do not block the reader on unsolicited control traffic.
                    // The first challenge is sufficient for authentication;
                    // later control frames are invalid for LTP/1 and dropped.
                    let _ = control.try_send(response);
                    continue;
                }
                let sender = match inner.pending.lock() {
                    Ok(mut pending) => {
                        pending
                            .requests
                            .remove(&response.request_id)
                            .map(|request| {
                                pending.reserved_bytes = pending
                                    .reserved_bytes
                                    .saturating_sub(request.reserved_bytes);
                                request.sender
                            })
                    }
                    Err(_) => None,
                };
                if let Some(sender) = sender {
                    let _ = sender.send(Ok(response));
                }
            }
            Err(error) => {
                let message = error.to_string();
                let kind = error.kind();
                if let Ok(mut pending) = inner.pending.lock() {
                    for (_, request) in pending.requests.drain() {
                        let _ = request
                            .sender
                            .send(Err(io::Error::new(kind, message.clone())));
                    }
                    pending.reserved_bytes = 0;
                }
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_has_stable_big_endian_wire_layout() {
        let frame = Frame {
            kind: kind::PING,
            request_id: 0x0102_0304_0506_0708,
            payload: b"hello".to_vec(),
        };
        let bytes = frame.encode().expect("encode");
        assert_eq!(&bytes[..4], MAGIC);
        assert_eq!(&bytes[8..16], &0x0102_0304_0506_0708_u64.to_be_bytes());
        assert_eq!(
            Frame::read_from(&mut bytes.as_slice()).expect("decode"),
            frame
        );
    }

    #[test]
    fn oversized_frames_are_rejected_before_allocation() {
        let frame = Frame {
            kind: kind::PING,
            request_id: 1,
            payload: vec![0; MAX_FRAME_BYTES + 1],
        };
        assert!(frame.encode().is_err());
    }

    #[test]
    fn client_dispatches_out_of_order_responses_to_the_right_request() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket =
            std::env::temp_dir().join(format!("lattice-client-{}-{}.sock", std::process::id(), 17));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let first = Frame::read_from(&mut stream).expect("first request");
            let second = Frame::read_from(&mut stream).expect("second request");
            for request in [second, first] {
                let response = Frame {
                    kind: kind::PONG,
                    request_id: request.request_id,
                    payload: request.payload,
                };
                stream
                    .write_all(&response.encode().expect("encode response"))
                    .expect("write response");
            }
        });
        let client = Client::connect(&socket).expect("connect");
        let first = client
            .request_async(kind::PING, b"first")
            .expect("first async");
        let second = client
            .request_async(kind::PING, b"second")
            .expect("second async");
        assert_eq!(
            first
                .recv()
                .expect("first channel")
                .expect("first response")
                .payload,
            b"first"
        );
        assert_eq!(
            second
                .recv()
                .expect("second channel")
                .expect("second response")
                .payload,
            b"second"
        );
        server.join().expect("server join");
        std::fs::remove_file(socket).expect("remove test socket");
    }

    #[test]
    fn client_rejects_work_above_its_backpressure_limit() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket = std::env::temp_dir().join(format!(
            "lattice-client-limit-{}-{}.sock",
            std::process::id(),
            19
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind test socket");
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept client");
            thread::sleep(std::time::Duration::from_millis(50));
        });
        let client = Client::connect_with_options(
            &socket,
            ClientOptions {
                max_pending: 1,
                max_pending_bytes: 1024,
            },
        )
        .expect("connect");
        let _first = client
            .request_async(kind::PING, b"one")
            .expect("first request");
        assert_eq!(
            client
                .request_async(kind::PING, b"two")
                .expect_err("must apply backpressure")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        server.join().expect("server join");
        std::fs::remove_file(socket).expect("remove test socket");
    }

    #[test]
    fn client_rejects_an_oversized_pending_response_budget() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket = std::env::temp_dir().join(format!(
            "lattice-client-byte-limit-{}-{}.sock",
            std::process::id(),
            23
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind test socket");
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept client");
            thread::sleep(std::time::Duration::from_millis(50));
        });
        let client = Client::connect_with_options(
            &socket,
            ClientOptions {
                max_pending: 4,
                max_pending_bytes: 3,
            },
        )
        .expect("connect");
        assert_eq!(
            client
                .request_async(kind::PING, b"four")
                .expect_err("must reserve the response bytes")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        server.join().expect("server join");
        std::fs::remove_file(socket).expect("remove test socket");
    }

    #[test]
    fn client_rejects_pending_limits_above_the_hard_ceiling() {
        let socket = std::env::temp_dir().join("lattice-client-invalid-options.sock");
        assert!(matches!(
            Client::connect_with_options(
                &socket,
                ClientOptions {
                    max_pending: HARD_MAX_PENDING + 1,
                    max_pending_bytes: DEFAULT_MAX_PENDING_BYTES,
                }
            ),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
        assert!(matches!(
            Client::connect_with_options(
                &socket,
                ClientOptions {
                    max_pending: DEFAULT_MAX_PENDING,
                    max_pending_bytes: HARD_MAX_PENDING_BYTES + 1,
                }
            ),
            Err(error) if error.kind() == io::ErrorKind::InvalidInput
        ));
    }

    #[test]
    fn client_drops_unsolicited_control_frames_after_the_first() {
        use std::os::unix::net::UnixListener;
        use std::thread;

        let socket = std::env::temp_dir().join(format!(
            "lattice-client-control-limit-{}-{}.sock",
            std::process::id(),
            29
        ));
        let _ = std::fs::remove_file(&socket);
        let listener = UnixListener::bind(&socket).expect("bind test socket");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            for byte in [1_u8, 2_u8] {
                stream
                    .write_all(
                        &Frame {
                            kind: kind::CHALLENGE,
                            request_id: 0,
                            payload: vec![byte; 32],
                        }
                        .encode()
                        .expect("encode challenge"),
                    )
                    .expect("write challenge");
            }
            thread::sleep(std::time::Duration::from_millis(75));
        });
        let client = Client::connect(&socket).expect("connect");
        // Let the reader see both frames before freeing the single slot.
        thread::sleep(std::time::Duration::from_millis(25));
        let control = client.control.lock().expect("control lock");
        assert_eq!(
            control
                .recv_timeout(std::time::Duration::from_secs(1))
                .expect("first challenge")
                .payload,
            vec![1_u8; 32]
        );
        assert!(matches!(
            control.try_recv(),
            Err(mpsc::TryRecvError::Empty) | Err(mpsc::TryRecvError::Disconnected)
        ));
        drop(control);
        drop(client);
        server.join().expect("server join");
        std::fs::remove_file(socket).expect("remove test socket");
    }
}
