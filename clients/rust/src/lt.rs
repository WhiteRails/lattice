//! `lt` is a deliberately narrow local agent for Lattice operations.
//!
//! It borrows the small Unix-agent form factor of Vercel's fx, but does not
//! inherit its general shell, filesystem, browser, MCP, or remote-network
//! tools. The local model may only request the two operations implemented in
//! `execute_tool`; this process remains the authority for every side effect.

use lattice_client::Client;
use serde_json::{json, Value};
use std::env;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode};

const MODEL_FILE: &str = "lt-smollm2-135m-instruct-q4_k_m.gguf";
const MAX_PROMPT_BYTES: usize = 8 * 1024;
const MAX_MODEL_REPLY_BYTES: usize = 16 * 1024;
const MAX_PING_BYTES: usize = 1024;
const MAX_AGENT_STEPS: usize = 4;

#[derive(Clone)]
struct Settings {
    socket: Option<String>,
    model_path: PathBuf,
    inference_bin: PathBuf,
    max_steps: usize,
}

enum AgentReply {
    Final(String),
    Status,
    Ping(String),
}

fn usage() {
    eprintln!(
        "Usage: lt [--socket <path>] [--max-steps <1-4>] [ask <prompt>]\n\n\
lt is a local Lattice agent. With no command it reads prompts interactively.\n\
It embeds llama.cpp and the bundled SmolLM2-135M Q4 model; no model server is used.\n\
The agent can only call lattice_status and lattice_ping. It cannot run shell commands,\n\
read or write files, use MCP, browse the web, manage keys, or sign payloads."
    );
}

fn embedded_runtime_paths() -> Result<(PathBuf, PathBuf), String> {
    let executable =
        env::current_exe().map_err(|error| format!("cannot locate lt executable: {error}"))?;
    let bin_dir = executable
        .parent()
        .ok_or_else(|| "lt executable has no parent directory".to_owned())?;
    let bundle_root = bin_dir
        .parent()
        .ok_or_else(|| "lt must run from its release bundle".to_owned())?;
    let inference_bin = bin_dir.join("lt-llm");
    let model_path = bundle_root.join("models").join(MODEL_FILE);
    if !inference_bin.is_file() || !model_path.is_file() {
        return Err(
            "embedded inference runtime or model is missing; install a complete lt release bundle"
                .to_owned(),
        );
    }
    Ok((inference_bin, model_path))
}

fn parse_settings() -> Result<(Settings, Option<String>), String> {
    let mut socket = None;
    let mut max_steps = 3_usize;
    let mut remainder = Vec::new();
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "-h" | "--help" => return Err(String::new()),
            "--version" => {
                println!("lt {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            "--socket" => socket = args.next(),
            "--max-steps" => {
                max_steps = args
                    .next()
                    .ok_or_else(|| "--max-steps requires a value".to_owned())?
                    .parse::<usize>()
                    .map_err(|_| "--max-steps must be an integer from 1 to 4".to_owned())?;
                if !(1..=MAX_AGENT_STEPS).contains(&max_steps) {
                    return Err("--max-steps must be an integer from 1 to 4".to_owned());
                }
            }
            "ask" => {
                remainder.extend(args);
                break;
            }
            _ if argument.starts_with('-') => return Err(format!("unknown option: {argument}")),
            _ => return Err("use `lt ask <prompt>` or run `lt` interactively".to_owned()),
        }
    }
    if socket.is_none() {
        socket = env::var("LATTICE_SOCKET")
            .ok()
            .or_else(|| env::var("LATTICE_DAEMON_SOCKET").ok());
    }
    let prompt = (!remainder.is_empty()).then(|| remainder.join(" "));
    let (inference_bin, model_path) = embedded_runtime_paths()?;
    Ok((
        Settings {
            socket,
            model_path,
            inference_bin,
            max_steps,
        },
        prompt,
    ))
}

fn system_prompt() -> &'static str {
    "You are lt, the local Lattice connectivity assistant. Reply with exactly one JSON object and no markdown.\n\
Allowed shapes:\n\
{\"type\":\"tool\",\"tool\":\"lattice_status\",\"arguments\":{}}\n\
{\"type\":\"tool\",\"tool\":\"lattice_ping\",\"arguments\":{\"payload\":\"short text\"}}\n\
{\"type\":\"final\",\"message\":\"short user-facing answer\"}\n\
Never request shell commands, files, web access, MCP, daemon configuration, keys, policies, agents, or signing.\n\
Use a tool only when needed to answer a Lattice connectivity question."
}

fn request_model(settings: &Settings, messages: &[Value]) -> Result<String, String> {
    let mut prompt = String::new();
    for message in messages {
        let role = message
            .get("role")
            .and_then(Value::as_str)
            .ok_or_else(|| "invalid local model message role".to_owned())?;
        let content = message
            .get("content")
            .and_then(Value::as_str)
            .ok_or_else(|| "invalid local model message content".to_owned())?;
        prompt.push_str("<|im_start|>");
        prompt.push_str(role);
        prompt.push('\n');
        prompt.push_str(content);
        prompt.push_str("<|im_end|>\n");
    }
    prompt.push_str("<|im_start|>assistant\n");
    let output = Command::new(&settings.inference_bin)
        .args([
            "-m",
            settings
                .model_path
                .to_str()
                .ok_or_else(|| "model path is not UTF-8".to_owned())?,
            "-p",
            &prompt,
            "-n",
            "384",
            "--temp",
            "0",
            "--no-display-prompt",
            "--simple-io",
        ])
        .output()
        .map_err(|error| format!("cannot start embedded inference: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "embedded inference failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    if output.stdout.len() > MAX_MODEL_REPLY_BYTES {
        return Err("embedded model response exceeds 16 KiB".to_owned());
    }
    let content = String::from_utf8(output.stdout)
        .map_err(|_| "embedded model returned non-UTF-8 output".to_owned())?;
    Ok(content.trim().to_owned())
}

fn parse_reply(content: &str) -> Result<AgentReply, String> {
    let value: Value = serde_json::from_str(content).map_err(|_| {
        "local model did not return the required JSON envelope; no action was run".to_owned()
    })?;
    let object = value.as_object().ok_or_else(|| {
        "local model response must be a JSON object; no action was run".to_owned()
    })?;
    match object.get("type").and_then(Value::as_str) {
        Some("final") => {
            let message = object
                .get("message")
                .and_then(Value::as_str)
                .ok_or_else(|| "final response requires a message".to_owned())?;
            if message.is_empty() || message.len() > 4096 {
                return Err("final message must be between 1 and 4096 bytes".to_owned());
            }
            Ok(AgentReply::Final(message.to_owned()))
        }
        Some("tool") => {
            let arguments = object
                .get("arguments")
                .and_then(Value::as_object)
                .ok_or_else(|| "tool response requires an arguments object".to_owned())?;
            match object.get("tool").and_then(Value::as_str) {
                Some("lattice_status") if arguments.is_empty() => Ok(AgentReply::Status),
                Some("lattice_ping") => {
                    if arguments.len() != 1 {
                        return Err("lattice_ping accepts only payload".to_owned());
                    }
                    let payload = arguments
                        .get("payload")
                        .and_then(Value::as_str)
                        .ok_or_else(|| "lattice_ping requires text payload".to_owned())?;
                    if payload.len() > MAX_PING_BYTES {
                        return Err("lattice_ping payload exceeds 1024 bytes".to_owned());
                    }
                    Ok(AgentReply::Ping(payload.to_owned()))
                }
                _ => Err(
                    "requested tool is outside lt's Lattice-only capability boundary".to_owned(),
                ),
            }
        }
        _ => Err("model response type must be final or tool; no action was run".to_owned()),
    }
}

fn execute_tool(settings: &Settings, reply: &AgentReply) -> Result<String, String> {
    let socket = settings.socket.as_deref().ok_or_else(|| {
        "Lattice socket is required: pass --socket or set LATTICE_SOCKET".to_owned()
    })?;
    match reply {
        AgentReply::Status => {
            eprintln!("lt audit action=lattice_status socket={socket}");
            Client::connect(socket)
                .and_then(|client| client.stats())
                .map_err(|error| format!("lattice_status failed: {error}"))
        }
        AgentReply::Ping(payload) => {
            eprintln!(
                "lt audit action=lattice_ping socket={socket} payload_bytes={}",
                payload.len()
            );
            Client::connect(socket)
                .and_then(|client| client.ping(payload.as_bytes()))
                .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                .map_err(|error| format!("lattice_ping failed: {error}"))
        }
        AgentReply::Final(_) => unreachable!("final messages do not execute tools"),
    }
}

fn ask(settings: &Settings, prompt: &str) -> Result<String, String> {
    if prompt.is_empty() || prompt.len() > MAX_PROMPT_BYTES {
        return Err("prompt must be between 1 and 8192 bytes".to_owned());
    }
    let mut messages = vec![
        json!({ "role": "system", "content": system_prompt() }),
        json!({ "role": "user", "content": prompt }),
    ];
    for _ in 0..settings.max_steps {
        let content = request_model(settings, &messages)?;
        match parse_reply(&content)? {
            AgentReply::Final(message) => return Ok(message),
            action => {
                let result = execute_tool(settings, &action)?;
                messages.push(json!({ "role": "assistant", "content": content }));
                messages.push(json!({ "role": "user", "content": format!("Lattice tool result: {result}. Return a final JSON response now, or one further allowed tool call.") }));
            }
        }
    }
    Err("lt reached its four-step Lattice action ceiling".to_owned())
}

fn interactive(settings: &Settings) -> Result<(), String> {
    eprintln!("lt — local Lattice agent. Type /exit to leave.");
    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|error| format!("cannot read prompt: {error}"))?;
        if line.trim() == "/exit" {
            return Ok(());
        }
        if line.trim().is_empty() {
            continue;
        }
        match ask(settings, &line) {
            Ok(answer) => println!("{answer}"),
            Err(error) => eprintln!("lt: {error}"),
        }
        eprint!("lt> ");
        io::stderr()
            .flush()
            .map_err(|error| format!("cannot render prompt: {error}"))?;
    }
    Ok(())
}

fn main() -> ExitCode {
    match parse_settings() {
        Ok((settings, Some(prompt))) => match ask(&settings, &prompt) {
            Ok(answer) => {
                println!("{answer}");
                ExitCode::SUCCESS
            }
            Err(error) => {
                eprintln!("lt: {error}");
                ExitCode::from(1)
            }
        },
        Ok((settings, None)) => {
            eprint!("lt> ");
            let _ = io::stderr().flush();
            match interactive(&settings) {
                Ok(()) => ExitCode::SUCCESS,
                Err(error) => {
                    eprintln!("lt: {error}");
                    ExitCode::from(1)
                }
            }
        }
        Err(error) if error.is_empty() => {
            usage();
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("lt: {error}");
            usage();
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_two_lattice_tools() {
        assert!(matches!(
            parse_reply(r#"{"type":"tool","tool":"lattice_status","arguments":{}}"#),
            Ok(AgentReply::Status)
        ));
        assert!(matches!(
            parse_reply(r#"{"type":"tool","tool":"lattice_ping","arguments":{"payload":"ok"}}"#),
            Ok(AgentReply::Ping(_))
        ));
        assert!(
            parse_reply(r#"{"type":"tool","tool":"sign","arguments":{"payload":"x"}}"#).is_err()
        );
        assert!(parse_reply(r#"{"type":"tool","tool":"terminal","arguments":{}}"#).is_err());
    }

    #[test]
    fn caps_ping_payloads_before_lattice_is_contacted() {
        let payload = "a".repeat(MAX_PING_BYTES + 1);
        assert!(parse_reply(&format!(
            r#"{{"type":"tool","tool":"lattice_ping","arguments":{{"payload":"{payload}"}}}}"#
        ))
        .is_err());
    }
}
