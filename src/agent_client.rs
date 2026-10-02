use crate::crypto;
use crate::state;
use anyhow::Context;
use base64::Engine as _;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

/// Agent-plane CLI — the "super easy for AI" front door (ADR-0007).
/// Every command prints ONE line of JSON on stdout (compact, parseable),
/// or the server's error JSON on stderr with a §66 exit code (ADR-0022).
#[derive(Clone)]
pub struct Ctx {
    agent: ureq::Agent,
    base: String,
    token: String,
    /// v1.1 (ADR-0025): the logged-in device id — signs + travels as
    /// X-Far-Device on every request. None = legacy v1.0 token mode.
    device: Option<String>,
    raw: bool,
}

fn call(ctx: &Ctx, method: &str, path: &str, query: Option<&str>, body: Option<&str>) -> Result<(u16, String), String> {
    let url = match query {
        Some(q) => format!("{}{}?{}", ctx.base, path, q),
        None => format!("{}{}", ctx.base, path),
    };
    let ts = state::now().to_string();
    let nonce = crypto::gen_nonce();
    let body_str = body.unwrap_or("");
    let body_sha = crypto::sha256_hex(body_str.as_bytes());
    // v1.1: the device claim is the 6th signed line (bound, not swappable).
    let mut payload = crypto::signing_payload(&ts, &nonce, method, path, &body_sha);
    if let Some(dev) = &ctx.device {
        payload.push('\n');
        payload.push_str(dev);
    }
    let sig = crypto::hmac_hex(&ctx.token, &payload);

    let req = if method == "GET" {
        ctx.agent.get(&url)
    } else {
        ctx.agent.post(&url)
    };
    let mut req = req
        .set("X-Far-Timestamp", &ts)
        .set("X-Far-Nonce", &nonce)
        .set("X-Far-Signature", &sig)
        .set("Content-Type", "application/json");
    if let Some(dev) = &ctx.device {
        req = req.set("X-Far-Device", dev);
    }

    let resp = if method == "GET" {
        req.call()
    } else {
        req.send_string(body_str)
    };
    match resp {
        Ok(r) => {
            let code = r.status();
            let text = r.into_string().map_err(|e| format!("read response failed: {e}"))?;
            Ok((code, text))
        }
        Err(ureq::Error::Status(code, r)) => {
            let text = r.into_string().map_err(|e| format!("read response failed: {e}"))?;
            Ok((code, text))
        }
        Err(e) => Err(format!(
            "network error: {e} — is the daemon running? ('frtrol start' on the owner machine) [fail closed: no action taken]"
        )),
    }
}

/// §66 exit code for a transport-level failure: connection refused /
/// unreachable = 6 (unavailable); transport timeout = 5 (timeout).
/// Fail closed either way — no action was taken.
fn net_exit(e: &str) -> i32 {
    if e.contains("timed out") || e.contains("timed-out") || e.contains("Timeout") {
        5
    } else {
        6
    }
}

/// Extracts the wire error code from a server error envelope and maps it to
/// the §66 exit code (ADR-0022). Unparseable → generic 1.
fn err_exit(body: &str) -> i32 {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(|s| s.to_string()))
        .map(|c| crate::error::exit_for(&c))
        .unwrap_or(1)
}

fn emit(_ctx: &Ctx, code: u16, body: String) -> anyhow::Result<i32> {
    if (200..300).contains(&code) {
        // compact single-line JSON — easiest for an LLM/tool to parse
        let v: Value = serde_json::from_str(&body).unwrap_or(json!({ "raw": body }));
        println!("{}", serde_json::to_string(&v).unwrap_or(body));
        Ok(0)
    } else {
        eprintln!("{body}");
        Ok(err_exit(&body))
    }
}

fn emit_exec(ctx: &Ctx, code: u16, body: String) -> anyhow::Result<i32> {
    if (200..300).contains(&code) {
        if ctx.raw {
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            if v["status"] == "completed" {
                print!("{}", v["stdout"].as_str().unwrap_or(""));
                eprint!("{}", v["stderr"].as_str().unwrap_or(""));
                Ok(0)
            } else {
                eprintln!("status: {}", v["status"].as_str().unwrap_or("?"));
                // §66: the command hit its timeout — exit 5, not 0.
                Ok(if v["status"] == "timeout" { 5 } else { 1 })
            }
        } else {
            println!("{body}");
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            Ok(if v["status"] == "timeout" { 5 } else { 0 })
        }
    } else {
        eprintln!("{body}");
        Ok(err_exit(&body))
    }
}

fn emit_read(ctx: &Ctx, code: u16, body: String) -> anyhow::Result<i32> {
    if (200..300).contains(&code) {
        if ctx.raw {
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let data = base64::engine::general_purpose::STANDARD
                .decode(v["content_b64"].as_str().unwrap_or(""))
                .unwrap_or_default();
            use std::io::Write;
            std::io::stdout().write_all(&data).ok();
            Ok(0)
        } else {
            println!("{body}");
            Ok(0)
        }
    } else {
        eprintln!("{body}");
        Ok(err_exit(&body))
    }
}

pub fn run(
    data_dir: &Path,
    url: Option<String>,
    token: Option<String>,
    device: Option<String>,
    timeout_secs: u64,
    raw: bool,
    cmd: crate::AgentCmd,
) -> anyhow::Result<i32> {
    // v1.1 (ADR-0025 §2): login runs BEFORE credentials exist — it performs
    // TOFU cert capture/pin, then exchanges the password for a device key.
    if let crate::AgentCmd::Login { device_id, expect_fp } = &cmd {
        return login(data_dir, url.as_deref(), device_id, expect_fp.as_deref(), timeout_secs);
    }

    // v0.2: default URL follows the daemon's TLS mode (cert.pem present = https),
    // and https pins the daemon's own self-signed cert (TOFU — cert travels
    // with the token; override the CA with FARCONTROL_CA).
    let base = url
        .or_else(|| std::env::var("FARCONTROL_URL").ok())
        .unwrap_or_else(|| {
            if data_dir.join("cert.pem").exists() {
                "https://127.0.0.1:7788".into()
            } else {
                "http://127.0.0.1:7788".into()
            }
        });
    // v1.1 credential resolution — device mode (device-id + device-key files)
    // wins; the v1.0 agent-token flow keeps working unchanged (legacy compat).
    let dev_from_file = std::fs::read_to_string(data_dir.join("device-id"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let key_from_file = std::fs::read_to_string(data_dir.join("device-key"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let device = device
        .or_else(|| std::env::var("FARCONTROL_DEVICE").ok())
        .or(dev_from_file);
    let token = token
        .or_else(|| std::env::var("FARCONTROL_TOKEN").ok())
        .or(key_from_file)
        .or_else(|| std::fs::read_to_string(data_dir.join("agent-token")).ok().map(|s| s.trim().to_string()))
        .context("no credentials — run 'frtrol agent login <FAR-XXXX-XXXX>' (or pass --token / FARCONTROL_TOKEN for the legacy v1.0 flow)")?;
    let agent = if base.starts_with("https") {
        let ca = std::env::var("FARCONTROL_CA")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| data_dir.join("cert.pem"));
        let pem = std::fs::read_to_string(&ca)
            .with_context(|| format!("https needs the daemon cert: {} (run 'frtrol agent login' to capture + pin it, or set FARCONTROL_CA)", ca.display()))?;
        crate::tls::https_agent(&pem, Duration::from_secs(timeout_secs.max(1)))?
    } else {
        ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(timeout_secs.max(1)))
            .build()
    };
    let ctx = Ctx { agent, base, token, device, raw };

    // §66 (ADR-0022): classify failures — transport problems exit 6
    // (unavailable) or 5 (timeout); server error envelopes already carry the
    // right code via err_exit(); local usage errors stay generic 1.
    match cmd_exec(&ctx, cmd) {
        Ok(rc) => Ok(rc),
        Err(e) => {
            let msg = format!("{e:#}");
            eprintln!("{msg}");
            Ok(if msg.starts_with("network error") { net_exit(&msg) } else { 1 })
        }
    }
}

/// v1.1 (ADR-0025 §2/§4): device login — the agent's ONLY onboarding step.
/// Flow: validate id → resolve the server cert (pin existing / FARCONTROL_CA /
/// TOFU capture + fingerprint display + optional --expect-fp strict compare) →
/// POST password over the pinned channel → store device-id + device-key (0600).
fn login(
    data_dir: &Path,
    url: Option<&str>,
    device_id: &str,
    expect_fp: Option<&str>,
    timeout_secs: u64,
) -> anyhow::Result<i32> {
    let device_id = device_id.trim().to_string();
    if !crate::crypto::device_id_valid(&device_id) {
        eprintln!(
            "'{device_id}' is not a valid FAR-XXXX-XXXX device id — single typos are caught by the check char (got it from 'frtrol device add' output?)"
        );
        return Ok(2);
    }
    let base = url
        .map(|s| s.to_string())
        .or_else(|| std::env::var("FARCONTROL_URL").ok())
        .unwrap_or_else(|| "https://127.0.0.1:7788".into());

    // Password: env (script/AI mode) → stdin prompt. Never a CLI flag (shell
    // history / process list is a leak surface).
    let password = match std::env::var("FARCONTROL_PASSWORD") {
        Ok(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => {
            eprint!("password for {device_id}: ");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line.trim().to_string()
        }
    };
    if password.is_empty() {
        eprintln!("empty password — aborting (fail closed)");
        return Ok(2);
    }

    let timeout = Duration::from_secs(timeout_secs.max(1));
    let agent = if !base.starts_with("https") {
        ureq::AgentBuilder::new().timeout(timeout).build()
    } else {
        // Pin resolution order: FARCONTROL_CA → existing cert.pem → TOFU capture.
        let existing = std::env::var("FARCONTROL_CA")
            .map(std::path::PathBuf::from)
            .ok()
            .or_else(|| data_dir.join("cert.pem").exists().then(|| data_dir.join("cert.pem")));
        match existing {
            Some(ca) => {
                let pem = std::fs::read_to_string(&ca)
                    .with_context(|| format!("cannot read pinned cert {ca:?}"))?;
                crate::tls::https_agent(&pem, timeout)?
            }
            None => {
                // TOFU (ADR-0025 §4): handshake-only probe with the capture agent
                // (carries NO password), display + pin, THEN send secrets.
                let (cap, captured) = crate::tls::capture_agent(timeout)?;
                let _ = cap.get(&format!("{base}/v1/ping")).call(); // 401 is fine — the handshake already captured the cert
                let der = captured
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                    .context("TLS handshake failed — no certificate captured (is the daemon running? 'frtrol start' on the owner machine)")?;
                let fp = crate::crypto::cert_fingerprint(&der);
                println!("server fingerprint: {fp}");
                if let Some(expect) = expect_fp {
                    if fp != expect.trim() {
                        eprintln!("FINGERPRINT MISMATCH — aborting BEFORE sending the password (expected {expect})");
                        return Ok(3);
                    }
                    println!("fingerprint matches --expect-fp ✓ (strict TOFU verified)");
                } else {
                    println!("pinned (TOFU). For full MITM protection compare this out-of-band with 'frtrol fingerprint' on the owner side.");
                }
                let pem = crate::tls::der_to_pem(&der, "CERTIFICATE");
                std::fs::create_dir_all(data_dir)?;
                std::fs::write(data_dir.join("cert.pem"), &pem)?;
                crate::tls::https_agent(&pem, timeout)?
            }
        }
    };

    // Exchange the password over the pinned channel (no HMAC — pre-auth).
    let resp = agent
        .post(&format!("{base}/v1/auth/login"))
        .set("Content-Type", "application/json")
        .send_string(&json!({ "device_id": device_id, "password": password }).to_string());
    let (code, body) = match resp {
        Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
        Err(e) => {
            let msg = format!("network error: {e} — is the daemon running? [fail closed: no action taken]");
            eprintln!("{msg}");
            return Ok(net_exit(&msg));
        }
    };
    if !(200..300).contains(&code) {
        eprintln!("{body}");
        return Ok(err_exit(&body));
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let key = v["device_key"].as_str().unwrap_or("").to_string();
    if key.is_empty() {
        eprintln!("server response carried no device_key — aborting (fail closed)");
        return Ok(1);
    }
    // Persist the credentials (0600) — this is the agent's identity material.
    std::fs::create_dir_all(data_dir)?;
    let write_secret = |name: &str, content: &str| -> anyhow::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let p = data_dir.join(name);
        std::fs::write(&p, content)?;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    };
    write_secret("device-id", &format!("{device_id}\n"))?;
    write_secret("device-key", &format!("{key}\n"))?;
    // a stale legacy agent-token file would shadow nothing (device-key has
    // priority) — remove it to keep the home clean.
    let _ = std::fs::remove_file(data_dir.join("agent-token"));

    println!(
        "{}",
        json!({
            "ok": true,
            "device_id": device_id,
            "stored": format!("{}/device-id + device-key (0600)", data_dir.display()),
            "next": "frtrol agent request <name> <scope> <hours> <reason…> — the owner approves",
        })
    );
    Ok(0)
}

fn cmd_exec(ctx: &Ctx, cmd: crate::AgentCmd) -> anyhow::Result<i32> {
    match cmd {
        // Login is intercepted in run() before credentials exist — unreachable here.
        crate::AgentCmd::Login { .. } => unreachable!("agent login handled in run()"),
        crate::AgentCmd::Ping => {
            let (c, b) = call(ctx, "GET", "/v1/ping", None, None).map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Request { name, scope, hours, reason } => {
            let reason = if reason.is_empty() {
                "no reason given".to_string()
            } else {
                reason.join(" ")
            };
            // ADR-0022 (spec §11): optional declared identity. Forwarded
            // AS-IS (even half-set) — the server is the single enforcement
            // point (S4) and rejects provider-without-model there. Set both:
            //   FAR_AGENT_PROVIDER=z_ai FAR_AGENT_MODEL=glm-5.3
            let mut body = json!({ "agent_name": name, "scope": scope, "hours": hours, "reason": reason });
            if let Ok(p) = std::env::var("FAR_AGENT_PROVIDER") {
                body["provider"] = json!(p);
            }
            if let Ok(m) = std::env::var("FAR_AGENT_MODEL") {
                body["model"] = json!(m);
            }
            let (c, b) = call(ctx, "POST", "/v1/session/request", None, Some(&body.to_string()))
                .map_err(anyhow::Error::msg)?;
            let rc = emit(ctx, c, b.clone())?;
            if rc == 0 {
                if let Ok(v) = serde_json::from_str::<Value>(&b) {
                    if let Some(rid) = v["request_id"].as_str() {
                        eprintln!("waiting for owner approval — poll: frtrol agent status {rid}");
                    }
                }
            }
            Ok(rc)
        }
        crate::AgentCmd::Status { id } => {
            // auto-detect: req_... is a request, ses_... is a session
            let query = if id.starts_with("ses") {
                format!("session_id={id}")
            } else if id.starts_with("req") {
                format!("request_id={id}")
            } else {
                anyhow::bail!("'{id}' does not look like a request id (req_...) or session id (ses_...)")
            };
            let (c, b) = call(ctx, "GET", "/v1/session/status", Some(&query), None).map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Exec { session, command, timeout_ms } => {
            if command.is_empty() {
                anyhow::bail!("no command given — usage: frtrol agent exec <session-id> <command...>");
            }
            let body = json!({
                "session_id": session,
                "command": command[0],
                "args": command[1..],
                "timeout_ms": timeout_ms,
            });
            let (c, b) = call(ctx, "POST", "/v1/exec", None, Some(&body.to_string())).map_err(anyhow::Error::msg)?;
            emit_exec(ctx, c, b)
        }
        crate::AgentCmd::Read { session, path } => {
            let body = json!({ "session_id": session, "path": path });
            let (c, b) = call(ctx, "POST", "/v1/file/read", None, Some(&body.to_string())).map_err(anyhow::Error::msg)?;
            emit_read(ctx, c, b)
        }
        crate::AgentCmd::Write { session, path, content, b64 } => {
            let content_b64 = match (b64, content) {
                (Some(b), _) => b,
                (None, Some(d)) => base64::engine::general_purpose::STANDARD.encode(d.as_bytes()),
                (None, None) => {
                    // no content given → read stdin (pipe friendly: echo hi | frtrol agent write ...)
                    eprintln!("no content given — reading stdin (pipe data or end with Ctrl-D)…");
                    let mut buf = Vec::new();
                    use std::io::Read;
                    std::io::stdin().lock().read_to_end(&mut buf)?;
                    if buf.is_empty() {
                        anyhow::bail!("no content — pass it as the last argument, or pipe stdin");
                    }
                    base64::engine::general_purpose::STANDARD.encode(&buf)
                }
            };
            let body = json!({ "session_id": session, "path": path, "content_b64": content_b64 });
            let (c, b) = call(ctx, "POST", "/v1/file/write", None, Some(&body.to_string())).map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Ls { session, path } => {
            let body = json!({ "session_id": session, "path": path });
            let (c, b) = call(ctx, "POST", "/v1/file/list", None, Some(&body.to_string())).map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Ps { session } => {
            let body = json!({ "session_id": session });
            let (c, b) = call(ctx, "POST", "/v1/process/list", None, Some(&body.to_string()))
                .map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Kill { session, pid, force } => {
            let body = json!({ "session_id": session, "pid": pid, "force": force });
            let (c, b) = call(ctx, "POST", "/v1/process/kill", None, Some(&body.to_string()))
                .map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::App { session, command } => {
            if command.is_empty() {
                anyhow::bail!("no command given — usage: frtrol agent app <session-id> <command...>");
            }
            let body = json!({ "session_id": session, "command": command[0], "args": &command[1..] });
            let (c, b) = call(ctx, "POST", "/v1/app/launch", None, Some(&body.to_string()))
                .map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Shot { session } => {
            let body = json!({ "session_id": session });
            let (c, b) = call(ctx, "POST", "/v1/desktop/screenshot", None, Some(&body.to_string()))
                .map_err(anyhow::Error::msg)?;
            if ctx.raw {
                // --raw: dump the PNG bytes to stdout (file-friendly)
                let v: Value = serde_json::from_str(&b).unwrap_or(Value::Null);
                if c == 200 {
                    use std::io::Write;
                    let data = base64::engine::general_purpose::STANDARD
                        .decode(v["content_b64"].as_str().unwrap_or(""))
                        .unwrap_or_default();
                    std::io::stdout().write_all(&data).ok();
                    return Ok(0);
                }
            }
            emit(ctx, c, b)
        }
        crate::AgentCmd::Type { session, text } => {
            if text.is_empty() {
                anyhow::bail!("no text given — usage: frtrol agent type <session-id> <text...>");
            }
            let body = json!({ "session_id": session, "text": text.join(" ") });
            let (c, b) = call(ctx, "POST", "/v1/desktop/input", None, Some(&body.to_string()))
                .map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Revoke { session } => {
            let body = json!({ "session_id": session });
            let (c, b) = call(ctx, "POST", "/v1/session/revoke", None, Some(&body.to_string())).map_err(anyhow::Error::msg)?;
            emit(ctx, c, b)
        }
        crate::AgentCmd::Term { session, command } => {
            if command.is_empty() {
                anyhow::bail!("no command given — usage: frtrol agent term <session-id> <command...>");
            }
            term_interactive(ctx, &session, command)
        }
    }
}

/// Interactive terminal: open a PTY on the server, pipe local stdin to it,
/// stream its output to stdout, close on EOF/Ctrl-D. Agents that prefer the
/// raw JSON API use /v1/term/{open,write,read,close} directly.
fn term_interactive(ctx: &Ctx, session: &str, command: Vec<String>) -> anyhow::Result<i32> {
    use std::io::{BufRead, Write};

    let body = json!({ "session_id": session, "command": command[0], "args": &command[1..] });
    let (c, b) = call(ctx, "POST", "/v1/term/open", None, Some(&body.to_string()))
        .map_err(anyhow::Error::msg)?;
    if !(200..300).contains(&c) {
        eprintln!("{b}");
        return Ok(err_exit(&b));
    }
    let v: Value = serde_json::from_str(&b)?;
    let term_id = v["term_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("server response missing term_id"))?
        .to_string();
    eprintln!("[farcontrol] terminal {term_id} open — type input, Ctrl-D to close");

    // Output pump: poll /v1/term/read every 120ms, print raw.
    let pump_ctx = ctx.clone();
    let pump_term = term_id.clone();
    let pump = std::thread::spawn(move || {
        loop {
            let body = json!({ "term_id": pump_term }).to_string();
            // HMAC-signed call (call() does ts/nonce/signature for us)
            let ok = call(&pump_ctx, "POST", "/v1/term/read", None, Some(&body))
                .ok()
                .filter(|(c, _)| (200..300).contains(c))
                .and_then(|(_, t)| serde_json::from_str::<Value>(&t).ok());
            match ok {
                Some(v) => {
                    let chunk = base64::engine::general_purpose::STANDARD
                        .decode(v["output_b64"].as_str().unwrap_or(""))
                        .unwrap_or_default();
                    if !chunk.is_empty() {
                        let mut out = std::io::stdout();
                        let _ = out.write_all(&chunk);
                        let _ = out.flush();
                    }
                    if v["status"] == "exited" {
                        return;
                    }
                }
                // 404 (terminal closed / session gone) or transport failure:
                // stop pumping — fail closed, never spin forever.
                None => return,
            }
            std::thread::sleep(std::time::Duration::from_millis(120));
        }
    });

    // Input pump: local stdin lines → /v1/term/write.
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line?;
        let payload = format!("{line}\n");
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload.as_bytes());
        let body = json!({ "term_id": term_id, "data_b64": b64 }).to_string();
        match call(ctx, "POST", "/v1/term/write", None, Some(&body)) {
            Ok((c, _)) if (200..300).contains(&c) => {}
            _ => break, // terminal closed or daemon gone — stop feeding stdin
        }
    }
    // stdin EOF → wait for the remote process to finish (drain output, like
    // piping into ssh), then close the terminal and exit.
    let _ = pump.join();
    let body = json!({ "term_id": term_id }).to_string();
    let _ = call(ctx, "POST", "/v1/term/close", None, Some(&body));
    eprintln!("[farcontrol] terminal closed");
    Ok(0)
}
