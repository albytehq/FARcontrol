use crate::crypto;
use crate::state;
use anyhow::Context;
use base64::Engine as _;
use serde_json::{json, Value};
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Agent-plane CLI — the "super easy for AI" front door (ADR-0007, v1.2: ADR-0029/0030).
/// Every command prints ONE line of JSON on stdout (compact, parseable),
/// or the server's error JSON on stderr with a §66 exit code (ADR-0022).
#[derive(Clone)]
pub struct Ctx {
    agent: ureq::Agent,
    base: String,
    token: String,
    /// v1.2: the machine device id — signs + travels as X-Far-Device.
    device: String,
    raw: bool,
}

// ============================================================
// v1.2 (ADR-0029): agent home — connection store, runtime state
// ============================================================

pub fn default_agent_home() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| anyhow::anyhow!("HOME environment variable is not set — pass --home <dir>"))?;
    Ok(PathBuf::from(home).join(".farcontrol-agent"))
}

/// connection.json — the saved session connection (0600). This is the agent's
/// identity material after `frtrol agent` connects. Cleared on stop/expiry.
#[derive(Clone)]
struct Conn {
    base: String,
    device_id: String,
    session_id: String,
    key: String,
    agent_name: String,
}

fn conn_path(home: &Path) -> PathBuf {
    home.join("connection.json")
}
fn pid_path(home: &Path) -> PathBuf {
    home.join("agentd.pid")
}
fn status_path(home: &Path) -> PathBuf {
    home.join("status.json")
}

fn read_conn(home: &Path) -> Option<Conn> {
    let text = std::fs::read_to_string(conn_path(home)).ok()?;
    let v: Value = serde_json::from_str(&text).ok()?;
    Some(Conn {
        base: v["base_url"].as_str()?.to_string(),
        device_id: v["device_id"].as_str()?.to_string(),
        session_id: v["session_id"].as_str().unwrap_or("").to_string(),
        key: v["key"].as_str()?.to_string(),
        agent_name: v["agent_name"].as_str().unwrap_or("agent").to_string(),
    })
}

fn write_secret_file(path: &Path, content: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn write_conn(home: &Path, c: &Conn) -> anyhow::Result<()> {
    std::fs::create_dir_all(home)?;
    let body = json!({
        "version": 2,
        "base_url": c.base,
        "device_id": c.device_id,
        "session_id": c.session_id,
        "key": c.key,
        "agent_name": c.agent_name,
    });
    write_secret_file(&conn_path(home), &serde_json::to_string(&body)?)
}

fn clear_conn(home: &Path) {
    let _ = std::fs::remove_file(conn_path(home));
}

/// status.json — the runtime's live state (atomic write: tmp + rename).
#[derive(serde::Serialize)]
struct RuntimeStatus {
    state: String,
    agent_name: String,
    device_id: String,
    session_id: String,
    base_url: String,
    pid: u32,
    last_ok: Option<i64>,
    last_error: Option<String>,
    updated_at: i64,
}

fn write_status(home: &Path, s: &RuntimeStatus) {
    let tmp = home.join("status.json.tmp");
    if let Ok(body) = serde_json::to_string(s) {
        if std::fs::write(&tmp, body).is_ok() {
            let _ = std::fs::rename(&tmp, status_path(home));
        }
    }
}

fn read_status(home: &Path) -> Option<Value> {
    serde_json::from_str(&std::fs::read_to_string(status_path(home)).ok()?).ok()
}

fn runtime_pid(home: &Path) -> Option<u32> {
    let text = std::fs::read_to_string(pid_path(home)).ok()?;
    let pid: u32 = text.trim().parse().ok()?;
    // liveness check (a stale pid file from a crash is reclaimed later)
    let alive = std::path::Path::new(&format!("/proc/{pid}")).exists();
    if alive { Some(pid) } else { None }
}

fn pid_alive(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

// ============================================================
// Shared HTTP call machinery (unchanged v1.1 HMAC pipeline)
// ============================================================

fn call(ctx: &Ctx, method: &str, path: &str, query: Option<&str>, body: Option<&str>) -> Result<(u16, String), String> {
    let url = match query {
        Some(q) => format!("{}{}?{}", ctx.base, path, q),
        None => format!("{}{}", ctx.base, path),
    };
    let ts = state::now().to_string();
    let nonce = crypto::gen_nonce();
    let body_str = body.unwrap_or("");
    let body_sha = crypto::sha256_hex(body_str.as_bytes());
    // the device claim is the 6th signed line (bound, not swappable)
    let payload = format!("{}\n{}", crypto::signing_payload(&ts, &nonce, method, path, &body_sha), ctx.device);
    let sig = crypto::hmac_hex(&ctx.token, &payload);

    let req = if method == "GET" {
        ctx.agent.get(&url)
    } else {
        ctx.agent.post(&url)
    };
    let req = req
        .set("X-Far-Timestamp", &ts)
        .set("X-Far-Nonce", &nonce)
        .set("X-Far-Signature", &sig)
        .set("X-Far-Device", &ctx.device)
        .set("Content-Type", "application/json");

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
            "network error: {e} — is the owner's FARcontrol session running? [fail closed: no action taken]"
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

fn err_code(body: &str) -> String {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v["error"]["code"].as_str().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// call() with the §66 transport mapping (r14, e2e-found): a network failure
/// prints the r9-style error and exits 6 (5 on timeout) at the CLI boundary —
/// the previous anyhow propagation collapsed every transport error to a
/// generic 1, hiding the contract from scripts.
fn call_net(ctx: &Ctx, method: &str, path: &str, query: Option<&str>, body: Option<&str>) -> (u16, String) {
    match call(ctx, method, path, query, body) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("✗ {e} [fail closed]");
            std::process::exit(net_exit(&e))
        }
    }
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

// ============================================================
// v1.2 (ADR-0029): the connect flow — device id + session password only
// ============================================================

/// Hidden password input via termios (echo off). Requires stdin to be a tty —
/// scripts use --password-file / env instead (an echoed piped password is a
/// leak; fail closed, r7).
fn read_hidden(prompt: &str) -> anyhow::Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("stdin is not a terminal — pass --password-file <path> or set FARCONTROL_SESSION_PASSWORD");
    }
    eprint!("{prompt}");
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(libc::STDIN_FILENO, &mut t) != 0 {
            anyhow::bail!("cannot read terminal attributes — pass --password-file <path> or set FARCONTROL_SESSION_PASSWORD");
        }
        let mut t_off = t;
        t_off.c_lflag &= !libc::ECHO;
        if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t_off) != 0 {
            anyhow::bail!("cannot disable echo — pass --password-file <path> or set FARCONTROL_SESSION_PASSWORD");
        }
        let mut line = String::new();
        let res = std::io::stdin().read_line(&mut line);
        let _ = libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &t); // always restore
        eprintln!();
        res?;
        Ok(line.trim().to_string())
    }
}

fn read_line_visible(prompt: &str) -> anyhow::Result<String> {
    if !std::io::stdin().is_terminal() {
        anyhow::bail!("stdin is not a terminal — pass --device <FAR-XXXX-XXXX> or set FARCONTROL_DEVICE");
    }
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

/// The endpoint resolution ladder (ADR-0029): explicit override → remembered
/// host (saved for this device) → localhost (same machine / SSH tunnel).
/// A 1 s unauth probe — ANY HTTP answer (even 401) means "a FARcontrol lives here".
fn resolve_base(
    url_override: Option<&str>,
    device_id: &str,
    saved: Option<&Conn>,
) -> anyhow::Result<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(u) = url_override {
        candidates.push(u.trim_end_matches('/').to_string());
    } else if let Some(c) = saved {
        if c.device_id == device_id && !c.base.is_empty() {
            candidates.push(c.base.clone());
        }
    }
    candidates.push("https://127.0.0.1:7788".into());
    candidates.push("http://127.0.0.1:7788".into());
    for base in &candidates {
        // ANY HTTP answer — including 401/403 — means a FARcontrol lives
        // there. ureq turns non-2xx into Err(Status(..)); that is still alive.
        let answered = |r: Result<ureq::Response, ureq::Error>| {
            !matches!(r, Err(ureq::Error::Transport(_)))
        };
        if base.starts_with("http://") {
            let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(1)).build();
            if answered(agent.get(&format!("{base}/v1/ping")).call()) {
                return Ok(base.clone());
            }
        } else {
            // https: accept any cert for the PROBE (capture agent, no secrets sent)
            if let Ok((cap, _captured)) = crate::tls::capture_agent(Duration::from_secs(1)) {
                if answered(cap.get(&format!("{base}/v1/ping")).call()) {
                    return Ok(base.clone());
                }
            }
        }
    }
    anyhow::bail!(
        "no FARcontrol answered at: {} — if the owner's machine is remote, pass --url https://<host>:7788 once (it is remembered)",
        candidates.iter().map(|c| c.as_str()).collect::<Vec<_>>().join(", ")
    )
}

/// Build the pinned-TLS (or plain) HTTP agent for a base URL, and report the
/// SHA-256 fingerprint of the cert actually in use ("" for plain http). TOFU:
/// first connect captures + pins the daemon cert into the agent home
/// (ADR-0025 §4).
fn pinned_agent(home: &Path, base: &str, timeout: Duration) -> anyhow::Result<(ureq::Agent, String)> {
    if !base.starts_with("https") {
        return Ok((ureq::AgentBuilder::new().timeout(timeout).build(), String::new()));
    }
    let pin = home.join("cert.pem");
    if pin.exists() {
        let pem = std::fs::read_to_string(&pin)
            .with_context(|| format!("cannot read pinned cert {}", pin.display()))?;
        let fp = crate::tls::pem_first_block(&pem, "CERTIFICATE")
            .map(|der| crate::crypto::cert_fingerprint(&der))
            .unwrap_or_default();
        Ok((crate::tls::https_agent(&pem, timeout)?, fp))
    } else {
        // TOFU capture: handshake-only probe (no secrets sent), display the
        // fingerprint, pin it, THEN send the password.
        let (cap, captured) = crate::tls::capture_agent(timeout)?;
        let _ = cap.get(&format!("{base}/v1/ping")).call(); // 401 is fine — handshake captured the cert
        let der = captured
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .context("TLS handshake failed — no certificate captured (is the daemon running?")?;
        let fp = crate::crypto::cert_fingerprint(&der);
        println!("server fingerprint: {fp}  (pinned, TOFU — compare with 'frtrol fingerprint' on the owner side)");
        let pem = crate::tls::der_to_pem(&der, "CERTIFICATE");
        std::fs::create_dir_all(home)?;
        write_secret_file(&pin, &pem)?;
        Ok((crate::tls::https_agent(&pem, timeout)?, fp))
    }
}

/// Everything the v1.2 connect flow needs at the edge (r14: flags + env
/// twins, grouped so the signature stays reviewable).
struct ConnectOpts<'a> {
    url: Option<&'a str>,
    device: Option<&'a str>,
    name: Option<&'a str>,
    password_file: Option<&'a Path>,
    expect_fp: Option<&'a str>,
    timeout_secs: u64,
    as_json: bool,
}

/// The v1.2 connect flow (master prompt §11 / ADR-0029): asks for exactly
/// device id + session password, resolves the endpoint, TOFU-pins, logs in,
/// saves the connection, spawns the background runtime, prints a receipt.
fn connect(home: &Path, o: ConnectOpts) -> anyhow::Result<i32> {
    let ConnectOpts { url, device: device_flag, name: name_flag, password_file, expect_fp, timeout_secs, as_json } = o;
    let saved = read_conn(home);
    let timeout = Duration::from_secs(timeout_secs.max(1));

    // ---- inputs: flags/env beat prompts (r14); prompts need a tty ----
    let device_id = match device_flag.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()) {
        Some(d) => d,
        None => read_line_visible("device id (FAR-XXXX-XXXX): ")?,
    };
    if !crypto::device_id_valid(&device_id) {
        eprintln!("✗ '{device_id}' is not a valid FAR-XXXX-XXXX id — single typos are caught by the check char");
        eprintln!("  get the real one from the owner's 'frtrol start' output");
        return Ok(2);
    }
    let password = if let Some(pf) = password_file {
        std::fs::read_to_string(pf)
            .with_context(|| format!("cannot read --password-file {}", pf.display()))?
            .trim()
            .to_string()
    } else if let Ok(p) = std::env::var("FARCONTROL_SESSION_PASSWORD").or_else(|_| std::env::var("FARCONTROL_PASSWORD")) {
        p.trim().to_string()
    } else {
        read_hidden(&format!("session password for {device_id}: "))?
    };
    if password.is_empty() {
        eprintln!("✗ empty session password — aborting (fail closed)");
        return Ok(2);
    }
    let agent_name = name_flag
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "agent".to_string());

    // Already connected to the SAME live session? Idempotent receipt (§41 spirit).
    if let Some(c) = saved.as_ref() {
        if c.device_id == device_id {
            if let Ok((agent, _)) = pinned_agent(home, &c.base, Duration::from_secs(3)) {
                let ctx = Ctx { agent, base: c.base.clone(), token: c.key.clone(), device: c.device_id.clone(), raw: false };
                if let Ok((200, _)) = call(&ctx, "GET", "/v1/ping", None, None) {
                    let pid = runtime_pid(home);
                    if pid.is_none() {
                        // connection is valid but the runtime died — respawn it
                        spawn_runtime(home)?;
                    }
                    let msg = json!({
                        "ok": true,
                        "connected": true,
                        "device_id": c.device_id,
                        "session_id": c.session_id,
                        "base_url": c.base,
                        "agent_name": c.agent_name,
                        "note": "already connected to this session — 'frtrol agent status' for the runtime",
                    });
                    if as_json {
                        println!("{msg}");
                    } else {
                        println!("✓ already connected — device {} (session {})", c.device_id, c.session_id);
                        println!("  close the terminal anytime; access ends when the owner's session ends");
                    }
                    return Ok(0);
                }
            }
        }
    }

    // ---- endpoint ladder + TOFU ----
    let base = resolve_base(url, &device_id, saved.as_ref())?;
    let pin_existed = home.join("cert.pem").exists();
    let (agent, fp) = pinned_agent(home, &base, timeout)?;

    // Strict TOFU (ADR-0029): the expectation must match BEFORE the password
    // is sent. A mismatch removes a just-captured pin so an attacker's cert
    // can never become the trusted one by surviving this refusal.
    if let Some(want) = expect_fp.map(str::trim).filter(|s| !s.is_empty()) {
        if fp != want {
            if !pin_existed {
                let _ = std::fs::remove_file(home.join("cert.pem"));
            }
            eprintln!("✗ FINGERPRINT MISMATCH — expected {want}, daemon presented {fp}");
            eprintln!("  the session password was NOT sent; verify out-of-band ('frtrol fingerprint' on the owner machine)");
            return Ok(3);
        }
        println!("✓ fingerprint matches --expect-fp ({want}) — logging in over the pinned cert");
    }

    // ---- login: password → session key (ADR-0028) ----
    let resp = agent
        .post(&format!("{base}/v1/auth/login"))
        .set("Content-Type", "application/json")
        .send_string(&json!({ "device_id": device_id, "password": password, "agent_name": agent_name }).to_string());
    let (code, body) = match resp {
        Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(code, r)) => (code, r.into_string().unwrap_or_default()),
        Err(e) => {
            let msg = format!("network error: {e} — is the owner's session running? [fail closed]");
            eprintln!("✗ {msg}");
            return Ok(net_exit(&msg));
        }
    };
    if !(200..300).contains(&code) {
        let c = err_code(&body);
        eprintln!("{body}");
        if c == "invalid_credentials" {
            eprintln!("  the session password rotates on EVERY 'frtrol start' — get the current one");
        }
        return Ok(err_exit(&body));
    }
    let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
    let key = v["key"].as_str().unwrap_or("").to_string();
    let session_id = v["session_id"].as_str().unwrap_or("").to_string();
    if key.is_empty() {
        eprintln!("✗ server response carried no session key — aborting (fail closed)");
        return Ok(1);
    }

    // ---- save + hand off to the background runtime (ADR-0030) ----
    let conn = Conn { base: base.clone(), device_id: device_id.clone(), session_id: session_id.clone(), key: key.clone(), agent_name: agent_name.clone() };
    stop_runtime_quiet(home); // a previous runtime must not race the new connection.json
    write_conn(home, &conn)?;
    spawn_runtime(home)?;

    if as_json {
        println!(
            "{}",
            json!({
                "ok": true,
                "connected": true,
                "device_id": device_id,
                "session_id": session_id,
                "base_url": base,
                "agent_name": agent_name,
                "note": "background runtime is up — close this terminal anytime; access ends when the owner's session ends",
            })
        );
    } else {
        println!("✓ connected — device {device_id} @ {base} (agent '{agent_name}')");
        println!("  background runtime is up — close this terminal anytime.");
        println!("  access ends when the owner's session ends (they run 'frtrol stop' or restart).");
        println!("  next: frtrol agent request <name> <scope> <hours> <reason…>");
    }
    Ok(0)
}

// ============================================================
// v1.2 (ADR-0030): the background runtime — `frtrol agentd` (hidden)
// ============================================================

/// Backoff between failed heartbeats (r8): exponential, capped at 60 s.
/// Pure — unit-tested. attempt 0 → 1 s.
fn backoff_secs(attempt: u32) -> u64 {
    (1u64 << attempt.min(6)).min(60)
}

fn heartbeat_secs() -> u64 {
    if crate::policy::test_mode() { 1 } else { 15 }
}

/// Sleep that a SIGTERM can interrupt: the runtime must react to `frtrol agent
/// stop` within milliseconds, not after the current backoff nap (browser-test
/// finding: a 60 s backoff delayed the stop by up to a minute).
fn term_aware_sleep(total: Duration) {
    let step = Duration::from_millis(200);
    let mut slept = Duration::ZERO;
    while slept < total && !TERM.load(std::sync::atomic::Ordering::SeqCst) {
        std::thread::sleep(step.min(total - slept));
        slept += step;
    }
}

/// Spawn the detached runtime (ADR-0030 §decision): own process group
/// (survives the parent terminal's SIGHUP), stdio to agentd.log, single
/// instance enforced by the runtime itself via the pid file.
fn spawn_runtime(home: &Path) -> anyhow::Result<()> {
    use std::os::unix::process::CommandExt;
    std::fs::create_dir_all(home)?;
    let exe = std::env::current_exe().context("cannot resolve my own executable")?;
    let log = std::fs::OpenOptions::new().create(true).append(true).open(home.join("agentd.log"))?;
    let child = std::process::Command::new(exe)
        .arg("agentd")
        .env("FARCONTROL_AGENT_HOME", home)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log.try_clone()?))
        .stderr(std::process::Stdio::from(log))
        .process_group(0) // detach from the terminal's process group (§17)
        .spawn()
        .context("cannot spawn the background runtime")?;
    // Reap-on-exit guard: we deliberately do NOT wait — the runtime must
    // outlive this CLI. Log the pid for the receipt path.
    logline_agentd(home, &format!("runtime spawned (pid {})", child.id()));
    Ok(())
}

fn logline_agentd(home: &Path, msg: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(home.join("agentd.log")) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S");
        let _ = writeln!(f, "[{ts}] {msg}");
    }
}

/// Terminal states clear the credentials (fail closed — no zombie keys).
fn runtime_finish(home: &Path, state: &str, last_error: Option<String>) {
    if let Some(c) = read_conn(home) {
        write_status(
            home,
            &RuntimeStatus {
                state: state.to_string(),
                agent_name: c.agent_name,
                device_id: c.device_id,
                session_id: c.session_id,
                base_url: c.base,
                pid: std::process::id(),
                last_ok: Some(state::now()),
                last_error,
                updated_at: state::now(),
            },
        );
    }
    clear_conn(home);
    let _ = std::fs::remove_file(pid_path(home));
    logline_agentd(home, &format!("runtime exiting: state={state}"));
}

/// SIGTERM → the operator asked to stop (`frtrol agent stop`): clean exit,
/// credentials cleared (fail closed).
fn stop_runtime(home: &Path, as_json: bool) -> anyhow::Result<i32> {
    let pid = runtime_pid(home);
    if let Some(pid) = pid {
        let stopped = stop_pid(pid);
        if !stopped {
            runtime_finish(home, "stopped", None); // dead runtime: clear its state anyway
        }
        let msg = json!({ "ok": true, "stopped": pid, "note": "runtime stopped — saved connection cleared (fail closed)" });
        if as_json {
            println!("{msg}");
        } else {
            println!("✓ runtime stopped (pid {pid}) — saved connection cleared");
            println!("  reconnect any time: frtrol agent");
        }
        Ok(0)
    } else {
        // no runtime: still clear any leftover credentials
        runtime_finish(home, "stopped", None);
        let msg = json!({ "ok": true, "stopped": false, "note": "no runtime was running — any saved connection is cleared" });
        if as_json {
            println!("{msg}");
        } else {
            println!("✓ no runtime was running — any saved connection is cleared");
        }
        Ok(0)
    }
}

fn stop_pid(pid: u32) -> bool {
    // SIGTERM; wait up to 5 s for a clean exit (the handler clears creds);
    // escalate to SIGKILL so a stuck runtime can never block a reconnect
    // (browser-test finding: the old runtime outlived the new spawn).
    unsafe {
        if libc::kill(pid as i32, libc::SIGTERM) != 0 {
            return false;
        }
    }
    for _ in 0..50 {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    unsafe {
        libc::kill(pid as i32, libc::SIGKILL);
    }
    for _ in 0..20 {
        if !pid_alive(pid) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn stop_runtime_quiet(home: &Path) {
    if let Some(pid) = runtime_pid(home) {
        let _ = stop_pid(pid);
    }
}

/// `frtrol agent status` (no id) — the runtime state, from status.json +
/// pid liveness. No network needed (fail-open read of local state only).
fn runtime_status(home: &Path, as_json: bool) -> anyhow::Result<i32> {
    let st = read_status(home);
    let has_conn = read_conn(home).is_some();
    let pid = runtime_pid(home);
    let v = match st {
        Some(mut v) => {
            let alive = pid.map(pid_alive).unwrap_or(false);
            v["runtime_alive"] = json!(alive);
            v
        }
        None => json!({ "state": if has_conn { "starting" } else { "never-connected" }, "runtime_alive": pid.is_some() }),
    };
    if as_json {
        println!("{}", serde_json::to_string(&v)?);
        return Ok(0);
    }
    let state = v["state"].as_str().unwrap_or("?");
    let icon = match state {
        "connected" => "✓",
        "reconnecting" => "…",
        "expired" | "revoked" => "✗",
        _ => "·",
    };
    let name = v["agent_name"].as_str().unwrap_or("agent");
    let dev = v["device_id"].as_str().unwrap_or("?");
    println!("{icon} agent '{name}' — {state} (device {dev})");
    if let Some(e) = v["last_error"].as_str() {
        println!("  last error: {e}");
    }
    match state {
        "connected" => println!("  close the terminal anytime; ops: frtrol agent exec <ses_id> <cmd>"),
        "reconnecting" => println!("  network trouble — the runtime keeps retrying (backoff, cap 60s)"),
        "expired" | "revoked" => println!("  the owner's session ended — get the new session password, then: frtrol agent"),
        "stopped" => println!("  reconnect: frtrol agent"),
        _ => {}
    }
    Ok(0)
}

/// The hidden `frtrol agentd` entrypoint (ADR-0030). Owns the heartbeat loop:
/// CONNECTED → (network loss) → RECONNECTING (exp backoff, cap 60s) → …
/// Terminal: expired/revoked (credentials cleared, exit 0). SIGTERM: stopped.
pub fn agentd_main() -> anyhow::Result<i32> {
    let home: PathBuf = match std::env::var("FARCONTROL_AGENT_HOME") {
        Ok(h) => PathBuf::from(h),
        Err(_) => default_agent_home()?,
    };
    std::fs::create_dir_all(&home)?;
    let Some(conn) = read_conn(&home) else {
        eprintln!("agentd: no connection.json — run 'frtrol agent' first");
        return Ok(1);
    };
    // single instance per home: a live pid file means another runtime runs
    if let Some(pid) = runtime_pid(&home) {
        eprintln!("agentd: a runtime is already running (pid {pid}) — exiting");
        return Ok(0);
    }
    write_secret_file(&pid_path(&home), &std::process::id().to_string())?;
    logline_agentd(&home, "runtime starting");

    // SIGTERM → clean stop (credentials cleared — fail closed)
    unsafe {
        libc::signal(libc::SIGTERM, handle_term as *const () as usize);
    }

    let (agent, _) = pinned_agent(&home, &conn.base, Duration::from_secs(10))?;
    let ctx = Ctx { agent, base: conn.base.clone(), token: conn.key.clone(), device: conn.device_id.clone(), raw: false };
    let mut attempt: u32 = 0;
    let status = |state: &str, last_ok: Option<i64>, last_error: Option<String>| {
        write_status(
            &home,
            &RuntimeStatus {
                state: state.to_string(),
                agent_name: conn.agent_name.clone(),
                device_id: conn.device_id.clone(),
                session_id: conn.session_id.clone(),
                base_url: conn.base.clone(),
                pid: std::process::id(),
                last_ok,
                last_error,
                updated_at: state::now(),
            },
        )
    };
    loop {
        if TERM.load(std::sync::atomic::Ordering::SeqCst) {
            runtime_finish(&home, "stopped", None);
            return Ok(0);
        }
        match call(&ctx, "GET", "/v1/heartbeat", Some(&format!("name={}", conn.agent_name)), None) {
            Ok((200..300, body)) => {
                attempt = 0;
                // session mismatch guard: if the daemon restarted under us, the
                // key is dead and the next beat 401s — but check proactively.
                if let Ok(v) = serde_json::from_str::<Value>(&body) {
                    if v["session_id"].as_str().is_some_and(|s| s != conn.session_id) {
                        logline_agentd(&home, "daemon session changed — credentials are stale, ending");
                        runtime_finish(&home, "expired", Some("daemon session changed".into()));
                        return Ok(0);
                    }
                }
                status("connected", Some(state::now()), None);
                term_aware_sleep(Duration::from_secs(heartbeat_secs()));
            }
            Ok((code, body)) => {
                // a definitive rejection means OUR credentials are dead
                if code == 401 || code == 403 {
                    let c = err_code(&body);
                    let state = if c == "device_locked" { "revoked" } else { "expired" };
                    logline_agentd(&home, &format!("heartbeat rejected ({code} {c}) — {state}"));
                    runtime_finish(&home, state, Some(format!("rejected: {c}")));
                    return Ok(0);
                }
                // 429 rate_limited / 5xx: transient — back off and retry
                let err = format!("http {code}: {}", err_code(&body));
                status("reconnecting", None, Some(err));
                term_aware_sleep(Duration::from_secs(backoff_secs(attempt)));
                attempt += 1;
            }
            Err(e) => {
                // network down: retry forever with backoff (§20 — a temporary
                // failure must not destroy the logical session)
                status("reconnecting", None, Some(e.clone()));
                term_aware_sleep(Duration::from_secs(backoff_secs(attempt)));
                attempt += 1;
            }
        }
    }
}

static TERM: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn handle_term(_sig: libc::c_int) {
    TERM.store(true, std::sync::atomic::Ordering::SeqCst);
}

// ============================================================
// Entry
// ============================================================

/// Everything `frtrol agent` needs at the edge (r14: flags + env twins, one
/// struct so the signature stays reviewable).
pub struct AgentArgs {
    pub url: Option<String>,
    pub device: Option<String>,
    pub name: Option<String>,
    pub password_file: Option<PathBuf>,
    /// Strict TOFU (ADR-0029): abort before the password unless the daemon
    /// fingerprint is exactly this (SHA256:…).
    pub expect_fp: Option<String>,
    pub timeout_secs: u64,
    pub raw: bool,
    /// --json / FARCONTROL_JSON: machine-readable receipts (ADR-0026).
    pub json: bool,
}

pub fn run(home: &Path, args: AgentArgs, cmd: Option<crate::AgentCmd>) -> anyhow::Result<i32> {
    let AgentArgs { url, device, name, password_file, expect_fp, timeout_secs, raw, json } = args;
    // bare `frtrol agent` = the connect flow (ADR-0029)
    let Some(cmd) = cmd else {
        return connect(home, ConnectOpts {
            url: url.as_deref(),
            device: device.as_deref(),
            name: name.as_deref(),
            password_file: password_file.as_deref(),
            expect_fp: expect_fp.as_deref(),
            timeout_secs,
            as_json: json,
        });
    };
    match cmd {
        crate::AgentCmd::Stop => stop_runtime(home, json),
        crate::AgentCmd::Status { id: None } => runtime_status(home, json),
        crate::AgentCmd::Status { id: Some(id) } => {
            let conn = load_conn_ctx(home, timeout_secs, raw)?;
            let query = if id.starts_with("ses") {
                format!("session_id={id}")
            } else if id.starts_with("req") {
                format!("request_id={id}")
            } else {
                anyhow::bail!("'{id}' does not look like a request id (req_...) or session id (ses_...)")
            };
            let (c, b) = call_net(&conn, "GET", "/v1/session/status", Some(&query), None);
            emit(&conn, c, b)
        }
        crate::AgentCmd::Ping => {
            let conn = load_conn_ctx(home, timeout_secs, raw)?;
            let (c, b) = call_net(&conn, "GET", "/v1/ping", None, None);
            emit(&conn, c, b)
        }
        other => {
            // capability subcommands share the saved connection
            let conn = load_conn_ctx(home, timeout_secs, raw)?;
            cmd_exec(&conn, other)
        }
    }
}

/// Load the saved connection + pinned cert → a ready Ctx. Fails with a
/// next-command hint when nothing is saved (r9).
fn load_conn_ctx(home: &Path, timeout_secs: u64, raw: bool) -> anyhow::Result<Ctx> {
    let conn = read_conn(home).or_else(|| {
        // v1.1-style files in the AGENT home are honored (legacy layout)
        let dev = std::fs::read_to_string(home.join("device-id")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())?;
        let key = std::fs::read_to_string(home.join("device-key")).ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())?;
        let base = if home.join("cert.pem").exists() { "https://127.0.0.1:7788".to_string() } else { "http://127.0.0.1:7788".to_string() };
        Some(Conn { base, device_id: dev, session_id: String::new(), key, agent_name: "agent".into() })
    });
    let Some(conn) = conn else {
        anyhow::bail!("no saved connection — run 'frtrol agent' (device id + session password) on this machine first");
    };
    let (agent, _) = pinned_agent(home, &conn.base, Duration::from_secs(timeout_secs.max(1)))?;
    Ok(Ctx { agent, base: conn.base, token: conn.key, device: conn.device_id, raw })
}

fn cmd_exec(ctx: &Ctx, cmd: crate::AgentCmd) -> anyhow::Result<i32> {
    match cmd {
        crate::AgentCmd::Stop | crate::AgentCmd::Status { id: None } => unreachable!("handled in run()"),
        crate::AgentCmd::Ping => unreachable!(),
        crate::AgentCmd::Status { .. } => unreachable!(),
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
            let (c, b) = call_net(ctx, "POST", "/v1/session/request", None, Some(&body.to_string()));
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
        crate::AgentCmd::Exec { session, command, timeout_ms } => {
            if command.is_empty() {
                anyhow::bail!("no command given — usage: frtrol agent exec <session-id> <command...>");
            }
            let body = json!({
                "session_id": session,
                "command": command[0],
                "args": &command[1..],
                "timeout_ms": timeout_ms,
            });
            let (c, b) = call_net(ctx, "POST", "/v1/exec", None, Some(&body.to_string()));
            emit_exec(ctx, c, b)
        }
        crate::AgentCmd::Read { session, path } => {
            let body = json!({ "session_id": session, "path": path });
            let (c, b) = call_net(ctx, "POST", "/v1/file/read", None, Some(&body.to_string()));
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
            let (c, b) = call_net(ctx, "POST", "/v1/file/write", None, Some(&body.to_string()));
            emit(ctx, c, b)
        }
        crate::AgentCmd::Ls { session, path } => {
            let body = json!({ "session_id": session, "path": path });
            let (c, b) = call_net(ctx, "POST", "/v1/file/list", None, Some(&body.to_string()));
            emit(ctx, c, b)
        }
        crate::AgentCmd::Ps { session } => {
            let body = json!({ "session_id": session });
            let (c, b) = call_net(ctx, "POST", "/v1/process/list", None, Some(&body.to_string()));
            emit(ctx, c, b)
        }
        crate::AgentCmd::Kill { session, pid, force } => {
            let body = json!({ "session_id": session, "pid": pid, "force": force });
            let (c, b) = call_net(ctx, "POST", "/v1/process/kill", None, Some(&body.to_string()));
            emit(ctx, c, b)
        }
        crate::AgentCmd::App { session, command } => {
            if command.is_empty() {
                anyhow::bail!("no command given — usage: frtrol agent app <session-id> <command...>");
            }
            let body = json!({ "session_id": session, "command": command[0], "args": &command[1..] });
            let (c, b) = call_net(ctx, "POST", "/v1/app/launch", None, Some(&body.to_string()));
            emit(ctx, c, b)
        }
        crate::AgentCmd::Shot { session } => {
            let body = json!({ "session_id": session });
            let (c, b) = call_net(ctx, "POST", "/v1/desktop/screenshot", None, Some(&body.to_string()));
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
            let (c, b) = call_net(ctx, "POST", "/v1/desktop/input", None, Some(&body.to_string()));
            emit(ctx, c, b)
        }
        crate::AgentCmd::Revoke { session } => {
            let body = json!({ "session_id": session });
            let (c, b) = call_net(ctx, "POST", "/v1/session/revoke", None, Some(&body.to_string()));
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
    let (c, b) = call_net(ctx, "POST", "/v1/term/open", None, Some(&body.to_string()));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_exponential_and_capped() {
        assert_eq!(backoff_secs(0), 1);
        assert_eq!(backoff_secs(1), 2);
        assert_eq!(backoff_secs(2), 4);
        assert_eq!(backoff_secs(3), 8);
        assert_eq!(backoff_secs(5), 32);
        assert_eq!(backoff_secs(6), 60, "cap at 60s (r8)");
        assert_eq!(backoff_secs(20), 60, "cap holds forever");
    }

    #[test]
    fn connection_roundtrip_via_files() {
        let home = std::env::temp_dir().join(format!("farcontrol-agent-test-{}", crypto::gen_nonce()));
        std::fs::create_dir_all(&home).unwrap();
        assert!(read_conn(&home).is_none(), "no connection yet");
        let c = Conn {
            base: "https://127.0.0.1:7788".into(),
            device_id: "FAR-7K2M-QX94".into(),
            session_id: "ses_x".into(),
            key: "k".into(),
            agent_name: "tester".into(),
        };
        write_conn(&home, &c).unwrap();
        let got = read_conn(&home).expect("roundtrip");
        assert_eq!(got.base, c.base);
        assert_eq!(got.device_id, c.device_id);
        assert_eq!(got.session_id, c.session_id);
        assert_eq!(got.key, c.key);
        assert_eq!(got.agent_name, c.agent_name);
        // 0600 on the secret file
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(conn_path(&home)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "connection.json must be owner-only");
        clear_conn(&home);
        assert!(read_conn(&home).is_none());
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn endpoint_ladder_prefers_override_then_saved_then_localhost_order() {
        // pure candidate-order check without network: we can only assert the
        // ladder via resolve_base's failure message (all candidates listed).
        let home = std::env::temp_dir().join(format!("farcontrol-agent-test-{}", crypto::gen_nonce()));
        std::fs::create_dir_all(&home).unwrap();
        let err = resolve_base(Some("https://10.9.8.7:7788"), "FAR-7K2M-QX94", None).unwrap_err().to_string();
        assert!(err.contains("https://10.9.8.7:7788"), "override listed first: {err}");
        assert!(err.contains("https://127.0.0.1:7788"), "localhost in the ladder: {err}");
        let _ = std::fs::remove_dir_all(&home);
    }
}
