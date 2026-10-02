use crate::config::Config;
use crate::crypto;
use crate::state;
use anyhow::Context;
use serde_json::{json, Value};
use std::path::Path;
use std::time::Duration;

// Owner-plane CLI (ADR-0006): every decision goes through the daemon's loopback
// admin API — the CLI never opens the database directly.

fn set_dir_private(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
}

pub fn init(data_dir: &Path) -> anyhow::Result<()> {
    let did = init_quiet(data_dir)?;
    if !did {
        println!("already initialized: {}", data_dir.display());
    }
    Ok(())
}

/// Create data dir + tokens + db if missing. Returns true if it initialized now.
/// Idempotent: a pre-existing config.toml WITHOUT state.db is completed (not
/// rejected) so the owner can pre-seed `[identity] secret_store = "keyring"`
/// before the first run (ADR-0023).
pub fn init_quiet(data_dir: &Path) -> anyhow::Result<bool> {
    let cfg_path = data_dir.join("config.toml");
    let cfg: Config = if cfg_path.exists() {
        let text = std::fs::read_to_string(&cfg_path)?;
        let cfg: Config = toml::from_str(&text)
            .with_context(|| format!("config_invalid: cannot parse {}", cfg_path.display()))?;
        // SC-02 (ADR-0023): a bad pre-seeded config fails the init loudly.
        if let Err(e) = cfg.validate() {
            anyhow::bail!("config_invalid: {e}");
        }
        cfg
    } else {
        Config::default()
    };
    if data_dir.join("state.db").exists() {
        // truly initialized already (config + state both present)
        return Ok(false);
    }
    std::fs::create_dir_all(data_dir).with_context(|| format!("cannot create {}", data_dir.display()))?;
    set_dir_private(data_dir);

    if !cfg_path.exists() {
        std::fs::write(&cfg_path, toml::to_string_pretty(&cfg)?)?;
    }

    let keyring_mode = cfg.keyring_mode();
    if keyring_mode && !crate::keyring::usable() {
        anyhow::bail!(
            "config_invalid: [identity] secret_store = 'keyring' but this environment's kernel keyring is not fully usable (partial sandbox implementation) — use 'file' instead (fail closed)"
        );
    }

    let conn = state::open_db(&data_dir.join("state.db"))?;
    // v1.1 (ADR-0025): fresh installs create NO agent token — the owner
    // registers a device (`frtrol device add`) and hands the agent only
    // the device id + password. Legacy tokens migrate at daemon start.
    let admin_token = crypto::gen_token();
    if keyring_mode {
        // ID-04 (ADR-0023): device keys live in the kernel keyring only —
        // seeded as an empty map; no plaintext anywhere.
        crate::keyring::store(data_dir, "{}")
            .with_context(|| "kernel keyring store failed (secret_store=keyring)")?;
        state::set_meta(&conn, "secret_store", "keyring")?;
    } else {
        state::set_meta(&conn, "secret_store", "file")?;
    }
    state::set_meta(&conn, "admin_token", &admin_token)?;
    state::set_meta(&conn, "schema_version", "1")?;
    state::set_meta(&conn, "created_at", &state::now().to_string())?;
    crate::server::write_secret(&data_dir.join("admin-token"), &admin_token)?;
    state::audit(&conn, data_dir, "owner", "system.initialized", None, json!({ "version": env!("CARGO_PKG_VERSION"), "secret_store": if keyring_mode { "keyring" } else { "file" } }));

    // v0.2: generate the TLS pair up front so `start` and `doctor` always have it.
    let _ = crate::tls::ensure_cert(data_dir)?;

    println!("initialized {} (first run)", data_dir.display());
    println!();
    println!("next step — register a device for your AI agent:");
    println!("  frtrol device add <name>");
    println!("  → prints a device id (FAR-XXXX-XXXX) + password (shown once)");
    println!("  → the agent logs in with just those two: frtrol agent login <device-id>");
    println!();
    println!("admin token (web console login — stored in admin-token, mode 0600):");
    println!("  {admin_token}");
    println!();
    Ok(true)
}

struct Admin {
    agent: ureq::Agent,
    base: String,
    token: String,
}

/// Server-rejected owner action (ADR-0022 / §66). Carries the wire error code
/// so `main` can map it to the stable exit-code contract instead of a bare 1.
#[derive(Debug)]
pub struct OwnerErr {
    pub code: String,
    pub msg: String,
}
impl std::fmt::Display for OwnerErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.msg)
    }
}
impl std::error::Error for OwnerErr {}

fn admin(data_dir: &Path) -> anyhow::Result<Admin> {
    let cfg_path = data_dir.join("config.toml");
    if !cfg_path.exists() {
        anyhow::bail!("not initialized — run: frtrol start (auto-initializes)");
    }
    let cfg: Config = toml::from_str(&std::fs::read_to_string(&cfg_path)?)?;
    let token = std::fs::read_to_string(data_dir.join("admin-token"))
        .context("cannot read admin-token (0600) — is this the owner account? run: frtrol start")?;
    let timeout = Duration::from_secs(15);
    let (agent, scheme) = if cfg.use_tls {
        let pem = std::fs::read_to_string(data_dir.join("cert.pem"))
            .context("use_tls=true but cert.pem is missing — restart the daemon once to auto-generate it")?;
        (crate::tls::https_agent(&pem, timeout)?, "https")
    } else {
        (ureq::AgentBuilder::new().timeout(timeout).build(), "http")
    };
    Ok(Admin { agent, base: format!("{}://{}", scheme, cfg.admin_bind), token: token.trim().to_string() })
}

impl Admin {
    fn call(&self, method: &str, path: &str, body: Option<&Value>) -> anyhow::Result<Value> {
        let req = if method == "GET" {
            self.agent.get(&format!("{}{}", self.base, path))
        } else {
            self.agent.post(&format!("{}{}", self.base, path))
        };
        let req = req
            .set("Authorization", &format!("Bearer {}", self.token))
            .set("Content-Type", "application/json");
        let resp = match body {
            Some(b) => req.send_string(&b.to_string()),
            None => req.call(),
        };
        let resp = match resp {
            Ok(r) => r,
            // error bodies from our own daemon are JSON — surface them
            Err(ureq::Error::Status(_, r)) => r,
            Err(e) => anyhow::bail!("cannot reach daemon: {e} — is 'frtrol start' running?"),
        };
        let status = resp.status();
        let text = resp.into_string()?;
        let v: Value = serde_json::from_str(&text).unwrap_or(json!({ "raw": text }));
        if status >= 400 {
            let code = v["error"]["code"].as_str().unwrap_or("unknown_error");
            let msg = v["error"]["message"].as_str().unwrap_or("");
            return Err(anyhow::Error::new(OwnerErr {
                code: code.to_string(),
                msg: format!("[{code}] {msg}"),
            }));
        }
        Ok(v)
    }
    fn get(&self, path: &str) -> anyhow::Result<Value> {
        self.call("GET", path, None)
    }
    fn post(&self, path: &str, body: &Value) -> anyhow::Result<Value> {
        self.call("POST", path, Some(body))
    }
}

fn iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

pub fn status(data_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.get("/admin/ping")?;
    let devs = a.get("/admin/devices")?;
    if as_json {
        // §45 (CL-02) + ADR-0026: stable machine output, one line, additive schema.
        println!("{}", serde_json::to_string(&json!({
            "service": "farcontrol",
            "version": v["version"],
            "daemon": true,
            "pending_count": v["pending_count"],
            "active_count": v["active_count"],
            "devices": devs["count"],
            "uptime_secs": v["uptime_secs"],
        }))?);
        return Ok(());
    }
    crate::out::section(&format!("FARcontrol {} — daemon up", v["version"].as_str().unwrap_or("?")));
    let uptime = v["uptime_secs"].as_i64().unwrap_or(0);
    crate::out::dim(&format!("{} up, {} pending · {} active session(s) · {} device(s)",
        crate::out::humanize(uptime),
        v["pending_count"].as_i64().unwrap_or(0),
        v["active_count"].as_i64().unwrap_or(0),
        devs["count"].as_i64().unwrap_or(0),
    ));
    crate::out::hint("frtrol list shows every pending request and session");
    Ok(())
}

pub fn list(data_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let reqs = a.get("/admin/requests?status=pending")?;
    let sess = a.get("/admin/sessions")?;
    if as_json {
        // §45 (CL-02): stable machine-readable requests + sessions lists.
        println!("{}", serde_json::to_string(&json!({ "requests": reqs["requests"], "sessions": sess["sessions"] }))?);
        return Ok(());
    }

    crate::out::section("Pending requests");
    let pending = reqs["requests"].as_array().cloned().unwrap_or_default();
    if pending.is_empty() {
        crate::out::empty("no pending requests — nothing is waiting on you.");
    } else {
        let rows: Vec<Vec<String>> = pending
            .iter()
            .map(|r| {
                // AGENT cell carries the declared identity when present (§11)
                let mut agent_cell = r["agent_name"].as_str().unwrap_or("?").to_string();
                if let (Some(p), Some(m)) = (r["agent_provider"].as_str(), r["agent_model"].as_str()) {
                    agent_cell.push_str(&format!("\n{p}/{m}"));
                }
                vec![
                    r["id"].as_str().unwrap_or("?").into(),
                    agent_cell,
                    r["scope"].as_str().unwrap_or("?").into(),
                    format!("{:.1}h", r["requested_hours"].as_f64().unwrap_or(0.0)),
                    crate::out::ago(r["created_at"].as_i64()),
                    crate::out::trunc(r["reason"].as_str().unwrap_or(""), 30),
                    r["device_id"].as_str().unwrap_or("legacy").into(),
                ]
            })
            .collect();
        println!("{}", crate::out::table(&["ID", "AGENT", "SCOPE", "ASKED", "WAITING", "REASON", "DEVICE"], &rows));
        let first_id = pending[0]["id"].as_str().unwrap_or("?");
        crate::out::hint(&format!("frtrol approve {first_id} — optional hours shortens it · frtrol deny {first_id}"));
    }
    println!();
    crate::out::section("Sessions");
    let sessions = sess["sessions"].as_array().cloned().unwrap_or_default();
    if sessions.is_empty() {
        crate::out::empty("no sessions yet — agents get access only after you approve.");
    } else {
        let now = state::now();
        let rows: Vec<Vec<String>> = sessions
            .iter()
            .map(|s| {
                let eff = s["effective_status"].as_str().unwrap_or("?");
                let dot = match eff {
                    "active" => {
                        let remaining = s["expires_at"].as_i64().unwrap_or(0) - now;
                        if remaining < 3600 {
                            format!("{} {} left", crate::out::dot(crate::out::Dot::Warn), crate::out::humanize(remaining))
                        } else {
                            format!("{} {} left", crate::out::dot(crate::out::Dot::Active), crate::out::humanize(remaining))
                        }
                    }
                    "expired" => crate::out::dot(crate::out::Dot::Dead2),
                    "revoked" => crate::out::dot(crate::out::Dot::Revoked),
                    other => other.to_string(),
                };
                let mut agent_cell = s["agent_name"].as_str().unwrap_or("?").to_string();
                if let (Some(p), Some(m)) = (s["agent_provider"].as_str(), s["agent_model"].as_str()) {
                    agent_cell.push_str(&format!("\n{p}/{m}"));
                }
                vec![
                    s["id"].as_str().unwrap_or("?").into(),
                    agent_cell,
                    s["scope"].as_str().unwrap_or("?").into(),
                    dot,
                    s["device_id"].as_str().unwrap_or("legacy").into(),
                    iso(s["expires_at"].as_i64().unwrap_or(0)),
                ]
            })
            .collect();
        println!("{}", crate::out::table(&["ID", "AGENT", "SCOPE", "STATE", "DEVICE", "EXPIRES"], &rows));
        for s in &sessions {
            if s["effective_status"] == "active" {
                crate::out::hint(&format!("frtrol revoke {} — access dies immediately", s["id"].as_str().unwrap_or("?")));
                break;
            }
        }
    }
    Ok(())
}

pub fn approve(data_dir: &Path, id: &str, hours: Option<f64>) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let mut body = json!({ "request_id": id });
    if let Some(h) = hours {
        body["hours"] = json!(h);
    }
    let v = a.post("/admin/approve", &body)?;
    let s = &v["session"];
    let sid = s["id"].as_str().unwrap_or("?");
    let scope = s["scope"].as_str().unwrap_or("?");
    // session payloads carry expires_at (authoritative) — derive the duration
    let left = s["expires_at"].as_i64().unwrap_or(0) - state::now();
    let dev = s["device_id"].as_str().unwrap_or("legacy");
    crate::out::ok_receipt(&format!("approved {id} → {sid} ({}, {scope}, device {dev})", crate::out::humanize(left.max(0))));
    crate::out::hint(&format!("agent runs commands: frtrol agent exec {sid} <command>"));
    Ok(())
}

pub fn deny(data_dir: &Path, id: &str, reason: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/deny", &json!({ "request_id": id, "reason": reason }))?;
    crate::out::err_receipt(&format!("denied {} — no session was created", v["request"]["id"].as_str().unwrap_or(id)));
    Ok(())
}

pub fn revoke(data_dir: &Path, id: &str, reason: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    a.post("/admin/revoke", &json!({ "session_id": id, "reason": reason }))?;
    crate::out::err_receipt(&format!("revoked {id} — access died immediately"));
    Ok(())
}

pub fn rotate(data_dir: &Path) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/rotate", &json!({}))?;
    println!("NEW legacy-device key (old one is dead — update the v1.0 agent NOW):");
    println!("  {}", v["agent_token"].as_str().unwrap_or("?"));
    Ok(())
}

// ============================================================
// v1.1 (ADR-0025 §5): device management — via the admin plane like every
// other owner decision (ADR-0006: the CLI never opens the DB directly).
// ============================================================

pub fn device_add(data_dir: &Path, name: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/devices/add", &json!({ "name": name }))?;
    let id = v["device_id"].as_str().unwrap_or("?");
    let password = v["password"].as_str().unwrap_or("?");
    println!("✓ device created — {id} \"{name}\"");
    println!();
    println!("DEVICE PASSWORD (shown once — store it now):");
    println!("  {password}");
    println!();
    println!("The agent needs ONLY two things:");
    println!("  device id : {id}");
    println!("  password  : (the line above)");
    println!();
    println!("Agent onboarding (on the agent machine):");
    println!("  frtrol agent login {id}        # password prompted, or FARCONTROL_PASSWORD=… ");
    Ok(())
}

pub fn device_list(data_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.get("/admin/devices")?;
    if as_json {
        println!("{}", serde_json::to_string(&v)?);
        return Ok(());
    }
    let devices = v["devices"].as_array().cloned().unwrap_or_default();
    crate::out::section("Devices");
    if devices.is_empty() {
        crate::out::empty("no devices registered — add one: frtrol device add <name>");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = devices
        .iter()
        .map(|d| {
            let status = if d["key_only"].as_bool().unwrap_or(false) {
                format!("{} key-only", crate::out::dot(crate::out::Dot::Dead))
            } else if d["login_enabled"].as_bool().unwrap_or(false) {
                crate::out::dot(crate::out::Dot::Active)
            } else {
                crate::out::dot(crate::out::Dot::Locked)
            };
            vec![
                d["id"].as_str().unwrap_or("?").into(),
                crate::out::trunc(d["name"].as_str().unwrap_or("?"), 18),
                status,
                crate::out::ago(d["last_seen"].as_i64()),
                d["active_sessions"].as_i64().unwrap_or(0).to_string(),
            ]
        })
        .collect();
    println!("{}", crate::out::table(&["ID", "NAME", "STATUS", "LAST SEEN", "SESSIONS"], &rows));
    crate::out::hint("frtrol device passwd <id> rotates its password · lock/unlock gates its login");
    Ok(())
}

pub fn device_lock(data_dir: &Path, id: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/devices/lock", &json!({ "id": id }))?;
    let n = v["revoked_sessions"].as_array().map(|s| s.len()).unwrap_or(0);
    println!("✓ device {id} LOCKED — login disabled, key rotated, {n} session(s) revoked");
    Ok(())
}

pub fn device_unlock(data_dir: &Path, id: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    a.post("/admin/devices/unlock", &json!({ "id": id }))?;
    println!("✓ device {id} unlocked — login re-enabled (password unchanged)");
    Ok(())
}

pub fn device_passwd(data_dir: &Path, id: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/devices/passwd", &json!({ "id": id }))?;
    println!("✓ device {id} — password + key rotated (the old key is dead)");
    println!();
    println!("NEW DEVICE PASSWORD (shown once):");
    println!("  {}", v["password"].as_str().unwrap_or("?"));
    println!();
    println!("The device must re-login: frtrol agent login {id}");
    Ok(())
}

pub fn device_remove(data_dir: &Path, id: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/devices/remove", &json!({ "id": id }))?;
    let n = v["revoked_sessions"].as_array().map(|s| s.len()).unwrap_or(0);
    println!("✗ device {id} removed — key destroyed, {n} session(s) revoked");
    Ok(())
}

/// v1.1 (ADR-0025 §4): owner-side cert fingerprint — compare with what the
/// agent shows at `frtrol agent login` (out-of-band TOFU verification).
pub fn fingerprint(data_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let pem = std::fs::read_to_string(data_dir.join("cert.pem"))
        .with_context(|| "cert.pem missing — run 'frtrol start' once (auto-generates it)")?;
    let fp = crate::tls::pem_first_block(&pem, "CERTIFICATE")
        .map(|der| crate::crypto::cert_fingerprint(&der))
        .context("cert.pem carries no CERTIFICATE block — regenerate it (delete cert.pem + restart)");
    if as_json {
        println!("{}", json!({ "fingerprint": fp? }));
    } else {
        crate::out::section("Daemon certificate fingerprint");
        println!("  {}", fp?);
        crate::out::hint("compare with the 'server fingerprint:' line the agent prints at login");
    }
    Ok(())
}

pub fn audit(data_dir: &Path, limit: u32, as_json: bool) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.get(&format!("/admin/audit?limit={}", limit.min(1000)))?;
    let events = v["events"].as_array().cloned().unwrap_or_default();
    if as_json {
        println!("{}", serde_json::to_string(&json!({ "events": events, "count": events.len() }))?);
        return Ok(());
    }
    crate::out::section(&format!("Audit — last {} event(s)", events.len()));
    if events.is_empty() {
        crate::out::empty("no audit events yet.");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = events
        .iter()
        .map(|e| {
            vec![
                iso(e["ts"].as_i64().unwrap_or(0)),
                crate::out::trunc(e["actor"].as_str().unwrap_or("?"), 24),
                crate::out::trunc(e["action"].as_str().unwrap_or("?"), 26),
                e["subject"].as_str().unwrap_or("").to_string(),
            ]
        })
        .collect();
    println!("{}", crate::out::table(&["TIME", "ACTOR", "ACTION", "SUBJECT"], &rows));
    crate::out::hint("full detail (JSON fields) — frtrol audit --json");
    Ok(())
}

/// EMERGENCY STOP (SE-11): one call — every session revoked, every pending
/// request expired, every terminal killed, every device key rotated (ADR-0025 §5).
pub fn panic_stop(data_dir: &Path, reason: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/panic", &json!({ "reason": reason }))?;
    println!("PANIC executed:");
    println!("  revoked sessions   : {}", v["revoked_sessions"].as_i64().unwrap_or(0));
    println!("  expired pending    : {}", v["expired_pending"].as_i64().unwrap_or(0));
    println!("  killed terminals   : {}", v["killed_terminals"].as_i64().unwrap_or(0));
    println!("  device keys rotated: {}", v["rotated_device_keys"].as_i64().unwrap_or(0));
    println!();
    println!("Every device key is dead — agents must re-login (device id + password).");
    println!("Trust a device again: frtrol device passwd <FAR-XXXX-XXXX> → hand out the new password.");
    Ok(())
}

/// Health checks (spec §46): local first (works with the daemon down), then
/// remote via the admin plane. Exit code 0 = all green.
pub fn doctor(data_dir: &Path) -> anyhow::Result<i32> {
    let mut bad = 0usize;
    let mut check = |name: &str, ok: bool, detail: &str, action: &str| {
        if ok {
            println!("[ ok ] {name:<12} {detail}");
        } else {
            bad += 1;
            println!("[FAIL] {name:<12} {detail}");
            println!("       fix: {action}");
        }
    };

    // ---- local checks (no daemon needed) ----
    let cfg_path = data_dir.join("config.toml");
    let mut parsed: Option<Config> = None;
    let cfg_ok = cfg_path.exists()
        && std::fs::read_to_string(&cfg_path)
            .map(|t| {
                match toml::from_str::<Config>(&t) {
                    Ok(c) => {
                        // SC-02 (ADR-0023): parse + validate, not just parse.
                        let ok = c.validate().is_ok();
                        parsed = Some(c);
                        ok
                    }
                    Err(_) => false,
                }
            })
            .unwrap_or(false);
    check("config", cfg_ok, "config.toml parses and validates", "fix the config.toml values shown by 'frtrol start' (config_invalid: ...)");

    // v0.9→v1.1 (ADR-0023/0025): secret-store checks. File mode keys live in
    // the devices table (state.db) — admin-token is the only secret FILE the
    // owner box must keep 0600 (agent-token is a v1.0 leftover, tolerated).
    let keyring_mode = parsed.as_ref().map(|c| c.keyring_mode()).unwrap_or(false);
    if keyring_mode {
        let readable = crate::keyring::load(data_dir).ok().flatten().is_some();
        let stray = data_dir.join("agent-token").exists() || data_dir.join("device-keys.json").exists();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let adm_ok = std::fs::metadata(data_dir.join("admin-token")).map(|m| (m.mode() & 0o777) == 0o600).unwrap_or(false);
            let s_ok = readable && !stray && adm_ok;
            check("secret_store", s_ok, "kernel keyring holds the device keys (admin-token 0600, no plaintext key files)", "if key missing: frtrol device passwd or re-init; if stray file: rm it");
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode_ok = |p: &std::path::Path| std::fs::metadata(p).map(|m| (m.mode() & 0o777) == 0o600).unwrap_or(false);
            let adm = data_dir.join("admin-token");
            let t_ok = mode_ok(&adm);
            check("token_perms", t_ok, "admin-token mode 0600 (device keys live in state.db)", "chmod 600 admin-token");
        }
        // v1.1: the devices table must exist and carry keys for its rows.
        if let Ok(conn) = state::open_db(&data_dir.join("state.db")) {
            let n = state::count_devices(&conn);
            let broken = state::device_list(&conn).iter().filter(|d| d.device_key.as_deref().unwrap_or("").is_empty() && d.password_hash.is_some()).count();
            let detail = format!("{n} device(s) registered, all with keys");
            check("devices", broken == 0, &detail, "re-init or restore a valid backup");
        }
    }

    let cert_ok = data_dir.join("cert.pem").exists() && data_dir.join("key.pem").exists();
    check("tls_cert", cert_ok, "cert.pem + key.pem present", "run frtrol start once — it auto-generates the pair");

    let db_ok = data_dir.join("state.db").exists();
    check("state_db", db_ok, "state.db present", "run frtrol start once (auto-initializes)");

    // ---- remote checks (daemon) ----
    match admin(data_dir) {
        Ok(a) => match a.get("/admin/doctor") {
            Ok(v) => {
                for c in v["checks"].as_array().unwrap_or(&vec![]) {
                    let name = c["name"].as_str().unwrap_or("?");
                    let ok = c["ok"].as_bool().unwrap_or(false);
                    let detail = c["detail"].as_str().unwrap_or("");
                    let action = c["action"].as_str().unwrap_or("");
                    check(name, ok, detail, action);
                }
            }
            Err(e) => {
                bad += 1;
                println!("[FAIL] daemon        admin API error: {e:#}");
            }
        },
        Err(e) => {
            bad += 1;
            println!("[FAIL] daemon        {e:#}");
            println!("       fix: frtrol start");
        }
    }

    if bad == 0 {
        println!("ALL GREEN — farcontrol looks healthy");
        Ok(0)
    } else {
        println!("{bad} check(s) failed");
        Ok(1)
    }
}

// ============================================================
// v0.6 backup / restore (§72, §103, ADR-0020)
// ============================================================

/// Fetch the archive from the RUNNING daemon over the admin plane
/// (the CLI never touches state files directly while the daemon owns them).
pub fn backup(data_dir: &Path, out_path: &Path) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let req = a.agent.post(&format!("{}/admin/backup", a.base)).set("Authorization", &format!("Bearer {}", a.token));
    let resp = req.call().map_err(|e| anyhow::anyhow!("backup call failed: {e}"))?;
    if resp.status() != 200 {
        let text = resp.into_string().unwrap_or_default();
        anyhow::bail!("backup failed: {text}");
    }
    let mut buf = Vec::new();
    use std::io::Read;
    resp.into_reader().read_to_end(&mut buf)?;
    if buf.len() < 100 {
        anyhow::bail!("backup suspiciously small ({} bytes) — refusing to write it", buf.len());
    }
    // write 0600 — it contains every secret
    std::fs::write(out_path, &buf)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(out_path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!("backup written: {} ({} bytes, mode 0600 — contains ALL secrets)", out_path.display(), buf.len());
    Ok(())
}

/// Files a valid archive may contain — anything else (paths, ../, dirs) is
/// rejected before extraction. Path-traversal-proof by allowlist.
const RESTORE_ALLOW: [&str; 10] = [
    "state.db", "state.db-wal", "state.db-shm", "config.toml",
    "agent-token", "admin-token", "audit.jsonl", "cert.pem", "key.pem", "device-keys.json",
];

/// Offline restore: daemon MUST be down. Validate → extract to temp → verify
/// (open_db runs migrations = DB-03 upgrade path) → atomic-ish swap with .bak.
pub fn restore(data_dir: &Path, archive: &Path) -> anyhow::Result<()> {
    if !archive.exists() {
        anyhow::bail!("archive not found: {}", archive.display());
    }
    // 1. list + validate the archive FIRST (fixed argv tar, §77) — a garbage
    //    file is rejected before we even look at the daemon
    let list = std::process::Command::new("tar")
        .arg("-tzf").arg(archive)
        .output()
        .map_err(|e| anyhow::anyhow!("cannot run tar: {e}"))?;
    if !list.status.success() {
        anyhow::bail!("not a valid gzip tar: {}", String::from_utf8_lossy(&list.stderr));
    }
    let entries: Vec<String> = String::from_utf8_lossy(&list.stdout)
        .lines()
        .map(|l| l.trim().trim_end_matches('/').to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if entries.is_empty() {
        anyhow::bail!("archive is empty");
    }
    for e in &entries {
        if !RESTORE_ALLOW.contains(&e.as_str()) {
            anyhow::bail!("archive contains '{}' — not a known FARcontrol state file (refusing: possible path traversal)", e);
        }
    }
    for must in ["state.db", "config.toml", "admin-token"] {
        if !entries.iter().any(|e| e == must) {
            anyhow::bail!("archive is missing required file '{must}' — not a complete backup");
        }
    }
    // 2. daemon must be stopped (state files must not be owned by a live daemon)
    if data_dir.join("config.toml").exists() {
        if let Ok(a) = admin(data_dir) {
            if a.get("/admin/ping").is_ok() {
                anyhow::bail!("daemon is RUNNING — stop it first (Ctrl-C the frtrol start process), then re-run restore");
            }
        }
    }
    // 3. extract into a temp dir NEXT TO the data dir (same filesystem → rename works)
    let tmp = data_dir.with_extension("restore-tmp");
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp)?;
    let ex = std::process::Command::new("tar")
        .arg("-xzf").arg(archive).arg("-C").arg(&tmp)
        .output()
        .map_err(|e| anyhow::anyhow!("extract failed: {e}"))?;
    if !ex.status.success() {
        let _ = std::fs::remove_dir_all(&tmp);
        anyhow::bail!("extract failed: {}", String::from_utf8_lossy(&ex.stderr));
    }
    // 4. verify the extracted state: open_db runs migrations (v-old → current)
    //    — a failed migration must NOT touch the live dir (§79).
    {
        let conn = state::open_db(&tmp.join("state.db"))
            .with_context(|| "restored state.db failed to open/migrate — archive rejected, live data untouched")?;
        let ver = state::get_meta(&conn, "schema_version");
        if ver.is_none() {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!("restored db has no schema_version — archive rejected");
        }
        // v1.1: agent-token is a v1.0-era artifact (optional); device keys live
        // in state.db (file mode) or device-keys.json (keyring archive).
        if tmp.join("agent-token").exists() {
            let tok = std::fs::read_to_string(tmp.join("agent-token")).context("restored agent-token unreadable")?;
            if tok.trim().is_empty() {
                let _ = std::fs::remove_dir_all(&tmp);
                anyhow::bail!("restored agent-token is empty — archive rejected");
            }
        }
        if tmp.join("device-keys.json").exists() {
            let map = std::fs::read_to_string(tmp.join("device-keys.json")).context("restored device-keys.json unreadable")?;
            if state::parse_key_payload(&map).is_empty() {
                let _ = std::fs::remove_dir_all(&tmp);
                anyhow::bail!("restored device-keys.json is not a key map — archive rejected");
            }
        }
    }
    set_dir_private(&tmp);
    // 5. swap: live → .bak-<ts>, tmp → live. The old data is never destroyed.
    if data_dir.exists() {
        let bak = data_dir.with_extension(format!("bak-{}", state::now()));
        std::fs::rename(data_dir, &bak)
            .with_context(|| format!("cannot move current data dir aside ({})", bak.display()))?;
        println!("current data preserved at: {}", bak.display());
    }
    std::fs::rename(&tmp, data_dir)
        .with_context(|| format!("cannot move restored data into place: {}", data_dir.display()))?;
    // 6. offline marker — the CLI writes the restored db directly here ONLY
    //    (documented ADR-0020 exception: daemon down, owner-driven recovery)
    {
        let conn = state::open_db(&data_dir.join("state.db"))?;
        state::set_meta(&conn, "restored_at", &state::now().to_string())?;
    }
    // 7. v0.9→v1.1 (ADR-0023/0025): converge to the restored config's secret
    //    store. Keyring mode: write the key material back into the kernel and
    //    remove the plaintext (v1.1 maps via device-keys.json; v1.0 archives
    //    carry a bare agent-token → wrapped as the legacy key).
    {
        let cfg: Config = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
        if cfg.keyring_mode() {
            let payload = if data_dir.join("device-keys.json").exists() {
                std::fs::read_to_string(data_dir.join("device-keys.json"))?.trim().to_string()
            } else {
                let tok = std::fs::read_to_string(data_dir.join("agent-token"))?.trim().to_string();
                // v1.0 archive in keyring mode: bare token → legacy payload
                let mut map = std::collections::BTreeMap::new();
                map.insert("legacy".to_string(), tok);
                state::serialize_key_payload(&map)
            };
            crate::keyring::store(data_dir, &payload)?;
            let _ = std::fs::remove_file(data_dir.join("device-keys.json"));
            let _ = std::fs::remove_file(data_dir.join("agent-token"));
            let conn = state::open_db(&data_dir.join("state.db"))?;
            state::set_meta(&conn, "secret_store", "keyring")?;
            // purge any file-mode meta copy so there is exactly one source of truth
            let _ = conn.execute("DELETE FROM meta WHERE key = 'agent_token'", []);
            println!("  device keys restored into the kernel keyring (no plaintext file kept)");
        } else {
            // file-mode restore over a dir that previously ran in keyring mode:
            // drop the now-stale kernel key (hygiene — one source of truth).
            let _ = crate::keyring::remove(data_dir);
            let conn = state::open_db(&data_dir.join("state.db"))?;
            let _ = conn.execute("DELETE FROM meta WHERE key = 'secret_store'", []);
        }
    }
    println!("restore complete: {}", data_dir.display());
    println!("  identity/tokens/audit restored as they were — start the daemon: frtrol start");
    Ok(())
}
