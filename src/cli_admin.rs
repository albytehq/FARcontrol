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
    let agent_token = crypto::gen_token();
    let admin_token = crypto::gen_token();
    if keyring_mode {
        // ID-04 (ADR-0023): the agent secret lives in the kernel keyring only —
        // no plaintext file, no agent_token meta row in SQLite.
        crate::keyring::store(data_dir, &agent_token)
            .with_context(|| "kernel keyring store failed (secret_store=keyring)")?;
        state::set_meta(&conn, "secret_store", "keyring")?;
    } else {
        state::set_meta(&conn, "agent_token", &agent_token)?;
        state::set_meta(&conn, "secret_store", "file")?;
        crate::server::write_secret(&data_dir.join("agent-token"), &agent_token)?;
    }
    state::set_meta(&conn, "admin_token", &admin_token)?;
    state::set_meta(&conn, "schema_version", "1")?;
    state::set_meta(&conn, "created_at", &state::now().to_string())?;
    crate::server::write_secret(&data_dir.join("admin-token"), &admin_token)?;
    state::audit(&conn, data_dir, "owner", "system.initialized", None, json!({ "version": env!("CARGO_PKG_VERSION"), "secret_store": if keyring_mode { "keyring" } else { "file" } }));

    // v0.2: generate the TLS pair up front so `start` and `doctor` always have it.
    let _ = crate::tls::ensure_cert(data_dir)?;

    println!("initialized {} (first run)", data_dir.display());
    println!("AGENT TOKEN — give this to your AI agent (shown once):");
    println!("  {}", agent_token);
    if keyring_mode {
        println!("(stored in the Linux kernel keyring — never written to disk)");
    } else {
        println!("(stored in agent-token file, mode 0600)");
    }
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

fn hum(secs: i64) -> String {
    if secs <= 0 {
        "expired".into()
    } else if secs < 3600 {
        format!("{}m", (secs + 59) / 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

pub fn status(data_dir: &Path, as_json: bool) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.get("/admin/ping")?;
    if as_json {
        // §45 (CL-02): stable machine-readable output — one line, unchanged payload.
        println!("{}", serde_json::to_string(&v)?);
        return Ok(());
    }
    println!("daemon  : running (v{})", v["version"].as_str().unwrap_or("?"));
    println!("pending : {}", v["pending_count"].as_i64().unwrap_or(0));
    println!("active  : {}", v["active_count"].as_i64().unwrap_or(0));
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

    println!("PENDING REQUESTS (frtrol approve <id>  /  frtrol deny <id>):");
    let empty = reqs["requests"].as_array().map(|r| r.is_empty()).unwrap_or(true);
    if empty {
        println!("  (none)");
    } else {
        for r in reqs["requests"].as_array().unwrap() {
            let identity = match (r["agent_provider"].as_str(), r["agent_model"].as_str()) {
                (Some(p), Some(m)) => format!(" {p}/{m} (declared)"),
                _ => String::new(),
            };
            println!(
                "  {}  agent={}{} scope={} hours={} reason='{}'",
                r["id"].as_str().unwrap_or("?"),
                r["agent_name"].as_str().unwrap_or("?"),
                identity,
                r["scope"].as_str().unwrap_or("?"),
                r["requested_hours"].as_f64().unwrap_or(0.0),
                r["reason"].as_str().unwrap_or(""),
            );
        }
    }
    println!();
    println!("SESSIONS:");
    let empty_s = sess["sessions"].as_array().map(|r| r.is_empty()).unwrap_or(true);
    if empty_s {
        println!("  (none)");
    } else {
        let now = state::now();
        for s in sess["sessions"].as_array().unwrap() {
            let eff = s["effective_status"].as_str().unwrap_or("?");
            let remaining = s["expires_at"].as_i64().unwrap_or(0) - now;
            let identity = match (s["agent_provider"].as_str(), s["agent_model"].as_str()) {
                (Some(p), Some(m)) => format!(" {p}/{m} (declared)"),
                _ => String::new(),
            };
            println!(
                "  {}  agent={}{} scope={} status={} expires={} ({})",
                s["id"].as_str().unwrap_or("?"),
                s["agent_name"].as_str().unwrap_or("?"),
                identity,
                s["scope"].as_str().unwrap_or("?"),
                eff,
                iso(s["expires_at"].as_i64().unwrap_or(0)),
                if eff == "active" { hum(remaining) } else { eff.to_string() },
            );
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
    println!("approved request {}", id);
    println!("  session_id : {}", s["id"].as_str().unwrap_or("?"));
    println!("  agent      : {}", s["agent_name"].as_str().unwrap_or("?"));
    println!("  scope      : {}", s["scope"].as_str().unwrap_or("?"));
    println!("  expires    : {}", iso(s["expires_at"].as_i64().unwrap_or(0)));
    let sid = s["id"].as_str().unwrap_or("?");
    println!("agent can now run: frtrol agent exec {sid} <command>");
    Ok(())
}

pub fn deny(data_dir: &Path, id: &str, reason: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/deny", &json!({ "request_id": id, "reason": reason }))?;
    println!("denied request {} — no session was created", v["request"]["id"].as_str().unwrap_or(id));
    Ok(())
}

pub fn revoke(data_dir: &Path, id: &str, reason: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    a.post("/admin/revoke", &json!({ "session_id": id, "reason": reason }))?;
    println!("revoked session {id} — access is dead immediately");
    Ok(())
}

pub fn rotate(data_dir: &Path) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/rotate", &json!({}))?;
    println!("NEW agent token (old one is dead — update the agent NOW):");
    println!("  {}", v["agent_token"].as_str().unwrap_or("?"));
    Ok(())
}

pub fn audit(data_dir: &Path, limit: u32) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.get(&format!("/admin/audit?limit={}", limit.min(1000)))?;
    if let Some(events) = v["events"].as_array() {
        for e in events.iter() {
            println!(
                "{}  {:<18} {:<18} {} {}",
                iso(e["ts"].as_i64().unwrap_or(0)),
                e["actor"].as_str().unwrap_or("?"),
                e["action"].as_str().unwrap_or("?"),
                e["subject"].as_str().unwrap_or(""),
                e["detail"].as_str().map(|s| s.to_string()).unwrap_or_default(),
            );
        }
        if events.is_empty() {
            println!("(no audit events)");
        }
    }
    Ok(())
}

/// EMERGENCY STOP (SE-11): one call — every session revoked, every pending
/// request expired, every terminal killed, agent token rotated.
pub fn panic_stop(data_dir: &Path, reason: &str) -> anyhow::Result<()> {
    let a = admin(data_dir)?;
    let v = a.post("/admin/panic", &json!({ "reason": reason }))?;
    println!("PANIC executed:");
    println!("  revoked sessions : {}", v["revoked_sessions"].as_i64().unwrap_or(0));
    println!("  expired pending  : {}", v["expired_pending"].as_i64().unwrap_or(0));
    println!("  killed terminals : {}", v["killed_terminals"].as_i64().unwrap_or(0));
    println!("NEW agent token (old one is DEAD):");
    println!("  {}", v["agent_token"].as_str().unwrap_or("?"));
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

    // v0.9 (ADR-0023): secret-store checks replace the unconditional file check.
    let keyring_mode = parsed.as_ref().map(|c| c.keyring_mode()).unwrap_or(false);
    if keyring_mode {
        let readable = crate::keyring::load(data_dir).ok().flatten().is_some();
        let stray = data_dir.join("agent-token").exists();
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let adm_ok = std::fs::metadata(data_dir.join("admin-token")).map(|m| (m.mode() & 0o777) == 0o600).unwrap_or(false);
            let s_ok = readable && !stray && adm_ok;
            check("secret_store", s_ok, "kernel keyring holds the agent token (admin-token 0600, no plaintext agent-token)", "if key missing: frtrol rotate or re-init; if stray file: rm agent-token");
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let mode_ok = |p: &std::path::Path| std::fs::metadata(p).map(|m| (m.mode() & 0o777) == 0o600).unwrap_or(false);
            let tok = data_dir.join("agent-token");
            let adm = data_dir.join("admin-token");
            let t_ok = mode_ok(&tok) && mode_ok(&adm);
            check("token_perms", t_ok, "agent-token + admin-token mode 0600", "chmod 600 the token files");
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
const RESTORE_ALLOW: [&str; 9] = [
    "state.db", "state.db-wal", "state.db-shm", "config.toml",
    "agent-token", "admin-token", "audit.jsonl", "cert.pem", "key.pem",
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
    for must in ["state.db", "config.toml", "agent-token", "admin-token"] {
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
        let tok = std::fs::read_to_string(tmp.join("agent-token")).context("restored agent-token unreadable")?;
        if tok.trim().is_empty() {
            let _ = std::fs::remove_dir_all(&tmp);
            anyhow::bail!("restored agent-token is empty — archive rejected");
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
    // 7. v0.9 (ADR-0023): converge to the restored config's secret store. In
    //    keyring mode the archive's plaintext agent-token is written back into
    //    the kernel keyring and the file removed — disk never keeps it.
    {
        let cfg: Config = toml::from_str(&std::fs::read_to_string(data_dir.join("config.toml"))?)?;
        if cfg.keyring_mode() {
            let tok = std::fs::read_to_string(data_dir.join("agent-token"))?.trim().to_string();
            crate::keyring::store(data_dir, &tok)?;
            let _ = std::fs::remove_file(data_dir.join("agent-token"));
            let conn = state::open_db(&data_dir.join("state.db"))?;
            state::set_meta(&conn, "secret_store", "keyring")?;
            // purge any file-mode meta copy so there is exactly one source of truth
            let _ = conn.execute("DELETE FROM meta WHERE key = 'agent_token'", []);
            println!("  agent token restored into the kernel keyring (no plaintext file kept)");
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
