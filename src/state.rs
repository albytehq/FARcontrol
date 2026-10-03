use crate::error::ApiError;
use crate::policy::Policy;
use rusqlite::{params, Connection};
use serde::Serialize;
use serde_json::{json, Value};
use std::path::Path;

pub fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// Single source of truth for the schema version (readyz/doctor/migrate all
/// read THIS — a literal in two places is how the v0.8 readyz regression happened).
pub const SCHEMA_VERSION: &str = "4";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT,
    device_key TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    login_enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    last_seen INTEGER,
    last_rotate INTEGER
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    agent_name TEXT NOT NULL,
    agent_provider TEXT,
    agent_model TEXT,
    scope TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    requested_hours REAL NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    decided_at INTEGER,
    decided_by TEXT,
    session_id TEXT,
    deny_reason TEXT,
    device_id TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    request_id TEXT,
    agent_name TEXT NOT NULL,
    agent_provider TEXT,
    agent_model TEXT,
    scope TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    revoked_at INTEGER,
    revoke_reason TEXT,
    device_id TEXT
);
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, seen_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    subject TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);
CREATE INDEX IF NOT EXISTS idx_nonces_seen ON nonces(seen_at);
CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status);
"#;

pub fn open_db(path: &Path) -> anyhow::Result<Connection> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;")?;
    conn.execute_batch(SCHEMA)?;
    migrate(&conn)?;
    Ok(conn)
}

/// Forward-compatible migration runner (DB-03). Each step runs once, in order;
/// the applied set is recorded in `migrations` so upgrades are traceable.
fn migrate(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);",
    )?;
    // migration 1 = baseline schema; 2 = v0.2 audit hash chain marker;
    // 3 = v0.8 agent identity columns (ADR-0022). The ALTERs are guarded by
    // PRAGMA so they are idempotent on both fresh and upgraded databases.
    let add_col = |table: &str, col: &str| -> anyhow::Result<()> {
        let has: bool = {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
            let names: Vec<String> = stmt
                .query_map([], |r| r.get::<_, String>(1))?
                .flatten()
                .collect();
            names.iter().any(|n| n == col)
        };
        if !has {
            conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {col} TEXT"), [])?;
        }
        Ok(())
    };
    add_col("requests", "agent_provider")?;
    add_col("requests", "agent_model")?;
    add_col("sessions", "agent_provider")?;
    add_col("sessions", "agent_model")?;
    // migration 4 (v1.1, ADR-0025): device registry + request/session ↔ device
    // binding. Devices are created by `CREATE TABLE` in SCHEMA (fresh DBs); the
    // ALTERs bind the legacy tables.
    add_col("requests", "device_id")?;
    add_col("sessions", "device_id")?;
    for (id, name) in [
        (1i64, "baseline-v0.1"),
        (2, "audit-hash-chain-v0.2"),
        (3, "agent-identity-v0.8"),
        (4, "device-auth-v1.1"),
    ] {
        let done: bool = conn
            .query_row("SELECT COUNT(*) FROM migrations WHERE id = ?1", params![id], |r| r.get::<_, i64>(0))
            .map(|n| n > 0)
            .unwrap_or(false);
        if !done {
            conn.execute("INSERT INTO migrations(id, name, applied_at) VALUES (?1, ?2, ?3)", params![id, name, now()])?;
        }
    }
    set_meta(conn, "schema_version", SCHEMA_VERSION)?;
    Ok(())
}

#[cfg(test)]
pub fn open_mem() -> anyhow::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(SCHEMA)?;
    // migration bookkeeping table exists in every real DB (open_db); the
    // session-model tests query it directly.
    conn.execute_batch("CREATE TABLE IF NOT EXISTS migrations (id INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL);")?;
    Ok(conn)
}

// ---------- meta ----------

pub fn get_meta(conn: &Connection, key: &str) -> Option<String> {
    conn.query_row("SELECT value FROM meta WHERE key = ?1", params![key], |r| r.get(0)).ok()
}

pub fn set_meta(conn: &Connection, key: &str, val: &str) -> anyhow::Result<()> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, val],
    )?;
    Ok(())
}

// ---------- audit (invariant 8: every security action is auditable) ----------

/// Appends to the audit table AND to audit.jsonl (append-only forensic copy).
/// Never fails the calling operation — but errors are swallowed silently only
/// after attempting both writes.
pub fn audit(conn: &Connection, dir: &Path, actor: &str, action: &str, subject: Option<&str>, detail: Value) {
    let ts = now();
    let detail_s = detail.to_string();
    let _ = conn.execute(
        "INSERT INTO audit(ts, actor, action, subject, detail) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![ts, actor, action, subject, detail_s],
    );
    // v0.2: jsonl lines form a SHA-256 hash chain - tamper/truncation is
    // detectable by `frtrol doctor` (invariant 8 hardening).
    let prev = get_meta(conn, "audit_last_hash").unwrap_or_else(|| "genesis".into());
    let mut line = json!({"ts": ts, "actor": actor, "action": action, "subject": subject, "detail": detail, "prev": prev});
    let hash = crate::crypto::sha256_hex(line.to_string().as_bytes());
    line["hash"] = json!(hash);
    let _ = set_meta(conn, "audit_last_hash", &hash);
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(dir.join("audit.jsonl")) {
        use std::io::Write;
        let _ = writeln!(f, "{line}");
    }
    // ADR-0022 (AD-08): opt-in retention. [audit] max_events = N (server
    // start persists it as meta). Absent/0 = keep forever — evidence is never
    // destroyed unless the owner configured a limit.
    if let Some(max) = get_meta(conn, "audit_retention_max").and_then(|v| v.parse::<i64>().ok()) {
        if max > 0 {
            trim_retention(conn, dir, max);
        }
    }
}

/// Retention trim (ADR-0022): delete the oldest audit rows beyond `max_events`,
/// then re-chain `audit.jsonl` from a fresh genesis whose first event is
/// `audit.trimmed` recording {removed, retained, prior_head}. Retained events
/// stay tamper-evident; the cut itself is audited; `doctor` verification stays
/// green. The file is rewritten atomically (write `.new` → rename).
fn trim_retention(conn: &Connection, dir: &Path, max_events: i64) {
    let count: i64 = match conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0)) {
        Ok(c) => c,
        Err(_) => return,
    };
    if count <= max_events {
        return;
    }
    let remove = count - max_events;
    let prior_head = get_meta(conn, "audit_last_hash").unwrap_or_else(|| "genesis".into());
    if conn
        .execute("DELETE FROM audit WHERE id IN (SELECT id FROM audit ORDER BY id ASC LIMIT ?1)", params![remove])
        .is_err()
    {
        return; // fail closed: no trim without the DB delete succeeding
    }
    let mut rows: Vec<(i64, String, String, Option<String>, String)> = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT ts, actor, action, subject, detail FROM audit ORDER BY id ASC") {
        let _ = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))
            .map(|m| {
                for v in m.flatten() {
                    rows.push(v);
                }
            });
    }
    let mut prev = "genesis".to_string();
    let mut out = String::new();
    let mut trim_line = json!({
        "ts": now(),
        "actor": "system",
        "action": "audit.trimmed",
        "subject": Value::Null,
        "detail": json!({"removed": remove, "retained": max_events, "prior_head": prior_head}),
        "prev": prev
    });
    let trim_hash = crate::crypto::sha256_hex(trim_line.to_string().as_bytes());
    trim_line["hash"] = json!(trim_hash);
    out.push_str(&trim_line.to_string());
    out.push('\n');
    prev = trim_hash;
    for (ts, actor, action, subject, detail) in rows {
        let detail_v: Value = serde_json::from_str(&detail).unwrap_or(Value::Null);
        let mut line = json!({"ts": ts, "actor": actor, "action": action, "subject": subject, "detail": detail_v, "prev": prev});
        let h = crate::crypto::sha256_hex(line.to_string().as_bytes());
        line["hash"] = json!(h);
        out.push_str(&line.to_string());
        out.push('\n');
        prev = h;
    }
    let _ = set_meta(conn, "audit_last_hash", &prev);
    let tmp = dir.join("audit.jsonl.new");
    if std::fs::write(&tmp, out).is_ok() {
        let _ = std::fs::rename(&tmp, dir.join("audit.jsonl"));
    }
}

/// Walks audit.jsonl and verifies the hash chain end-to-end (used by `doctor`).
/// Returns (checked_lines, legacy_lines, ok). Legacy = pre-v0.2 lines without
/// `hash` - they precede the chain and are skipped, not trusted.
pub fn verify_audit_chain(dir: &Path) -> (usize, usize, bool) {
    let text = match std::fs::read_to_string(dir.join("audit.jsonl")) {
        Ok(t) => t,
        Err(_) => return (0, 0, true),
    };
    let mut prev: Option<String> = None;
    let mut checked = 0usize;
    let mut legacy = 0usize;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let v: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return (checked, legacy, false),
        };
        let Some(hash) = v["hash"].as_str().map(|s| s.to_string()) else {
            legacy += 1;
            continue;
        };
        let claimed_prev = v["prev"].as_str().unwrap_or("");
        if let Some(p) = &prev {
            if claimed_prev != p {
                return (checked, legacy, false);
            }
        }
        let mut bare = v.clone();
        if let Some(m) = bare.as_object_mut() {
            m.remove("hash");
        }
        let expect = crate::crypto::sha256_hex(bare.to_string().as_bytes());
        if expect != hash {
            return (checked, legacy, false);
        }
        prev = Some(hash);
        checked += 1;
    }
    (checked, legacy, true)
}

/// `frtrol panic` (SE-11): revoke every active session + expire every pending
/// request. Returns (revoked_sessions, expired_pending).
pub fn panic_stop(conn: &Connection, dir: &Path, reason: &str) -> anyhow::Result<(usize, usize)> {
    let active: Vec<String> = {
        let mut out = Vec::new();
        let mut stmt = conn.prepare("SELECT id FROM sessions WHERE status='active'")?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
        for r in rows.flatten() {
            out.push(r);
        }
        out
    };
    for id in &active {
        let _ = revoke_session(conn, dir, id, reason, "owner");
    }
    let expired = expire_stale_requests(conn, dir, 0); // TTL 0 = expire ALL pending now
    Ok((active.len(), expired.len()))
}

pub fn list_audit(conn: &Connection, limit: u32) -> Vec<Value> {
    let mut out = Vec::new();
    let Ok(mut stmt) = conn.prepare("SELECT ts, actor, action, subject, detail FROM audit ORDER BY id DESC LIMIT ?1") else {
        return out;
    };
    let rows = stmt.query_map(params![limit], |r| {
        Ok((
            r.get::<_, i64>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, String>(2)?,
            r.get::<_, Option<String>>(3)?,
            r.get::<_, Option<String>>(4)?,
        ))
    });
    if let Ok(rows) = rows {
        for row in rows.flatten() {
            let (ts, actor, action, subject, detail) = row;
            let d = detail
                .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                .unwrap_or(Value::Null);
            out.push(json!({"ts": ts, "actor": actor, "action": action, "subject": subject, "detail": d}));
        }
    }
    out
}

// ---------- requests ----------

#[derive(Debug, Clone, Serialize)]
pub struct RequestRow {
    pub id: String,
    pub agent_name: String,
    pub agent_provider: Option<String>,
    pub agent_model: Option<String>,
    pub scope: String,
    pub reason: String,
    pub requested_hours: f64,
    pub status: String,
    pub created_at: i64,
    pub decided_at: Option<i64>,
    pub decided_by: Option<String>,
    pub session_id: Option<String>,
    pub deny_reason: Option<String>,
    /// v1.1 (ADR-0025 §7): device that filed the request; NULL = legacy
    /// headerless requests from pre-1.1 agents.
    pub device_id: Option<String>,
}

const REQ_COLS: &str = "id, agent_name, agent_provider, agent_model, scope, reason, requested_hours, status, created_at, decided_at, decided_by, session_id, deny_reason, device_id";

fn row_to_request(r: &rusqlite::Row) -> rusqlite::Result<RequestRow> {
    Ok(RequestRow {
        id: r.get(0)?,
        agent_name: r.get(1)?,
        agent_provider: r.get(2)?,
        agent_model: r.get(3)?,
        scope: r.get(4)?,
        reason: r.get(5)?,
        requested_hours: r.get(6)?,
        status: r.get(7)?,
        created_at: r.get(8)?,
        decided_at: r.get(9)?,
        decided_by: r.get(10)?,
        session_id: r.get(11)?,
        deny_reason: r.get(12)?,
        device_id: r.get(13)?,
    })
}

pub fn get_request(conn: &Connection, id: &str) -> Result<RequestRow, ApiError> {
    conn.query_row(&format!("SELECT {REQ_COLS} FROM requests WHERE id = ?1"), params![id], row_to_request)
        .map_err(|_| ApiError::not_found("request_not_found", format!("no request with id {id}")))
}

pub fn list_requests(conn: &Connection, status: Option<&str>) -> Vec<RequestRow> {
    let mut out = Vec::new();
    let sql = match status {
        Some(_s) => format!("SELECT {REQ_COLS} FROM requests WHERE status = ?1 ORDER BY created_at DESC"),
        None => format!("SELECT {REQ_COLS} FROM requests ORDER BY created_at DESC"),
    };
    if let Ok(mut stmt) = conn.prepare(&sql) {
        let rows = match status {
            Some(s) => stmt.query_map(params![s], row_to_request),
            None => stmt.query_map([], row_to_request),
        };
        if let Ok(rows) = rows {
            for r in rows.flatten() {
                out.push(r);
            }
        }
    }
    out
}

/// Total audit events (DB table — the canonical counter; jsonl mirrors it).
pub fn count_audit(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0)).unwrap_or(0)
}

pub fn count_pending(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM requests WHERE status='pending'", [], |r| r.get(0)).unwrap_or(0)
}

/// Arguments for `create_request` (keeps the call sites readable and clippy
/// happy — 8 positional params invite transposition bugs).
pub struct NewRequest<'a> {
    pub agent_name: &'a str,
    /// Optional declared identity (provider, model) — validated upstream (ADR-0022).
    pub agent_identity: Option<(&'a str, &'a str)>,
    pub scope: &'a str,
    pub hours: f64,
    pub reason: &'a str,
    /// v1.1: filing device id (None = legacy headerless agent, ADR-0025 §6).
    pub device_id: Option<&'a str>,
}

pub fn create_request(
    conn: &Connection,
    dir: &Path,
    pol: &Policy,
    req: NewRequest<'_>,
) -> Result<RequestRow, ApiError> {
    let NewRequest { agent_name, agent_identity, scope, hours, reason, device_id } = req;
    let hours = pol.validate_hours(hours).map_err(|m| ApiError::bad_request("invalid_request", m))?;
    let pending: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM requests WHERE status='pending' AND agent_name = ?1",
            params![agent_name],
            |r| r.get(0),
        )
        .map_err(ApiError::from)?;
    if pending as usize >= pol.max_pending_requests {
        return Err(ApiError::forbidden(
            "request_limit",
            format!("too many pending requests for '{agent_name}' (max {})", pol.max_pending_requests),
        ));
    }
    let id = crate::crypto::gen_id("req");
    let ts = now();
    let (agent_provider, agent_model) = match agent_identity {
        Some((p, m)) => (Some(p.to_string()), Some(m.to_string())),
        None => (None, None),
    };
    conn.execute(
        "INSERT INTO requests(id, agent_name, agent_provider, agent_model, scope, reason, requested_hours, status, created_at, device_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8, ?9)",
        params![id, agent_name, agent_provider, agent_model, scope, reason, hours, ts, device_id],
    )
    .map_err(ApiError::from)?;
    audit(
        conn,
        dir,
        &format!("agent:{agent_name}"),
        "request.created",
        Some(&id),
        json!({"scope": scope, "hours": hours, "reason": reason, "device": device_id}),
    );
    Ok(RequestRow {
        id,
        agent_name: agent_name.into(),
        agent_provider,
        agent_model,
        scope: scope.into(),
        reason: reason.into(),
        requested_hours: hours,
        status: "pending".into(),
        created_at: ts,
        decided_at: None,
        decided_by: None,
        session_id: None,
        deny_reason: None,
        device_id: device_id.map(|s| s.to_string()),
    })
}

pub fn deny_request(conn: &Connection, dir: &Path, id: &str, reason: &str) -> Result<RequestRow, ApiError> {
    let row = get_request(conn, id)?;
    if row.status != "pending" {
        return Err(ApiError::conflict(
            "request_not_pending",
            format!("request {id} is already '{}' — only pending requests can be denied", row.status),
        ));
    }
    let ts = now();
    conn.execute(
        "UPDATE requests SET status='denied', decided_at=?1, decided_by='owner', deny_reason=?2 WHERE id=?3",
        params![ts, reason, id],
    )
    .map_err(ApiError::from)?;
    audit(conn, dir, "owner", "request.denied", Some(id), json!({"reason": reason}));
    get_request(conn, id)
}

// ---------- sessions ----------

#[derive(Debug, Clone, Serialize)]
pub struct SessionRow {
    pub id: String,
    pub request_id: Option<String>,
    pub agent_name: String,
    pub agent_provider: Option<String>,
    pub agent_model: Option<String>,
    pub scope: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub status: String,
    pub revoked_at: Option<i64>,
    pub revoke_reason: Option<String>,
    pub device_id: Option<String>,
}

const SES_COLS: &str = "id, request_id, agent_name, agent_provider, agent_model, scope, created_at, expires_at, status, revoked_at, revoke_reason, device_id";

fn row_to_session(r: &rusqlite::Row) -> rusqlite::Result<SessionRow> {
    Ok(SessionRow {
        id: r.get(0)?,
        request_id: r.get(1)?,
        agent_name: r.get(2)?,
        agent_provider: r.get(3)?,
        agent_model: r.get(4)?,
        scope: r.get(5)?,
        created_at: r.get(6)?,
        expires_at: r.get(7)?,
        status: r.get(8)?,
        revoked_at: r.get(9)?,
        revoke_reason: r.get(10)?,
        device_id: r.get(11)?,
    })
}

pub fn get_session(conn: &Connection, id: &str) -> Result<SessionRow, ApiError> {
    conn.query_row(&format!("SELECT {SES_COLS} FROM sessions WHERE id = ?1"), params![id], row_to_session)
        .map_err(|_| ApiError::not_found("session_not_found", format!("no session with id {id}")))
}

pub fn list_sessions(conn: &Connection) -> Vec<SessionRow> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(&format!("SELECT {SES_COLS} FROM sessions ORDER BY created_at DESC")) {
        if let Ok(rows) = stmt.query_map([], row_to_session) {
            for r in rows.flatten() {
                out.push(r);
            }
        }
    }
    out
}

pub fn count_active(conn: &Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM sessions WHERE status='active' AND expires_at > ?1",
        params![now()],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

/// Session as seen from outside: an 'active' row whose TTL passed is 'expired'.
pub fn effective_status(s: &SessionRow) -> String {
    if s.status == "active" && s.expires_at <= now() {
        "expired".into()
    } else {
        s.status.clone()
    }
}

pub fn approve_request(
    conn: &Connection,
    dir: &Path,
    pol: &Policy,
    id: &str,
    hours_override: Option<f64>,
) -> Result<SessionRow, ApiError> {
    let req = get_request(conn, id)?;
    if req.status != "pending" {
        return Err(ApiError::conflict(
            "request_not_pending",
            format!("request {id} is already '{}'", req.status),
        ));
    }
    // RQ-02/D-005: a pending request older than the TTL can never be approved.
    if now() - req.created_at > pol.pending_ttl_secs {
        let _ = conn.execute("UPDATE requests SET status='expired' WHERE id=?1", params![id]);
        audit(conn, dir, "system", "request.expired", Some(id), json!({}));
        return Err(ApiError::conflict("request_not_pending", format!("request {id} expired (pending TTL {}s)", pol.pending_ttl_secs)));
    }
    // D-004: max concurrent active sessions (standard package: 1).
    let active = count_active(conn);
    if active as usize >= pol.max_active_sessions {
        return Err(ApiError::conflict(
            "session_limit",
            format!("{} active session(s) already exist — revoke or let it expire first (max {})", active, pol.max_active_sessions),
        ));
    }
    let mut hours = req.requested_hours;
    if let Some(h) = hours_override {
        if !h.is_finite() || h <= 0.0 {
            return Err(ApiError::bad_request("invalid_request", "hours must be a positive number"));
        }
        // The owner may only shorten, never extend beyond what the agent asked for.
        hours = hours.min(h);
    }
    hours = pol.validate_hours(hours).map_err(|m| ApiError::bad_request("invalid_request", m))?;

    let ses_id = crate::crypto::gen_id("ses");
    let ts = now();
    let expires = ts + (hours * 3600.0) as i64;

    // RQ-06: approve is ONE atomic transaction — session INSERT + request UPDATE
    // commit together or not at all (no orphan session can ever exist).
    let tx: Result<(), ApiError> = (|| {
        conn.execute_batch("BEGIN IMMEDIATE").map_err(ApiError::from)?;
        let r = (|| -> Result<(), ApiError> {
            conn.execute(
                "INSERT INTO sessions(id, request_id, agent_name, agent_provider, agent_model, scope, created_at, expires_at, status, device_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active', ?9)",
                params![ses_id, id, req.agent_name, req.agent_provider, req.agent_model, req.scope, ts, expires, req.device_id],
            )
            .map_err(ApiError::from)?;
            conn.execute(
                "UPDATE requests SET status='approved', decided_at=?1, decided_by='owner', session_id=?2 WHERE id=?3 AND status='pending'",
                params![ts, ses_id, id],
            )
            .map_err(ApiError::from)?;
            Ok(())
        })();
        match r {
            Ok(()) => {
                conn.execute_batch("COMMIT").map_err(ApiError::from)?;
                Ok(())
            }
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    })();
    tx?;

    audit(
        conn,
        dir,
        "owner",
        "session.approved",
        Some(&ses_id),
        json!({"request_id": id, "scope": req.scope, "hours": hours, "expires_at": expires, "device": req.device_id}),
    );
    get_session(conn, &ses_id)
}

/// THE authorization gate (invariants 1–4). Lazily persists expiry, audits it,
/// then enforces status + scope. Fail-closed on any unknown state.
pub fn authorize_session(
    conn: &Connection,
    dir: &Path,
    id: &str,
    needed_scope: &str,
) -> Result<SessionRow, ApiError> {
    let s = get_session(conn, id)?;
    if s.status == "active" && s.expires_at <= now() {
        let _ = conn.execute("UPDATE sessions SET status='expired' WHERE id=?1 AND status='active'", params![id]);
        audit(conn, dir, "system", "session.expired", Some(id), json!({"expires_at": s.expires_at}));
        return Err(ApiError::forbidden("session_expired", format!("session {id} has expired")));
    }
    match s.status.as_str() {
        "revoked" => Err(ApiError::forbidden(
            "session_revoked",
            format!("session {id} was revoked: {}", s.revoke_reason.clone().unwrap_or_default()),
        )),
        "expired" => Err(ApiError::forbidden("session_expired", format!("session {id} has expired"))),
        "active" => {
            if needed_scope == "full_access" && s.scope != "full_access" {
                Err(ApiError::forbidden(
                    "scope_denied",
                    format!("session scope is '{}' — full_access is required for this operation", s.scope),
                ))
            } else {
                Ok(s)
            }
        }
        other => Err(ApiError::internal(format!("session {id} has unknown status '{other}'"))),
    }
}

pub fn revoke_session(conn: &Connection, dir: &Path, id: &str, reason: &str, actor: &str) -> Result<SessionRow, ApiError> {
    let s = get_session(conn, id)?;
    if s.status != "active" {
        return Err(ApiError::conflict(
            "session_not_active",
            format!("session {id} is '{}' — nothing to revoke", s.status),
        ));
    }
    let ts = now();
    conn.execute(
        "UPDATE sessions SET status='revoked', revoked_at=?1, revoke_reason=?2 WHERE id=?3",
        params![ts, reason, id],
    )
    .map_err(ApiError::from)?;
    audit(conn, dir, actor, "session.revoked", Some(id), json!({"reason": reason}));
    get_session(conn, id)
}

/// Sweeper: expire all due sessions, return their ids (for console logging).
pub fn active_session_ids(conn: &Connection) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT id FROM sessions WHERE status='active'") {
        if let Ok(rows) = stmt.query_map([], |r| r.get::<_, String>(0)) {
            for r in rows.flatten() {
                out.push(r);
            }
        }
    }
    out
}

pub fn expire_due(conn: &Connection, dir: &Path) -> Vec<String> {
    let ids: Vec<String> = {
        let mut out = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT id FROM sessions WHERE status='active' AND expires_at <= ?1") {
            if let Ok(rows) = stmt.query_map(params![now()], |r| r.get::<_, String>(0)) {
                for r in rows.flatten() {
                    out.push(r);
                }
            }
        }
        out
    };
    for id in &ids {
        let _ = conn.execute("UPDATE sessions SET status='expired' WHERE id=?1", params![id]);
        audit(conn, dir, "system", "session.expired", Some(id), json!({}));
    }
    ids
}

/// Sweeper: expire pending requests past the TTL (D-005) — they can never be approved after.
pub fn expire_stale_requests(conn: &Connection, dir: &Path, ttl_secs: i64) -> Vec<String> {
    let ids: Vec<String> = {
        let mut out = Vec::new();
        if let Ok(mut stmt) = conn.prepare("SELECT id FROM requests WHERE status='pending' AND created_at < ?1") {
            if let Ok(rows) = stmt.query_map(params![now() - ttl_secs], |r| r.get::<_, String>(0)) {
                for r in rows.flatten() {
                    out.push(r);
                }
            }
        }
        out
    };
    for id in &ids {
        let _ = conn.execute("UPDATE requests SET status='expired' WHERE id=?1 AND status='pending'", params![id]);
        audit(conn, dir, "system", "request.expired", Some(id), json!({"ttl_secs": ttl_secs}));
    }
    ids
}

// ---------- nonces (anti-replay, invariant 7) ----------

/// Returns false if the nonce was already used (replay) — or on any DB failure,
/// which is treated as replay (fail-closed).
pub fn nonce_insert(conn: &Connection, nonce: &str) -> bool {
    conn.execute("INSERT INTO nonces(nonce, seen_at) VALUES (?1, ?2)", params![nonce, now()]).is_ok()
}

pub fn nonces_cleanup(conn: &Connection) {
    let _ = conn.execute("DELETE FROM nonces WHERE seen_at < ?1", params![now() - 700]);
}

// ---------- token rotation ----------
// v1.1: the meta-table token rotator is gone — keys live in the devices table
// and rotate through device_set_key / persist_device_key (ADR-0025).
// v1.2: the session model lives below (ADR-0028).

// ============================================================
// v1.2.0 (ADR-0028): ephemeral session credentials + machine device
// ============================================================

/// The stable identity of THIS machine (meta `device_id`, created once).
/// An identifier, never a credential — ADR-0028 §2 / master prompt §4.
pub fn machine_id(conn: &Connection) -> String {
    if let Some(id) = get_meta(conn, "device_id") {
        if crate::crypto::device_id_valid(&id) {
            return id;
        }
    }
    // first run (or corrupt meta): mint one, collision-checked like any device id
    let mut id = crate::crypto::gen_device_id();
    for _ in 0..8 {
        if query_device(conn, "SELECT id FROM devices WHERE id = ?1", params![id]).is_none() {
            break;
        }
        id = crate::crypto::gen_device_id();
    }
    let _ = set_meta(conn, "device_id", &id);
    id
}

/// The single v1.2 device row: the machine itself (ADR-0028 §2). Created with
/// no password — `begin_daemon_session` mints the per-run credentials. The
/// v1.1 login/backoff machinery is reused against this row unchanged.
pub fn ensure_machine_device(conn: &Connection, dir: &Path, machine_id: &str) -> anyhow::Result<DeviceRow> {
    if device_get(conn, machine_id).is_none() {
        conn.execute(
            "INSERT INTO devices(id, name, password_hash, device_key, status, login_enabled, created_at) VALUES (?1, 'machine', NULL, NULL, 'active', 1, ?2)",
            params![machine_id, now()],
        )?;
        audit(conn, dir, "system", "device.machine_created", Some(machine_id), json!({"note": "v1.2 session model — the machine device carries per-start session credentials"}));
    }
    device_get(conn, machine_id).ok_or_else(|| anyhow::anyhow!("machine device row missing after ensure"))
}

/// Migration v5 `session-model-v1.2` (ADR-0031 §5): every v1.1 registry device
/// is locked, its key rotated to noise, its active grants revoked. Runs ONCE
/// (guarded by the migrations table); idempotent + safe to re-run.
pub fn migrate_session_model(conn: &Connection, dir: &Path, machine_id: &str) -> anyhow::Result<()> {
    ensure_machine_device(conn, dir, machine_id)?;
    let done: bool = conn
        .query_row("SELECT COUNT(*) FROM migrations WHERE id = 5", [], |r| r.get::<_, i64>(0))
        .map(|n| n > 0)
        .unwrap_or(false);
    if done {
        return Ok(());
    }
    let stale: Vec<DeviceRow> = device_list(conn).into_iter().filter(|d| d.id != machine_id).collect();
    let mut revoked = 0usize;
    for d in &stale {
        for sid in sessions_of_device(conn, &d.id) {
            if revoke_session(conn, dir, &sid, "v1.2 session model migration — legacy device locked", "system").is_ok() {
                revoked += 1;
            }
        }
        conn.execute(
            "UPDATE devices SET login_enabled = 0, status = 'locked', device_key = ?1, last_rotate = ?2 WHERE id = ?3",
            params![crate::crypto::gen_device_key(), now(), d.id],
        )?;
    }
    audit(
        conn,
        dir,
        "system",
        "device.model_migrated",
        None,
        json!({
            "legacy_devices_locked": stale.len(),
            "sessions_revoked": revoked,
            "machine_id": machine_id,
            "note": "v1.1 registry credentials are dead — agents reconnect with the v1.2 session password"
        }),
    );
    conn.execute("INSERT INTO migrations(id, name, applied_at) VALUES (5, 'session-model-v1.2', ?1)", params![now()])?;
    Ok(())
}

/// What one `frtrol start` mints (ADR-0028 §1). The password is shown ONCE by
/// the caller; the admin token is persisted to meta + the 0600 file by the
/// caller (server.rs owns the file write); the key is persisted here (DB) or
/// by the caller (keyring mode).
pub struct SessionCreds {
    pub password: String,
    pub key: String,
    pub admin_token: String,
}

/// Mint the ephemeral credential set for THIS daemon run. Rotates the machine
/// device's password + key — the previous run's credentials die now (the core
/// v1.2 invariant, master prompt §6: old session credentials must not
/// silently regain access after a restart).
pub fn begin_daemon_session(conn: &Connection, dir: &Path, machine_id: &str, store_key_in_db: bool) -> anyhow::Result<SessionCreds> {
    let password = crate::crypto::gen_password();
    let key = crate::crypto::gen_device_key();
    let admin_token = crate::crypto::gen_token();
    let hash = crate::crypto::password_hash(&password)?;
    conn.execute(
        "UPDATE devices SET password_hash = ?1, device_key = ?2, login_enabled = 1, status = 'active', last_rotate = ?3 WHERE id = ?4",
        params![hash, if store_key_in_db { Some(key.clone()) } else { None }, now(), machine_id],
    )?;
    set_meta(conn, "admin_token", &admin_token)?;
    audit(
        conn,
        dir,
        "owner",
        "session.started",
        Some(machine_id),
        json!({ "note": "session password + key + admin token rotated — all previous credentials are dead" }),
    );
    Ok(SessionCreds { password, key, admin_token })
}

// ============================================================
// v1.1.0 (ADR-0025): device registry
// ============================================================

#[derive(Debug, Clone, Serialize)]
pub struct DeviceRow {
    pub id: String,
    pub name: String,
    /// Argon2id PHC string; NULL = key-only legacy row (no password login).
    pub password_hash: Option<String>,
    /// HMAC key. In keyring mode this stays NULL in the DB — the key lives in
    /// the kernel keyring payload map (never on disk).
    #[serde(skip_serializing)]
    pub device_key: Option<String>,
    pub status: String,
    pub login_enabled: bool,
    pub created_at: i64,
    pub last_seen: Option<i64>,
    pub last_rotate: Option<i64>,
}

const DEV_COLS: &str = "id, name, password_hash, device_key, status, login_enabled, created_at, last_seen, last_rotate";

fn row_to_device(r: &rusqlite::Row) -> rusqlite::Result<DeviceRow> {
    Ok(DeviceRow {
        id: r.get(0)?,
        name: r.get(1)?,
        password_hash: r.get(2)?,
        device_key: r.get(3)?,
        status: r.get(4)?,
        login_enabled: r.get::<_, i64>(5)? != 0,
        created_at: r.get(6)?,
        last_seen: r.get(7)?,
        last_rotate: r.get(8)?,
    })
}

fn query_device(conn: &Connection, sql: &str, p: &[&dyn rusqlite::ToSql]) -> Option<DeviceRow> {
    conn.query_row(sql, p, row_to_device).ok()
}

/// Create a device with a generated FAR-XXXX-XXXX id (collision-checked) and a
/// fresh random device key. `password` is stored Argon2-hashed; pass None for a
/// key-only (legacy) row. Caller hands `{id, password, key}` to the right side.
pub fn device_create(
    conn: &Connection,
    dir: &Path,
    name: &str,
    password: Option<&str>,
    key: &str,
) -> anyhow::Result<DeviceRow> {
    let name = name.trim();
    if name.is_empty() || name.len() > 64 {
        anyhow::bail!("device name must be 1–64 chars");
    }
    let hash = match password {
        Some(p) => Some(crate::crypto::password_hash(p)?),
        None => None,
    };
    // id collision check (paranoid; 35-bit space)
    let mut id = crate::crypto::gen_device_id();
    for _ in 0..8 {
        if query_device(conn, "SELECT id FROM devices WHERE id = ?1", params![id]).is_none() {
            break;
        }
        id = crate::crypto::gen_device_id();
    }
    let ts = now();
    conn.execute(
        "INSERT INTO devices(id, name, password_hash, device_key, status, login_enabled, created_at) VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6)",
        params![id, name, hash, key, password.is_some() as i64, ts],
    )?;
    audit(
        conn,
        dir,
        "owner",
        "device.created",
        Some(&id),
        json!({"name": name, "login_enabled": password.is_some()}),
    );
    Ok(query_device(
        conn,
        &format!("SELECT {DEV_COLS} FROM devices WHERE id = ?1"),
        params![id],
    )
    .expect("just inserted"))
}

pub fn device_get(conn: &Connection, id: &str) -> Option<DeviceRow> {
    query_device(conn, &format!("SELECT {DEV_COLS} FROM devices WHERE id = ?1"), params![id])
}

pub fn device_list(conn: &Connection) -> Vec<DeviceRow> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare(&format!("SELECT {DEV_COLS} FROM devices ORDER BY created_at ASC")) {
        if let Ok(rows) = stmt.query_map([], row_to_device) {
            for r in rows.flatten() {
                out.push(r);
            }
        }
    }
    out
}

pub fn count_devices(conn: &Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0)).unwrap_or(0)
}

/// The key-only legacy device (v1.0 agent-token migration, ADR-0025 §6).
pub fn legacy_device(conn: &Connection) -> Option<DeviceRow> {
    query_device(
        conn,
        &format!("SELECT {DEV_COLS} FROM devices WHERE login_enabled = 0 AND password_hash IS NULL ORDER BY created_at ASC LIMIT 1"),
        &[],
    )
}

/// v1.0 → v1.1 migration: the meta agent_token becomes the legacy device's key.
/// Idempotent — no-op when the devices table already has a legacy row or the
/// meta token is absent. Returns the legacy device when a migration happened.
pub fn migrate_legacy_token(conn: &Connection, dir: &Path) -> anyhow::Result<Option<DeviceRow>> {
    if legacy_device(conn).is_some() {
        return Ok(None);
    }
    let Some(token) = get_meta(conn, "agent_token") else { return Ok(None) };
    if token.is_empty() {
        return Ok(None);
    }
    let dev = device_create(conn, dir, "legacy", None, &token)?;
    // The devices table is now the single source of truth for this key.
    let _ = conn.execute("DELETE FROM meta WHERE key = 'agent_token'", []);
    audit(
        conn,
        dir,
        "system",
        "device.legacy_migrated",
        Some(&dev.id),
        json!({"note": "v1.0 agent token became the legacy device key (key-only, login disabled)"}),
    );
    Ok(Some(dev))
}

pub fn device_set_key(conn: &Connection, dir: &Path, id: &str, key: &str, actor: &str) -> anyhow::Result<()> {
    let n = conn.execute("UPDATE devices SET device_key = ?1, last_rotate = ?2 WHERE id = ?3", params![key, now(), id])?;
    if n == 0 {
        anyhow::bail!("device {id} not found");
    }
    audit(conn, dir, actor, "device.key_rotated", Some(id), json!({}));
    Ok(())
}

/// Rotate the password: new Argon2 hash + fresh key (forces re-login).
pub fn device_set_password(
    conn: &Connection,
    dir: &Path,
    id: &str,
    password: &str,
    key: &str,
    actor: &str,
) -> anyhow::Result<()> {
    let hash = crate::crypto::password_hash(password)?;
    let n = conn.execute(
        "UPDATE devices SET password_hash = ?1, device_key = ?2, last_rotate = ?3 WHERE id = ?4 AND login_enabled = 1",
        params![hash, key, now(), id],
    )?;
    if n == 0 {
        anyhow::bail!("device {id} not found or login disabled (legacy key-only row)");
    }
    audit(conn, dir, actor, "device.passwd_rotated", Some(id), json!({"note": "password + key rotated — old key dies now"}));
    Ok(())
}

pub fn device_set_login(conn: &Connection, dir: &Path, id: &str, enabled: bool) -> anyhow::Result<()> {
    let n = conn.execute("UPDATE devices SET login_enabled = ?1 WHERE id = ?2", params![enabled as i64, id])?;
    if n == 0 {
        anyhow::bail!("device {id} not found");
    }
    audit(
        conn,
        dir,
        "owner",
        if enabled { "device.unlocked" } else { "device.locked" },
        Some(id),
        json!({}),
    );
    Ok(())
}

pub fn device_remove(conn: &Connection, dir: &Path, id: &str) -> anyhow::Result<()> {
    let n = conn.execute("DELETE FROM devices WHERE id = ?1", params![id])?;
    if n == 0 {
        anyhow::bail!("device {id} not found");
    }
    audit(conn, dir, "owner", "device.removed", Some(id), json!({}));
    Ok(())
}

pub fn device_touch(conn: &Connection, id: &str) {
    let _ = conn.execute("UPDATE devices SET last_seen = ?1 WHERE id = ?2", params![now(), id]);
}

/// Every active session bound to a device (lock/remove must revoke them).
pub fn sessions_of_device(conn: &Connection, id: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(mut stmt) = conn.prepare("SELECT id FROM sessions WHERE device_id = ?1 AND status = 'active'") {
        if let Ok(rows) = stmt.query_map(params![id], |r| r.get::<_, String>(0)) {
            for r in rows.flatten() {
                out.push(r);
            }
        }
    }
    out
}

/// Device JSON for listings (never leaks hash or key).
pub fn device_json(d: &DeviceRow) -> Value {
    let sessions = 0; // callers patch this in with a DB count when needed
    json!({
        "id": d.id,
        "name": d.name,
        "status": d.status,
        "login_enabled": d.login_enabled,
        "key_only": d.password_hash.is_none(),
        "created_at": d.created_at,
        "last_seen": d.last_seen,
        "last_rotate": d.last_rotate,
        "sessions_hint": sessions,
    })
}

// ============================================================
// Keyring payload map (pure functions — unit-testable without a kernel).
// v1.1 keyring mode stores {"FAR-…": "key"} in ONE kernel key; v1.0 payloads
// (a bare token string) are recognized and wrapped on load.
// ============================================================

pub fn parse_key_payload(payload: &str) -> std::collections::BTreeMap<String, String> {
    let mut map = std::collections::BTreeMap::new();
    let trimmed = payload.trim();
    if let Ok(v) = serde_json::from_str::<std::collections::BTreeMap<String, String>>(trimmed) {
        return v;
    }
    // v1.0 legacy payload: a bare token = the legacy device's key.
    if !trimmed.is_empty() {
        map.insert("legacy".into(), trimmed.to_string());
    }
    map
}

pub fn serialize_key_payload(map: &std::collections::BTreeMap<String, String>) -> String {
    serde_json::to_string(map).unwrap_or_else(|_| "{}".into())
}

// ---------- helpers ----------

/// §11-shaped request JSON: flat struct fields + a nested `agent` object
/// `{name, provider, model}` (provider/model are null when undeclared).
/// Identity is a declaration — never authority (AG-03).
pub fn request_json(r: &RequestRow) -> Value {
    let mut v = serde_json::to_value(r).unwrap_or(Value::Null);
    if let Value::Object(ref mut map) = v {
        map.insert(
            "agent".into(),
            json!({"name": r.agent_name, "provider": r.agent_provider, "model": r.agent_model}),
        );
    }
    v
}

pub fn session_json(s: &SessionRow) -> Value {
    let eff = effective_status(s);
    let seconds_remaining = if eff == "active" { Some((s.expires_at - now()).max(0)) } else { None };
    let mut v = serde_json::to_value(s).unwrap_or(Value::Null);
    if let Value::Object(ref mut map) = v {
        map.insert("effective_status".into(), json!(eff));
        map.insert("seconds_remaining".into(), json!(seconds_remaining));
        map.insert(
            "agent".into(),
            json!({"name": s.agent_name, "provider": s.agent_provider, "model": s.agent_model}),
        );
    }
    v
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    #[test]
    fn audit_chain_verifies_and_detects_tamper() {
        let dir = std::env::temp_dir().join(format!("frtrol-chain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let conn = open_mem().unwrap();
        for i in 0..5 {
            audit(&conn, &dir, "t", "test.event", Some(&format!("s{i}")), json!({"i": i}));
        }
        let (checked, legacy, ok) = verify_audit_chain(&dir);
        assert!(ok, "fresh chain must verify");
        assert_eq!(checked, 5);
        assert_eq!(legacy, 0);

        // tamper: rewrite one event name in the middle of the file
        let p = dir.join("audit.jsonl");
        let text = std::fs::read_to_string(&p).unwrap().replacen("test.event", "EVIL.event", 2);
        std::fs::write(&p, text).unwrap();
        let (_, _, ok2) = verify_audit_chain(&dir);
        assert!(!ok2, "tampered chain must fail");

        // truncation: cut the tail, then emit one more event — the stored
        // last_hash links past the cut, so the chain must break
        let text2 = std::fs::read_to_string(&p).unwrap();
        let mut lines: Vec<&str> = text2.lines().collect();
        lines.pop();
        std::fs::write(&p, lines.join("\n")).unwrap();
        audit(&conn, &dir, "t", "after.truncation", None, json!({}));
        let (_, _, ok3) = verify_audit_chain(&dir);
        assert!(!ok3, "truncated history must fail once new events link past the cut");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {

    /// DB-03/§79: an OLD (v0.1-style) database must upgrade in place on open,
    /// preserving its data. We simulate a v0.1 db by building the baseline
    /// tables without the migrations bookkeeping, then open_db() it.
    #[test]
    fn old_db_upgrades_in_place_preserving_data() {
        let dir = std::env::temp_dir().join(format!("farcontrol-mig-{}", crate::crypto::gen_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("state.db");
        {
            // v0.1 reality: schema applied, no migrations table, version = 1
            let conn = Connection::open(&db).unwrap();
            conn.execute_batch(SCHEMA).unwrap();
            set_meta(&conn, "schema_version", "1").unwrap();
            set_meta(&conn, "agent_token", "old-token-value").unwrap();
        }
        // upgrade path: open_db runs migrate()
        let conn = open_db(&db).unwrap();
        assert_eq!(get_meta(&conn, "schema_version").as_deref(), Some("4"), "version must be upgraded to 4 (v1.1 devices)");
        assert_eq!(get_meta(&conn, "agent_token").as_deref(), Some("old-token-value"), "data must survive");
        let m2: i64 = conn
            .query_row("SELECT COUNT(*) FROM migrations WHERE id=2", [], |r| r.get(0))
            .unwrap();
        assert_eq!(m2, 1, "migration 2 recorded as applied");
        // v0.8 (ADR-0022): migration 3 adds the agent-identity columns
        let m3: i64 = conn
            .query_row("SELECT COUNT(*) FROM migrations WHERE id=3", [], |r| r.get(0))
            .unwrap();
        assert_eq!(m3, 1, "migration 3 recorded as applied");
        let cols: Vec<String> = {
            let mut stmt = conn.prepare("PRAGMA table_info(requests)").unwrap();
            stmt.query_map([], |r| r.get::<_, String>(1)).unwrap().flatten().collect()
        };
        assert!(cols.contains(&"agent_provider".to_string()) && cols.contains(&"agent_model".to_string()), "identity columns added");
        // re-opening must be idempotent (no double migration)
        drop(conn);
        let conn2 = open_db(&db).unwrap();
        let n: i64 = conn2
            .query_row("SELECT COUNT(*) FROM migrations", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 4, "migrations do not re-run (4 after device-auth v1.1)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupted database must FAIL CLOSED on open (§79: no insecure partial state).
    #[test]
    fn garbage_db_fails_closed() {
        let dir = std::env::temp_dir().join(format!("farcontrol-gdb-{}", crate::crypto::gen_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("state.db");
        std::fs::write(&db, b"this is definitely not a sqlite database").unwrap();
        assert!(open_db(&db).is_err(), "garbage file must be rejected, not 'repaired'");
        let _ = std::fs::remove_dir_all(&dir);
    }

    use super::*;
    use std::path::PathBuf;

    struct TempDir(PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("farcontrol-test-{}", crate::crypto::gen_nonce()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup() -> (Connection, TempDir) {
        (open_mem().unwrap(), TempDir::new())
    }

    #[test]
    fn request_lifecycle_approve() {
        let (conn, dir) = setup();
        let pol = Policy::default();
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-a", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "test", device_id: None }).unwrap();
        assert_eq!(req.status, "pending");

        let ses = approve_request(&conn, dir.path(), &pol, &req.id, None).unwrap();
        assert_eq!(ses.status, "active");
        assert_eq!(ses.scope, "terminal_only");
        assert!(ses.expires_at > ses.created_at);

        // request is no longer pending
        let again = approve_request(&conn, dir.path(), &pol, &req.id, None);
        assert_eq!(again.unwrap_err().code, "request_not_pending");

        // authz: terminal ok, full_access denied
        let ok = authorize_session(&conn, dir.path(), &ses.id, "terminal_only").unwrap();
        assert_eq!(ok.id, ses.id);
        let err = authorize_session(&conn, dir.path(), &ses.id, "full_access").unwrap_err();
        assert_eq!(err.code, "scope_denied");
    }

    #[test]
    fn request_lifecycle_deny() {
        let (conn, dir) = setup();
        let pol = Policy::default();
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-b", agent_identity: None, scope: "full_access", hours: 5.0, reason: "r", device_id: None }).unwrap();
        let denied = deny_request(&conn, dir.path(), &req.id, "no").unwrap();
        assert_eq!(denied.status, "denied");
        assert_eq!(denied.deny_reason.as_deref(), Some("no"));
        // denied request never produces a session
        assert!(denied.session_id.is_none());
    }

    #[test]
    fn expiry_enforced_lazily() {
        let (conn, dir) = setup();
        let pol = Policy::default();
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-c", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r", device_id: None }).unwrap();
        let ses = approve_request(&conn, dir.path(), &pol, &req.id, None).unwrap();
        // force expiry in the past
        conn.execute("UPDATE sessions SET expires_at = 1 WHERE id = ?1", params![ses.id]).unwrap();
        let err = authorize_session(&conn, dir.path(), &ses.id, "terminal_only").unwrap_err();
        assert_eq!(err.code, "session_expired");
        // persisted
        let s2 = get_session(&conn, &ses.id).unwrap();
        assert_eq!(s2.status, "expired");
    }

    #[test]
    fn revoke_enforced() {
        let (conn, dir) = setup();
        let pol = Policy::default();
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-d", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r", device_id: None }).unwrap();
        let ses = approve_request(&conn, dir.path(), &pol, &req.id, None).unwrap();
        let r = revoke_session(&conn, dir.path(), &ses.id, "owner changed mind", "owner").unwrap();
        assert_eq!(r.status, "revoked");
        let err = authorize_session(&conn, dir.path(), &ses.id, "terminal_only").unwrap_err();
        assert_eq!(err.code, "session_revoked");
        // double revoke → conflict
        let err2 = revoke_session(&conn, dir.path(), &ses.id, "x", "owner").unwrap_err();
        assert_eq!(err2.code, "session_not_active");
    }

    #[test]
    fn nonce_replay_rejected() {
        let (conn, _dir) = setup();
        assert!(nonce_insert(&conn, "n-1"));
        assert!(!nonce_insert(&conn, "n-1"), "same nonce twice must fail");
        assert!(nonce_insert(&conn, "n-2"));
    }

    #[test]
    fn approve_can_only_shorten() {
        let (conn, dir) = setup();
        let pol = Policy::default();
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-e", agent_identity: None, scope: "terminal_only", hours: 10.0, reason: "r", device_id: None }).unwrap();
        let ses = approve_request(&conn, dir.path(), &pol, &req.id, Some(50.0)).unwrap();
        assert_eq!(ses.expires_at - ses.created_at, 10 * 3600, "override beyond requested is clamped");
    }

    #[test]
    fn audit_writes_table_and_jsonl() {
        let (conn, dir) = setup();
        audit(&conn, dir.path(), "owner", "unit.test", Some("x"), json!({"k": 1}));
        let rows = list_audit(&conn, 10);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["action"], "unit.test");
        let jsonl = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap();
        assert!(jsonl.contains("unit.test"));
    }

    #[test]
    fn second_concurrent_session_denied() {
        let (conn, dir) = setup();
        let pol = Policy::default(); // max_active_sessions = 1 (D-004)
        let req1 = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-h", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r1", device_id: None }).unwrap();
        let req2 = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-h", agent_identity: None, scope: "full_access", hours: 6.0, reason: "r2", device_id: None }).unwrap();
        approve_request(&conn, dir.path(), &pol, &req1.id, None).unwrap();
        let err = approve_request(&conn, dir.path(), &pol, &req2.id, None).unwrap_err();
        assert_eq!(err.code, "session_limit");
        // after revoke, a new session can be approved
        let ses = list_sessions(&conn).remove(0);
        revoke_session(&conn, dir.path(), &ses.id, "x", "owner").unwrap();
        approve_request(&conn, dir.path(), &pol, &req2.id, None).unwrap();
    }

    #[test]
    fn stale_pending_request_cannot_be_approved() {
        let (conn, dir) = setup();
        let pol = Policy::default();
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-i", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r", device_id: None }).unwrap();
        conn.execute("UPDATE requests SET created_at = 1 WHERE id=?1", params![req.id]).unwrap();
        let err = approve_request(&conn, dir.path(), &pol, &req.id, None).unwrap_err();
        assert_eq!(err.code, "request_not_pending");
        let row = get_request(&conn, &req.id).unwrap();
        assert_eq!(row.status, "expired");
        // never approvable afterwards
        let err2 = approve_request(&conn, dir.path(), &pol, &req.id, None).unwrap_err();
        assert_eq!(err2.code, "request_not_pending");
    }

    #[test]
    fn pending_request_limit() {
        // guard against a polluted environment from outside cargo test
        std::env::remove_var("FARCONTROL_TEST_MODE");
        let (conn, dir) = setup();
        let pol = Policy::default();
        for i in 0..pol.max_pending_requests {
            create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-f", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: &format!("r{i}"), device_id: None }).unwrap();
        }
        let err = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-f", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "one too many", device_id: None }).unwrap_err();
        assert_eq!(err.code, "request_limit");
    }

    #[test]
    fn hours_validation_in_normal_mode() {
        // guard against a polluted environment from outside cargo test
        std::env::remove_var("FARCONTROL_TEST_MODE");
        let (conn, dir) = setup();
        let pol = Policy::default();
        let err = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-g", agent_identity: None, scope: "terminal_only", hours: 1.0, reason: "too short", device_id: None }).unwrap_err();
        assert_eq!(err.code, "invalid_request");
    }
}

#[cfg(test)]
mod retention_tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("frtrol-retention-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn retention_trims_to_limit_and_rechains() {
        let dir = tmpdir("trim");
        let conn = open_db(&dir.join("t.db")).unwrap();
        set_meta(&conn, "audit_retention_max", "3").unwrap();
        for i in 0..8 {
            audit(&conn, &dir, "t", "test.event", None, json!({"i": i}));
        }
        // DB keeps at most max_events rows
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0)).unwrap();
        assert!(count <= 3, "DB must be trimmed to ≤3, got {count}");
        // jsonl re-chains from an audit.trimmed genesis and still verifies
        let (checked, _legacy, ok) = verify_audit_chain(&dir);
        assert!(ok, "re-chained audit.jsonl must verify");
        assert!(checked >= 1);
        let first = std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .next()
            .unwrap_or("")
            .to_string();
        assert!(first.contains("audit.trimmed"), "first line must be the trim marker: {first}");
        assert!(first.contains("\"removed\":"), "trim marker records the cut: {first}");
        assert!(first.contains("\"retained\":3"), "trim marker states the ceiling: {first}");
        // incremental design (ADR-0022): trim runs after EVERY append once the
        // ceiling is crossed — so the file is exactly 1 marker + N retained.
        let lines = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap().lines().count();
        assert!(lines <= 4, "file = trim marker + retained events, got {lines} lines");
        // the NEWEST event survives (i=7)
        let last = std::fs::read_to_string(dir.join("audit.jsonl"))
            .unwrap()
            .lines()
            .last()
            .unwrap_or("")
            .to_string();
        assert!(last.contains("\"i\":7"), "newest event retained: {last}");
    }

    #[test]
    fn retention_default_keeps_everything() {
        let dir = tmpdir("keep");
        let conn = open_db(&dir.join("t.db")).unwrap();
        // no audit_retention_max set → keep forever (default, AD-08)
        for i in 0..8 {
            audit(&conn, &dir, "t", "test.event", None, json!({"i": i}));
        }
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit", [], |r| r.get(0)).unwrap();
        assert_eq!(count, 8, "no retention configured → nothing deleted");
        let (checked, _legacy, ok) = verify_audit_chain(&dir);
        assert!(ok && checked == 8);
        let first = std::fs::read_to_string(dir.join("audit.jsonl")).unwrap().lines().next().unwrap().to_string();
        assert!(!first.contains("audit.trimmed"), "no trim marker when retention is off");
    }

    #[test]
    fn tampering_a_retained_event_still_detected() {
        let dir = tmpdir("tamper");
        let conn = open_db(&dir.join("t.db")).unwrap();
        set_meta(&conn, "audit_retention_max", "4").unwrap();
        for i in 0..10 {
            audit(&conn, &dir, "t", "test.event", None, json!({"i": i}));
        }
        // flip one byte inside a retained line
        let p = dir.join("audit.jsonl");
        let mut text = std::fs::read_to_string(&p).unwrap();
        text = text.replace("\"i\":9", "\"i\":8"); // forge the newest event
        std::fs::write(&p, text).unwrap();
        let (_, _, ok) = verify_audit_chain(&dir);
        assert!(!ok, "forged retained event must break the chain");
    }
}

#[cfg(test)]
mod device_tests {
    use super::*;

    fn d() -> (std::path::PathBuf, Connection) {
        let dir = std::env::temp_dir().join(format!("frtrol-dev-{}-{}", std::process::id(), crate::crypto::gen_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        let conn = open_db(&dir.join("t.db")).unwrap();
        (dir, conn)
    }

    fn pol() -> Policy {
        Policy::default()
    }

    #[test]
    fn device_lifecycle_create_get_list() {
        let (dir, conn) = d();
        let key = crate::crypto::gen_device_key();
        let dev = device_create(&conn, &dir, "office-laptop", Some("harbor-tiger-42-blue"), &key).unwrap();
        assert!(crate::crypto::device_id_valid(&dev.id));
        assert_eq!(dev.name, "office-laptop");
        assert!(dev.login_enabled);
        assert!(dev.password_hash.is_some());
        assert!(dev.password_hash.unwrap().starts_with("$argon2id$"));
        assert_eq!(dev.device_key.as_deref(), Some(key.as_str()));
        assert_eq!(count_devices(&conn), 1);
        assert_eq!(device_list(&conn).len(), 1);

        // get + json must never leak hash/key
        let got = device_get(&conn, &dev.id).unwrap();
        assert_eq!(got.id, dev.id);
        let j = device_json(&got).to_string();
        assert!(!j.contains("argon2"));
        assert!(!j.contains(&key), "device_json must not leak the key");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_name_validation() {
        let (dir, conn) = d();
        assert!(device_create(&conn, &dir, "", Some("x"), "k").is_err());
        let long = "a".repeat(65);
        assert!(device_create(&conn, &dir, &long, Some("x"), "k").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn login_disabled_for_key_only_rows() {
        let (dir, conn) = d();
        let dev = device_create(&conn, &dir, "legacy", None, "key-only").unwrap();
        assert!(!dev.login_enabled);
        assert!(dev.password_hash.is_none());
        assert_eq!(legacy_device(&conn).map(|d| d.id), Some(dev.id));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_token_migration_is_idempotent_and_moves_source_of_truth() {
        let (dir, conn) = d();
        set_meta(&conn, "agent_token", "old-v1-token").unwrap();
        let migrated = migrate_legacy_token(&conn, &dir).unwrap();
        assert!(migrated.is_some(), "first call migrates");
        let id = migrated.unwrap().id;
        // token moved: meta gone, key lives in devices
        assert!(get_meta(&conn, "agent_token").is_none(), "meta token must be consumed");
        assert_eq!(device_get(&conn, &id).unwrap().device_key.as_deref(), Some("old-v1-token"));
        // second call = no-op
        assert!(migrate_legacy_token(&conn, &dir).unwrap().is_none());
        assert_eq!(count_devices(&conn), 1);
        // fresh DB (no token) → nothing to migrate
        let (dir2, conn2) = d();
        assert!(migrate_legacy_token(&conn2, &dir2).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    #[test]
    fn passwd_rotation_kills_old_key_and_hash() {
        let (dir, conn) = d();
        let dev = device_create(&conn, &dir, "d1", Some("first-password"), "k1").unwrap();
        device_set_password(&conn, &dir, &dev.id, "second-password", "k2", "owner:test").unwrap();
        let after = device_get(&conn, &dev.id).unwrap();
        assert_eq!(after.device_key.as_deref(), Some("k2"));
        assert!(crate::crypto::password_verify(after.password_hash.as_deref().unwrap(), "second-password"));
        assert!(!crate::crypto::password_verify(after.password_hash.as_deref().unwrap(), "first-password"));
        assert!(after.last_rotate.is_some());
        // key-only (legacy) rows cannot rotate a password
        let legacy = device_create(&conn, &dir, "legacy", None, "kl").unwrap();
        assert!(device_set_password(&conn, &dir, &legacy.id, "nope", "k3", "owner:test").is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn device_lock_unlock_and_remove() {
        let (dir, conn) = d();
        let dev = device_create(&conn, &dir, "d1", Some("pw"), "k").unwrap();
        device_set_login(&conn, &dir, &dev.id, false).unwrap();
        assert!(!device_get(&conn, &dev.id).unwrap().login_enabled);
        device_set_login(&conn, &dir, &dev.id, true).unwrap();
        assert!(device_get(&conn, &dev.id).unwrap().login_enabled);
        device_remove(&conn, &dir, &dev.id).unwrap();
        assert!(device_get(&conn, &dev.id).is_none());
        assert!(device_remove(&conn, &dir, &dev.id).is_err(), "double remove must fail");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sessions_bind_to_device_and_can_be_swept() {
        let (dir, conn) = d();
        let dev = device_create(&conn, &dir, "d1", Some("pw"), "k").unwrap();
        let req = create_request(
            &conn,
            &dir,
            &pol(),
            NewRequest {
                agent_name: "myai",
                agent_identity: None,
                scope: "terminal_only",
                hours: 6.0,
                reason: "test",
                device_id: Some(&dev.id),
            },
        )
        .unwrap();
        assert_eq!(req.device_id.as_deref(), Some(dev.id.as_str()));
        let ses = approve_request(&conn, &dir, &pol(), &req.id, None).unwrap();
        assert_eq!(ses.device_id.as_deref(), Some(dev.id.as_str()));
        assert_eq!(sessions_of_device(&conn, &dev.id), vec![ses.id.clone()]);
        revoke_session(&conn, &dir, &ses.id, "owner test", "owner").unwrap();
        assert!(sessions_of_device(&conn, &dev.id).is_empty(), "revoked session leaves the device sweep");

        // legacy (headerless) request: device_id NULL
        let req2 = create_request(
            &conn,
            &dir,
            &pol(),
            NewRequest { agent_name: "myai", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "legacy", device_id: None },
        )
        .unwrap();
        assert!(req2.device_id.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keyring_payload_map_roundtrip_and_legacy_wrap() {
        // v1.1 map format roundtrips
        let mut map = std::collections::BTreeMap::new();
        map.insert("FAR-7K2M-QX94".into(), "key-one".into());
        map.insert("FAR-ABCD-EFGH".into(), "key-two".into());
        let s = serialize_key_payload(&map);
        assert_eq!(parse_key_payload(&s), map);

        // v1.0 bare-token payload wraps as the legacy key
        let legacy = parse_key_payload("old-bare-token");
        assert_eq!(legacy.get("legacy").map(|s| s.as_str()), Some("old-bare-token"));

        // garbage/empty → empty map (fail closed, nothing to verify against)
        assert!(parse_key_payload("").is_empty());
        assert!(parse_key_payload("not json {").is_empty() || parse_key_payload("not json {").len() <= 1);
        // note: "not json {" is not a bare token? it IS a bare string → wrapped as legacy.
        // acceptable: any non-JSON payload is treated as a bare v1.0 token.
    }
}

// ============================================================
// v1.2.0 session model tests (ADR-0028 / ADR-0031 §5)
// ============================================================

#[cfg(test)]
mod session_model_tests {
    use super::*;

    struct TempDir(std::path::PathBuf);
    impl TempDir {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!("farcontrol-v12-{}", crate::crypto::gen_nonce()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn setup() -> (Connection, TempDir) {
        (open_mem().unwrap(), TempDir::new())
    }

    // ---------- v1.2 session model (ADR-0028 / ADR-0031 §5) ----------

    #[test]
    fn machine_id_is_stable_and_valid() {
        let (conn, _dir) = setup();
        let a = machine_id(&conn);
        let b = machine_id(&conn);
        assert_eq!(a, b, "machine id must be stable across calls");
        assert!(crate::crypto::device_id_valid(&a), "format FAR-XXXX-XXXX: {a}");
        assert_eq!(get_meta(&conn, "device_id").as_deref(), Some(a.as_str()), "persisted in meta");
    }

    #[test]
    fn migrate_session_model_locks_v11_devices_and_revokes_their_grants() {
        let (conn, dir) = setup();
        // simulate a v1.1 install: a registry device with password + key + an active grant
        let old = device_create(&conn, dir.path(), "v1.1-device", Some("some-old-password"), "v1.1-key-material").unwrap();
        let req = create_request(
            &conn,
            dir.path(),
            &crate::policy::Policy::default(),
            NewRequest { agent_name: "old-agent", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r", device_id: Some(&old.id) },
        )
        .unwrap();
        let ses = approve_request(&conn, dir.path(), &crate::policy::Policy::default(), &req.id, None).unwrap();
        assert_eq!(ses.status, "active");

        let mid = machine_id(&conn);
        migrate_session_model(&conn, dir.path(), &mid).unwrap();

        let d = device_get(&conn, &old.id).unwrap();
        assert!(!d.login_enabled, "legacy device login disabled");
        assert_eq!(d.status, "locked", "legacy device locked");
        assert_ne!(d.device_key.as_deref(), Some("v1.1-key-material"), "old key rotated to noise");
        let s2 = get_session(&conn, &ses.id).unwrap();
        assert_eq!(effective_status(&s2), "revoked", "legacy device grants are revoked at migration");

        let machine = device_get(&conn, &mid).expect("machine device exists");
        assert!(machine.login_enabled, "machine device stays logable");
        assert_eq!(machine.status, "active");

        // idempotent: re-run changes nothing
        migrate_session_model(&conn, dir.path(), &mid).unwrap();
        assert!(device_get(&conn, &old.id).unwrap().login_enabled == false);
        let n5: i64 = conn.query_row("SELECT COUNT(*) FROM migrations WHERE id=5", [], |r| r.get(0)).unwrap();
        assert_eq!(n5, 1, "migration 5 recorded exactly once");
    }

    #[test]
    fn begin_daemon_session_rotates_every_credential() {
        let (conn, dir) = setup();
        let mid = machine_id(&conn);
        migrate_session_model(&conn, dir.path(), &mid).unwrap();

        let s1 = begin_daemon_session(&conn, dir.path(), &mid, true).unwrap();
        let tok1 = get_meta(&conn, "admin_token").unwrap();
        let d1 = device_get(&conn, &mid).unwrap();
        assert!(crate::crypto::password_verify(d1.password_hash.as_deref().unwrap(), &s1.password), "hash verifies");
        assert_eq!(d1.device_key.as_deref(), Some(s1.key.as_str()), "key stored in DB (file mode)");
        assert_ne!(tok1, "");

        // a second start kills the first credentials (master prompt §6)
        let s2 = begin_daemon_session(&conn, dir.path(), &mid, true).unwrap();
        let d2 = device_get(&conn, &mid).unwrap();
        assert!(!crate::crypto::password_verify(d2.password_hash.as_deref().unwrap(), &s1.password), "OLD password must fail against the current stored hash after restart");
        assert!(crate::crypto::password_verify(d2.password_hash.as_deref().unwrap(), &s2.password), "NEW password verifies");
        assert_ne!(s1.key, s2.key, "session key rotates");
        assert_ne!(s1.admin_token, s2.admin_token, "admin token rotates");
        assert_ne!(get_meta(&conn, "admin_token").unwrap(), tok1);

        // keyring mode: the key never lands in the DB
        let s3 = begin_daemon_session(&conn, dir.path(), &mid, false).unwrap();
        assert!(device_get(&conn, &mid).unwrap().device_key.is_none(), "keyring mode keeps the key out of the DB");
        assert!(!s3.key.is_empty());
    }
}
