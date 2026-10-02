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
pub const SCHEMA_VERSION: &str = "3";

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
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
    deny_reason TEXT
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
    revoke_reason TEXT
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
    for (id, name) in [(1i64, "baseline-v0.1"), (2, "audit-hash-chain-v0.2"), (3, "agent-identity-v0.8")] {
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
}

const REQ_COLS: &str = "id, agent_name, agent_provider, agent_model, scope, reason, requested_hours, status, created_at, decided_at, decided_by, session_id, deny_reason";

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
}

pub fn create_request(
    conn: &Connection,
    dir: &Path,
    pol: &Policy,
    req: NewRequest<'_>,
) -> Result<RequestRow, ApiError> {
    let NewRequest { agent_name, agent_identity, scope, hours, reason } = req;
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
        "INSERT INTO requests(id, agent_name, agent_provider, agent_model, scope, reason, requested_hours, status, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'pending', ?8)",
        params![id, agent_name, agent_provider, agent_model, scope, reason, hours, ts],
    )
    .map_err(ApiError::from)?;
    audit(
        conn,
        dir,
        &format!("agent:{agent_name}"),
        "request.created",
        Some(&id),
        json!({"scope": scope, "hours": hours, "reason": reason}),
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
}

const SES_COLS: &str = "id, request_id, agent_name, agent_provider, agent_model, scope, created_at, expires_at, status, revoked_at, revoke_reason";

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
                "INSERT INTO sessions(id, request_id, agent_name, agent_provider, agent_model, scope, created_at, expires_at, status) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 'active')",
                params![ses_id, id, req.agent_name, req.agent_provider, req.agent_model, req.scope, ts, expires],
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
        json!({"request_id": id, "scope": req.scope, "hours": hours, "expires_at": expires}),
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

pub fn rotate_agent_token(conn: &Connection, dir: &Path) -> anyhow::Result<String> {
    let tok = crate::crypto::gen_token();
    set_meta(conn, "agent_token", &tok)?;
    audit(conn, dir, "owner", "token.rotated", None, json!({}));
    Ok(tok)
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
        assert_eq!(get_meta(&conn, "schema_version").as_deref(), Some("3"), "version must be upgraded to 3");
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
        assert_eq!(n, 3, "migrations do not re-run");
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
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-a", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "test" }).unwrap();
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
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-b", agent_identity: None, scope: "full_access", hours: 5.0, reason: "r" }).unwrap();
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
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-c", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r" }).unwrap();
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
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-d", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r" }).unwrap();
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
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-e", agent_identity: None, scope: "terminal_only", hours: 10.0, reason: "r" }).unwrap();
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
        let req1 = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-h", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r1" }).unwrap();
        let req2 = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-h", agent_identity: None, scope: "full_access", hours: 6.0, reason: "r2" }).unwrap();
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
        let req = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-i", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "r" }).unwrap();
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
            create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-f", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: &format!("r{i}") }).unwrap();
        }
        let err = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-f", agent_identity: None, scope: "terminal_only", hours: 6.0, reason: "one too many" }).unwrap_err();
        assert_eq!(err.code, "request_limit");
    }

    #[test]
    fn hours_validation_in_normal_mode() {
        // guard against a polluted environment from outside cargo test
        std::env::remove_var("FARCONTROL_TEST_MODE");
        let (conn, dir) = setup();
        let pol = Policy::default();
        let err = create_request(&conn, dir.path(), &pol, NewRequest { agent_name: "agent-g", agent_identity: None, scope: "terminal_only", hours: 1.0, reason: "too short" }).unwrap_err();
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
