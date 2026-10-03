use crate::config::Config;
use crate::error::ApiError;
use crate::keyring;
use crate::policy::Policy;
use crate::state;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;
use crate::term;
use crate::tls;
use crate::webui;

pub const AUTH_WINDOW_SECS: i64 = 300;

pub struct App {
    pub db: Mutex<rusqlite::Connection>,
    pub cfg: Config,
    pub data_dir: PathBuf,
    pub home_root: PathBuf,
    /// The LIVE admin token (v1.2 fix, e2e-found): rotate/panic update it
    /// in place — the file + meta alone were not enough, the owner CLI went
    /// dead (`admin_auth_failed`) after any rotation until restart.
    pub admin_token: Mutex<String>,
    pub pol: Policy,
    /// Live interactive terminals (v0.2, ADR-0013). Die with their session.
    pub terms: term::Terms,
    /// Global auth-failure timestamps (sliding window) — brute-force backoff
    /// (SE-09). Single-tenant box: one global window is the honest scope.
    pub auth_fails: Mutex<Vec<i64>>,
    /// Progressive lockout state (SC-01, ADR-0023; v1.1 ADR-0025 re-keyed per
    /// principal): consecutive-failure strikes escalate an exponentially
    /// growing lock window. Reset ONLY by a successful auth. In-memory: a
    /// daemon restart clears it (documented). Keys: device ids, "legacy",
    /// "webui", "admin" — one attacked device never locks out the others.
    pub auth_locks: Mutex<std::collections::HashMap<String, AuthLock>>,
    /// Agent secret lives in the kernel keyring (ADR-0023) — read per request.
    pub keyring_mode: bool,
    /// v0.3 web UI cookie sessions (ADR-0017) — token → expires_at (unix).
    /// In-memory: a daemon restart logs the console out (fail closed).
    pub ui_sessions: crate::webui::UiSessions,
    /// v0.7 observability: daemon start time (uptime metric, §35/App B).
    pub started_at: i64,
    /// v1.2 (ADR-0028): identifies THIS daemon run. Generated per start;
    /// the agent stores it to detect "the session I connected to is gone".
    pub session_id: String,
    /// v1.2 (ADR-0030): live agent runtimes seen via /v1/heartbeat —
    /// name → state. Display/liveness only; never authority.
    pub agents: Mutex<std::collections::HashMap<String, AgentState>>,
    /// v1.2 (ADR-0031): graceful shutdown channel — `frtrol stop` fires it.
    pub shutdown: tokio::sync::Notify,
}

/// v1.2 (ADR-0030): liveness record for one connected agent runtime.
#[derive(Debug, Clone, Serialize)]
pub struct AgentState {
    pub name: String,
    pub connected_at: i64,
    pub last_seen: i64,
}

/// An agent counts as connected while its heartbeat is fresher than this
/// (3 × the 15 s interval; test mode uses a 1 s interval so the window
/// shrinks too). Stale entries are swept + audited once.
pub const AGENT_STALE_SECS: i64 = 45;

impl App {
    /// Serializes the live agent map (newest first) with a derived `connected`
    /// flag — feeds `frtrol status` and the console header (r10).
    pub fn agents_json(&self) -> Vec<Value> {
        let now = state::now();
        let mut v: Vec<Value> = self
            .agents
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|a| {
                json!({
                    "name": a.name,
                    "connected_at": a.connected_at,
                    "last_seen": a.last_seen,
                    "connected": now - a.last_seen < agent_stale_secs(),
                })
            })
            .collect();
        v.sort_by(|a, b| b["last_seen"].as_i64().cmp(&a["last_seen"].as_i64()));
        v
    }
}

fn agent_stale_secs() -> i64 {
    if crate::policy::test_mode() { 3 } else { AGENT_STALE_SECS }
}

const MAX_TERMS: usize = 8;
const RATE_WINDOW_SECS: i64 = 60;
const RATE_MAX_FAILS: usize = 10;

// ============================================================
// v1.2 (ADR-0032 §4): Host-header allowlist for the admin plane.
// A browser pointed at a rebindable name (evil.example → 127.0.0.1) still
// sends Host: evil.example — reject anything that is not a loopback name.
// The agent plane is unaffected (HMAC, no ambient cookies).
// ============================================================
pub fn host_allowed(host_header: &str) -> bool {
    let h = host_header.trim().to_ascii_lowercase();
    // strip the port (last colon, but not inside an IPv6 literal)
    let name = if h.starts_with('[') {
        h.split(']').next().unwrap_or(&h).to_string() + "]"
    } else {
        h.rsplit_once(':').map(|(n, _)| n.to_string()).unwrap_or(h)
    };
    matches!(name.as_str(), "127.0.0.1" | "localhost" | "[::1]" | "::1")
}

async fn host_guard(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let host = req.headers().get(axum::http::header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !host_allowed(host) {
        return ApiError::forbidden(
            "bad_host",
            format!("Host '{host}' is not allowed on the local admin plane (DNS-rebinding guard)"),
        )
        .into_response();
    }
    next.run(req).await
}

/// Progressive lockout state (SC-01, ADR-0023).
#[derive(Default)]
pub struct AuthLock {
    /// Consecutive failed auths (reset to 0 only by a success).
    pub strikes: u32,
    /// Unix time the box stays locked (0 = unlocked).
    pub locked_until: i64,
    /// Last lock duration emitted — used to audit only real changes.
    pub last_lock: i64,
}

pub(crate) struct LockParams {
    pub max: usize,
    pub base: i64,
    pub cap: i64,
}

fn lock_params() -> LockParams {
    if crate::policy::test_mode() { LockParams { max: 6, base: 2, cap: 8 } } else { LockParams { max: RATE_MAX_FAILS, base: 60, cap: 3600 } }
}

/// Pure escalation math (SC-01): lock = base × 2^(strikes − max), capped.
/// Below the strike threshold there is no lock at all. Kept pure so it is
/// unit-testable without touching the env-dependent params.
pub(crate) fn lock_secs(strikes: u32, p: &LockParams) -> i64 {
    if (strikes as usize) < p.max {
        return 0;
    }
    let e = (strikes.saturating_sub(p.max as u32)).min(12);
    p.base.saturating_mul(1i64 << e).min(p.cap)
}

pub type Shared = Arc<App>;

pub(crate) fn lock(app: &App) -> std::sync::MutexGuard<'_, rusqlite::Connection> {
    app.db.lock().unwrap_or_else(|e| e.into_inner())
}

fn iso(ts: i64) -> String {
    chrono::DateTime::from_timestamp(ts, 0)
        .map(|d| d.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| ts.to_string())
}

pub(crate) fn logline(msg: &str) {
    println!("[{}] {}", iso(state::now()), msg);
}

fn is_root() -> bool {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Uid:"))
                .and_then(|l| l.split_whitespace().nth(1).map(|uid| uid == "0"))
        })
        .unwrap_or(false)
}

// ============================================================
// Daemon entry
// ============================================================

pub async fn run(
    data_dir: &std::path::Path,
    bind_override: Option<String>,
    allow_root: bool,
    verbose: bool,
) -> anyhow::Result<()> {
    let cfg_path = data_dir.join("config.toml");
    let mut cfg: Config = if cfg_path.exists() {
        toml::from_str(&std::fs::read_to_string(&cfg_path)?)?
    } else {
        Config::default()
    };
    if let Some(b) = bind_override {
        cfg.agent_bind = b;
    }
    // SC-02 (ADR-0023): validate the config BEFORE anything binds or opens.
    if let Err(e) = cfg.validate() {
        anyhow::bail!("config_invalid: {e}");
    }

    let db_path = data_dir.join("state.db");
    if !db_path.exists() {
        anyhow::bail!("not initialized — run: frtrol init");
    }
    if is_root() && !allow_root {
        anyhow::bail!("refusing to run as root — FARcontrol must run as the owner user (override with --allow-root)");
    }

    let keyring_mode = cfg.keyring_mode();

    let conn = state::open_db(&db_path)?;

    // v1.2 (ADR-0028/0031 §5): the machine device + one-time migration of
    // any v1.1 registry (legacy rows locked, keys rotated to noise, their
    // grants revoked, everything audited).
    let machine_id = state::machine_id(&conn);
    state::migrate_session_model(&conn, data_dir, &machine_id)?;
    // Secret-store mode must match how this data dir was initialized — a
    // mismatch is a misconfiguration, not something to silently paper over.
    let mode_meta = state::get_meta(&conn, "secret_store");
    if keyring_mode && mode_meta.as_deref() == Some("file") {
        anyhow::bail!(
            "config_invalid: this data dir was initialized with secret_store=file, but config.toml says keyring — fix [identity] secret_store or re-init"
        );
    }
    if !keyring_mode && mode_meta.as_deref() == Some("keyring") {
        anyhow::bail!(
            "config_invalid: this data dir was initialized with secret_store=keyring, but config.toml says file — fix [identity] secret_store or re-init"
        );
    }

    // Admin plane MUST be loopback (ADR-0004) — the approval path never touches the network.
    let admin_ip: IpAddr = cfg
        .admin_bind
        .split_once(':')
        .map(|(ip, _)| ip)
        .unwrap_or("")
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid admin_bind: {}", cfg.admin_bind))?;
    if !admin_ip.is_loopback() {
        anyhow::bail!("admin_bind ({}) must be a loopback address", cfg.admin_bind);
    }

    let home_root = PathBuf::from(&cfg.home_root)
        .canonicalize()
        .map_err(|_| anyhow::anyhow!("home_root '{}' does not exist", cfg.home_root))?;

    let pol = Policy::from_config(&cfg.policy);

    // ADR-0022 (AD-08): audit retention is opt-in via [audit] max_events.
    // Absent/0 = keep forever. Persisted to meta so state::audit() honors it.
    {
        let rc = state::open_db(&db_path)?;
        let max = cfg
            .audit
            .as_ref()
            .and_then(|t| t.get("max_events"))
            .and_then(|v| v.as_integer())
            .unwrap_or(0);
        if max < 0 {
            anyhow::bail!("[audit] max_events must be ≥ 0 (0 = keep forever)");
        }
        state::set_meta(&rc, "audit_retention_max", &max.to_string())?;
    }

    // v0.2 TLS: auto self-signed cert, both planes speak HTTPS (ADR-0004).
    let use_tls = cfg.use_tls;
    let acceptor = if use_tls {
        let (certs, key) = tls::ensure_cert(data_dir)?;
        let sc = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("tls config: {e}"))?;
        Some(tokio_rustls::TlsAcceptor::from(Arc::new(sc)))
    } else {
        None
    };
    let scheme = if use_tls { "https" } else { "http" };

    // Single-session enforcement (master prompt §41): the ports are claimed
    // BEFORE any credential is minted — a failed second start must never
    // rotate the running session's on-disk credentials (smoke-found bug).
    let admin_listener = TcpListener::bind(&cfg.admin_bind)
        .await
        .map_err(|_| anyhow::anyhow!("cannot bind admin {} — another frtrol session is already running (frtrol status / frtrol stop)", cfg.admin_bind))?;
    let agent_listener = TcpListener::bind(&cfg.agent_bind)
        .await
        .map_err(|_| anyhow::anyhow!("cannot bind agent {} — another frtrol session is already running (frtrol status / frtrol stop)", cfg.agent_bind))?;

    // v1.2 (ADR-0028 §1): mint THIS run's ephemeral credentials — only after
    // this start has proven it owns the ports. Every credential from any
    // previous run dies right here.
    let creds = state::begin_daemon_session(&conn, data_dir, &machine_id, !keyring_mode)?;
    if keyring_mode {
        // the kernel payload becomes exactly {machine_id: key} — old keys
        // (v1.1 registry, v1.0 token) are gone from the ring by construction.
        let mut map = std::collections::BTreeMap::new();
        map.insert(machine_id.clone(), creds.key.clone());
        keyring::store(data_dir, &state::serialize_key_payload(&map))?;
    }
    write_secret(&data_dir.join("admin-token"), &creds.admin_token)?;
    let first_start = state::get_meta(&conn, "v12_first_start").is_none();
    state::set_meta(&conn, "v12_first_start", "1")?;

    let app: Shared = Arc::new(App {
        db: Mutex::new(conn),
        cfg,
        data_dir: data_dir.to_path_buf(),
        home_root,
        admin_token: Mutex::new(creds.admin_token.clone()),
        pol,
        terms: term::Terms::default(),
        auth_fails: Mutex::new(Vec::new()),
        auth_locks: Mutex::new(std::collections::HashMap::new()),
        keyring_mode,
        ui_sessions: webui::UiSessions::default(),
        started_at: state::now(),
        session_id: crate::crypto::gen_id("ses"),
        agents: Mutex::new(std::collections::HashMap::new()),
        shutdown: tokio::sync::Notify::new(),
    });

    // v1.2 (ADR-0028, research r6): the session box — everything the owner
    // needs, nothing they don't. Operator detail lives behind --verbose.
    logline(&format!(
        "FARcontrol {} session started | pid {} | session {}",
        env!("CARGO_PKG_VERSION"),
        std::process::id(),
        app.session_id
    ));
    println!("\nFARcontrol {} — session started{}", env!("CARGO_PKG_VERSION"), if first_start { "  (first run)" } else { "" });
    println!("  device id        : {machine_id}");
    println!("  session password : {}", creds.password);
    // r6 discipline: value lines must stay uniquely greppable — no other
    // banner line may contain the labels "session password" / "admin token"
    // (e2e-found: "(login: admin token below)" here poisoned every grep).
    println!("  web console      : {}://{}/   (login: the token on the next line)", scheme, app.cfg.admin_bind);
    println!("  admin token      : {}", creds.admin_token);
    println!();
    println!("  hand those two lines to your AI agent's operator, then on the");
    println!("  agent machine run:   frtrol agent");
    println!();
    println!("  everything above dies when this process stops (Ctrl-C, or:");
    println!("  frtrol stop).  waiting for agent requests…\n");
    if verbose {
        println!("  ── operator detail (frtrol start --verbose) ──");
        println!("  data dir   : {}", app.data_dir.display());
        println!("  os/arch    : {} / {}", std::env::consts::OS, std::env::consts::ARCH);
        println!("  session id : {}", app.session_id);
        println!("  agent API  : {}://{}  (machine device + HMAC + TLS, ADR-0028/0005/0004)", scheme, app.cfg.agent_bind);
        println!("  admin API  : {}://{}  (owner only, loopback + Host allowlist, ADR-0032)", scheme, app.cfg.admin_bind);
        if use_tls {
            let fp = std::fs::read_to_string(data_dir.join("cert.pem"))
                .ok()
                .and_then(|pem| crate::tls::pem_first_block(&pem, "CERTIFICATE"))
                .map(|der| crate::crypto::cert_fingerprint(&der))
                .unwrap_or_else(|| "unavailable".into());
            println!("  fingerprint: {fp}   (SSH-style TOFU — compare with 'frtrol fingerprint')");
        }
        println!("  home root  : {}", app.home_root.display());
        println!("  policy     : standard — session 5–72h, exec ≤300s, output 256KiB, files ≤1MiB under $HOME");
        println!("  secret store: {}", if keyring_mode { "kernel keyring" } else { "state.db (0600 dir)" });
    }

    // Sweeper: expire due sessions + stale pending requests + old nonces
    // (defense in depth on top of the lazy check in authorize_session),
    // + v1.2 silent-agent sweep (ADR-0030: heartbeat gone → audit once).
    {
        let app2 = app.clone();
        tokio::spawn(async move {
            let sweep_secs = if crate::policy::test_mode() { 1 } else { 30 };
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(sweep_secs));
            loop {
                tick.tick().await;
                let expired = {
                    let conn = lock(&app2);
                    state::expire_due(&conn, &app2.data_dir)
                };
                for id in expired {
                    logline(&format!("session {id} expired"));
                }
                let stale = {
                    let conn = lock(&app2);
                    state::expire_stale_requests(&conn, &app2.data_dir, app2.pol.pending_ttl_secs)
                };
                for id in stale {
                    logline(&format!("request {id} expired (pending TTL {}s)", app2.pol.pending_ttl_secs));
                }
                // v0.2: terminals die with their session — reap strays every sweep.
                let active: Vec<String> = {
                    let conn = lock(&app2);
                    state::active_session_ids(&conn)
                };
                let killed = app2.terms.reap_inactive(&active);
                if killed > 0 {
                    logline(&format!("{killed} terminal(s) killed — session no longer active"));
                }
                {
                    let conn = lock(&app2);
                    state::nonces_cleanup(&conn);
                }
                // v1.2 (ADR-0030): agents whose heartbeat went silent past the
                // stale window are dropped + audited once (no per-sweep spam —
                // removal from the map makes it exactly once).
                let silent: Vec<AgentState> = {
                    let mut agents = app2.agents.lock().unwrap_or_else(|e| e.into_inner());
                    let cutoff = state::now() - agent_stale_secs();
                    let silent: Vec<AgentState> = agents.values().filter(|a| a.last_seen < cutoff).cloned().collect();
                    for a in &silent {
                        agents.remove(&a.name);
                    }
                    silent
                };
                for a in silent {
                    logline(&format!("agent '{}' went silent — no heartbeat", a.name));
                    let conn = lock(&app2);
                    state::audit(&conn, &app2.data_dir, &format!("agent:{}", a.name), "agent.timeout", None, json!({ "last_seen": a.last_seen }));
                }
            }
        });
    }

    let agent_router = build_agent_router(&app);
    let admin_router = build_admin_router(&app);

    let agent_task = tokio::spawn(serve_plane(agent_listener, acceptor.clone(), agent_router));
    let admin_task = tokio::spawn(serve_plane(admin_listener, acceptor, admin_router));

    // Block until Ctrl-C, `frtrol stop`, or a server task dies.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = app.shutdown.notified() => {
            logline("shutdown requested by owner (frtrol stop) — session ends, all credentials die");
        },
        _ = agent_task => {},
        _ = admin_task => {},
    }
    logline("shutting down");
    Ok(())
}


/// Body-limit rejections from axum's default 2 MiB cap arrive as plain text —
/// rewrite them into the JSON error envelope so machine clients (the whole
/// point of this product) always get a parseable error. Found by the v0.5
/// fuzz harness (ADR-0019); status stays 413, semantics unchanged.
async fn body_limit_json(resp: Response) -> Response {
    if resp.status() == StatusCode::PAYLOAD_TOO_LARGE {
        return ApiError::too_large(
            "payload_too_large",
            "request body exceeds the 2 MiB body limit (policy file limits apply separately)",
        )
        .into_response();
    }
    resp
}

/// Agent-plane routes (v0.1 core + v0.2 term + v0.4 adapters).
/// Split out of run() so the fuzz harness can hammer the REAL router
/// in-process (spec §75, ADR-0019).
pub(crate) fn build_agent_router(app: &Shared) -> Router {
    Router::new()
        .route("/v1/ping", get(ping))
        .route("/v1/auth/login", post(auth_login))
        // v1.2 (ADR-0030): agent-runtime liveness — HMAC-signed, updates the
        // owner-visible agent map, carries the session id for reconnect logic.
        .route("/v1/heartbeat", get(heartbeat))
        .route("/v1/session/request", post(session_request))
        .route("/v1/session/status", get(session_status))
        .route("/v1/session/revoke", post(agent_revoke))
        .route("/v1/exec", post(exec_handler))
        .route("/v1/file/read", post(file_read))
        .route("/v1/file/write", post(file_write))
        .route("/v1/file/list", post(file_list))
        .route("/v1/term/open", post(term_open))
        .route("/v1/term/write", post(term_write))
        .route("/v1/term/read", post(term_read))
        .route("/v1/term/close", post(term_close))
        // v0.4 Full Access adapters (Phase 4, ADR-0018)
        .route("/v1/process/list", post(process_list))
        .route("/v1/process/kill", post(process_kill))
        .route("/v1/app/launch", post(app_launch))
        .route("/v1/app/close", post(app_close))
        .route("/v1/desktop/screenshot", post(desktop_screenshot))
        .route("/v1/desktop/input", post(desktop_input))
        .fallback(not_found)
        .layer(axum::middleware::map_response(body_limit_json))
        .with_state(app.clone())
}

/// Admin-plane routes: owner API + v0.3 web console (ADR-0017).
/// v1.2 (ADR-0032 §4): every request passes the Host allowlist first —
/// DNS-rebinding names never reach the cookie-authenticated console.
pub(crate) fn build_admin_router(app: &Shared) -> Router {
    Router::new()
        .route("/admin/ping", get(admin_ping))
        .route("/admin/requests", get(admin_requests))
        .route("/admin/approve", post(admin_approve))
        .route("/admin/deny", post(admin_deny))
        .route("/admin/revoke", post(admin_revoke))
        .route("/admin/sessions", get(admin_sessions))
        .route("/admin/rotate", post(admin_rotate))
        .route("/admin/audit", get(admin_audit))
        .route("/admin/panic", post(admin_panic))
        .route("/admin/doctor", get(admin_doctor))
        .route("/admin/backup", post(admin_backup))
        // v1.2 (ADR-0031): graceful session stop — `frtrol stop`.
        .route("/admin/shutdown", post(admin_shutdown))
        // v0.7 observability (App B): unauthenticated local probes — loopback
        // plane only, zero secret data, for systemd/monitoring.
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/admin/metrics", get(admin_metrics))
        // v0.3: owner web console rides the admin plane (loopback + TLS, ADR-0017)
        .merge(webui::routes())
        .fallback(not_found)
        .layer(axum::middleware::map_response(body_limit_json))
        .layer(axum::middleware::from_fn(host_guard))
        .with_state(app.clone())
}

/// Serves one plane (agent or admin) over TLS or plain TCP.
async fn serve_plane(listener: TcpListener, acceptor: Option<tokio_rustls::TlsAcceptor>, router: Router) {
    let Some(acc) = acceptor else {
        if let Err(e) = axum::serve(listener, router).await {
            eprintln!("[farcontrol] server error: {e}");
        }
        return;
    };
    // Manual accept loop: TCP → TLS handshake → hyper serves the axum Router
    // per connection (fail closed: a failed handshake = dead connection).
    loop {
        let Ok((sock, _)) = listener.accept().await else { continue };
        let acc = acc.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let tls = match acc.accept(sock).await {
                Ok(t) => t,
                Err(_) => return,
            };
            let svc = hyper_util::service::TowerToHyperService::new(router);
            let io = hyper_util::rt::TokioIo::new(tls);
            let builder = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
            let _ = builder.serve_connection(io, svc).await;
        });
    }
}

// ============================================================
// Rate limiting (SE-09) + progressive lockout (SC-01, ADR-0023).
// Layer 1: sliding window of auth failures (burst brake).
// Layer 2: strike counter → exponential lock window; attempts while
//          locked EXTEND the lock; only a successful auth resets it.
// Test mode shrinks both so e2e can verify lockout + recovery.
// ============================================================

fn rate_window() -> (i64, usize) {
    if crate::policy::test_mode() { (2, 6) } else { (RATE_WINDOW_SECS, RATE_MAX_FAILS) }
}

/// Layer-2 lockout state for ONE principal (device id / "webui" / "admin").
fn principal_lock<'a>(
    locks: &'a mut std::collections::HashMap<String, AuthLock>,
    principal: &str,
) -> &'a mut AuthLock {
    locks.entry(principal.to_string()).or_default()
}

/// Count one strike + (re)compute the lock. Returns (audit_worthy, lock_secs)
/// where audit_worthy means the lock duration actually changed (bounded audit
/// growth: hammering at cap produces no new rows).
fn apply_strike(lk: &mut AuthLock, nowts: i64, p: &LockParams) -> (bool, i64) {
    lk.strikes = lk.strikes.saturating_add(1);
    if (lk.strikes as usize) < p.max {
        return (false, 0);
    }
    let secs = lock_secs(lk.strikes, p);
    let until = (nowts + secs).max(lk.locked_until);
    let changed = until > lk.locked_until || secs != lk.last_lock;
    lk.locked_until = until;
    lk.last_lock = secs;
    (changed, secs)
}

/// Global burst brake (layer 1) + per-principal lockout (layer 2, ADR-0025).
/// `principal` scopes the progressive lock so one attacked device (or the
/// webui login) never locks out the rest; the short global window still stops
/// network-level floods. The admin plane never *checks* a lock — the owner
/// panic path stays alive during an attack (ADR-0023).
pub(crate) fn rate_limit_check(app: &App, principal: &str) -> Result<(), ApiError> {
    let nowts = state::now();
    let p = lock_params();
    let mut locks = app.auth_locks.lock().unwrap_or_else(|e| e.into_inner());
    // Progressive lockout: an attempt while locked EXTENDS the lock.
    {
        let lk = principal_lock(&mut locks, principal);
        if lk.locked_until > nowts {
            let (changed, secs) = apply_strike(lk, nowts, &p);
            let retry = (lk.locked_until - nowts).max(1);
            let strikes = lk.strikes;
            drop(locks);
            let conn = lock(app);
            if changed {
                state::audit(&conn, &app.data_dir, "network", "auth.backoff", Some(principal), json!({ "strikes": strikes, "lock_secs": secs }));
            }
            return Err(ApiError::new(
                axum::http::StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                format!("auth locked — progressive backoff, retry in {retry}s (fail closed; strikes {strikes})"),
            ));
        }
    }
    drop(locks);
    // Burst window (unchanged v0.2 semantics — global, seconds-scale only).
    // v1.2 fix (e2e-found): the brake REFUSES this request but does NOT put
    // strikes onto the calling principal — an innocent heartbeat next to a
    // brute-force storm must not inherit the storm's strike count and wedge
    // its own progressive lock. A principal's lock still grows from its OWN
    // failures (rate_record_fail) and still extends while locked (above).
    let (win, max) = rate_window();
    let mut fails = app.auth_fails.lock().unwrap_or_else(|e| e.into_inner());
    fails.retain(|t| nowts - *t < win);
    if fails.len() >= max {
        let retry = (win - (nowts - fails[0])).max(1);
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("too many failed auth attempts — retry in {retry}s (fail closed)"),
        ));
    }
    Ok(())
}

pub(crate) fn rate_record_fail(app: &App, principal: &str) {
    {
        let mut fails = app.auth_fails.lock().unwrap_or_else(|e| e.into_inner());
        fails.push(state::now());
    }
    let (changed, secs) = {
        let mut locks = app.auth_locks.lock().unwrap_or_else(|e| e.into_inner());
        let lk = principal_lock(&mut locks, principal);
        apply_strike(lk, state::now(), &lock_params())
    };
    if changed {
        let conn = lock(app);
        state::audit(&conn, &app.data_dir, "network", "auth.backoff", Some(principal), json!({ "lock_secs": secs }));
    }
}

/// Successful auth resets both layers for the principal (owner/agent recovery).
fn rate_record_success(app: &App, principal: &str) {
    {
        let mut locks = app.auth_locks.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(lk) = locks.get_mut(principal) {
            lk.strikes = 0;
            lk.locked_until = 0;
            lk.last_lock = 0;
        }
    }
    app.auth_fails.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

// ============================================================
// Authentication
// ============================================================

fn auth_reject(app: &App, principal: &str, code: &str) {
    rate_record_fail(app, principal);
    let conn = lock(app);
    state::audit(&conn, &app.data_dir, "network", "auth.rejected", Some(principal), json!({ "code": code }));
}

use rusqlite::Connection;

/// Per-request device-key loader (ID-04 discipline, ADR-0025): file mode reads
/// the devices table per request (rotation instant); keyring mode reads the
/// kernel keyring payload map per request. No in-memory copy to go stale.
fn load_device_key(app: &App, conn: &Connection, device_id: &str) -> Result<String, ApiError> {
    if app.keyring_mode {
        let payload = keyring::load(&app.data_dir)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::internal("device keys missing from the kernel keyring — re-run: frtrol init"))?;
        let map = state::parse_key_payload(&payload);
        // migrated installs key by device id; an unmigrated bare payload keys
        // the legacy token under "legacy" (migrate_devices rewrites at start).
        let key = map.get(device_id).or_else(|| if device_id == "legacy" { map.get("legacy") } else { None });
        key.filter(|k| !k.is_empty())
            .cloned()
            .ok_or_else(|| ApiError::unauthorized("unknown_device", format!("device {device_id} has no valid key")))
    } else {
        state::device_get(conn, device_id)
            .and_then(|d| d.device_key)
            .filter(|k| !k.is_empty())
            .ok_or_else(|| ApiError::unauthorized("unknown_device", format!("device {device_id} has no valid key")))
    }
}

/// The authenticated principal of an agent-plane request (ADR-0025).
/// v1.2: always `Some(device_id)` — the machine device (X-Far-Device is
/// mandatory now; the v1.0 headerless compat shim is retired, ADR-0031).
#[derive(Debug, Clone)]
pub struct Authed {
    pub device_id: Option<String>,
}

/// Agent-plane auth: HMAC-SHA256 proof-of-possession + anti-replay (ADR-0005)
/// + device identity (ADR-0025).
///
/// Order: headers, timestamp window, device resolve, lockout, signature, nonce burn.
fn verify_agent(
    app: &App,
    headers: &HeaderMap,
    method: &Method,
    uri: &Uri,
    body: &[u8],
) -> Result<Authed, ApiError> {
    // ADR-0022 (§44 / AU-06): protocol version negotiation, fail-closed form:
    // an advertised version we do not speak is rejected. Absent header is
    // treated as FAR-PROTO/1 (documented — 0.x clients stay compatible).
    if let Some(v) = headers.get("x-far-proto").and_then(|v| v.to_str().ok()) {
        if v.trim() != "1" {
            return Err(ApiError::bad_request(
                "unsupported_proto",
                format!("server speaks FAR-PROTO/1, client advertised '{v}'"),
            ));
        }
    }
    let missing = |app: &App, what: &str| -> ApiError {
        auth_reject(app, "unknown", "missing_headers");
        ApiError::unauthorized("missing_headers", format!("missing header: {what}"))
    };
    let ts_hdr = match headers.get("x-far-timestamp").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Err(missing(app, "X-Far-Timestamp")),
    };
    let nonce = match headers.get("x-far-nonce").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Err(missing(app, "X-Far-Nonce")),
    };
    let sig_hex = match headers.get("x-far-signature").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => return Err(missing(app, "X-Far-Signature")),
    };
    // v1.2: the device selector header is REQUIRED (machine device, ADR-0028).
    let Some(device_hdr) = headers
        .get("x-far-device")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
    else {
        auth_reject(app, "unknown", "missing_headers");
        return Err(ApiError::unauthorized(
            "missing_headers",
            "missing header: X-Far-Device (connect with 'frtrol agent' — it wires the headers for you)",
        ));
    };

    let ts: i64 = match ts_hdr.parse() {
        Ok(v) => v,
        Err(_) => {
            auth_reject(app, "unknown", "invalid_timestamp");
            return Err(ApiError::unauthorized("invalid_timestamp", "X-Far-Timestamp must be unix seconds (decimal)"));
        }
    };
    let now = state::now();
    if (now - ts).abs() > AUTH_WINDOW_SECS {
        auth_reject(app, "unknown", "stale_timestamp");
        return Err(ApiError::unauthorized(
            "stale_timestamp",
            format!("timestamp {ts} is outside the ±{AUTH_WINDOW_SECS}s window (server time {now})"),
        ));
    }

    let sig_bytes = match hex::decode(&sig_hex) {
        Ok(b) => b,
        Err(_) => {
            auth_reject(app, "unknown", "invalid_signature");
            return Err(ApiError::unauthorized("invalid_signature", "X-Far-Signature must be hex"));
        }
    };

    // Resolve the principal FIRST — rate limiting happens BEFORE the device
    // row resolves so unknown ids and floods still hit the brake
    // (v1.1 fix: no unthrottled rejection path).
    let principal = format!("dev:{device_hdr}");
    rate_limit_check(app, &principal)?;

    // Resolve the device + key. Fail-closed at every step. Scoped so the lock
    // is released before the signature stage takes it again (std::sync::Mutex
    // is NOT reentrant — a held guard + second lock() = same-thread deadlock).
    let device_id = {
        let conn = lock(app);
        if !crate::crypto::device_id_valid(&device_hdr) {
            drop(conn);
            auth_reject(app, &principal, "invalid_device_id");
            return Err(ApiError::unauthorized(
                "invalid_device_id",
                format!("'{device_hdr}' is not a valid FAR-XXXX-XXXX device id (typo? the check char catches single mistakes)"),
            ));
        }
        match state::device_get(&conn, &device_hdr) {
            Some(d) if d.login_enabled => device_hdr.clone(),
            Some(_) => {
                drop(conn);
                auth_reject(app, &principal, "device_locked");
                return Err(ApiError::forbidden(
                    "device_locked",
                    format!("device {device_hdr} is locked — its credentials were retired at a v1.2 migration or panic; connect with the current session password"),
                ));
            }
            None => {
                drop(conn);
                auth_reject(app, &principal, "unknown_device");
                return Err(ApiError::unauthorized("unknown_device", format!("no device with id {device_hdr}")));
            }
        }
    };

    // Build the signed payload: 6 fields, device claim bound (ADR-0025 §2).
    let body_sha = crate::crypto::sha256_hex(body);
    let payload = format!(
        "{}\n{device_id}",
        crypto::signing_payload(&ts_hdr, &nonce, method.as_str(), uri.path(), &body_sha)
    );

    let conn = lock(app);
    let device_key = load_device_key(app, &conn, &device_id)?;
    let expected = hex::decode(crypto::hmac_hex(&device_key, &payload))
        .map_err(|_| ApiError::internal("hmac failure"))?;
    let sig_ok = crypto::ct_eq(&sig_bytes, &expected);
    if !sig_ok {
        drop(conn);
        auth_reject(app, &principal, "invalid_signature");
        return Err(ApiError::unauthorized("invalid_signature", "signature verification failed"));
    }

    let fresh = state::nonce_insert(&conn, &nonce);
    if !fresh {
        drop(conn);
        auth_reject(app, &principal, "replay_detected");
        return Err(ApiError::unauthorized("replay_detected", "nonce already used — request replay"));
    }
    // Verified → touch the device + reset this principal's backoff (SC-01).
    state::device_touch(&conn, &device_id);
    drop(conn);
    rate_record_success(app, &principal);
    Ok(Authed { device_id: Some(device_id) })
}

use crate::crypto;

fn verify_admin(app: &App, headers: &HeaderMap) -> Result<(), ApiError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("admin_auth_failed", "missing Authorization: Bearer <admin-token>"))?;
    let tok = app.admin_token.lock().unwrap_or_else(|e| e.into_inner());
    if !crypto::ct_eq(auth.as_bytes(), tok.as_bytes()) {
        drop(tok);
        // Recorded (auditable) but never LOCKED — the owner panic path stays
        // alive while under attack (ADR-0023, kept in v1.1).
        rate_record_fail(app, "admin");
        let conn = lock(app);
        state::audit(&conn, &app.data_dir, "network", "auth.rejected", Some("admin"), json!({ "code": "admin_auth_failed" }));
        return Err(ApiError::unauthorized("admin_auth_failed", "invalid admin token"));
    }
    Ok(())
}

async fn not_found() -> Response {
    ApiError::not_found("not_found", "unknown endpoint — see README for the API map").into_response()
}

pub(crate) fn parse_body<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|e| ApiError::bad_request("invalid_request", format!("invalid JSON body: {e}")))
}

fn qparam(uri: &Uri, key: &str) -> Option<String> {
    let q = uri.query()?;
    for pair in q.split('&') {
        let mut it = pair.splitn(2, '=');
        let k = it.next().unwrap_or("");
        if k == key {
            return Some(it.next().unwrap_or("").to_string());
        }
    }
    None
}

// ============================================================
// Agent-plane handlers
// ============================================================

async fn ping(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &[])?;
    Ok(Json(json!({
        "ok": true,
        "service": "farcontrol",
        "version": env!("CARGO_PKG_VERSION"),
        "server_time": state::now()
    })))
}

// ============================================================
// v1.2 (ADR-0028 §1): session login → session key
// ============================================================

#[derive(Deserialize)]
struct LoginBody {
    device_id: String,
    password: Option<String>,
    /// v1.2: display name for the agent runtime (audit + console only —
    /// a declaration, never authority; AG-03 semantics unchanged).
    agent_name: Option<String>,
}

/// One shared dummy Argon2 hash so unknown-device logins cost the same as
/// known ones — no user-enumeration timing oracle. Generated once per process.
fn dummy_argon2() -> &'static str {
    use std::sync::OnceLock;
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| {
        crate::crypto::password_hash("frtrol-timing-equalization-dummy").unwrap_or_default()
    })
}

/// Sanitize a declared agent name (1–64 chars, no control chars) — display only.
fn agent_name_ok(name: &str) -> String {
    let n: String = name.trim().chars().filter(|c| !c.is_control()).collect();
    if n.is_empty() { "agent".to_string() } else { n.chars().take(64).collect() }
}

/// POST /v1/auth/login — session password → THIS run's session key (ADR-0028).
/// No HMAC here: pre-auth endpoint. TLS carries the password; the global burst
/// brake + per-principal backoff throttle guessing (Argon2id m=64 MiB).
///
/// v1.2 semantics: exactly one device (the machine). The key is NOT rotated on
/// login — several agents may hold it concurrently (the session credential is
/// one shared secret, like a Wi-Fi password; ADR-0028 §1). It dies at the next
/// `frtrol start` / `frtrol panic`.
async fn auth_login(
    State(app): State<Shared>,
    _headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    let _ = (&method, &uri); // same router shape as agent handlers (fuzz parity)
    let b: LoginBody = parse_body(&body)?;
    let id = b.device_id.trim().to_string();
    let pw = b.password.unwrap_or_default();
    let agent_name = b.agent_name.as_deref().map(agent_name_ok).unwrap_or_else(|| "agent".into());
    let principal = format!("login:{id}");

    if !crate::crypto::device_id_valid(&id) {
        let _ = crate::crypto::password_verify(dummy_argon2(), &pw); // equalize timing
        rate_record_fail(&app, &principal);
        return Err(ApiError::unauthorized(
            "invalid_device_id",
            format!("'{id}' is not a valid FAR-XXXX-XXXX device id (typo? the check char catches single mistakes)"),
        ));
    }
    rate_limit_check(&app, &principal)?;

    let machine_id = {
        let conn = lock(&app);
        state::machine_id(&conn)
    };
    let conn = lock(&app);
    let dev = match state::device_get(&conn, &id) {
        Some(d) => d,
        None => {
            let _ = crate::crypto::password_verify(dummy_argon2(), &pw); // equalize timing
            drop(conn);
            rate_record_fail(&app, &principal);
            let conn = lock(&app);
            state::audit(&conn, &app.data_dir, "network", "auth.login_failed", Some(&id), json!({ "reason": "unknown_device" }));
            return Err(ApiError::unauthorized("invalid_credentials", "device id or password is wrong"));
        }
    };
    if id != machine_id {
        // v1.2: only the machine device exists. Anything else — including a
        // pre-migration v1.1 device id — fails closed with the same generic
        // error (no existence oracle beyond v1.1 behavior).
        let _ = crate::crypto::password_verify(dummy_argon2(), &pw);
        drop(conn);
        rate_record_fail(&app, &principal);
        let conn = lock(&app);
        state::audit(&conn, &app.data_dir, "network", "auth.login_failed", Some(&id), json!({ "reason": "not_the_machine_device" }));
        return Err(ApiError::unauthorized("invalid_credentials", "device id or password is wrong (get both from 'frtrol start' on the owner machine)"));
    }
    if !dev.login_enabled || dev.status == "locked" {
        return Err(ApiError::forbidden(
            "device_locked",
            format!("device {id} is locked — restart the session (frtrol stop && frtrol start)"),
        ));
    }
    let Some(hash) = dev.password_hash.clone() else {
        return Err(ApiError::forbidden(
            "login_disabled",
            "no session password is set — (re)start the daemon: frtrol start",
        ));
    };
    drop(conn);

    if !crate::crypto::password_verify(&hash, &pw) {
        rate_record_fail(&app, &principal);
        let conn = lock(&app);
        state::audit(&conn, &app.data_dir, "network", "auth.login_failed", Some(&id), json!({ "reason": "bad_password" }));
        return Err(ApiError::unauthorized("invalid_credentials", "device id or session password is wrong (the password rotates on every 'frtrol start')"));
    }
    rate_record_success(&app, &principal);

    // Password proven → hand out THIS run's session key (not rotated on login,
    // ADR-0028). Load through the same per-request path verify_agent uses.
    let session_key = {
        let conn = lock(&app);
        let k = load_device_key(&app, &conn, &id)?;
        state::device_touch(&conn, &id);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{agent_name}"),
            "auth.login",
            Some(&id),
            json!({ "session_id": app.session_id, "name": agent_name, "note": "declared name — not verified" }),
        );
        k
    };
    logline(&format!("agent '{agent_name}' logged in with the session password (device {id})"));
    Ok(Json(json!({
        "ok": true,
        "device_id": id,
        "session_id": app.session_id,
        "key": session_key,
        "agent_name": agent_name,
        "note": "this key dies when the owner's session ends (frtrol stop / restart / panic)"
    })))
}

// ============================================================
// v1.2 (ADR-0030): agent runtime heartbeat
// ============================================================

/// GET /v1/heartbeat?name=<agent> — HMAC-signed liveness ping. Updates the
/// owner-visible agent map; first sighting audits `agent.seen`. The response
/// carries the session id so a runtime that reconnected to a NEW daemon run
/// can detect the mismatch and re-authenticate.
async fn heartbeat(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<Json<Value>, ApiError> {
    let authed = verify_agent(&app, &headers, &method, &uri, &[])?;
    let name = qparam(&uri, "name").map(|n| agent_name_ok(&n)).unwrap_or_else(|| "agent".into());
    let device = authed.device_id.clone().unwrap_or_default();
    let nowts = state::now();
    let first;
    {
        let mut agents = app.agents.lock().unwrap_or_else(|e| e.into_inner());
        match agents.get_mut(&name) {
            Some(a) => {
                a.last_seen = nowts;
                first = false;
            }
            None => {
                agents.insert(name.clone(), AgentState { name: name.clone(), connected_at: nowts, last_seen: nowts });
                first = true;
            }
        }
    }
    if first {
        let conn = lock(&app);
        state::audit(&conn, &app.data_dir, &format!("agent:{name}"), "agent.seen", Some(&device), json!({ "session_id": app.session_id }));
        logline(&format!("agent runtime '{name}' connected (heartbeat)"));
    }
    Ok(Json(json!({
        "ok": true,
        "session_id": app.session_id,
        "device_id": device,
        "server_time": nowts,
    })))
}

#[derive(Deserialize)]
struct SessionRequestBody {
    agent_name: Option<String>,
    provider: Option<String>,
    model: Option<String>,
    scope: Option<String>,
    hours: Option<f64>,
    reason: Option<String>,
}

async fn session_request(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Response, ApiError> {
    let authed = verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: SessionRequestBody = parse_body(&body)?;

    let mut agent_name = b.agent_name.unwrap_or_else(|| "unnamed-agent".into());
    agent_name = agent_name.trim().to_string();
    if agent_name.is_empty() {
        agent_name = "unnamed-agent".into();
    }
    if agent_name.len() > 64 || agent_name.chars().any(|c| c.is_control()) {
        return Err(ApiError::bad_request("invalid_request", "agent_name must be ≤64 printable characters"));
    }
    let scope = b.scope.unwrap_or_else(|| "terminal_only".into());
    if scope != "terminal_only" && scope != "full_access" {
        return Err(ApiError::bad_request(
            "invalid_scope",
            "scope must be 'terminal_only' or 'full_access'",
        ));
    }
    // ADR-0022 (spec §11 / §9.2–9.5): agent identity is optional, declaration-
    // only, both-or-none, and validated against the embedded catalog. One
    // enforcement point — server-side (S4). Identity never grants authority.
    let agent_identity = crate::catalog::validate(b.provider.as_deref(), b.model.as_deref())
        .map_err(|m| ApiError::bad_request("invalid_agent_identity", m))?;
    let identity_ref = agent_identity.as_ref().map(|(p, m)| (p.as_str(), m.as_str()));
    let hours = b.hours.unwrap_or(6.0);
    let reason: String = b.reason.unwrap_or_default().chars().take(256).collect();

    let row = {
        let conn = lock(&app);
        state::create_request(&conn, &app.data_dir, &app.pol, state::NewRequest {
            agent_name: &agent_name,
            agent_identity: identity_ref,
            scope: &scope,
            hours,
            reason: &reason,
            device_id: authed.device_id.as_deref(),
        })?
    };

    logline(&format!(
        "REQUEST {} from agent='{}' identity='{}' scope={} hours={} reason='{}'",
        row.id,
        row.agent_name,
        match (&row.agent_provider, &row.agent_model) {
            (Some(p), Some(m)) => format!("{p}/{m} (declared, not verified)"),
            _ => "undeclared".into(),
        },
        row.scope,
        row.requested_hours,
        row.reason
    ));
    println!("    → approve: frtrol approve {}    |    deny: frtrol deny {}", row.id, row.id);

    let body = json!({
        "request_id": row.id,
        "status": "pending_approval",
        "poll": format!("GET /v1/session/status?request_id={}", row.id),
        "note": "no access is granted until the owner approves"
    });
    Ok((StatusCode::ACCEPTED, Json(body)).into_response())
}

async fn session_status(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &[])?;
    let mut out = json!({});
    if let Some(rid) = qparam(&uri, "request_id") {
        let conn = lock(&app);
        let req = state::get_request(&conn, &rid)?;
        if let Some(sid) = &req.session_id {
            if let Ok(s) = state::get_session(&conn, sid) {
                out["session"] = state::session_json(&s);
            }
        }
        out["request"] = state::request_json(&req);
    } else if let Some(sid) = qparam(&uri, "session_id") {
        let conn = lock(&app);
        let s = state::get_session(&conn, &sid)?;
        out["session"] = state::session_json(&s);
    } else {
        return Err(ApiError::bad_request("invalid_request", "pass ?request_id=… or ?session_id=…"));
    }
    Ok(Json(out))
}

#[derive(Deserialize)]
struct AgentRevokeBody {
    session_id: String,
}

async fn agent_revoke(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: AgentRevokeBody = parse_body(&body)?;
    let (agent_name, existed) = {
        let conn = lock(&app);
        match state::get_session(&conn, &b.session_id) {
            Ok(s) => (Some(s.agent_name), true),
            Err(_) => (None, false),
        }
    };
    if !existed {
        return Err(ApiError::not_found("session_not_found", format!("no session with id {}", b.session_id)));
    }
    let row = {
        let conn = lock(&app);
        state::revoke_session(&conn, &app.data_dir, &b.session_id, "revoked by agent", &format!("agent:{}", agent_name.as_deref().unwrap_or("unknown")))?
    };
    let killed = app.terms.kill_for_session(&row.id);
    if killed > 0 {
        logline(&format!("{killed} terminal(s) killed with session {}", row.id));
    }
    logline(&format!("session {} self-revoked by agent", row.id));
    Ok(Json(json!({ "session": state::session_json(&row) })))
}

#[derive(Deserialize)]
struct ExecBody {
    session_id: String,
    command: Option<String>,
    args: Option<Vec<String>>,
    cwd: Option<String>,
    timeout_ms: Option<u64>,
}

async fn exec_handler(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: ExecBody = parse_body(&body)?;

    let command = b
        .command
        .filter(|c| !c.trim().is_empty())
        .ok_or_else(|| ApiError::bad_request("invalid_request", "command is required (non-empty string)"))?;
    if command.len() > app.pol.max_command_len {
        return Err(ApiError::bad_request("invalid_request", format!("command exceeds {} chars", app.pol.max_command_len)));
    }
    let args = b.args.unwrap_or_default();
    if args.len() > app.pol.max_args {
        return Err(ApiError::bad_request("invalid_request", format!("too many args (max {})", app.pol.max_args)));
    }
    if args.iter().any(|a| a.len() > 8192) {
        return Err(ApiError::bad_request("invalid_request", "single arg exceeds 8192 chars"));
    }

    // Invariant 1/2/3: authorization gate — every exec needs an ACTIVE session.
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "terminal_only")?
    };

    // Invariant 4: policy gate — denylist check on the full command line.
    let line = if args.is_empty() {
        command.clone()
    } else {
        format!("{command} {}", args.join(" "))
    };
    if let Some(pattern) = app.pol.is_denied(&line) {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "exec.denied",
            Some(&session.id),
            json!({ "command": line, "pattern": pattern }),
        );
        logline(&format!("exec DENIED on {} — policy pattern '{pattern}'", session.id));
        return Err(ApiError::forbidden(
            "policy_denied",
            format!("command matches policy denylist pattern '{pattern}' (standard package, ADR-0008)"),
        ));
    }

    // cwd: optional, must be an existing directory; default = home root.
    let cwd = match &b.cwd {
        Some(c) => {
            let p = PathBuf::from(c);
            if !p.is_dir() {
                return Err(ApiError::bad_request("invalid_cwd", format!("cwd '{c}' is not an existing directory")));
            }
            p
        }
        None => app.home_root.clone(),
    };

    let timeout_ms = app.pol.clamp_timeout_ms(b.timeout_ms);

    let outcome = crate::exec::run(&command, &args, &cwd, timeout_ms, app.pol.max_output_bytes)
        .await
        .map_err(|e| ApiError::internal(format!("spawn failed: {e} (command may not exist)")))?;

    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "exec.run",
            Some(&session.id),
            json!({
                "command": line,
                "status": outcome.status,
                "exit_code": outcome.exit_code,
                "duration_ms": outcome.duration_ms,
                "stdout_bytes": outcome.stdout.len(),
                "stderr_bytes": outcome.stderr.len(),
            }),
        );
    }
    logline(&format!(
        "exec {} status={} exit={:?} ({}ms) cmd='{}'",
        session.id, outcome.status, outcome.exit_code, outcome.duration_ms, line
    ));

    Ok(Json(json!({
        "session_id": session.id,
        "status": outcome.status,
        "exit_code": outcome.exit_code,
        "stdout": outcome.stdout,
        "stderr": outcome.stderr,
        "stdout_truncated": outcome.stdout_truncated,
        "stderr_truncated": outcome.stderr_truncated,
        "duration_ms": outcome.duration_ms,
    })))
}

#[derive(Deserialize)]
struct FileBody {
    session_id: String,
    path: String,
}

async fn file_read(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: FileBody = parse_body(&body)?;
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    let (path, data) = crate::files::read(&app.home_root, &b.path, app.pol.max_file_bytes)?;
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "file.read",
            Some(&session.id),
            json!({ "path": path.display().to_string(), "bytes": data.len() }),
        );
    }
    Ok(Json(json!({
        "session_id": session.id,
        "path": path.display().to_string(),
        "size": data.len(),
        "encoding": "base64",
        "content_b64": base64::engine::general_purpose::STANDARD.encode(&data),
    })))
}

#[derive(Deserialize)]
struct FileWriteBody {
    session_id: String,
    path: String,
    content_b64: String,
    append: Option<bool>,
}

async fn file_write(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: FileWriteBody = parse_body(&body)?;
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    let data = base64::engine::general_purpose::STANDARD
        .decode(&b.content_b64)
        .map_err(|_| ApiError::bad_request("invalid_base64", "content_b64 is not valid base64"))?;
    if data.len() > app.pol.max_file_bytes {
        return Err(ApiError::too_large(
            "payload_too_large",
            format!("decoded payload is {} bytes, policy maximum is {}", data.len(), app.pol.max_file_bytes),
        ));
    }
    let (path, written) = crate::files::write(&app.home_root, &b.path, &data, b.append.unwrap_or(false))?;
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "file.write",
            Some(&session.id),
            json!({ "path": path.display().to_string(), "bytes": written, "append": b.append.unwrap_or(false) }),
        );
    }
    logline(&format!(
        "file.write {} bytes → {} (session {})",
        written,
        path.display(),
        session.id
    ));
    Ok(Json(json!({
        "session_id": session.id,
        "path": path.display().to_string(),
        "written": written,
    })))
}

async fn file_list(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: FileBody = parse_body(&body)?;
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    let (path, entries, truncated) = crate::files::list(&app.home_root, &b.path, app.pol.max_list_entries)?;
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "file.list",
            Some(&session.id),
            json!({ "path": path.display().to_string(), "entries": entries.len() }),
        );
    }
    let entries_json: Vec<Value> = entries
        .iter()
        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
        .collect();
    Ok(Json(json!({
        "session_id": session.id,
        "path": path.display().to_string(),
        "entries": entries_json,
        "count": entries.len(),
        "truncated": truncated,
    })))
}

// ============================================================
// v0.4: Full Access adapters (Phase 4, ADR-0018) — process,
// application, desktop. Every call: full_access session → policy
// → adapter → audit. An adapter can never bypass the pipeline.
// ============================================================

#[derive(Deserialize)]
struct ProcessListBody {
    session_id: String,
}

async fn process_list(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: ProcessListBody = parse_body(&body)?;
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    let (procs, truncated) = crate::adapters::list_processes(500);
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "process.list",
            Some(&session.id),
            json!({ "count": procs.len(), "truncated": truncated }),
        );
    }
    let v: Vec<Value> = procs.iter().map(|p| serde_json::to_value(p).unwrap_or(Value::Null)).collect();
    Ok(Json(json!({
        "session_id": session.id,
        "processes": v,
        "count": v.len(),
        "truncated": truncated,
        "note": "is_self=true is the frtrol daemon — kill is refused there",
    })))
}

#[derive(Deserialize)]
struct ProcessKillBody {
    session_id: String,
    pid: i64,
    #[serde(default)]
    force: bool,
}

async fn process_kill(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: ProcessKillBody = parse_body(&body)?;
    if b.pid < i32::MIN as i64 || b.pid > i32::MAX as i64 {
        return Err(ApiError::bad_request("invalid_request", "pid out of range"));
    }
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    // Invariant 8: security actions are auditable — kill ALWAYS leaves a record.
    match crate::adapters::kill_pid(b.pid as i32, b.force) {
        Ok(()) => {
            {
                let conn = lock(&app);
                state::audit(
                    &conn,
                    &app.data_dir,
                    &format!("agent:{}", session.agent_name),
                    "process.kill",
                    Some(&session.id),
                    json!({ "pid": b.pid, "signal": if b.force { "KILL" } else { "TERM" } }),
                );
            }
            logline(&format!("process.kill pid={} ({}) by session {}", b.pid, if b.force { "KILL" } else { "TERM" }, session.id));
            Ok(Json(json!({ "killed": true, "pid": b.pid, "signal": if b.force { "KILL" } else { "TERM" } })))
        }
        Err(e) => {
            {
                let conn = lock(&app);
                state::audit(
                    &conn,
                    &app.data_dir,
                    &format!("agent:{}", session.agent_name),
                    "process.kill.denied",
                    Some(&session.id),
                    json!({ "pid": b.pid, "reason": e }),
                );
            }
            Err(ApiError::forbidden("kill_refused", e))
        }
    }
}

#[derive(Deserialize)]
struct AppLaunchBody {
    session_id: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
}

async fn app_launch(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: AppLaunchBody = parse_body(&body)?;
    let command = b.command.trim().to_string();
    if command.is_empty() {
        return Err(ApiError::bad_request("invalid_request", "command is required (non-empty)"));
    }
    if command.len() > app.pol.max_command_len {
        return Err(ApiError::bad_request("invalid_request", format!("command exceeds {} chars", app.pol.max_command_len)));
    }
    if b.args.len() > app.pol.max_args {
        return Err(ApiError::bad_request("invalid_request", format!("too many args (max {})", app.pol.max_args)));
    }
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    // policy gate — same denylist as exec (a launch IS an execution)
    let line = if b.args.is_empty() { command.clone() } else { format!("{command} {}", b.args.join(" ")) };
    if let Some(pattern) = app.pol.is_denied(&line) {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "app.launch.denied",
            Some(&session.id),
            json!({ "command": line, "pattern": pattern }),
        );
        return Err(ApiError::forbidden("policy_denied", format!("command matches policy denylist pattern '{pattern}'")));
    }
    let pid = crate::adapters::launch_app(&command, &b.args, &app.home_root)
        .await
        .map_err(|e| ApiError::bad_request("spawn_failed", format!("{e} (env is scrubbed: PATH/HOME/LANG/TERM/SHELL only)")))?;
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "app.launch",
            Some(&session.id),
            json!({ "command": line, "pid": pid }),
        );
    }
    logline(&format!("app.launch pid={pid} cmd='{}' on session {}", line, session.id));
    Ok(Json(json!({
        "pid": pid,
        "command": line,
        "detached": true,
        "note": "output is not captured (use exec/term for that); close it with app/close or process/kill",
    })))
}

#[derive(Deserialize)]
struct AppCloseBody {
    session_id: String,
    pid: i64,
}

/// application.close — refuses to be a generic kill-shot: it only reaches
/// process.kill's guards (PID 1 + self protected), audited as app.close.
async fn app_close(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: AppCloseBody = parse_body(&body)?;
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    match crate::adapters::kill_pid(b.pid as i32, false) {
        Ok(()) => {
            {
                let conn = lock(&app);
                state::audit(
                    &conn,
                    &app.data_dir,
                    &format!("agent:{}", session.agent_name),
                    "app.close",
                    Some(&session.id),
                    json!({ "pid": b.pid, "signal": "TERM" }),
                );
            }
            Ok(Json(json!({ "closed": true, "pid": b.pid, "signal": "TERM" })))
        }
        Err(e) => {
            let conn = lock(&app);
            state::audit(
                &conn,
                &app.data_dir,
                &format!("agent:{}", session.agent_name),
                "app.close.denied",
                Some(&session.id),
                json!({ "pid": b.pid, "reason": e }),
            );
            Err(ApiError::forbidden("kill_refused", e))
        }
    }
}

#[derive(Deserialize)]
struct DesktopBody {
    session_id: String,
}

/// desktop.read — fails CLOSED with a clean machine error on headless boxes.
async fn desktop_screenshot(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: DesktopBody = parse_body(&body)?;
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    match crate::adapters::screenshot(app.pol.max_file_bytes).await {
        Ok(data) => {
            {
                let conn = lock(&app);
                state::audit(
                    &conn,
                    &app.data_dir,
                    &format!("agent:{}", session.agent_name),
                    "desktop.screenshot",
                    Some(&session.id),
                    json!({ "bytes": data.len() }),
                );
            }
            Ok(Json(json!({
                "session_id": session.id,
                "bytes": data.len(),
                "encoding": "base64",
                "content_b64": base64::engine::general_purpose::STANDARD.encode(&data),
            })))
        }
        Err(e) => {
            let code = if e == "DESKTOP_UNAVAILABLE" { "desktop_unavailable" } else { "desktop_failed" };
            let msg = if e == "DESKTOP_UNAVAILABLE" {
                "no graphical session (DISPLAY/WAYLAND_DISPLAY unset) — this capability needs a desktop".to_string()
            } else {
                e
            };
            let conn = lock(&app);
            state::audit(
                &conn,
                &app.data_dir,
                &format!("agent:{}", session.agent_name),
                "desktop.screenshot.denied",
                Some(&session.id),
                json!({ "code": code }),
            );
            Err(ApiError::conflict(code, msg))
        }
    }
}

#[derive(Deserialize)]
struct DesktopInputBody {
    session_id: String,
    text: String,
}

/// desktop.input — xdotool type. Clean error when headless.
async fn desktop_input(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: DesktopInputBody = parse_body(&body)?;
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "full_access")?
    };
    match crate::adapters::desktop_type(&b.text).await {
        Ok(()) => {
            {
                let conn = lock(&app);
                state::audit(
                    &conn,
                    &app.data_dir,
                    &format!("agent:{}", session.agent_name),
                    "desktop.input",
                    Some(&session.id),
                    json!({ "chars": b.text.len() }),
                );
            }
            Ok(Json(json!({ "typed": true, "chars": b.text.len() })))
        }
        Err(e) => {
            let code = if e == "DESKTOP_UNAVAILABLE" { "desktop_unavailable" } else { "desktop_failed" };
            let msg = if e == "DESKTOP_UNAVAILABLE" {
                "no graphical session (DISPLAY/WAYLAND_DISPLAY unset) — this capability needs a desktop".to_string()
            } else {
                e
            };
            Err(ApiError::conflict(code, msg))
        }
    }
}

// ============================================================
// Admin-plane handlers (owner only, loopback + bearer token)
// ============================================================

async fn admin_ping(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let conn = lock(&app);
    let machine_id = state::machine_id(&conn);
    let (pending, active) = (state::count_pending(&conn), state::count_active(&conn));
    drop(conn);
    Ok(Json(json!({
        "ok": true,
        "service": "farcontrol",
        "version": env!("CARGO_PKG_VERSION"),
        "server_time": state::now(),
        "daemon": true,
        "session_id": app.session_id,
        "device_id": machine_id,
        "started_at": app.started_at,
        "uptime_secs": state::now() - app.started_at,
        "pending_count": pending,
        "active_count": active,
        "agents": app.agents_json(),
    })))
}

async fn admin_requests(
    State(app): State<Shared>,
    headers: HeaderMap,
    uri: Uri,
) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let status = qparam(&uri, "status");
    let conn = lock(&app);
    let rows = state::list_requests(&conn, status.as_deref());
    let v: Vec<Value> = rows.iter().map(state::request_json).collect();
    Ok(Json(json!({ "requests": v, "count": v.len() })))
}

#[derive(Deserialize)]
struct ApproveBody {
    request_id: String,
    hours: Option<f64>,
}

async fn admin_approve(
    State(app): State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let b: ApproveBody = parse_body(&body)?;
    let ses = {
        let conn = lock(&app);
        state::approve_request(&conn, &app.data_dir, &app.pol, &b.request_id, b.hours)?
    };
    logline(&format!(
        "session {} APPROVED (agent='{}' scope={} expires {})",
        ses.id, ses.agent_name, ses.scope, iso(ses.expires_at)
    ));
    Ok(Json(json!({ "session": state::session_json(&ses) })))
}

#[derive(Deserialize)]
struct DenyBody {
    request_id: String,
    reason: Option<String>,
}

async fn admin_deny(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let b: DenyBody = parse_body(&body)?;
    let row = {
        let conn = lock(&app);
        state::deny_request(&conn, &app.data_dir, &b.request_id, &b.reason.unwrap_or_else(|| "denied by owner".into()))?
    };
    logline(&format!("request {} DENIED", row.id));
    Ok(Json(json!({ "request": state::request_json(&row) })))
}

#[derive(Deserialize)]
struct RevokeBody {
    session_id: String,
    reason: Option<String>,
}

async fn admin_revoke(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let b: RevokeBody = parse_body(&body)?;
    let row = {
        let conn = lock(&app);
        state::revoke_session(
            &conn,
            &app.data_dir,
            &b.session_id,
            &b.reason.unwrap_or_else(|| "revoked by owner".into()),
            "owner",
        )?
    };
    let killed = app.terms.kill_for_session(&row.id);
    if killed > 0 {
        logline(&format!("{killed} terminal(s) killed with session {}", row.id));
    }
    logline(&format!("session {} REVOKED", row.id));
    Ok(Json(json!({ "session": state::session_json(&row) })))
}

async fn admin_sessions(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let conn = lock(&app);
    let rows = state::list_sessions(&conn);
    let v: Vec<Value> = rows.iter().map(state::session_json).collect();
    Ok(Json(json!({ "sessions": v, "count": v.len() })))
}

async fn admin_rotate(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    // v1.2 (ADR-0028 §1): rotate = credential hygiene — a NEW session
    // password + admin token, shown once. The session KEY is untouched:
    // already-connected agents keep working; anyone holding only the old
    // password must be given the new one. (Key rotation = `frtrol panic`.)
    let password = crate::crypto::gen_password();
    let admin_token = crate::crypto::gen_token();
    let machine_id = {
        let conn = lock(&app);
        let mid = state::machine_id(&conn);
        let hash = crate::crypto::password_hash(&password).map_err(ApiError::from)?;
        conn.execute(
            "UPDATE devices SET password_hash = ?1, last_rotate = ?2 WHERE id = ?3",
            rusqlite::params![hash, state::now(), mid],
        )
        .map_err(ApiError::from)?;
        state::set_meta(&conn, "admin_token", &admin_token).map_err(ApiError::from)?;
        state::audit(&conn, &app.data_dir, "owner", "session.rotated", Some(&mid), json!({ "note": "session password + admin token rotated (key untouched — connected agents stay connected)" }));
        mid
    };
    write_secret(&app.data_dir.join("admin-token"), &admin_token)?;
    // keep the LIVE in-memory token in step (v1.2 fix): the owner CLI reads
    // the file; the server must accept what the file says after a rotation.
    *app.admin_token.lock().unwrap_or_else(|e| e.into_inner()) = admin_token.clone();
    logline("session credentials ROTATED — the old session password is dead");
    Ok(Json(json!({
        "password": password,
        "admin_token": admin_token,
        "device_id": machine_id,
        "note": "shown once — give the new session password to agents that need to (re)connect",
    })))
}

/// POST /admin/shutdown — `frtrol stop`. Graceful session end: the daemon
/// exits, in-memory session state dies, and the next start mints fresh
/// credentials (ADR-0031). Approved grants persist (time-bounded policy
/// objects) but are unusable until an agent re-logins with the new password.
async fn admin_shutdown(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    {
        let conn = lock(&app);
        state::audit(&conn, &app.data_dir, "owner", "session.stopped", None, json!({ "session_id": app.session_id }));
    }
    logline("shutdown requested — ending session");
    app.shutdown.notify_waiters();
    Ok(Json(json!({ "ok": true, "note": "session ending — every credential from this run dies now" })))
}

async fn admin_audit(State(app): State<Shared>, headers: HeaderMap, uri: Uri) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let limit = qparam(&uri, "limit").and_then(|s| s.parse::<u32>().ok()).unwrap_or(100).min(1000);
    let conn = lock(&app);
    let rows = state::list_audit(&conn, limit);
    Ok(Json(json!({ "events": rows, "count": rows.len() })))
}


/// v0.6 backup (§72/§103, ADR-0020): checkpoint WAL, then tar -czf the six
/// state files via FIXED argv (§77 — no shell, no user input on any command
/// line). Returns the archive bytes to the owner CLI over the admin plane.
async fn admin_backup(State(app): State<Shared>, headers: HeaderMap) -> Result<Response, ApiError> {
    verify_admin(&app, &headers)?;
    // checkpoint WAL so state.db is self-contained at this instant
    {
        let conn = lock(&app);
        let ckpt: String = conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
            .map(|v: i64| v.to_string())
            .unwrap_or_else(|_| "error".into());
        if ckpt == "error" {
            return Err(ApiError::internal("backup_failed: WAL checkpoint error"));
        }
    }
    // ADR-0023 (keyring mode): the archive is the disaster-recovery artifact and
    // inherently carries every secret — so we materialize the keyring payload
    // map (v1.1) to a 0600 file for the duration of the tar, then unlink it. The
    // secret never persists on disk beyond the archive itself.
    let mut keyring_materialized = false;
    if app.keyring_mode {
        let payload = keyring::load(&app.data_dir)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::internal("device keys missing from the kernel keyring — cannot back up"))?;
        write_secret(&app.data_dir.join("device-keys.json"), &payload)?;
        keyring_materialized = true;
    }
    // only files that exist: agent-token is a v1.0 leftover (migrated installs
    // keep it for reference); fresh v1.1 dirs have none. cert/key: TLS only.
    let mut files: Vec<&str> = vec!["state.db", "config.toml", "admin-token", "audit.jsonl"];
    if keyring_materialized {
        files.push("device-keys.json");
    }
    if app.data_dir.join("agent-token").exists() {
        files.push("agent-token");
    }
    for f in ["cert.pem", "key.pem"] {
        if app.data_dir.join(f).exists() {
            files.push(f);
        }
    }
    let mut cmd = std::process::Command::new("tar");
    cmd.arg("-czf").arg("-").arg("-C").arg(&app.data_dir);
    for f in &files {
        cmd.arg(f);
    }
    let out = cmd
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output();
    if keyring_materialized {
        let _ = std::fs::remove_file(app.data_dir.join("device-keys.json"));
    }
    let out = out
        .map_err(|e| ApiError::internal(format!("backup: tar failed to start: {e} (is tar installed?)")))?;
    if !out.status.success() {
        return Err(ApiError::internal(format!(
            "backup: tar exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    let size = out.stdout.len();
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            "owner",
            "system.backup",
            None,
            json!({ "bytes": size, "files": files.len() }),
        );
    }
    logline(&format!("BACKUP taken — {size} bytes, {} files", files.len()));
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/gzip")
        .header("Content-Disposition", "attachment; filename=\"farcontrol-backup.tar.gz\"")
        .body(axum::body::Body::from(out.stdout))
        .map_err(|e| ApiError::internal(e.to_string()))?;
    resp.headers_mut().insert("X-Far-Backup-Bytes", size.to_string().parse().unwrap());
    Ok(resp)
}


// ============================================================
// v0.7 observability (App B / §35): health, readiness, metrics.
// healthz/readyz are UNAUTHENTICATED but only reachable on the
// loopback admin plane and leak nothing but liveness/readiness.
// ============================================================

async fn healthz() -> &'static str {
    "ok\n"
}

/// Ready = the state DB answers AND the schema is at the expected version.
async fn readyz(State(app): State<Shared>) -> Response {
    let ok = {
        let conn = lock(&app);
        conn.query_row("SELECT 1", [], |r| r.get::<_, i64>(0)).is_ok()
            && state::get_meta(&conn, "schema_version").as_deref() == Some(state::SCHEMA_VERSION)
    };
    if ok {
        (StatusCode::OK, "ready\n").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not-ready\n").into_response()
    }
}

/// Prometheus text exposition (auth: admin token). Single-tenant scope:
/// what the owner can see on the dashboard, minus secrets.
async fn admin_metrics(State(app): State<Shared>, headers: HeaderMap) -> Result<Response, ApiError> {
    verify_admin(&app, &headers)?;
    let (active, pending, terms, audit_total, ui_sessions, schema) = {
        let conn = lock(&app);
        (
            state::count_active(&conn),
            state::count_pending(&conn),
            app.terms.count(),
            state::count_audit(&conn),
            app.ui_sessions.lock().unwrap_or_else(|e| e.into_inner()).len(),
            state::get_meta(&conn, "schema_version").unwrap_or_default(),
        )
    };
    let uptime = (state::now() - app.started_at).max(0);
    let auth_fails = app.auth_fails.lock().unwrap_or_else(|e| e.into_inner()).len();
    // v1.1: lockout metrics aggregated across per-principal locks (ADR-0025).
    let (strikes, locked, devices) = {
        let locks = app.auth_locks.lock().unwrap_or_else(|e| e.into_inner());
        let strikes: u32 = locks.values().map(|l| l.strikes).sum();
        let locked = locks.values().filter(|l| l.locked_until > state::now()).count();
        let conn = lock(&app);
        (strikes, locked, state::count_devices(&conn))
    };
    let keyring_gauge = if app.keyring_mode { 1 } else { 0 };
    let body = format!(
        "# TYPE farcontrol_up gauge\nfarcontrol_up 1\n# TYPE farcontrol_version_info gauge\nfarcontrol_version_info{{version=\"{v}\"}} 1\n# TYPE farcontrol_uptime_seconds gauge\nfarcontrol_uptime_seconds {uptime}\n# TYPE farcontrol_active_sessions gauge\nfarcontrol_active_sessions {active}\n# TYPE farcontrol_pending_requests gauge\nfarcontrol_pending_requests {pending}\n# TYPE farcontrol_open_terminals gauge\nfarcontrol_open_terminals {terms}\n# TYPE farcontrol_ui_sessions gauge\nfarcontrol_ui_sessions {ui}\n# TYPE farcontrol_audit_events_total counter\nfarcontrol_audit_events_total {audit}\n# TYPE farcontrol_auth_failures_window gauge\nfarcontrol_auth_failures_window {fails}\n# TYPE farcontrol_schema_version gauge\nfarcontrol_schema_version {schema}\n# TYPE farcontrol_auth_lockout gauge\nfarcontrol_auth_lockout {locked}\n# TYPE farcontrol_auth_strikes gauge\nfarcontrol_auth_strikes {strikes}\n# TYPE farcontrol_keyring_mode gauge\nfarcontrol_keyring_mode {keyring_gauge}\n# TYPE farcontrol_devices gauge\nfarcontrol_devices {devices}\n",
        v = env!("CARGO_PKG_VERSION"),
        active = active,
        pending = pending,
        terms = terms,
        ui = ui_sessions,
        audit = audit_total,
        fails = auth_fails,
        schema = schema,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/plain; version=0.0.4")
        .body(axum::body::Body::from(body))
        .map_err(|e| ApiError::internal(e.to_string()))
}

pub fn write_secret(path: &std::path::Path, value: &str) -> anyhow::Result<()> {
    std::fs::write(path, value)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ============================================================
// Tests: auth verification (invariant 5/6/7)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) struct TempDir(PathBuf);
    impl TempDir {
        pub(super) fn new() -> Self {
            let p = std::env::temp_dir().join(format!("farcontrol-auth-{}", crate::crypto::gen_nonce()));
            std::fs::create_dir_all(&p).unwrap();
            TempDir(p)
        }
        pub(super) fn path(&self) -> &PathBuf {
            &self.0
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// v1.2 (ADR-0028): the test fixture models the real session — ONE machine
    /// device with key "test-agent-token" (what `frtrol start` minted) and a
    /// session password "test-session-password" for login tests.
    pub(super) fn test_app() -> (Shared, TempDir) {
        let conn = state::open_mem().unwrap();
        let dir = TempDir::new();
        let mid = state::machine_id(&conn);
        state::migrate_session_model(&conn, dir.path(), &mid).unwrap();
        let hash = crate::crypto::password_hash("test-session-password").unwrap();
        conn.execute(
            "UPDATE devices SET password_hash = ?1, device_key = 'test-agent-token' WHERE id = ?2",
            rusqlite::params![hash, mid],
        )
        .unwrap();
        let app = App {
            db: Mutex::new(conn),
            terms: term::Terms::default(),
            auth_fails: Mutex::new(Vec::new()),
            auth_locks: Mutex::new(std::collections::HashMap::new()),
            keyring_mode: false,
            ui_sessions: webui::UiSessions::default(),
            started_at: state::now(),
            session_id: "ses_test".into(),
            agents: Mutex::new(std::collections::HashMap::new()),
            shutdown: tokio::sync::Notify::new(),
            cfg: Config::default(),
            data_dir: dir.path().clone(),
            home_root: dir.path().clone(),
            admin_token: std::sync::Mutex::new("test-admin-token".into()),
            pol: Policy::default(),
        };
        (Arc::new(app), dir)
    }

    /// The machine device id + its session key as seeded by test_app().
    pub(super) fn machine(app: &Shared) -> (String, String) {
        let conn = lock(app);
        (state::machine_id(&conn), "test-agent-token".to_string())
    }

    /// v1.1: signed headers carrying a DEVICE claim (6-field payload).
    pub(super) fn signed_headers_device(token: &str, device_id: &str, method: &str, path: &str, body: &str, age: i64) -> HeaderMap {
        let ts = (state::now() - age).to_string();
        let nonce = crypto::gen_nonce();
        let mut payload = crypto::signing_payload(&ts, &nonce, method, path, &crypto::sha256_hex(body.as_bytes()));
        payload.push('\n');
        payload.push_str(device_id);
        let sig = crypto::hmac_hex(token, &payload);
        let mut h = HeaderMap::new();
        h.insert("x-far-timestamp", ts.parse().unwrap());
        h.insert("x-far-nonce", nonce.parse().unwrap());
        h.insert("x-far-signature", sig.parse().unwrap());
        h.insert("x-far-device", device_id.parse().unwrap());
        h
    }

    #[test]
    fn lock_math_escalates_and_caps() {
        // production params: 10 strikes → 60s base, cap 3600s
        let p = LockParams { max: 10, base: 60, cap: 3600 };
        assert_eq!(lock_secs(9, &p), 0, "below threshold: no lock");
        assert_eq!(lock_secs(10, &p), 60);
        assert_eq!(lock_secs(11, &p), 120);
        assert_eq!(lock_secs(12, &p), 240);
        assert_eq!(lock_secs(16, &p), 3600, "capped at 1h");
        assert_eq!(lock_secs(9_000, &p), 3600, "saturating: never overflows, never exceeds cap");
        // test params: 6 strikes → 2s base, cap 8s
        let t = LockParams { max: 6, base: 2, cap: 8 };
        assert_eq!(lock_secs(5, &t), 0);
        assert_eq!(lock_secs(6, &t), 2);
        assert_eq!(lock_secs(7, &t), 4);
        assert_eq!(lock_secs(9, &t), 8);
        assert_eq!(lock_secs(100, &t), 8);
    }

    #[test]
    fn apply_strike_sets_lock_and_extends() {
        let p = LockParams { max: 6, base: 2, cap: 8 };
        let mut lk = AuthLock::default();
        let now = 1_000_000i64;
        for i in 1..=5 {
            let (changed, _) = apply_strike(&mut lk, now, &p);
            assert!(!changed, "strike {i} below max must not lock");
            assert_eq!(lk.locked_until, 0);
        }
        let (changed, secs) = apply_strike(&mut lk, now, &p);
        assert!(changed && secs == 2 && lk.locked_until == now + 2, "6th strike locks for base");
        // hammering during the lock extends it
        let (changed, secs) = apply_strike(&mut lk, now + 1, &p);
        assert!(changed && secs == 4, "7th strike extends to 2×base, got {secs}");
        assert_eq!(lk.locked_until, now + 1 + 4);
        // at cap, further strikes change nothing (bounded audit rows)
        let (changed, secs) = apply_strike(&mut lk, now + 1, &p);
        assert!(changed && secs == 8);
        let (changed, secs) = apply_strike(&mut lk, now + 1, &p);
        assert!(!changed && secs == 8, "no change once capped");
    }

    pub(super) fn signed_headers(token: &str, method: &str, path: &str, body: &str, age: i64) -> HeaderMap {
        let ts = (state::now() - age).to_string();
        let nonce = crypto::gen_nonce();
        let sig = crypto::hmac_hex(token, &crypto::signing_payload(&ts, &nonce, method, path, &crypto::sha256_hex(body.as_bytes())));
        let mut h = HeaderMap::new();
        h.insert("x-far-timestamp", ts.parse().unwrap());
        h.insert("x-far-nonce", nonce.parse().unwrap());
        h.insert("x-far-signature", sig.parse().unwrap());
        h
    }

    #[tokio::test]
    async fn valid_signature_accepted() {
        let (app, _d) = test_app();
        let (mid, key) = machine(&app);
        let headers = signed_headers_device(&key, &mid, "POST", "/v1/exec", "{}", 0);
        let uri: Uri = "/v1/exec".parse().unwrap();
        let method = Method::POST;
        verify_agent(&app, &headers, &method, &uri, b"{}").unwrap();
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let (app, _d) = test_app();
        let (mid, _key) = machine(&app);
        let mut headers = signed_headers_device("WRONG-token", &mid, "POST", "/v1/exec", "{}", 0);
        headers.insert("x-far-timestamp", state::now().to_string().parse().unwrap());
        let uri: Uri = "/v1/exec".parse().unwrap();
        let method = Method::POST;
        let err = verify_agent(&app, &headers, &method, &uri, b"{}").unwrap_err();
        assert_eq!(err.code, "invalid_signature");
    }

    #[tokio::test]
    async fn tampered_body_rejected() {
        let (app, _d) = test_app();
        // signed for body "{}" but server sees tampered body
        let (mid, key) = machine(&app);
        let headers = signed_headers_device(&key, &mid, "POST", "/v1/exec", "{}", 0);
        let uri: Uri = "/v1/exec".parse().unwrap();
        let method = Method::POST;
        let err = verify_agent(&app, &headers, &method, &uri, b"{\"cmd\":\"evil\"}").unwrap_err();
        assert_eq!(err.code, "invalid_signature");
    }

    #[tokio::test]
    async fn replay_rejected() {
        let (app, _d) = test_app();
        let (mid, key) = machine(&app);
        let headers = signed_headers_device(&key, &mid, "GET", "/v1/ping", "", 0);
        let uri: Uri = "/v1/ping".parse().unwrap();
        let method = Method::GET;
        verify_agent(&app, &headers, &method, &uri, b"").unwrap();
        let err = verify_agent(&app, &headers, &method, &uri, b"").unwrap_err();
        assert_eq!(err.code, "replay_detected");
    }

    #[tokio::test]
    async fn stale_timestamp_rejected() {
        let (app, _d) = test_app();
        let (mid, key) = machine(&app);
        let headers = signed_headers_device(&key, &mid, "GET", "/v1/ping", "", 3600);
        let uri: Uri = "/v1/ping".parse().unwrap();
        let method = Method::GET;
        let err = verify_agent(&app, &headers, &method, &uri, b"").unwrap_err();
        assert_eq!(err.code, "stale_timestamp");
    }

    #[tokio::test]
    async fn missing_headers_rejected() {
        let (app, _d) = test_app();
        let uri: Uri = "/v1/ping".parse().unwrap();
        let method = Method::GET;
        let err = verify_agent(&app, &HeaderMap::new(), &method, &uri, b"").unwrap_err();
        assert_eq!(err.code, "missing_headers");
    }

    #[test]
    fn admin_token_required() {
        let (app, _d) = test_app();
        assert!(verify_admin(&app, &HeaderMap::new()).is_err());
        let mut h = HeaderMap::new();
        h.insert("authorization", "Bearer wrong".parse().unwrap());
        assert!(verify_admin(&app, &h).is_err());
        let mut h2 = HeaderMap::new();
        h2.insert("authorization", "Bearer test-admin-token".parse().unwrap());
        assert!(verify_admin(&app, &h2).is_ok());
    }
}

// ============================================================
// v0.2: interactive terminals (ADR-0013) — PTY per approved session
// ============================================================

#[derive(Deserialize)]
struct TermOpenBody {
    session_id: String,
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    cols: u16,
    #[serde(default)]
    rows: u16,
}

#[derive(Deserialize)]
struct TermIdBody {
    term_id: String,
}

#[derive(Deserialize)]
struct TermWriteBody {
    term_id: String,
    data_b64: String,
}

/// Returns the term's session id, checking the session is still authorized —
/// terminals never outlive their grant (expiry/revoke kills them).
fn term_session_check(app: &App, term_id: &str) -> Result<String, ApiError> {
    let sid = app
        .terms
        .with(term_id, |t| t.session_id.clone())
        .ok_or_else(|| ApiError::not_found("term_not_found", format!("no terminal with id {term_id}")))?;
    {
        let conn = lock(app);
        state::authorize_session(&conn, &app.data_dir, &sid, "terminal_only")?;
    }
    Ok(sid)
}

async fn term_open(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: TermOpenBody = parse_body(&body)?;
    let command = b.command.trim().to_string();
    if command.is_empty() {
        return Err(ApiError::bad_request("invalid_request", "command is required (non-empty)"));
    }
    if command.len() > app.pol.max_command_len {
        return Err(ApiError::bad_request("invalid_request", format!("command exceeds {} chars", app.pol.max_command_len)));
    }
    if b.args.len() > app.pol.max_args {
        return Err(ApiError::bad_request("invalid_request", format!("too many args (max {})", app.pol.max_args)));
    }
    let session = {
        let conn = lock(&app);
        state::authorize_session(&conn, &app.data_dir, &b.session_id, "terminal_only")?
    };
    let line = if b.args.is_empty() { command.clone() } else { format!("{command} {}", b.args.join(" ")) };
    if let Some(pattern) = app.pol.is_denied(&line) {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "term.denied",
            Some(&session.id),
            json!({ "command": line, "pattern": pattern }),
        );
        return Err(ApiError::forbidden("policy_denied", format!("command matches policy denylist pattern '{pattern}'")));
    }
    if app.terms.count() >= MAX_TERMS {
        return Err(ApiError::conflict("term_limit", format!("too many open terminals (max {MAX_TERMS}) — close one first")));
    }
    let cols = if b.cols == 0 { 80 } else { b.cols.min(500) };
    let rows = if b.rows == 0 { 24 } else { b.rows.min(200) };
    let id = crypto::gen_id("trm");
    let t = term::Term::open(&b.session_id, &command, &b.args, &app.home_root, cols, rows)
        .map_err(|e| ApiError::bad_request("spawn_failed", format!("{e} (env is scrubbed: PATH/HOME/LANG/TERM/SHELL only)")))?;
    app.terms.insert(id.clone(), t);
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            &format!("agent:{}", session.agent_name),
            "term.open",
            Some(&id),
            json!({ "command": line, "cols": cols, "rows": rows }),
        );
    }
    logline(&format!("term {id} OPEN on session {} cmd='{}'", session.id, line));
    Ok(Json(json!({
        "term_id": id, "cols": cols, "rows": rows, "status": "running",
        "note": "poll POST /v1/term/read; POST /v1/term/write for stdin; dies with the session"
    })))
}

async fn term_write(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: TermWriteBody = parse_body(&body)?;
    term_session_check(&app, &b.term_id)?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(&b.data_b64)
        .map_err(|_| ApiError::bad_request("invalid_base64", "data_b64 is not valid base64"))?;
    if data.len() > 64 * 1024 {
        return Err(ApiError::too_large("payload_too_large", "stdin chunk exceeds 64 KiB — split your writes"));
    }
    let written = app
        .terms
        .with(&b.term_id, |t| t.write_stdin(&data))
        .ok_or_else(|| ApiError::not_found("term_not_found", format!("no terminal with id {}", b.term_id)))?
        .map_err(|e| ApiError::conflict("term_closed", e))?;
    Ok(Json(json!({ "written": written })))
}

async fn term_read(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: TermIdBody = parse_body(&body)?;
    term_session_check(&app, &b.term_id)?;
    let out = app
        .terms
        .with(&b.term_id, |t| t.read(app.pol.max_output_bytes))
        .ok_or_else(|| ApiError::not_found("term_not_found", format!("no terminal with id {}", b.term_id)))?;
    let running = app
        .terms
        .with(&b.term_id, |t| t.is_running())
        .unwrap_or(false);
    let status = if running { "running" } else { "exited" };
    Ok(Json(json!({
        "output_b64": base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &out),
        "bytes": out.len(),
        "status": status,
    })))
}

async fn term_close(
    State(app): State<Shared>,
    headers: HeaderMap,
    method: Method,
    uri: Uri,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_agent(&app, &headers, &method, &uri, &body)?;
    let b: TermIdBody = parse_body(&body)?;
    let existed = app.terms.remove(&b.term_id);
    if !existed {
        return Err(ApiError::not_found("term_not_found", format!("no terminal with id {}", b.term_id)));
    }
    {
        let conn = lock(&app);
        state::audit(&conn, &app.data_dir, "agent", "term.close", Some(&b.term_id), json!({}));
    }
    logline(&format!("term {} CLOSED", b.term_id));
    Ok(Json(json!({ "closed": true, "term_id": b.term_id })))
}

// ============================================================
// v0.2: panic (SE-11) + doctor (spec §46)
// ============================================================

#[derive(Deserialize)]
struct PanicBody {
    #[serde(default)]
    reason: Option<String>,
}

/// EMERGENCY STOP: revoke every active session, expire every pending request,
/// kill every terminal, rotate the agent token. One admin call, everything dies.
async fn admin_panic(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let b: PanicBody = parse_body(&body)?;
    let reason = b.reason.unwrap_or_else(|| "owner panic".into());
    let (revoked, expired) = {
        let conn = lock(&app);
        state::panic_stop(&conn, &app.data_dir, &reason)?
    };
    let killed = app.terms.reap_inactive(&[]);
    // v1.2 (ADR-0028): panic rotates the WHOLE credential set — password, key,
    // admin token — and clears every live agent state. A stolen anything must
    // not survive the owner's emergency stop.
    let password = crate::crypto::gen_password();
    let admin_token = crate::crypto::gen_token();
    let machine_id = {
        let conn = lock(&app);
        let mid = state::machine_id(&conn);
        let key = crate::crypto::gen_device_key();
        let hash = crate::crypto::password_hash(&password).map_err(ApiError::from)?;
        conn.execute(
            "UPDATE devices SET password_hash = ?1, device_key = ?2, last_rotate = ?3 WHERE id = ?4",
            rusqlite::params![hash, if app.keyring_mode { None } else { Some(key.clone()) }, state::now(), mid],
        )
        .map_err(ApiError::from)?;
        if app.keyring_mode {
            let mut map = std::collections::BTreeMap::new();
            map.insert(mid.clone(), key);
            keyring::store(&app.data_dir, &state::serialize_key_payload(&map)).map_err(ApiError::from)?;
        }
        state::set_meta(&conn, "admin_token", &admin_token).map_err(ApiError::from)?;
        state::audit(
            &conn,
            &app.data_dir,
            "owner",
            "system.panic",
            None,
            json!({ "revoked_sessions": revoked, "expired_pending": expired, "killed_terminals": killed, "credentials_rotated": "password+key+admin_token" }),
        );
        mid
    };
    write_secret(&app.data_dir.join("admin-token"), &admin_token)?;
    // keep the LIVE in-memory token in step (v1.2 fix, e2e-found): the owner
    // CLI reads the file — panic must not brick it for the rest of the run.
    *app.admin_token.lock().unwrap_or_else(|e| e.into_inner()) = admin_token.clone();
    app.agents.lock().unwrap_or_else(|e| e.into_inner()).clear();
    logline(&format!(
        "PANIC — {revoked} session(s) revoked, {expired} pending expired, {killed} terminal(s) killed, all credentials rotated"
    ));
    Ok(Json(json!({
        "revoked_sessions": revoked,
        "expired_pending": expired,
        "killed_terminals": killed,
        "password": password,
        "admin_token": admin_token,
        "device_id": machine_id,
        "note": "every credential is dead — this new session password is shown once; agents reconnect with it",
    })))
}

/// Health checks (spec §46 style): each check has a name, a verdict, and an
/// action. The CLI prints them; anything red means "fix before relying on it".
async fn admin_doctor(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_admin(&app, &headers)?;
    let mut checks: Vec<Value> = Vec::new();
    let mut push = |name: &str, ok: bool, detail: String, action: &str| {
        checks.push(json!({ "name": name, "ok": ok, "detail": detail, "action": action }));
    };

    // 1. SQLite integrity
    let quick: String = {
        let conn = lock(&app);
        conn.query_row("PRAGMA quick_check", [], |r| r.get(0)).unwrap_or_else(|_| "error".into())
    };
    push("db_integrity", quick == "ok", format!("PRAGMA quick_check = {quick}"), "if not ok: stop the daemon and restore state.db from backup");

    // 2. Audit hash chain (tamper evidence)
    let (checked, legacy, chain_ok) = state::verify_audit_chain(&app.data_dir);
    push(
        "audit_chain",
        chain_ok,
        format!("{checked} chained events verified, {legacy} legacy (pre-v0.2) lines"),
        "if broken: audit.jsonl was tampered/truncated — investigate immediately",
    );

    // 3. Schema version + migrations
    let ver = {
        let conn = lock(&app);
        state::get_meta(&conn, "schema_version").unwrap_or_else(|| "0".into())
    };
    push("schema", ver == state::SCHEMA_VERSION, format!("schema_version = {ver} (expect {})", state::SCHEMA_VERSION), "if wrong: run the newest frtrol once to apply migrations");

    // 3b. Agent identity catalog (v0.8, ADR-0022) — data-driven, embedded.
    {
        let cat = crate::catalog::catalog();
        let providers = cat["providers"].as_object().map(|p| p.len()).unwrap_or(0);
        let models: usize = cat["providers"].as_object().map(|p| p.values().filter_map(|m| m.as_array()).map(|m| m.len()).sum()).unwrap_or(0);
        push(
            "agent_catalog",
            providers >= 1,
            format!("v{} — {providers} providers, {models} models (identity = declaration only)", crate::catalog::version()),
            "if empty: the embedded catalog is broken — report it",
        );
    }

    // 3c. Audit retention (v0.8, ADR-0022) — report the configured ceiling.
    {
        let conn = lock(&app);
        let max = state::get_meta(&conn, "audit_retention_max").unwrap_or_else(|| "0".into());
        push(
            "audit_retention",
            true,
            if max == "0" { "keep forever (no [audit] max_events configured)".into() } else { format!("max_events = {max} — oldest events are trimmed, every trim is itself audited") },
            "set [audit] max_events in config.toml if you want bounded audit growth",
        );
    }

    // 3d. Secret store (v0.9, ADR-0023): keyring mode must be readable and must
    // NOT have a stray plaintext file next to it.
    if app.keyring_mode {
        let readable = keyring::load(&app.data_dir).ok().flatten().is_some();
        let stray_file = app.data_dir.join("agent-token").exists();
        push(
            "secret_store",
            readable && !stray_file,
            if readable && !stray_file {
                "kernel keyring holds the agent token (no plaintext file)".into()
            } else if stray_file {
                "agent-token file exists in keyring mode — remove it (the keyring is the source of truth)".into()
            } else {
                "agent token missing from the kernel keyring".into()
            },
            "if missing: frtrol rotate (re-stores the key) or re-init; if stray: rm the agent-token file",
        );
    } else {
        push("secret_store", true, "file mode (agent-token 0600 + state.db) — deviation D-023, documented".into(), "switch to [identity] secret_store = \"keyring\" for OS-keyring storage");
    }

    // 4. Token file permissions (v1.1: admin-token is the owner-side secret file;
    //    device keys live in state.db / the kernel keyring; agent-token is a
    //    tolerated v1.0 leftover when present)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode_ok = |p: &std::path::Path| std::fs::metadata(p).map(|m| (m.mode() & 0o777) == 0o600).unwrap_or(false);
        let mut ok = mode_ok(&app.data_dir.join("admin-token"));
        let mut detail = "admin-token 0600 (device keys in state.db/keyring)".to_string();
        if app.data_dir.join("agent-token").exists() {
            ok = ok && mode_ok(&app.data_dir.join("agent-token"));
            detail = "admin-token + legacy agent-token mode 0600".into();
        }
        push("token_perms", ok, detail, "chmod 600 the token files");
    }
    // 4b. v1.1: device registry health (every password device must hold a key)
    {
        let conn = lock(&app);
        let devs = state::device_list(&conn);
        let broken = devs.iter().filter(|d| d.device_key.as_deref().unwrap_or("").is_empty() && d.password_hash.is_some()).count();
        let n = devs.len();
        drop(conn);
        push("devices", broken == 0, format!("{n} device(s), all with keys"), "frtrol device passwd <id> to re-mint a key");
    }

    // 5. TLS certificate present (when enabled)
    if app.cfg.use_tls {
        let ok = app.data_dir.join("cert.pem").exists() && app.data_dir.join("key.pem").exists();
        push("tls_cert", ok, "cert.pem + key.pem in data dir".into(), "if missing: restart the daemon — it auto-generates on first start");
    }

    // 6. Clock sanity (HMAC window depends on it)
    let nowts = state::now();
    push("clock", nowts > 1_700_000_000, format!("server clock = {nowts}"), "if wrong: fix system time — HMAC rejects ±300s skew");

    // 7. Live state summary
    let (active, pending, terms) = {
        let conn = lock(&app);
        (
            state::list_sessions(&conn).iter().filter(|s| s.status == "active").count(),
            {
                let mut stmt = conn.prepare("SELECT COUNT(*) FROM requests WHERE status='pending'").map_err(ApiError::from)?;
                let n: i64 = stmt.query_row([], |r| r.get(0)).unwrap_or(0);
                n as usize
            },
            app.terms.count(),
        )
    };
    push("state", true, format!("{active} active session(s), {pending} pending request(s), {terms} open terminal(s)"), "revoke sessions you do not recognize: frtrol revoke <ses-id>");

    let all_ok = checks.iter().all(|c| c["ok"].as_bool().unwrap_or(false));
    Ok(Json(json!({ "all_ok": all_ok, "version": env!("CARGO_PKG_VERSION"), "checks": checks })))
}
// ============================================================
// v0.5: adversarial-input fuzz harness (spec §75, ADR-0019).
// Hammers the REAL agent-plane router in-process — every request
// is HMAC-signed so the corpus reaches the parsers/handlers, not
// just the auth gate. Deterministic corpus covers every §75 class
// + a seeded-random phase. PASS = no panic, clean 4xx JSON always,
// server still serves valid requests afterwards.
// ============================================================

#[cfg(test)]
mod fuzz {
    use super::tests::test_app;
    use super::*;
    use rand::Rng;
    use rand::SeedableRng;
    use tower::ServiceExt;

    /// v1.2: every fuzz request carries the machine-device claim (6-field
    /// payload) so the corpus reaches the real parsers, not just the auth gate.
    fn signed_parts(token: &str, device: &str, method: &str, path: &str, body: &[u8]) -> HeaderMap {
        let ts = state::now().to_string();
        let nonce = crypto::gen_nonce();
        let mut payload = crypto::signing_payload(&ts, &nonce, method, path, &crypto::sha256_hex(body));
        payload.push('\n');
        payload.push_str(device);
        let sig = crypto::hmac_hex(token, &payload);
        let mut h = HeaderMap::new();
        h.insert("x-far-timestamp", ts.parse().unwrap());
        h.insert("x-far-nonce", nonce.parse().unwrap());
        h.insert("x-far-signature", sig.parse().unwrap());
        h.insert("x-far-device", device.parse().unwrap());
        h.insert("content-type", "application/json".parse().unwrap());
        h
    }

    async fn fire(router: &Router, token: &str, method: &str, path: &str, body: &[u8]) -> (u16, Option<String>) {
        let req = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .body(axum::body::Body::from(body.to_vec()))
            .unwrap();
        let (mut parts, _) = req.into_parts();
        for (k, v) in signed_parts(token, fuzz_device().as_str(), method, path, body).iter() {
            parts.headers.insert(k, v.clone());
        }
        let req = axum::http::Request::from_parts(parts, axum::body::Body::from(body.to_vec()));
        let resp = router.clone().oneshot(req).await.expect("router call must not panic");
        let code = resp.status().as_u16();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024).await.ok();
        let text = bytes.map(|b| String::from_utf8_lossy(&b).into_owned());
        (code, text)
    }

    fn fuzz_app() -> Shared {
        let (app, _dir) = test_app();
        let (mid, _key) = super::tests::machine(&app);
        FUZZ_DEVICE.with(|d| d.borrow_mut().replace(mid));
        app
    }

    thread_local! {
        static FUZZ_DEVICE: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
    }

    fn fuzz_device() -> String {
        FUZZ_DEVICE.with(|d| d.borrow().clone().unwrap_or_else(|| "FAR-TEST-FUZZ".into()))
    }

    /// Every response must be a controlled 4xx (or 2xx) JSON error — a 5xx
    /// means an unhandled path, a panic means the harness never returns.
    fn assert_controlled(code: u16, text: &Option<String>, what: &str) {
        assert!(code < 500, "FUZZ REGRESSION [{what}]: HTTP {code} — server error on malformed input");
        if let Some(t) = text {
            if code >= 400 {
                assert!(t.contains("\"error\""), "FUZZ REGRESSION [{what}]: non-JSON error body: {t}");
            }
        }
    }

    #[tokio::test]
    async fn deterministic_corpus_never_crashes() {
        let app = fuzz_app();
        let router = build_agent_router(&app);
        let token = "test-agent-token";

        // (label, body) — every §75 class, aimed at every JSON endpoint
        let bodies: Vec<(&str, Vec<u8>)> = vec![
            ("empty", b"".to_vec()),
            ("garbage-bytes", vec![0x00, 0xff, 0xfe, 0x92, 0x00, 0x01]),
            ("truncated-json", br#"{"session_id":"ses_x""#.to_vec()),
            ("invalid-utf8", b"{\"agent_name\":\"\xff\xfe\",\"scope\":\"terminal_only\"}".to_vec()),
            ("not-json-at-all", b"hello i am a banana".to_vec()),
            ("empty-object", b"{}".to_vec()),
            ("null-body", b"null".to_vec()),
            ("array-body", b"[1,2,3]".to_vec()),
            ("string-body", b"\"just a string\"".to_vec()),
            ("wrong-types", br#"{"session_id":123,"command":true,"args":"nope"}"#.to_vec()),
            ("invalid-enum", br#"{"agent_name":"x","scope":"banana","hours":6}"#.to_vec()),
            ("extreme-float", br#"{"agent_name":"x","scope":"terminal_only","hours":1e308}"#.to_vec()),
            ("negative-float", br#"{"agent_name":"x","scope":"terminal_only","hours":-1e308}"#.to_vec()),
            ("nan-string", br#"{"agent_name":"x","hours":"NaN"}"#.to_vec()),
            ("huge-int-pid", br#"{"session_id":"ses_x","pid":99999999999999999999999}"#.to_vec()),
            ("duplicated-fields", br#"{"session_id":"ses_a","session_id":"ses_b"}"#.to_vec()),
            ("oversized-string", format!("{{\"agent_name\":\"{}\",\"scope\":\"terminal_only\"}}", "A".repeat(1_000_000)).into_bytes()),
            ("deeply-nested", format!("{{\"x\":{}{}}}", "[".repeat(5000), "]".repeat(5000)).into_bytes()),
            ("unicode-escapes", br#"{"agent_name":"\ud800\udfff\u0000","scope":"terminal_only"}"#.to_vec()),
            ("huge-command", format!("{{\"session_id\":\"ses_x\",\"command\":\"{}\"}}", "rm ".repeat(100_000)).into_bytes()),
            ("path-traversal-json", br#"{"session_id":"ses_x","path":"../../../../etc/shadow"}"#.to_vec()),
            ("nul-in-path", b"{\"session_id\":\"ses_x\",\"path\":\"a\\0b\"}".to_vec()),
        ];

        let paths = [
            ("/v1/session/request", "POST"),
            ("/v1/exec", "POST"),
            ("/v1/file/read", "POST"),
            ("/v1/file/write", "POST"),
            ("/v1/file/list", "POST"),
            ("/v1/term/open", "POST"),
            ("/v1/process/list", "POST"),
            ("/v1/process/kill", "POST"),
            ("/v1/app/launch", "POST"),
            ("/v1/desktop/input", "POST"),
            ("/v1/session/status", "GET"),
        ];

        for (label, body) in &bodies {
            for (path, method) in &paths {
                // GET signature signs empty body — body param only matters for POST
                let b: &[u8] = if *method == "GET" { b"" } else { body.as_slice() };
                let (code, text) = fire(&router, token, method, path, b).await;
                assert_controlled(code, &text, &format!("{label} → {path}"));
                // no panic: we got here; no 5xx: asserted; no hang: returned.
            }
        }
        // oversized raw body (10 MB) — axum's default body limit must 413 it
        let big = vec![b'a'; 10 * 1024 * 1024];
        let (code, text) = fire(&router, token, "POST", "/v1/session/request", &big).await;
        assert_controlled(code, &text, "raw-10mb-body");

        // garbage auth headers (non-hex sig, non-numeric ts, huge nonce)
        for (ts, nonce, sig) in [
            ("not-a-number", "abc", "deadbeef"),
            ("999999999999999999999999", &"n".repeat(200), &"z".repeat(200)),
            ("0", "", ""),
        ] {
            let mut h = HeaderMap::new();
            h.insert("x-far-timestamp", ts.parse().unwrap());
            h.insert("x-far-nonce", nonce.parse().unwrap());
            h.insert("x-far-signature", sig.parse().unwrap());
            let req = axum::http::Request::builder()
                .method("POST")
                .uri("/v1/ping")
                .body(axum::body::Body::empty())
                .unwrap();
            let (mut parts, body) = req.into_parts();
            for (k, v) in h.iter() {
                parts.headers.insert(k, v.clone());
            }
            let req = axum::http::Request::from_parts(parts, body);
            let resp = router.clone().oneshot(req).await.expect("no panic on garbage headers");
            assert!(resp.status().as_u16() < 500, "garbage headers must not 5xx");
        }

        // after all of that, the server must still work perfectly
        let (code, _) = fire(&router, token, "GET", "/v1/ping", b"").await;
        assert_eq!(code, 200, "server must still serve valid requests after the corpus");
    }

    #[tokio::test]
    async fn seeded_random_fuzz_2000_requests() {
        let app = fuzz_app();
        let router = build_agent_router(&app);
        let token = "test-agent-token";
        let mut rng = rand::rngs::StdRng::seed_from_u64(0xFACC0DE1);
        let endpoints = [
            "/v1/session/request",
            "/v1/exec",
            "/v1/file/read",
            "/v1/file/write",
            "/v1/process/kill",
            "/v1/app/launch",
            "/v1/term/open",
            "/v1/desktop/input",
        ];

        for i in 0..2000 {
            let endpoint = endpoints[rng.gen_range(0..endpoints.len())];
            // random body: mix of mutated-JSON and raw noise
            let body: Vec<u8> = match rng.gen_range(0..4) {
                0 => {
                    // mutate a valid template
                    let mut s = format!(
                        "{{\"session_id\":\"ses_{}\",\"command\":\"echo {}\",\"path\":\"f{}\",\"pid\":{},\"text\":\"t{}\"}}",
                        rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>(), rng.gen::<u32>()
                    );
                    // random byte flip inside
                    if !s.is_empty() {
                        let pos = rng.gen_range(0..s.len());
                        let b = rng.gen::<u8>();
                        s.replace_range(pos..pos + 1, std::str::from_utf8(&[b]).unwrap_or("?"));
                    }
                    s.into_bytes()
                }
                1 => (0..rng.gen_range(0..300)).map(|_| rng.gen::<u8>()).collect(),
                2 => vec![b'{'; rng.gen_range(0..200)],
                _ => br#"{"session_id":null,"command":null}"#.to_vec(),
            };
            let (code, text) = fire(&router, token, "POST", endpoint, &body).await;
            assert_controlled(code, &text, &format!("random #{i} → {endpoint}"));
        }
        let (code, _) = fire(&router, token, "GET", "/v1/ping", b"").await;
        assert_eq!(code, 200, "alive after 2000 random requests");
    }

    /// Concurrent malformed traffic — shakes out races between the rate
    /// limiter, nonce table, and handlers (all behind one Mutex).
    #[tokio::test]
    async fn concurrent_chaos_no_race_panics() {
        let app = fuzz_app();
        let router = build_agent_router(&app);
        let token = "test-agent-token";
        let router = std::sync::Arc::new(router);
        let mut handles = Vec::new();
        for _ in 0..50 {
            let router = router.clone();
            let token = token.to_string();
            handles.push(tokio::spawn(async move {
                let mut rng = rand::rngs::StdRng::seed_from_u64(42);
                for _ in 0..40 {
                    let body: Vec<u8> = (0..rng.gen_range(0..300)).map(|_| rng.gen::<u8>()).collect();
                    let (code, _) = fire(&router, &token, "POST", "/v1/session/request", &body).await;
                    assert!(code < 500, "concurrent fuzz got {code}");
                }
            }));
        }
        for h in handles {
            h.await.expect("no task panicked");
        }
        let (code, _) = fire(&router, token, "GET", "/v1/ping", b"").await;
        assert_eq!(code, 200);
    }
}

#[cfg(test)]
mod session_login_tests {
    use super::tests::{machine, signed_headers_device, signed_headers, test_app};
    use super::*;
    use axum::body::Bytes;

    #[tokio::test]
    async fn machine_signed_request_accepted_and_bound() {
        let (app, _d) = test_app();
        let (mid, key) = machine(&app);
        let h = signed_headers_device(&key, &mid, "GET", "/v1/ping", "", 0);
        let uri: Uri = "/v1/ping".parse().unwrap();
        let authed = verify_agent(&app, &h, &Method::GET, &uri, b"").unwrap();
        assert_eq!(authed.device_id.as_deref(), Some(mid.as_str()));
    }

    #[tokio::test]
    async fn swapped_device_claim_fails_closed() {
        // sign with the machine key (claim inside the payload) but present a
        // different X-Far-Device → unknown device, fail closed
        let (app, _d) = test_app();
        let (mid, key) = machine(&app);
        let h = signed_headers_device(&key, &mid, "GET", "/v1/ping", "", 0);
        let mut h2 = h.clone();
        let other = crate::crypto::gen_device_id();
        h2.insert("x-far-device", other.parse().unwrap());
        let uri: Uri = "/v1/ping".parse().unwrap();
        let err = verify_agent(&app, &h2, &Method::GET, &uri, b"").unwrap_err();
        assert_eq!(err.code, "unknown_device", "claiming another device must fail closed");
    }

    #[tokio::test]
    async fn invalid_device_id_format_rejected_pre_key() {
        let (app, _d) = test_app();
        let (_mid, key) = machine(&app);
        let h = signed_headers_device(&key, "FAR-NOPE", "GET", "/v1/ping", "", 0);
        let uri: Uri = "/v1/ping".parse().unwrap();
        let err = verify_agent(&app, &h, &Method::GET, &uri, b"").unwrap_err();
        assert_eq!(err.code, "invalid_device_id");
    }

    #[tokio::test]
    async fn headerless_v10_request_rejected() {
        // v1.2 removed the v1.0 headerless compat shim (ADR-0031) — a 5-field
        // signature without X-Far-Device must fail closed.
        let (app, _d) = test_app();
        let h = signed_headers("test-agent-token", "GET", "/v1/ping", "", 0);
        let uri: Uri = "/v1/ping".parse().unwrap();
        let err = verify_agent(&app, &h, &Method::GET, &uri, b"").unwrap_err();
        assert_eq!(err.code, "missing_headers", "X-Far-Device is mandatory in v1.2");
    }

    #[tokio::test]
    async fn login_flow_and_non_rotating_key() {
        use tower::util::ServiceExt;
        let (app, _d) = test_app();
        let (mid, _key) = machine(&app);
        let router = build_agent_router(&app);

        // wrong password → 401
        let body = Bytes::from(serde_json::to_vec(&json!({"device_id": mid, "password": "wrong"})).unwrap());
        let res = router.clone().oneshot(
            axum::http::Request::builder().method("POST").uri("/v1/auth/login")
                .header("content-type", "application/json").body(axum::body::Body::from(body.to_vec())).unwrap()
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // unknown device id → 401 generic (no oracle)
        let body = Bytes::from(serde_json::to_vec(&json!({"device_id": crate::crypto::gen_device_id(), "password": "x"})).unwrap());
        let res = router.clone().oneshot(
            axum::http::Request::builder().method("POST").uri("/v1/auth/login")
                .header("content-type", "application/json").body(axum::body::Body::from(body.to_vec())).unwrap()
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // right password → the session key (NOT rotated on login, ADR-0028)
        let login = |router: &Router| {
            let body = Bytes::from(serde_json::to_vec(&json!({"device_id": mid, "password": "test-session-password", "agent_name": "t"})).unwrap());
            let router = router.clone();
            async move {
                router.oneshot(
                    axum::http::Request::builder().method("POST").uri("/v1/auth/login")
                        .header("content-type", "application/json").body(axum::body::Body::from(body.to_vec())).unwrap()
                ).await.unwrap()
            }
        };
        let res = login(&router).await;
        assert_eq!(res.status(), StatusCode::OK);
        let text = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&text).unwrap();
        let key1 = v["key"].as_str().unwrap().to_string();
        assert!(!key1.is_empty(), "login returns the session key once");
        assert_eq!(v["session_id"].as_str(), Some("ses_test"));

        // a SECOND login returns the SAME key (multi-agent, no rotation)
        let res = login(&router).await;
        assert_eq!(res.status(), StatusCode::OK);
        let text = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&text).unwrap();
        assert_eq!(v["key"].as_str(), Some(key1.as_str()), "v1.2: login does NOT rotate the session key");

        // the returned key WORKS for signed requests
        let h = signed_headers_device(&key1, &mid, "GET", "/v1/ping", "", 0);
        let uri: Uri = "/v1/ping".parse().unwrap();
        verify_agent(&app, &h, &Method::GET, &uri, b"").unwrap();
    }

    #[tokio::test]
    async fn heartbeat_updates_agent_map() {
        use tower::util::ServiceExt;
        let (app, _d) = test_app();
        let (mid, key) = machine(&app);
        let router = build_agent_router(&app);
        let h = signed_headers_device(&key, &mid, "GET", "/v1/heartbeat", "", 0);
        let res = router.oneshot(
            axum::http::Request::builder().method("GET").uri("/v1/heartbeat?name=heartbeat-test")
                .body(axum::body::Body::empty()).map(|r| {
                    let (mut parts, body) = r.into_parts();
                    for (k, v) in h.iter() { parts.headers.insert(k, v.clone()); }
                    axum::http::Request::from_parts(parts, body)
                }).unwrap()
        ).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let text = axum::body::to_bytes(res.into_body(), 1 << 20).await.unwrap();
        let v: Value = serde_json::from_slice(&text).unwrap();
        assert_eq!(v["session_id"].as_str(), Some("ses_test"));
        let agents = app.agents_json();
        assert!(agents.iter().any(|a| a["name"] == "heartbeat-test"), "agent visible to the owner: {agents:?}");
        // audit records the first sighting
        let conn = lock(&app);
        let audit = state::list_audit(&conn, 10);
        assert!(audit.iter().any(|e| e["action"] == "agent.seen"), "agent.seen audited");
    }

    #[tokio::test]
    async fn backoff_is_per_principal() {
        let (app, _d) = test_app();
        // hammer device A far in the past (strikes persist in the lock map)
        for _ in 0..12 {
            rate_record_fail(&app, "FAR-AAAA-BBBB");
        }
        // age out the global burst window so layer 1 is clean for everyone
        {
            let mut fails = app.auth_fails.lock().unwrap_or_else(|e| e.into_inner());
            let old = state::now() - 3600;
            for t in fails.iter_mut() {
                *t = old;
            }
        }
        let err = rate_limit_check(&app, "FAR-AAAA-BBBB").unwrap_err();
        assert_eq!(err.code, "rate_limited", "hammered device must be locked");
        // B: different principal, clean window -> allowed (per-device scope works)
        rate_limit_check(&app, "FAR-CCCC-DDDD").expect("other devices must not inherit the lock");
        // success resets ONLY the winning principal
        rate_record_success(&app, "FAR-AAAA-BBBB");
        rate_limit_check(&app, "FAR-AAAA-BBBB").expect("recovery after success");
    }
}
