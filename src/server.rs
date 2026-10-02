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
use serde::Deserialize;
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
    pub admin_token: String,
    pub pol: Policy,
    /// Live interactive terminals (v0.2, ADR-0013). Die with their session.
    pub terms: term::Terms,
    /// Global auth-failure timestamps (sliding window) — brute-force backoff
    /// (SE-09). Single-tenant box: one global window is the honest scope.
    pub auth_fails: Mutex<Vec<i64>>,
    /// Progressive lockout state (SC-01, ADR-0023): consecutive-failure strikes
    /// escalate an exponentially growing lock window. Reset ONLY by a successful
    /// auth. In-memory: a daemon restart clears it (documented).
    pub auth_lock: Mutex<AuthLock>,
    /// Agent secret lives in the kernel keyring (ADR-0023) — read per request.
    pub keyring_mode: bool,
    /// v0.3 web UI cookie sessions (ADR-0017) — token → expires_at (unix).
    /// In-memory: a daemon restart logs the console out (fail closed).
    pub ui_sessions: crate::webui::UiSessions,
    /// v0.7 observability: daemon start time (uptime metric, §35/App B).
    pub started_at: i64,
}

const MAX_TERMS: usize = 8;
const RATE_WINDOW_SECS: i64 = 60;
const RATE_MAX_FAILS: usize = 10;

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

pub async fn run(data_dir: &std::path::Path, bind_override: Option<String>, allow_root: bool) -> anyhow::Result<()> {
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
    // Credential presence checks — per-request loaders (file: DB meta; keyring:
    // kernel key) so rotation is effective instantly in both modes.
    if keyring_mode {
        let mode_meta = state::get_meta(&conn, "secret_store");
        if mode_meta.as_deref() != Some("keyring") && state::get_meta(&conn, "agent_token").is_some() {
            anyhow::bail!(
                "config_invalid: this data dir was initialized with secret_store=file, but config.toml says keyring — fix [identity] secret_store or re-init"
            );
        }
        if keyring::load(data_dir)?.is_none() {
            anyhow::bail!("agent token missing from the kernel keyring — run: frtrol init (or frtrol rotate while healthy)");
        }
    } else {
        if state::get_meta(&conn, "agent_token").is_none() {
            if state::get_meta(&conn, "secret_store").as_deref() == Some("keyring") {
                anyhow::bail!(
                    "config_invalid: this data dir was initialized with secret_store=keyring, but config.toml says file — fix [identity] secret_store or re-init"
                );
            }
            anyhow::bail!("agent_token missing from state — re-run frtrol init");
        }
    }
    let admin_token = state::get_meta(&conn, "admin_token")
        .ok_or_else(|| anyhow::anyhow!("admin_token missing from state — re-run frtrol init"))?;

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

    let app: Shared = Arc::new(App {
        db: Mutex::new(conn),
        cfg,
        data_dir: data_dir.to_path_buf(),
        home_root,
        admin_token,
        pol,
        terms: term::Terms::default(),
        auth_fails: Mutex::new(Vec::new()),
        auth_lock: Mutex::new(AuthLock::default()),
        keyring_mode,
        ui_sessions: webui::UiSessions::default(),
        started_at: state::now(),
    });

    let admin_listener = TcpListener::bind(&app.cfg.admin_bind)
        .await
        .map_err(|_| anyhow::anyhow!("cannot bind admin {} — is another frtrol daemon already running?", app.cfg.admin_bind))?;
    let agent_listener = TcpListener::bind(&app.cfg.agent_bind)
        .await
        .map_err(|_| anyhow::anyhow!("cannot bind agent {} — port in use?", app.cfg.agent_bind))?;

    logline(&format!(
        "FARcontrol {} daemon ready | pid {}",
        env!("CARGO_PKG_VERSION"),
        std::process::id()
    ));
    println!("  data dir  : {}", app.data_dir.display());
    println!("  os/arch   : {} / {}", std::env::consts::OS, std::env::consts::ARCH);
    println!("  agent API : {}://{}  (HMAC-signed + TLS, ADR-0005/0004)", scheme, app.cfg.agent_bind);
    println!("  admin API : {}://{}  (owner only, loopback)", scheme, app.cfg.admin_bind);
    println!("  web UI    : {}://{}/  (owner console — login with the admin token, ADR-0017)", scheme, app.cfg.admin_bind);
    println!("  cert      : {} (give cert.pem + token to the agent — TOFU pinning)", if use_tls { data_dir.join("cert.pem").display().to_string() } else { "disabled (use_tls=false)".into() });
    println!("  home root : {}", app.home_root.display());
    println!("  policy    : standard — session 5–72h, exec ≤300s, output 256KiB, files ≤1MiB under $HOME");
    println!("  waiting for agent requests… (Ctrl-C to stop)");

    // Sweeper: expire due sessions + stale pending requests + old nonces
    // (defense in depth on top of the lazy check in authorize_session).
    {
        let app2 = app.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(30));
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
                let conn = lock(&app2);
                state::nonces_cleanup(&conn);
            }
        });
    }

    let agent_router = build_agent_router(&app);
    let admin_router = build_admin_router(&app);

    let agent_task = tokio::spawn(serve_plane(agent_listener, acceptor.clone(), agent_router));
    let admin_task = tokio::spawn(serve_plane(admin_listener, acceptor, admin_router));

    // Block until Ctrl-C (or a server task dies).
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
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
        // v0.7 observability (App B): unauthenticated local probes — loopback
        // plane only, zero secret data, for systemd/monitoring.
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/admin/metrics", get(admin_metrics))
        // v0.3: owner web console rides the admin plane (loopback + TLS, ADR-0017)
        .merge(webui::routes())
        .fallback(not_found)
        .layer(axum::middleware::map_response(body_limit_json))
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

pub(crate) fn rate_limit_check(app: &App) -> Result<(), ApiError> {
    let nowts = state::now();
    let p = lock_params();
    let mut lk = app.auth_lock.lock().unwrap_or_else(|e| e.into_inner());
    // Progressive lockout: an attempt while locked EXTENDS the lock.
    if lk.locked_until > nowts {
        let (changed, secs) = apply_strike(&mut lk, nowts, &p);
        let retry = (lk.locked_until - nowts).max(1);
        let strikes = lk.strikes;
        if changed {
            drop(lk);
            let conn = lock(app);
            state::audit(&conn, &app.data_dir, "network", "auth.backoff", None, json!({ "strikes": strikes, "lock_secs": secs }));
        }
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("auth locked — progressive backoff, retry in {retry}s (fail closed; strikes {strikes})"),
        ));
    }
    drop(lk);
    // Burst window (unchanged v0.2 semantics).
    let (win, max) = rate_window();
    let mut fails = app.auth_fails.lock().unwrap_or_else(|e| e.into_inner());
    fails.retain(|t| nowts - *t < win);
    if fails.len() >= max {
        // window full AND strikes below max would mean stale strikes — trust the
        // bigger of the two, then escalate via the strike path.
        let mut lk = app.auth_lock.lock().unwrap_or_else(|e| e.into_inner());
        lk.strikes = lk.strikes.max(max as u32);
        let (changed, secs) = apply_strike(&mut lk, nowts, &p);
        let strikes = lk.strikes;
        drop(lk);
        if changed {
            let conn = lock(app);
            state::audit(&conn, &app.data_dir, "network", "auth.backoff", None, json!({ "strikes": strikes, "lock_secs": secs }));
        }
        let retry = (win - (nowts - fails[0])).max(1);
        return Err(ApiError::new(
            axum::http::StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            format!("too many failed auth attempts — retry in {retry}s (fail closed)"),
        ));
    }
    Ok(())
}

pub(crate) fn rate_record_fail(app: &App) {
    {
        let mut fails = app.auth_fails.lock().unwrap_or_else(|e| e.into_inner());
        fails.push(state::now());
    }
    let (changed, secs) = {
        let mut lk = app.auth_lock.lock().unwrap_or_else(|e| e.into_inner());
        apply_strike(&mut lk, state::now(), &lock_params())
    };
    if changed {
        let conn = lock(app);
        state::audit(&conn, &app.data_dir, "network", "auth.backoff", None, json!({ "lock_secs": secs }));
    }
}

/// Successful auth resets both layers (owner/agent recovery, ADR-0023).
fn rate_record_success(app: &App) {
    {
        let mut lk = app.auth_lock.lock().unwrap_or_else(|e| e.into_inner());
        lk.strikes = 0;
        lk.locked_until = 0;
        lk.last_lock = 0;
    }
    app.auth_fails.lock().unwrap_or_else(|e| e.into_inner()).clear();
}

// ============================================================
// Authentication
// ============================================================

fn auth_reject(app: &App, code: &str) {
    rate_record_fail(app);
    let conn = lock(app);
    state::audit(&conn, &app.data_dir, "network", "auth.rejected", None, json!({ "code": code }));
}

/// Per-request agent-secret loader (ID-04, ADR-0023). File mode reads the
/// DB meta per request (rotation instant — D-023 discipline); keyring mode
/// reads the kernel keyring per request. No in-memory copy to go stale.
fn load_agent_secret(app: &App) -> Result<String, ApiError> {
    if app.keyring_mode {
        keyring::load(&app.data_dir)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::internal("agent token missing from the kernel keyring — re-run: frtrol init"))
    } else {
        let conn = lock(app);
        state::get_meta(&conn, "agent_token")
            .ok_or_else(|| ApiError::internal("agent_token missing from state — re-run: frtrol init"))
    }
}

/// Agent-plane auth: HMAC-SHA256 proof-of-possession + anti-replay (ADR-0005).
/// Order: headers → timestamp window → signature → nonce burn.
fn verify_agent(app: &App, headers: &HeaderMap, method: &Method, uri: &Uri, body: &[u8]) -> Result<(), ApiError> {
    rate_limit_check(app)?;
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
    let missing = |what: &str| ApiError::unauthorized("missing_headers", format!("missing header: {what}"));
    let ts_hdr = match headers.get("x-far-timestamp").and_then(|v| v.to_str().ok()) {
        Some(v) => v,
        None => {
            auth_reject(app, "missing_headers");
            return Err(missing("X-Far-Timestamp"));
        }
    };
    let nonce = match headers.get("x-far-nonce").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => {
            auth_reject(app, "missing_headers");
            return Err(missing("X-Far-Nonce"));
        }
    };
    let sig_hex = match headers.get("x-far-signature").and_then(|v| v.to_str().ok()) {
        Some(v) => v.to_string(),
        None => {
            auth_reject(app, "missing_headers");
            return Err(missing("X-Far-Signature"));
        }
    };

    let ts: i64 = match ts_hdr.parse() {
        Ok(v) => v,
        Err(_) => {
            auth_reject(app, "invalid_timestamp");
            return Err(ApiError::unauthorized("invalid_timestamp", "X-Far-Timestamp must be unix seconds (decimal)"));
        }
    };
    let now = state::now();
    if (now - ts).abs() > AUTH_WINDOW_SECS {
        auth_reject(app, "stale_timestamp");
        return Err(ApiError::unauthorized(
            "stale_timestamp",
            format!("timestamp {ts} is outside the ±{AUTH_WINDOW_SECS}s window (server time {now})"),
        ));
    }

    let sig_bytes = match hex::decode(&sig_hex) {
        Ok(b) => b,
        Err(_) => {
            auth_reject(app, "invalid_signature");
            return Err(ApiError::unauthorized("invalid_signature", "X-Far-Signature must be hex"));
        }
    };
    // Read the token per request — rotation takes effect immediately, with no
    // in-memory copy to go stale (file mode: DB meta; keyring mode: kernel keyring).
    let agent_token = load_agent_secret(app)?;
    let payload = crypto::signing_payload(ts_hdr, &nonce, method.as_str(), uri.path(), &crate::crypto::sha256_hex(body));
    let expected = hex::decode(crate::crypto::hmac_hex(&agent_token, &payload));
    let sig_ok = match expected {
        Ok(exp) => crate::crypto::ct_eq(&sig_bytes, &exp),
        Err(_) => false,
    };
    if !sig_ok {
        auth_reject(app, "invalid_signature");
        return Err(ApiError::unauthorized("invalid_signature", "signature verification failed"));
    }

    let fresh = {
        let conn = lock(app);
        state::nonce_insert(&conn, &nonce)
    };
    if !fresh {
        auth_reject(app, "replay_detected");
        return Err(ApiError::unauthorized("replay_detected", "nonce already used — request replay"));
    }
    // Full pass (headers + ts + sig + nonce) → reset the backoff layers (SC-01).
    rate_record_success(app);
    Ok(())
}

use crate::crypto;

fn verify_admin(app: &App, headers: &HeaderMap) -> Result<(), ApiError> {
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::unauthorized("admin_auth_failed", "missing Authorization: Bearer <admin-token>"))?;
    if !crypto::ct_eq(auth.as_bytes(), app.admin_token.as_bytes()) {
        rate_record_fail(app);
        let conn = lock(app);
        state::audit(&conn, &app.data_dir, "network", "auth.rejected", None, json!({ "code": "admin_auth_failed" }));
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
    verify_agent(&app, &headers, &method, &uri, &body)?;
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
    Ok(Json(json!({
        "ok": true,
        "service": "farcontrol",
        "version": env!("CARGO_PKG_VERSION"),
        "server_time": state::now(),
        "pending_count": state::count_pending(&conn),
        "active_count": state::count_active(&conn),
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
    let new_token = {
        let conn = lock(&app);
        state::rotate_agent_token(&conn, &app.data_dir)?
    };
    if app.keyring_mode {
        // ADR-0023: update the kernel key in place; nothing touches the disk.
        keyring::store(&app.data_dir, &new_token).map_err(ApiError::from)?;
    } else {
        write_secret(&app.data_dir.join("agent-token"), &new_token)?;
    }
    logline("agent token ROTATED — old token is dead effective immediately");
    Ok(Json(json!({ "agent_token": new_token, "note": "give this to the agent now — shown once" })))
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
    // inherently carries every secret — so we materialize the token to a 0600
    // file for the duration of the tar, then unlink it. The secret never
    // persists on disk beyond the archive itself.
    let mut keyring_materialized = false;
    if app.keyring_mode {
        let tok = keyring::load(&app.data_dir)
            .map_err(ApiError::from)?
            .ok_or_else(|| ApiError::internal("agent token missing from the kernel keyring — cannot back up"))?;
        write_secret(&app.data_dir.join("agent-token"), &tok)?;
        keyring_materialized = true;
    }
    // only files that exist (cert/key depend on use_tls)
    let mut files: Vec<&str> = vec!["state.db", "config.toml", "agent-token", "admin-token", "audit.jsonl"];
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
        let _ = std::fs::remove_file(app.data_dir.join("agent-token"));
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
    let (strikes, locked) = {
        let lk = app.auth_lock.lock().unwrap_or_else(|e| e.into_inner());
        (lk.strikes, if lk.locked_until > state::now() { 1 } else { 0 })
    };
    let keyring_gauge = if app.keyring_mode { 1 } else { 0 };
    let body = format!(
        "# TYPE farcontrol_up gauge\nfarcontrol_up 1\n# TYPE farcontrol_version_info gauge\nfarcontrol_version_info{{version=\"{v}\"}} 1\n# TYPE farcontrol_uptime_seconds gauge\nfarcontrol_uptime_seconds {uptime}\n# TYPE farcontrol_active_sessions gauge\nfarcontrol_active_sessions {active}\n# TYPE farcontrol_pending_requests gauge\nfarcontrol_pending_requests {pending}\n# TYPE farcontrol_open_terminals gauge\nfarcontrol_open_terminals {terms}\n# TYPE farcontrol_ui_sessions gauge\nfarcontrol_ui_sessions {ui}\n# TYPE farcontrol_audit_events_total counter\nfarcontrol_audit_events_total {audit}\n# TYPE farcontrol_auth_failures_window gauge\nfarcontrol_auth_failures_window {fails}\n# TYPE farcontrol_schema_version gauge\nfarcontrol_schema_version {schema}\n# TYPE farcontrol_auth_lockout gauge\nfarcontrol_auth_lockout {locked}\n# TYPE farcontrol_auth_strikes gauge\nfarcontrol_auth_strikes {strikes}\n# TYPE farcontrol_keyring_mode gauge\nfarcontrol_keyring_mode {keyring_gauge}\n",
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

    pub(super) fn test_app() -> (Shared, TempDir) {
        let conn = state::open_mem().unwrap();
        state::set_meta(&conn, "agent_token", "test-agent-token").unwrap();
        let dir = TempDir::new();
        let app = App {
            db: Mutex::new(conn),
            terms: term::Terms::default(),
            auth_fails: Mutex::new(Vec::new()),
            auth_lock: Mutex::new(AuthLock::default()),
            keyring_mode: false,
            ui_sessions: webui::UiSessions::default(),
            started_at: state::now(),
            cfg: Config::default(),
            data_dir: dir.path().clone(),
            home_root: dir.path().clone(),
            admin_token: "test-admin-token".into(),
            pol: Policy::default(),
        };
        (Arc::new(app), dir)
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

    fn signed_headers(token: &str, method: &str, path: &str, body: &str, age: i64) -> HeaderMap {
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
        let headers = signed_headers("test-agent-token", "POST", "/v1/exec", "{}", 0);
        let uri: Uri = "/v1/exec".parse().unwrap();
        let method = Method::POST;
        verify_agent(&app, &headers, &method, &uri, b"{}").unwrap();
    }

    #[tokio::test]
    async fn bad_signature_rejected() {
        let (app, _d) = test_app();
        let mut headers = signed_headers("WRONG-token", "POST", "/v1/exec", "{}", 0);
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
        let headers = signed_headers("test-agent-token", "POST", "/v1/exec", "{}", 0);
        let uri: Uri = "/v1/exec".parse().unwrap();
        let method = Method::POST;
        let err = verify_agent(&app, &headers, &method, &uri, b"{\"cmd\":\"evil\"}").unwrap_err();
        assert_eq!(err.code, "invalid_signature");
    }

    #[tokio::test]
    async fn replay_rejected() {
        let (app, _d) = test_app();
        let headers = signed_headers("test-agent-token", "GET", "/v1/ping", "", 0);
        let uri: Uri = "/v1/ping".parse().unwrap();
        let method = Method::GET;
        verify_agent(&app, &headers, &method, &uri, b"").unwrap();
        let err = verify_agent(&app, &headers, &method, &uri, b"").unwrap_err();
        assert_eq!(err.code, "replay_detected");
    }

    #[tokio::test]
    async fn stale_timestamp_rejected() {
        let (app, _d) = test_app();
        let headers = signed_headers("test-agent-token", "GET", "/v1/ping", "", 3600);
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
    let new_token = {
        let conn = lock(&app);
        state::rotate_agent_token(&conn, &app.data_dir)?
    };
    if app.keyring_mode {
        keyring::store(&app.data_dir, &new_token).map_err(ApiError::from)?;
    } else {
        write_secret(&app.data_dir.join("agent-token"), &new_token)?;
    };
    {
        let conn = lock(&app);
        state::audit(
            &conn,
            &app.data_dir,
            "owner",
            "system.panic",
            None,
            json!({ "revoked_sessions": revoked, "expired_pending": expired, "killed_terminals": killed }),
        );
    }
    logline(&format!(
        "PANIC — {revoked} session(s) revoked, {expired} pending expired, {killed} terminal(s) killed, token rotated"
    ));
    Ok(Json(json!({
        "revoked_sessions": revoked,
        "expired_pending": expired,
        "killed_terminals": killed,
        "agent_token": new_token,
        "note": "give the NEW token to the agent only when you trust it again",
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

    // 4. Token file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mode_ok = |p: &std::path::Path| std::fs::metadata(p).map(|m| (m.mode() & 0o777) == 0o600).unwrap_or(false);
        let ok = mode_ok(&app.data_dir.join("agent-token")) && mode_ok(&app.data_dir.join("admin-token"));
        push("token_perms", ok, "agent-token and admin-token must be mode 0600".into(), "chmod 600 the token files");
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

    fn signed_parts(token: &str, method: &str, path: &str, body: &[u8]) -> HeaderMap {
        let ts = state::now().to_string();
        let nonce = crypto::gen_nonce();
        let sig = crypto::hmac_hex(token, &crypto::signing_payload(&ts, &nonce, method, path, &crypto::sha256_hex(body)));
        let mut h = HeaderMap::new();
        h.insert("x-far-timestamp", ts.parse().unwrap());
        h.insert("x-far-nonce", nonce.parse().unwrap());
        h.insert("x-far-signature", sig.parse().unwrap());
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
        for (k, v) in signed_parts(token, method, path, body).iter() {
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
        app
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
