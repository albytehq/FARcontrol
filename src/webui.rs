use crate::error::ApiError;
use crate::server::{lock, logline, parse_body, rate_limit_check, rate_record_fail, App, Shared};
use crate::state;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Mutex;

// v0.3 Web UI (ADR-0017) — the owner console served by the loopback admin
// plane. One embedded HTML page, vanilla JS, zero new dependencies.
//
// Security model:
// - login = the owner's admin token (same secret the CLI uses)
// - session cookie: HttpOnly + SameSite=Strict (+ Secure when TLS)
// - CSRF: every /ui POST requires the JS-only header `X-Far-Ui: 1`
//   (a forged cross-site form cannot set custom headers) + SameSite=Strict
// - XSS: the page NEVER uses innerHTML with server data — everything is
//   rendered via textContent, so stored agent_name/reason can't execute
// - brute force: login failures feed the same sliding-window backoff as the
//   agent plane (SE-09)
// - UI sessions are in-memory: daemon restart = re-login (fail closed)

/// Sliding UI-session lifetime in seconds.
pub const UI_SESSION_TTL_SECS: i64 = 3600;
const COOKIE_NAME: &str = "far_ui";
const CSRF_HEADER: &str = "x-far-ui";

pub type UiSessions = Mutex<HashMap<String, i64>>;

pub fn routes() -> Router<Shared> {
    Router::new()
        .route("/", axum::routing::get(ui_index))
        .route("/ui/login", axum::routing::post(ui_login))
        .route("/ui/logout", axum::routing::post(ui_logout))
        .route("/ui/state", axum::routing::get(ui_state))
        .route("/ui/approve", axum::routing::post(ui_approve))
        .route("/ui/deny", axum::routing::post(ui_deny))
        .route("/ui/revoke", axum::routing::post(ui_revoke))
        .route("/ui/panic", axum::routing::post(ui_panic))
        // v1.2 (ADR-0032): session stop from the console — same path as `frtrol stop`.
        .route("/ui/stop", axum::routing::post(ui_stop))
        // v1.2 (ADR-0032): credential rotation from the console (Advanced tab).
        .route("/ui/rotate", axum::routing::post(ui_rotate))
}

// ============================================================
// UI auth: cookie session + CSRF header
// ============================================================

fn cookie_token(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(header::COOKIE).and_then(|v| v.to_str().ok())?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some((k, v)) = pair.split_once('=') {
            if k == COOKIE_NAME {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// Valid UI session? Sliding TTL — a fresh request extends the session,
/// so an active owner never gets logged out mid-decision.
fn verify_ui(app: &App, headers: &HeaderMap, is_post: bool) -> Result<(), ApiError> {
    // CSRF: POSTs must carry the JS-only header. Combined with
    // SameSite=Strict this kills cross-site request forgery.
    if is_post && headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some("1") {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "csrf_blocked",
            "missing X-Far-Ui header — cross-site requests are rejected",
        ));
    }
    let token = cookie_token(headers)
        .ok_or_else(|| ApiError::unauthorized("ui_auth_failed", "not logged in"))?;
    let nowts = state::now();
    let mut sessions = app.ui_sessions.lock().unwrap_or_else(|e| e.into_inner());
    match sessions.get_mut(&token) {
        Some(exp) => {
            if nowts >= *exp {
                sessions.remove(&token);
                return Err(ApiError::unauthorized("ui_auth_failed", "session expired — log in again"));
            }
            *exp = nowts + UI_SESSION_TTL_SECS; // sliding refresh
            Ok(())
        }
        None => Err(ApiError::unauthorized("ui_auth_failed", "invalid or expired session — log in again")),
    }
}

fn ui_audit(app: &App, action: &str, subject: Option<&str>, detail: Value) {
    let conn = lock(app);
    state::audit(&conn, &app.data_dir, "owner:webui", action, subject, detail);
}

// ============================================================
// Handlers
// ============================================================

async fn ui_index(State(app): State<Shared>) -> Response {
    let html = include_str!("webui_index.html");
    let mut resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(html))
        .unwrap();
    // security headers (§77 spirit: sensible defaults, no debug endpoints)
    let h = resp.headers_mut();
    h.insert("X-Content-Type-Options", "nosniff".parse().unwrap());
    h.insert("X-Frame-Options", "DENY".parse().unwrap());
    h.insert("Referrer-Policy", "no-referrer".parse().unwrap());
    h.insert(
        header::SERVER,
        "farcontrol".parse().unwrap(),
    );
    let _ = &app; // state not needed to serve the shell — auth happens client-side via /ui/state
    resp
}

#[derive(Deserialize)]
struct LoginBody {
    password: String,
}

async fn ui_login(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Response, ApiError> {
    // CSRF first (uniform rule for /ui POSTs), then brute-force gate.
    if headers.get(CSRF_HEADER).and_then(|v| v.to_str().ok()) != Some("1") {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "csrf_blocked", "missing X-Far-Ui header"));
    }
    rate_limit_check(&app, "webui")?;
    let b: LoginBody = parse_body(&body)?;
    let tok = app.admin_token.lock().unwrap_or_else(|e| e.into_inner());
    if !crate::crypto::ct_eq(b.password.trim().as_bytes(), tok.as_bytes()) {
        drop(tok);
        rate_record_fail(&app, "webui");
        ui_audit(&app, "ui.login", None, json!({ "ok": false }));
        return Err(ApiError::unauthorized("ui_login_failed", "wrong password (it is the admin token — see 'frtrol start' output)"));
    }
    let token = crate::crypto::gen_token();
    {
        let mut sessions = app.ui_sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.insert(token.clone(), state::now() + UI_SESSION_TTL_SECS);
    }
    ui_audit(&app, "ui.login", None, json!({ "ok": true }));
    // Set-Cookie: HttpOnly (JS can't read it) + SameSite=Strict + Secure (TLS)
    let cookie = format!(
        "{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={UI_SESSION_TTL_SECS}{}",
        if app.cfg.use_tls { "; Secure" } else { "" }
    );
    let cookie_val: axum::http::HeaderValue = cookie
        .parse()
        .map_err(|e| ApiError::internal(format!("set-cookie: {e}")))?;
    let mut resp = (StatusCode::OK, Json(json!({ "ok": true }))).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie_val);
    Ok(resp)
}

async fn ui_logout(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    let _ = (body,);
    verify_ui(&app, &headers, true)?;
    if let Some(token) = cookie_token(&headers) {
        let mut sessions = app.ui_sessions.lock().unwrap_or_else(|e| e.into_inner());
        sessions.remove(&token);
    }
    ui_audit(&app, "ui.logout", None, json!({}));
    // expire the cookie client-side too
    Ok(Json(json!({ "ok": true, "bye": true })))
}

/// Everything the dashboard needs, in one poll (v1.2: session-first — r10).
async fn ui_state(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_ui(&app, &headers, false)?;
    let (pending, sessions, audit, machine_id, chain) = {
        let conn = lock(&app);
        let (checked, legacy, ok) = state::verify_audit_chain(&app.data_dir);
        (
            state::list_requests(&conn, Some("pending")),
            state::list_sessions(&conn),
            state::list_audit(&conn, 100),
            state::machine_id(&conn),
            json!({ "checked": checked, "legacy": legacy, "ok": ok }),
        )
    };
    let sessions_json: Vec<Value> = sessions.iter().map(state::session_json).collect();
    let pending_json: Vec<Value> = pending.iter().map(state::request_json).collect();
    let fp = std::fs::read_to_string(app.data_dir.join("cert.pem"))
        .ok()
        .and_then(|pem| crate::tls::pem_first_block(&pem, "CERTIFICATE"))
        .map(|der| crate::crypto::cert_fingerprint(&der));
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "server_time": state::now(),
        "session_id": app.session_id,
        "session_started_at": app.started_at,
        "device_id": machine_id,
        "agents": app.agents_json(),
        "tls": app.cfg.use_tls,
        "home_root": app.cfg.home_root,
        "fingerprint": fp,
        "keyring_mode": app.keyring_mode,
        "policy": {
            "session_hours": format!("{}–{}", app.pol.min_session_hours, app.pol.max_session_hours),
            "exec_timeout_s": app.pol.exec_timeout_ms_max / 1000,
            "max_output_kib": app.pol.max_output_bytes / 1024,
            "max_file_kib": app.pol.max_file_bytes / 1024,
        },
        "pending": pending_json,
        "sessions": sessions_json,
        "audit": audit,
        "audit_chain": chain,
    })))
}

#[derive(Deserialize)]
struct UiApproveBody {
    request_id: String,
    hours: Option<f64>,
}

async fn ui_approve(
    State(app): State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Value>, ApiError> {
    verify_ui(&app, &headers, true)?;
    let b: UiApproveBody = parse_body(&body)?;
    let ses = {
        let conn = lock(&app);
        state::approve_request(&conn, &app.data_dir, &app.pol, &b.request_id, b.hours)?
    };
    ui_audit(&app, "ui.approve", Some(&ses.id), json!({ "request_id": b.request_id, "expires_at": ses.expires_at }));
    logline(&format!(
        "session {} APPROVED via web UI (agent='{}' scope={})",
        ses.id, ses.agent_name, ses.scope
    ));
    Ok(Json(json!({ "session": state::session_json(&ses) })))
}

#[derive(Deserialize)]
struct UiDenyBody {
    request_id: String,
    reason: Option<String>,
}

async fn ui_deny(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    verify_ui(&app, &headers, true)?;
    let b: UiDenyBody = parse_body(&body)?;
    let row = {
        let conn = lock(&app);
        state::deny_request(&conn, &app.data_dir, &b.request_id, &b.reason.unwrap_or_else(|| "denied by owner (web UI)".into()))?
    };
    ui_audit(&app, "ui.deny", Some(&row.id), json!({ "request_id": b.request_id }));
    Ok(Json(json!({ "request": state::request_json(&row) })))
}

#[derive(Deserialize)]
struct UiRevokeBody {
    session_id: String,
    reason: Option<String>,
}

async fn ui_revoke(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    verify_ui(&app, &headers, true)?;
    let b: UiRevokeBody = parse_body(&body)?;
    let row = {
        let conn = lock(&app);
        state::revoke_session(
            &conn,
            &app.data_dir,
            &b.session_id,
            &b.reason.unwrap_or_else(|| "revoked by owner (web UI)".into()),
            "owner:webui",
        )?
    };
    let killed = app.terms.kill_for_session(&row.id);
    if killed > 0 {
        logline(&format!("{killed} terminal(s) killed with session {} (web UI revoke)", row.id));
    }
    ui_audit(&app, "ui.revoke", Some(&row.id), json!({ "killed_terminals": killed }));
    Ok(Json(json!({ "session": state::session_json(&row) })))
}

#[derive(Deserialize)]
struct UiPanicBody {
    reason: Option<String>,
}

/// Same emergency stop as `frtrol panic`, from the console (SE-11).
async fn ui_panic(State(app): State<Shared>, headers: HeaderMap, body: Bytes) -> Result<Json<Value>, ApiError> {
    verify_ui(&app, &headers, true)?;
    let b: UiPanicBody = parse_body(&body)?;
    let reason = b.reason.unwrap_or_else(|| "owner panic (web UI)".into());
    let (revoked, expired) = {
        let conn = lock(&app);
        state::panic_stop(&conn, &app.data_dir, &reason)?
    };
    let killed = app.terms.reap_inactive(&[]);
    // v1.2 (ADR-0028): panic rotates the WHOLE credential set — mirrors
    // admin_panic. The new session password is shown ONCE in the console.
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
            crate::keyring::store(&app.data_dir, &state::serialize_key_payload(&map)).map_err(ApiError::from)?;
        }
        state::set_meta(&conn, "admin_token", &admin_token).map_err(ApiError::from)?;
        mid
    };
    crate::server::write_secret(&app.data_dir.join("admin-token"), &admin_token)?;
    // keep the LIVE in-memory token in step (v1.2 fix, e2e-found)
    *app.admin_token.lock().unwrap_or_else(|e| e.into_inner()) = admin_token.clone();
    app.agents.lock().unwrap_or_else(|e| e.into_inner()).clear();
    ui_audit(&app, "ui.panic", None, json!({ "revoked_sessions": revoked, "expired_pending": expired, "killed_terminals": killed, "credentials_rotated": "password+key+admin_token" }));
    logline(&format!("PANIC via web UI — {revoked} revoked, {expired} pending expired, {killed} terminals killed, credentials rotated"));
    Ok(Json(json!({
        "revoked_sessions": revoked,
        "expired_pending": expired,
        "killed_terminals": killed,
        "password": password,
        "admin_token": admin_token,
        "device_id": machine_id,
        "note": "every credential is dead — this new session password is shown once",
    })))
}

/// v1.2 (ADR-0031): console-side session stop — same admin-plane path as
/// `frtrol stop` (UI cookie + CSRF instead of the bearer token).
async fn ui_stop(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_ui(&app, &headers, true)?;
    ui_audit(&app, "ui.stop", None, json!({ "session_id": app.session_id }));
    logline("shutdown requested via web UI — ending session");
    app.shutdown.notify_waiters();
    Ok(Json(json!({ "ok": true, "note": "session ending — this page will stop responding" })))
}

/// v1.2 (ADR-0032): rotate the session password + admin token from the
/// console — mirrors admin_rotate; the new password is shown ONCE in the modal.
async fn ui_rotate(State(app): State<Shared>, headers: HeaderMap) -> Result<Json<Value>, ApiError> {
    verify_ui(&app, &headers, true)?;
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
        mid
    };
    crate::server::write_secret(&app.data_dir.join("admin-token"), &admin_token)?;
    // keep the LIVE in-memory token in step (v1.2 fix, e2e-found)
    *app.admin_token.lock().unwrap_or_else(|e| e.into_inner()) = admin_token.clone();
    ui_audit(&app, "ui.rotate", Some(&machine_id), json!({ "note": "session password + admin token rotated (key untouched)" }));
    logline("session credentials ROTATED via web UI — the old session password is dead");
    Ok(Json(json!({
        "password": password,
        "admin_token": admin_token,
        "device_id": machine_id,
        "note": "shown once — connected agents keep working",
    })))
}

// ============================================================
// Tests: session store semantics (login → verify → slide → expiry)
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::App;
    use std::sync::{Arc, Mutex};

    fn app() -> Arc<App> {
        let conn = state::open_mem().unwrap();
        state::set_meta(&conn, "agent_token", "t").unwrap();
        let dir = std::env::temp_dir().join(format!("farcontrol-ui-{}", crate::crypto::gen_nonce()));
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(App {
            db: Mutex::new(conn),
            session_id: "ses_webui_test".into(),
            agents: Mutex::new(std::collections::HashMap::new()),
            shutdown: tokio::sync::Notify::new(),
            terms: crate::term::Terms::default(),
            auth_fails: Mutex::new(Vec::new()),
            auth_locks: Mutex::new(std::collections::HashMap::new()),
            keyring_mode: false,
            ui_sessions: Mutex::new(HashMap::new()),
            started_at: state::now(),
            cfg: crate::config::Config::default(),
            data_dir: dir.clone(),
            home_root: dir.clone(),
            admin_token: std::sync::Mutex::new("adminpw".into()),
            pol: crate::policy::Policy::default(),
        })
    }

    fn headers_with(token: &str, csrf: bool) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, format!("{COOKIE_NAME}={token}").parse().unwrap());
        if csrf {
            h.insert(CSRF_HEADER, "1".parse().unwrap());
        }
        h
    }

    fn insert(app: &App, token: &str, exp: i64) {
        app.ui_sessions.lock().unwrap().insert(token.into(), exp);
    }

    #[test]
    fn ui_session_valid_and_slides() {
        let app = app();
        insert(&app, "tok1", state::now() + 60);
        let h = headers_with("tok1", true);
        assert!(verify_ui(&app, &h, true).is_ok());
        // sliding: expiry must have moved forward
        let exp = app.ui_sessions.lock().unwrap().get("tok1").copied().unwrap();
        assert!(exp > state::now() + 60);
    }

    #[test]
    fn ui_session_expired_rejected() {
        let app = app();
        insert(&app, "tok2", state::now() - 1);
        let h = headers_with("tok2", true);
        let err = verify_ui(&app, &h, true).unwrap_err();
        assert_eq!(err.code, "ui_auth_failed");
        // expired token is removed from the store (no unbounded growth)
        assert!(!app.ui_sessions.lock().unwrap().contains_key("tok2"));
    }

    #[test]
    fn ui_session_unknown_rejected() {
        let app = app();
        let h = headers_with("nope", true);
        assert_eq!(verify_ui(&app, &h, true).unwrap_err().code, "ui_auth_failed");
    }

    #[test]
    fn ui_post_without_csrf_header_blocked() {
        let app = app();
        insert(&app, "tok3", state::now() + 60);
        let h = headers_with("tok3", false); // no X-Far-Ui
        let err = verify_ui(&app, &h, true).unwrap_err();
        assert_eq!(err.code, "csrf_blocked");
        // GETs don't need the header (no side effects)
        assert!(verify_ui(&app, &h, false).is_ok());
    }

    #[test]
    fn ui_cookie_parse() {
        let mut h = HeaderMap::new();
        h.insert(header::COOKIE, "other=x; far_ui=abc; more=y".parse().unwrap());
        assert_eq!(cookie_token(&h).as_deref(), Some("abc"));
        assert_eq!(cookie_token(&HeaderMap::new()), None);
    }
}
