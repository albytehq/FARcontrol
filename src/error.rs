use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};

/// Machine-readable API error. Every failure path in FARcontrol produces one of
/// these; the wire format is `{"error":{"code":"...","message":"..."}}` so that
/// AI agents can branch on `code` without parsing prose.
#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), details: None }
    }

    pub fn unauthorized(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, code, message)
    }

    pub fn forbidden(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, code, message)
    }

    pub fn not_found(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, code, message)
    }

    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNPROCESSABLE_ENTITY, code, message)
    }

    pub fn conflict(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, code, message)
    }

    pub fn too_large(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, code, message)
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    #[allow(dead_code)]
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut err = json!({ "code": self.code, "message": self.message });
        if let Some(d) = &self.details {
            err["details"] = d.clone();
        }
        (self.status, Json(json!({ "error": err }))).into_response()
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        match &e {
            rusqlite::Error::QueryReturnedNoRows => ApiError::not_found("not_found", "row not found"),
            _ => ApiError::internal(format!("database error: {e}")),
        }
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(e: serde_json::Error) -> Self {
        ApiError::bad_request("invalid_request", format!("invalid JSON body: {e}"))
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::internal(format!("{e:#}"))
    }
}

/// CLI exit codes (spec §66, ADR-0022 / CL-03). Stable contract — both the
/// agent CLI and the owner CLI map the server's wire error code to these:
///
/// ```text
/// 0 = success            4 = authorization denied
/// 1 = generic failure    5 = timeout
/// 2 = invalid usage      6 = unavailable
/// 3 = authentication     7 = conflict/state race
/// ```
pub fn exit_for(err_code: &str) -> i32 {
    match err_code {
        // authentication failures
        "auth_failed" | "invalid_token" | "missing_headers" | "nonce_replayed"
        | "invalid_signature" | "signature_invalid" | "timestamp_out_of_range" | "admin_auth_failed" => 3,
        // authorization denials (valid identity, no authority / access dead)
        "scope_denied" | "session_not_found" | "session_not_active" | "session_expired"
        | "session_revoked" | "request_not_found" | "request_denied" | "path_denied"
        | "desktop_unavailable" | "process_denied" | "denied_by_policy" => 4,
        // caller input / usage errors
        "invalid_request" | "invalid_scope" | "invalid_agent_identity" | "invalid_json"
        | "unsupported_proto" | "invalid_body" => 2,
        // conflict / state races
        "request_not_pending" | "session_limit" | "request_limit" => 7,
        // temporarily unavailable
        "rate_limited" => 6,
        // everything else: generic
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::exit_for;

    #[test]
    fn exit_codes_match_spec_66() {
        assert_eq!(exit_for("auth_failed"), 3);
        assert_eq!(exit_for("nonce_replayed"), 3);
        assert_eq!(exit_for("invalid_signature"), 3, "observed wire code (bad-token ping)");
        assert_eq!(exit_for("scope_denied"), 4);
        assert_eq!(exit_for("session_revoked"), 4);
        assert_eq!(exit_for("session_expired"), 4);
        assert_eq!(exit_for("invalid_scope"), 2);
        assert_eq!(exit_for("invalid_agent_identity"), 2);
        assert_eq!(exit_for("unsupported_proto"), 2);
        assert_eq!(exit_for("session_limit"), 7);
        assert_eq!(exit_for("request_not_pending"), 7);
        assert_eq!(exit_for("rate_limited"), 6);
        assert_eq!(exit_for("internal_error"), 1);
        assert_eq!(exit_for("something_new"), 1, "unknown codes fail generic, never 0");
    }
}
