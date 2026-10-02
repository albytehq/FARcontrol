use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Where the agent (device) secret lives (ID-04, ADR-0023).
/// "file" (default) = SQLite meta + agent-token file 0600 (deviation D-023).
/// "keyring" = Linux kernel keyring, never written to disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct IdentityConfig {
    pub secret_store: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self { secret_store: "file".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Agent plane bind address. Default loopback; use `frtrol start --bind 0.0.0.0:7788`
    /// to expose to the LAN (HMAC + TLS protected, see ADR-0004).
    pub agent_bind: String,
    /// Admin plane bind address. MUST be loopback — the daemon refuses otherwise.
    pub admin_bind: String,
    /// File-operation root for the `full_access` scope (see ADR-0009).
    pub home_root: String,
    /// Serve both planes over TLS (rustls) with the auto-generated self-signed cert
    /// in the data dir (`cert.pem`/`key.pem`). Default: true (ADR-0004 v0.2).
    /// Set false only for pure-loopback development.
    #[serde(default = "default_true")]
    pub use_tls: bool,
    /// Optional `[policy]` overrides — see Policy::from_config. Unknown keys are
    /// ignored (forward compatible); limits can only be as strict/loose as written.
    #[serde(default)]
    pub policy: Option<toml::Table>,
    /// Optional `[audit]` overrides (ADR-0022). Recognized: `max_events`
    /// (0/absent = keep audit forever). Unknown keys ignored.
    #[serde(default)]
    pub audit: Option<toml::Table>,
    /// `[identity]` — secret storage backend (ADR-0023).
    #[serde(default)]
    pub identity: IdentityConfig,
}

fn default_true() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            agent_bind: "127.0.0.1:7788".into(),
            admin_bind: "127.0.0.1:7789".into(),
            home_root: default_home(),
            use_tls: true,
            policy: None,
            audit: None,
            identity: IdentityConfig::default(),
        }
    }
}

impl Config {
    pub fn keyring_mode(&self) -> bool {
        self.identity.secret_store == "keyring"
    }

    /// Startup validation (SC-02, ADR-0023): reject a broken config BEFORE any
    /// listener binds or state opens. Recognized keys with wrong types or
    /// out-of-range values are hard errors; unknown keys stay ignored
    /// (forward compatibility). Errors are prefixed `config_invalid:` upstream.
    pub fn validate(&self) -> Result<(), String> {
        let sock = |s: &str, what: &str| -> Result<SocketAddr, String> {
            s.parse::<SocketAddr>().map_err(|_| format!("{what} '{s}' is not a valid host:port"))
        };
        let agent = sock(&self.agent_bind, "agent_bind")?;
        let admin = sock(&self.admin_bind, "admin_bind")?;
        if agent.port() == 0 {
            return Err("agent_bind port 0 is not allowed (use 1–65535)".into());
        }
        if admin.port() == 0 {
            return Err("admin_bind port 0 is not allowed (use 1–65535)".into());
        }
        if !admin.ip().is_loopback() {
            return Err(format!(
                "admin_bind '{}' must be a loopback address — the approval path never touches the network",
                self.admin_bind
            ));
        }
        if self.home_root.trim().is_empty() {
            return Err("home_root is empty — the full_access file root must be an existing directory".into());
        }
        if !matches!(self.identity.secret_store.as_str(), "file" | "keyring") {
            return Err(format!(
                "[identity] secret_store '{}' is not one of: file, keyring",
                self.identity.secret_store
            ));
        }

        let num = |v: &toml::Value| v.as_float().or_else(|| v.as_integer().map(|i| i as f64));
        if let Some(t) = &self.policy {
            let bad = |key: &str, why: &str| Err(format!("[policy] {key}: {why}"));
            if let Some(v) = t.get("session_min_hours") {
                let Some(h) = num(v) else { return bad("session_min_hours", "must be a number (hours)") };
                if !(h.is_finite() && h > 0.0) {
                    return bad("session_min_hours", "must be > 0");
                }
            }
            if let Some(v) = t.get("session_max_hours") {
                let Some(h) = num(v) else { return bad("session_max_hours", "must be a number (hours)") };
                if !(h.is_finite() && h > 0.0) {
                    return bad("session_max_hours", "must be > 0");
                }
            }
            if let (Some(a), Some(b)) = (t.get("session_min_hours").and_then(num), t.get("session_max_hours").and_then(num)) {
                if a > b {
                    return bad("session_max_hours", "must be ≥ session_min_hours");
                }
            }
            if let Some(v) = t.get("pending_ttl_secs") {
                let Some(x) = v.as_integer() else { return bad("pending_ttl_secs", "must be an integer (seconds)") };
                if x <= 0 {
                    return bad("pending_ttl_secs", "must be > 0");
                }
            }
            for key in ["exec_timeout_secs", "exec_max_secs"] {
                if let Some(v) = t.get(key) {
                    let Some(x) = v.as_integer() else { return bad(key, "must be an integer (seconds)") };
                    if x <= 0 {
                        return bad(key, "must be > 0");
                    }
                }
            }
            for key in ["output_max_kib", "file_max_kib", "max_pending_requests"] {
                if let Some(v) = t.get(key) {
                    let Some(x) = v.as_integer() else { return bad(key, "must be an integer") };
                    if x <= 0 {
                        return bad(key, "must be > 0");
                    }
                }
            }
            if let Some(v) = t.get("extra_denylist") {
                let Some(arr) = v.as_array() else { return bad("extra_denylist", "must be an array of strings") };
                for e in arr {
                    match e.as_str() {
                        Some(s) if !s.trim().is_empty() => {}
                        _ => return bad("extra_denylist", "entries must be non-empty strings"),
                    }
                }
            }
        }
        if let Some(t) = &self.audit {
            if let Some(v) = t.get("max_events") {
                let Some(x) = v.as_integer() else {
                    return Err("[audit] max_events: must be an integer (0 = keep forever)".into());
                };
                if x < 0 {
                    return Err("[audit] max_events: must be ≥ 0 (0 = keep forever)".into());
                }
            }
        }
        Ok(())
    }
}

pub fn default_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/".into())
}

pub fn default_data_dir() -> anyhow::Result<PathBuf> {
    let home = std::env::var("HOME")
        .map_err(|_| anyhow::anyhow!("HOME environment variable is not set — pass --data-dir"))?;
    Ok(PathBuf::from(home).join(".farcontrol"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        assert!(Config::default().validate().is_ok());
    }

    #[test]
    fn validate_rejects_bad_binds() {
        let c = Config { admin_bind: "0.0.0.0:7789".into(), ..Default::default() };
        assert!(c.validate().unwrap_err().contains("loopback"));

        let c = Config { agent_bind: "not-a-socket".into(), ..Default::default() };
        assert!(c.validate().unwrap_err().contains("agent_bind"));

        let c = Config { admin_bind: "127.0.0.1:0".into(), ..Default::default() };
        assert!(c.validate().unwrap_err().contains("port 0"));
    }

    #[test]
    fn validate_rejects_bad_policy_values() {
        let mk = |toml_policy: &str| {
            let c = Config { policy: Some(toml::from_str(toml_policy).unwrap()), ..Default::default() };
            c.validate()
        };
        assert!(mk("session_min_hours = -5").unwrap_err().contains("session_min_hours"));
        assert!(mk("session_min_hours = \"five\"").unwrap_err().contains("session_min_hours"));
        assert!(mk("pending_ttl_secs = 0").unwrap_err().contains("pending_ttl_secs"));
        assert!(mk("exec_timeout_secs = 0").unwrap_err().contains("exec_timeout_secs"));
        assert!(mk("output_max_kib = -1").unwrap_err().contains("output_max_kib"));
        assert!(mk("extra_denylist = [1, 2]").unwrap_err().contains("extra_denylist"));
        assert!(mk("session_min_hours = 80\nsession_max_hours = 20").unwrap_err().contains("session_max_hours"));
        // sane values pass, unknown keys stay ignored
        assert!(mk("session_max_hours = 24\nunknown_key = true").is_ok());
    }

    #[test]
    fn validate_rejects_bad_audit_and_identity() {
        let c = Config { audit: Some(toml::from_str("max_events = -1").unwrap()), ..Default::default() };
        assert!(c.validate().unwrap_err().contains("max_events"));

        let c = Config { identity: IdentityConfig { secret_store: "sqlite".into() }, ..Default::default() };
        assert!(c.validate().unwrap_err().contains("secret_store"));

        let c = Config { home_root: "  ".into(), ..Default::default() };
        assert!(c.validate().unwrap_err().contains("home_root"));
    }
}
