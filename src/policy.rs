/// Standard policy package (owner decision: "policy limit paket standart" — ADR-0008).
/// Values are enforced by the daemon BEFORE any capability executes. Fail-closed:
/// every check happens before spawn/read/write.
#[derive(Debug, Clone)]
pub struct Policy {
    pub min_session_hours: f64,
    pub max_session_hours: f64,
    /// D-004 (spec §35/§43): max concurrent ACTIVE sessions — standard default 1.
    pub max_active_sessions: usize,
    /// D-005 (spec §85): pending request TTL in seconds — default 300.
    pub pending_ttl_secs: i64,
    pub exec_timeout_ms_default: u64,
    pub exec_timeout_ms_max: u64,
    pub max_output_bytes: usize,
    pub max_file_bytes: usize,
    pub max_list_entries: usize,
    pub max_command_len: usize,
    pub max_args: usize,
    pub max_pending_requests: usize,
    /// Substring denylist for obviously destructive system commands.
    /// Intentionally conservative: a false positive is annoying, a false negative
    /// is catastrophic (documented in ADR-0008).
    pub denylist: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            min_session_hours: 5.0,
            max_session_hours: 72.0,
            max_active_sessions: 1,
            pending_ttl_secs: 300,
            exec_timeout_ms_default: 30_000,
            exec_timeout_ms_max: 300_000,
            max_output_bytes: 256 * 1024,
            max_file_bytes: 1024 * 1024,
            max_list_entries: 2048,
            max_command_len: 4096,
            max_args: 64,
            max_pending_requests: 10,
            denylist: [
                "mkfs", "wipefs", "dd if=/dev/", "dd of=/dev/",
                "shutdown", "reboot", "halt", "poweroff",
                "init 0", "init 6", "systemctl reboot", "systemctl poweroff",
                "rm -rf /", "rm -fr /", "rm -rf /*", "rm -rf ./*",
                "> /dev/sd", ":(){", "kill -9 1", "chmod -R 000 /",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        }
    }
}

/// Test-only escape hatch: allows sub-hour sessions so the e2e suite can verify
/// expiry without waiting hours. NEVER set in production.
pub fn test_mode() -> bool {
    std::env::var("FARCONTROL_TEST_MODE").map(|v| v == "1").unwrap_or(false)
}

impl Policy {
    /// Merge optional `[policy]` config-table overrides on top of the standard
    /// package defaults (ADR-0008). Unknown keys ignored; denylist entries are
    /// ADDED to the standard list (owner can tighten, never silently weaken).
    pub fn from_config(tbl: &Option<toml::Table>) -> Self {
        let mut p = Policy::default();
        let Some(t) = tbl else { return p };
        // TOML writes `24` as integer — accept both int and float for hours.
        let num = |v: &toml::Value| v.as_float().or_else(|| v.as_integer().map(|i| i as f64));
        if let Some(v) = t.get("session_min_hours").and_then(num) {
            p.min_session_hours = v;
        }
        if let Some(v) = t.get("session_max_hours").and_then(num) {
            p.max_session_hours = v;
        }
        if let Some(v) = t.get("pending_ttl_secs").and_then(|v| v.as_integer()) {
            p.pending_ttl_secs = v;
        }
        if let Some(v) = t.get("exec_timeout_secs").and_then(|v| v.as_integer()) {
            p.exec_timeout_ms_default = (v.max(1) * 1000) as u64;
        }
        if let Some(v) = t.get("exec_max_secs").and_then(|v| v.as_integer()) {
            p.exec_timeout_ms_max = (v.max(1) * 1000) as u64;
        }
        if let Some(v) = t.get("output_max_kib").and_then(|v| v.as_integer()) {
            p.max_output_bytes = (v.max(1) * 1024) as usize;
        }
        if let Some(v) = t.get("file_max_kib").and_then(|v| v.as_integer()) {
            p.max_file_bytes = (v.max(1) * 1024) as usize;
        }
        if let Some(v) = t.get("max_pending_requests").and_then(|v| v.as_integer()) {
            p.max_pending_requests = v.max(1) as usize;
        }
        if let Some(arr) = t.get("extra_denylist").and_then(|v| v.as_array()) {
            for e in arr.iter().filter_map(|e| e.as_str()) {
                let e = e.to_string();
                if !p.denylist.contains(&e) {
                    p.denylist.push(e);
                }
            }
        }
        p
    }

    /// Validate + clamp a requested session duration (hours).
    pub fn validate_hours(&self, hours: f64) -> Result<f64, String> {
        if !hours.is_finite() || hours <= 0.0 {
            return Err("hours must be a positive finite number".into());
        }
        if test_mode() {
            return Ok(hours.min(self.max_session_hours));
        }
        if hours < self.min_session_hours {
            return Err(format!(
                "session duration {hours}h is below the {}h minimum (standard package)",
                self.min_session_hours
            ));
        }
        Ok(hours.min(self.max_session_hours))
    }

    /// Returns the matching denylist pattern if the command line is denied.
    pub fn is_denied(&self, command_line: &str) -> Option<&str> {
        self.denylist.iter().find(|p| command_line.contains(p.as_str())).map(|s| s.as_str())
    }

    /// Clamp a requested exec timeout to the policy maximum.
    pub fn clamp_timeout_ms(&self, requested: Option<u64>) -> u64 {
        let t = requested.unwrap_or(self.exec_timeout_ms_default).max(1);
        t.min(self.exec_timeout_ms_max)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denylist_catches_destructive() {
        let p = Policy::default();
        assert!(p.is_denied("mkfs.ext4 /dev/sda1").is_some());
        assert!(p.is_denied("sudo rm -rf /").is_some());
        assert!(p.is_denied("sh -c 'dd of=/dev/sda'").is_some());
        assert!(p.is_denied("echo hi && shutdown now").is_some());
        assert!(p.is_denied("bash -c ':(){ :|:& };:'").is_some());
    }

    #[test]
    fn denylist_allows_normal() {
        let p = Policy::default();
        assert!(p.is_denied("echo hello world").is_none());
        assert!(p.is_denied("ls -la /home/user").is_none());
        assert!(p.is_denied("cargo build --release").is_none());
        assert!(p.is_denied("rm -rf /home/user/safe-project/target").is_some()); // conservative by design
    }

    #[test]
    fn hours_clamped_and_floored() {
        std::env::remove_var("FARCONTROL_TEST_MODE");
        let p = Policy::default();
        assert_eq!(p.validate_hours(100.0).unwrap(), 72.0);
        assert!(p.validate_hours(2.0).is_err());
        assert!(p.validate_hours(0.0).is_err());
        assert!(p.validate_hours(f64::NAN).is_err());
        assert_eq!(p.validate_hours(6.0).unwrap(), 6.0);
    }

    #[test]
    fn policy_from_config_overrides() {
        let tbl: toml::Table = toml::from_str(
            "session_max_hours = 24\nexec_max_secs = 120\nextra_denylist = [\"steamroller\"]\nunknown_key = true\n",
        )
        .unwrap();
        let p = Policy::from_config(&Some(tbl));
        assert_eq!(p.max_session_hours, 24.0);
        assert_eq!(p.exec_timeout_ms_max, 120_000);
        assert!(p.is_denied("run the steamroller now").is_some());
        assert_eq!(p.min_session_hours, 5.0); // untouched default

        let p2 = Policy::from_config(&None);
        assert_eq!(p2.max_session_hours, 72.0);
        assert_eq!(p2.exec_timeout_ms_max, 300_000);
    }

    #[test]
    fn timeout_clamped() {
        let p = Policy::default();
        assert_eq!(p.clamp_timeout_ms(None), 30_000);
        assert_eq!(p.clamp_timeout_ms(Some(500)), 500);
        assert_eq!(p.clamp_timeout_ms(Some(999_999_999)), 300_000);
    }
}
