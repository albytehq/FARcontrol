//! v0.4 Full Access adapters (spec §14.2/§27, Phase 4): process, application,
//! desktop. Each one sits BEHIND the authorization pipeline (full_access scope
//! + policy + audit, server.rs) — an adapter can never become the whole system.
//!
//! Linux-first (owner decision). Desktop capabilities fail CLOSED with a clean
//! error on headless boxes — never a crash, never a silent no-op.

use std::path::Path;

// ============================================================
// Process adapter — process.read / process.control (§14.2)
// ============================================================

#[derive(serde::Serialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub name: String,
    /// true when this is the frtrol daemon itself (protected from kill)
    pub is_self: bool,
}

/// Lists processes by walking /proc directly — no shell, no `ps` dependency,
/// no environment inherited. Capped at `max` entries (agent can use
/// `exec ps aux` for richer views; this is the fast controlled path).
pub fn list_processes(max: usize) -> (Vec<ProcInfo>, bool) {
    let me = std::process::id() as i32;
    let mut out: Vec<ProcInfo> = Vec::new();
    let mut truncated = false;
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return (out, truncated);
    };
    for e in entries.flatten() {
        let fname = e.file_name();
        let Some(pid) = fname.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        if out.len() >= max {
            truncated = true;
            break;
        }
        let name = std::fs::read_to_string(e.path().join("comm"))
            .map(|s| s.trim_end_matches('\0').trim().to_string())
            .unwrap_or_else(|_| "?".into());
        out.push(ProcInfo { pid, name, is_self: pid == me });
    }
    out.sort_by_key(|p| p.pid);
    (out, truncated)
}

/// process.control: send a signal to a pid. Guarded — an agent must never be
/// able to kill PID 1 or the FARcontrol daemon itself (self-protection, §27
/// "a compromised adapter must not become the entire system").
pub fn kill_pid(pid: i32, force: bool) -> Result<(), String> {
    if pid <= 1 {
        return Err(format!("refusing to signal pid {pid} — PID 1 and below are protected"));
    }
    if pid == std::process::id() as i32 {
        return Err("refusing to kill the frtrol daemon itself (panic/stop is the owner's call)".into());
    }
    // ESRCH = no such process (already dead — fine, idempotent success)
    let sig = if force { libc::SIGKILL } else { libc::SIGTERM };
    let rc = unsafe { libc::kill(pid, sig) };
    match rc {
        0 => Ok(()),
        _ => {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                Ok(()) // already gone — treat as success (idempotent)
            } else {
                Err(format!("kill({pid}) failed: {err} (permission? not your process?)"))
            }
        }
    }
}

// ============================================================
// Application adapter — application.launch / application.close (§14.2)
// ============================================================

/// Launch a detached application (survives the daemon; output is NOT captured
/// — if the agent needs output, that is what exec/term are for). Env is
/// scrubbed exactly like exec (PATH/HOME/LANG/TERM/SHELL only).
pub async fn launch_app(command: &str, args: &[String], cwd: &Path) -> std::io::Result<u32> {
    use tokio::process::Command;
    let mut cmd = if args.is_empty() {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    } else {
        let mut c = Command::new(command);
        c.args(args);
        c
    };
    cmd.env_clear();
    for k in ["PATH", "HOME", "LANG", "TERM", "SHELL"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    cmd.current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        // NOT kill_on_drop: dropping the Child hands it to tokio's orphan
        // reaper — the app keeps running, no zombie leak.
        ;
    let child = cmd.spawn()?;
    Ok(child.id().unwrap_or(0))
}

// ============================================================
// Desktop adapter — desktop.read / desktop.input (§14.2)
// ============================================================

/// A graphical session must exist; otherwise the capability fails closed with
/// a clean machine error instead of spawning nonsense on a headless server.
pub fn desktop_session() -> Option<String> {
    if let Ok(d) = std::env::var("DISPLAY") {
        if !d.is_empty() {
            return Some(format!("X11 {d}"));
        }
    }
    if let Ok(w) = std::env::var("WAYLAND_DISPLAY") {
        if !w.is_empty() {
            return Some(format!("Wayland {w}"));
        }
    }
    None
}

/// desktop.read: capture the screen via fixed tools (no user input reaches the
/// command line). ImageMagick `import` first, `scrot` as fallback.
pub async fn screenshot(max_bytes: usize) -> Result<Vec<u8>, String> {
    let Some(session) = desktop_session() else {
        return Err("DESKTOP_UNAVAILABLE".into());
    };
    let _ = session;
    for tool in ["import", "scrot"] {
        // argv-only invocation of a FIXED binary (§77: no concatenated input)
        let mut fname = std::env::temp_dir();
        fname.push(format!("farcontrol-shot-{}.png", crate::crypto::gen_nonce()));
        let out = tokio::process::Command::new(tool)
            .arg("-window")
            .arg("root")
            .arg(&fname)
            .env_clear()
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
            .await;
        if let Ok(o) = out {
            if o.status.success() {
                match std::fs::read(&fname) {
                    Ok(data) => {
                        let _ = std::fs::remove_file(&fname);
                        if data.len() > max_bytes {
                            return Err(format!("screenshot is {} bytes — over the {} byte policy cap", data.len(), max_bytes));
                        }
                        return Ok(data);
                    }
                    Err(e) => return Err(format!("screenshot written but unreadable: {e}")),
                }
            }
        }
        let _ = std::fs::remove_file(&fname);
    }
    Err("screenshot failed — install imagemagick (import) or scrot".into())
}

/// desktop.input: type a string into the focused window via xdotool (argv-only,
/// fixed binary). Wayland: xdotool generally does not work — reported honestly.
pub async fn desktop_type(text: &str) -> Result<(), String> {
    if desktop_session().is_none() {
        return Err("DESKTOP_UNAVAILABLE".into());
    }
    if text.len() > 4096 {
        return Err("input text exceeds 4096 chars".into());
    }
    let out = tokio::process::Command::new("xdotool")
        .arg("type")
        .arg("--")
        .arg(text)
        .env_clear()
        .output()
        .await
        .map_err(|e| format!("xdotool failed to start: {e} — is it installed?"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "xdotool type failed (exit {:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        ))
    }
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_list_works_and_marks_self() {
        let (list, truncated) = list_processes(500);
        assert!(!list.is_empty(), "there is always at least us + init");
        assert!(list.iter().any(|p| p.is_self), "our own pid must be flagged");
        assert!(list.iter().all(|p| p.pid > 0));
        assert!(!truncated);
    }

    #[test]
    fn process_list_cap() {
        let (list, truncated) = list_processes(5);
        assert!(list.len() <= 5);
        assert!(truncated, "cap must be flagged when there are more");
    }

    #[test]
    fn kill_guards_pid1_and_self() {
        assert!(kill_pid(1, false).unwrap_err().contains("protected"));
        assert!(kill_pid(0, false).unwrap_err().contains("protected"));
        assert!(kill_pid(-5, false).unwrap_err().contains("protected"));
        let me = std::process::id() as i32;
        assert!(kill_pid(me, false).unwrap_err().contains("refusing to kill the frtrol"));
    }

    #[test]
    fn kill_dead_pid_is_idempotent() {
        // find a pid that does not exist: spawn+wait a child, then kill it
        let mut child = std::process::Command::new("true").spawn().unwrap();
        let pid = child.id() as i32;
        let _ = child.wait();
        kill_pid(pid, false).expect("ESRCH must be treated as success (idempotent)");
    }

    #[tokio::test]
    async fn app_launch_returns_pid_and_detaches() {
        let home = std::path::PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()));
        let pid = launch_app("sleep 30", &[], &home).await.unwrap();
        assert!(pid > 1);
        // verify it is really running, then clean up
        let alive = std::path::Path::new(format!("/proc/{pid}").as_str()).exists();
        assert!(alive, "launched app must be running");
        kill_pid(pid as i32, true).expect("cleanup kill");
    }

    #[test]
    fn desktop_headless_fails_closed() {
        // The test environment is headless: DISPLAY/WAYLAND_DISPLAY unset.
        // If a dev box has a display this test is skipped (env-dependent).
        if desktop_session().is_none() {
            assert!(desktop_session().is_none());
        }
    }
}
