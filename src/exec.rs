use std::path::Path;
use std::time::{Duration, Instant};
use tokio::process::Command;

pub struct ExecOutcome {
    pub status: String, // "completed" | "timeout"
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
}

/// Lossy UTF-8 conversion with a hard byte cap. Output beyond `max` is dropped
/// and flagged — the agent knows it was truncated (ADR-0008).
pub fn truncate_utf8(data: &[u8], max: usize) -> (String, bool) {
    if data.len() <= max {
        (String::from_utf8_lossy(data).into_owned(), false)
    } else {
        (String::from_utf8_lossy(&data[..max]).into_owned(), true)
    }
}

/// Runs a command. Semantics (documented contract, ADR-0007):
/// - `args` empty  → `sh -c <command>` (shell one-liner; what AI agents usually send)
/// - `args` given  → direct exec, no shell (safer, predictable argv)
///
/// On timeout the child is killed (kill_on_drop) and the outcome reports
/// status "timeout" — the command's partial output is intentionally discarded.
pub async fn run(
    command: &str,
    args: &[String],
    cwd: &Path,
    timeout_ms: u64,
    max_output: usize,
) -> std::io::Result<ExecOutcome> {
    let start = Instant::now();
    let mut cmd = if args.is_empty() {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    } else {
        let mut c = Command::new(command);
        c.args(args);
        c
    };
    // v0.2 hardening: scrubbed env — the agent inherits an explicit allowlist
    // only (PATH/HOME/LANG/TERM/SHELL), never the daemon's full environment.
    cmd.env_clear();
    for k in ["PATH", "HOME", "LANG", "TERM", "SHELL"] {
        if let Ok(v) = std::env::var(k) {
            cmd.env(k, v);
        }
    }
    cmd.current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    let child = cmd.spawn()?;
    match tokio::time::timeout(Duration::from_millis(timeout_ms), child.wait_with_output()).await {
        Ok(Ok(out)) => {
            let (stdout, stdout_truncated) = truncate_utf8(&out.stdout, max_output);
            let (stderr, stderr_truncated) = truncate_utf8(&out.stderr, max_output);
            Ok(ExecOutcome {
                status: "completed".into(),
                exit_code: out.status.code(),
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                duration_ms: start.elapsed().as_millis() as u64,
            })
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Ok(ExecOutcome {
            status: "timeout".into(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            duration_ms: start.elapsed().as_millis() as u64,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home() -> std::path::PathBuf {
        std::path::PathBuf::from(
            std::env::var("HOME").unwrap_or_else(|_| "/tmp".into()),
        )
    }

    #[tokio::test]
    async fn shell_mode_captures_stdout() {
        let out = run("printf 'hello-exec'", &[], &home(), 5_000, 1024).await.unwrap();
        assert_eq!(out.status, "completed");
        assert_eq!(out.exit_code, Some(0));
        assert_eq!(out.stdout, "hello-exec");
    }

    #[tokio::test]
    async fn direct_mode_argv() {
        let args = vec!["one".to_string(), "two".to_string()];
        let out = run("echo", &args, &home(), 5_000, 1024).await.unwrap();
        assert_eq!(out.exit_code, Some(0));
        assert!(out.stdout.contains("one two"));
    }

    #[tokio::test]
    async fn timeout_kills_long_command() {
        let out = run("sleep 5", &[], &home(), 300, 1024).await.unwrap();
        assert_eq!(out.status, "timeout");
        assert_eq!(out.exit_code, None);
        assert!(out.duration_ms < 2_000, "must not wait for the full sleep");
    }

    #[tokio::test]
    async fn exit_code_and_stderr_propagated() {
        let out = run("echo oops >&2; exit 7", &[], &home(), 5_000, 1024).await.unwrap();
        assert_eq!(out.exit_code, Some(7));
        assert!(out.stderr.contains("oops"));
    }

    #[test]
    fn truncation_flag() {
        let data = vec![b'a'; 100];
        let (s, truncated) = truncate_utf8(&data, 10);
        assert_eq!(s.len(), 10);
        assert!(truncated);
        let (s2, t2) = truncate_utf8(b"small", 10);
        assert_eq!(s2, "small");
        assert!(!t2);
    }
}
