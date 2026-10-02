//! Interactive PTY terminals for approved sessions (ADR-0013).
//! The agent opens a terminal, writes stdin, polls output, closes it.
//! Everything is one-shot HTTP + JSON — trivially usable by an AI agent:
//!   POST /v1/term/open   {session_id, command, args?}          -> {term_id}
//!   POST /v1/term/write  {term_id, data_b64}                   -> {written}
//!   POST /v1/term/read   {term_id}                             -> {output_b64, status}
//!   POST /v1/term/close  {term_id}                             -> {closed}
//! A terminal dies with its session (expiry/revoke) — access never outlives
//! the grant. Output buffer is a rolling 1 MiB window; each read drains it.

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};

const BUF_CAP: usize = 1024 * 1024; // rolling output window

pub struct Term {
    pub session_id: String,
    buf: Arc<Mutex<Vec<u8>>>,
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    child: Mutex<Box<dyn Child + Send + Sync>>,
    _master: Box<dyn MasterPty + Send>,
}

fn scrubbed_env() -> Vec<(String, String)> {
    // Minimal allowlist (ADR-0008 hardening: no env leakage to agent commands).
    ["PATH", "HOME", "LANG", "TERM", "SHELL"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect()
}

impl Term {
    /// Spawns `command` in a fresh PTY. `args` empty → `sh -c <command>`.
    pub fn open(
        session_id: &str,
        command: &str,
        args: &[String],
        cwd: &Path,
        cols: u16,
        rows: u16,
    ) -> Result<Term, String> {
        let pty = native_pty_system();
        let pair = pty
            .openpty(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| format!("pty open failed: {e}"))?;

        let mut cmd = if args.is_empty() {
            let mut c = CommandBuilder::new("sh");
            c.arg("-c");
            c.arg(command);
            c
        } else {
            let mut c = CommandBuilder::new(command);
            c.args(args.iter().map(|a| a.as_str()));
            c
        };
        cmd.cwd(cwd);
        cmd.env_clear();
        for (k, v) in scrubbed_env() {
            cmd.env(k, v);
        }

        let child = pair
            .slave
            .spawn_command(cmd)
            .map_err(|e| format!("spawn failed: {e} (command may not exist)"))?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| format!("pty reader failed: {e}"))?;
        let writer = pair
            .master
            .take_writer()
            .map_err(|e| format!("pty writer failed: {e}"))?;
        drop(pair.slave); // keep EOF semantics when the child exits

        // Reader thread: PTY master → rolling buffer (cap 1 MiB, drop oldest).
        let buf = Arc::new(Mutex::new(Vec::<u8>::new()));
        let buf2 = buf.clone();
        std::thread::spawn(move || {
            let mut chunk = [0u8; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if let Ok(mut b) = buf2.lock() {
                            b.extend_from_slice(&chunk[..n]);
                            if b.len() > BUF_CAP {
                                let excess = b.len() - BUF_CAP;
                                b.drain(0..excess);
                            }
                        }
                    }
                }
            }
        });

        Ok(Term {
            session_id: session_id.to_string(),
            buf,
            writer: Mutex::new(Some(writer)),
            child: Mutex::new(child),
            _master: pair.master,
        })
    }

    /// Drains up to `max` bytes of pending output.
    pub fn read(&self, max: usize) -> Vec<u8> {
        match self.buf.lock() {
            Ok(mut b) => {
                let n = b.len().min(max);
                let out = b[..n].to_vec();
                b.drain(0..n);
                out
            }
            Err(_) => Vec::new(),
        }
    }

    /// Writes to the terminal's stdin (agent → process).
    pub fn write_stdin(&self, data: &[u8]) -> Result<usize, String> {
        let mut guard = self.writer.lock().map_err(|e| e.to_string())?;
        match guard.as_mut() {
            Some(w) => w.write_all(data).map(|_| data.len()).map_err(|e| format!("stdin write failed: {e}")),
            None => Err("terminal stdin is closed".into()),
        }
    }

    pub fn is_running(&self) -> bool {
        match self.child.lock() {
            Ok(mut c) => !matches!(c.try_wait(), Ok(Some(_))),
            Err(_) => false,
        }
    }

    /// Kills the process and reaps it. Idempotent.
    pub fn close(&self) {
        if let Ok(mut c) = self.child.lock() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Ok(mut w) = self.writer.lock() {
            *w = None;
        }
    }
}

/// Registry of live terminals: term_id → Term. Bounded by policy
/// (max_active_terms per daemon — default 8, plenty for one agent).
#[derive(Default)]
pub struct Terms {
    inner: Mutex<HashMap<String, Term>>,
}

impl Terms {
    pub fn insert(&self, id: String, t: Term) {
        if let Ok(mut m) = self.inner.lock() {
            m.insert(id, t);
        }
    }
    /// Runs `f` with the term if present.
    pub fn with<R>(&self, id: &str, f: impl FnOnce(&Term) -> R) -> Option<R> {
        let guard = self.inner.lock().ok()?;
        let t = guard.get(id)?;
        Some(f(t))
    }
    /// Removes + kills a terminal. Returns true if it existed.
    pub fn remove(&self, id: &str) -> bool {
        if let Ok(mut m) = self.inner.lock() {
            if let Some(t) = m.remove(id) {
                t.close();
                return true;
            }
        }
        false
    }
    /// Kills every terminal bound to a session id (called on revoke/expiry/panic).
    pub fn kill_for_session(&self, session_id: &str) -> usize {
        let mut killed = 0;
        if let Ok(mut m) = self.inner.lock() {
            let ids: Vec<String> = m
                .iter()
                .filter(|(_, t)| t.session_id == session_id)
                .map(|(k, _)| k.clone())
                .collect();
            for id in ids {
                if let Some(t) = m.remove(&id) {
                    t.close();
                    killed += 1;
                }
            }
        }
        killed
    }
    /// Kills every terminal bound to sessions NOT in the active set (sweeper).
    pub fn reap_inactive(&self, active: &[String]) -> usize {
        let mut killed = 0;
        if let Ok(mut m) = self.inner.lock() {
            let ids: Vec<String> = m
                .iter()
                .filter(|(_, t)| !active.contains(&t.session_id))
                .map(|(k, _)| k.clone())
                .collect();
            for id in ids {
                if let Some(t) = m.remove(&id) {
                    t.close();
                    killed += 1;
                }
            }
        }
        killed
    }
    pub fn count(&self) -> usize {
        self.inner.lock().map(|m| m.len()).unwrap_or(0)
    }
}
