mod adapters;
mod agent_client;
mod catalog;
mod cli_admin;
mod config;
mod crypto;
mod error;
mod exec;
mod files;
mod keyring;
mod policy;
mod server;
mod state;
mod term;
mod tls;
mod webui;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "frtrol",
    version,
    about = "FARcontrol 1.0.0 — approval-gated control plane for external AI agents (authentication ≠ authorization)"
)]
struct Cli {
    /// Data directory (state, tokens, config). Default: ~/.farcontrol
    #[arg(long, global = true, env = "FARCONTROL_HOME", hide = true)]
    data_dir: Option<PathBuf>,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start the daemon (auto-initializes on first run — everything just works)
    Start {
        /// Override the agent-plane bind (e.g. 0.0.0.0:7788 for LAN access)
        #[arg(long)]
        bind: Option<String>,
        /// Override the root refusal (not recommended)
        #[arg(long)]
        allow_root: bool,
    },
    /// Initialize the data directory (optional — start does this automatically)
    Init,
    /// Show daemon status (running? pending? active?)
    Status {
        /// Machine-readable single-line JSON (spec §45, stable)
        #[arg(long)]
        json: bool,
    },
    /// List pending requests and all sessions
    List {
        /// Machine-readable single-line JSON (spec §45, stable)
        #[arg(long)]
        json: bool,
    },
    /// Approve a pending request → creates a session grant
    Approve {
        id: String,
        /// Shorten the session (never extends beyond what was requested)
        #[arg(long)]
        hours: Option<f64>,
    },
    /// Deny a pending request
    Deny {
        id: String,
        #[arg(long, default_value = "denied by owner")]
        reason: String,
    },
    /// Revoke an active session (access dies immediately)
    Revoke {
        id: String,
        #[arg(long, default_value = "revoked by owner")]
        reason: String,
    },
    /// Rotate the agent token (the old token dies immediately)
    Rotate,
    /// Show recent audit events
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// EMERGENCY STOP: revoke every session, kill terminals, rotate the token
    Panic {
        /// Why (optional free text — audit record)
        reason: Option<String>,
    },
    /// Health checks — everything green means you can rely on it
    Doctor,
    /// Backup all state (running daemon) → tar.gz (contains ALL secrets, 0600)
    Backup {
        /// Output file (default: farcontrol-backup-<date>.tar.gz in cwd)
        out: Option<String>,
    },
    /// Restore state from a backup (daemon must be STOPPED — old data kept as .bak)
    Restore {
        archive: String,
    },
    /// Agent-side commands — run where the AI agent runs
    Agent {
        /// Base URL of the FARcontrol agent API [env: FARCONTROL_URL]
        #[arg(long, env = "FARCONTROL_URL")]
        url: Option<String>,
        /// Agent token [env: FARCONTROL_TOKEN]
        #[arg(long, env = "FARCONTROL_TOKEN")]
        token: Option<String>,
        /// HTTP timeout in seconds
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Print raw output (stdout for exec, file content for read)
        #[arg(long)]
        raw: bool,
        #[command(subcommand)]
        cmd: AgentCmd,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Check connectivity + authentication
    Ping,
    /// Ask for a session grant. e.g. frtrol agent request myai full_access 12 fix the nginx
    Request {
        /// Agent name shown to the owner (default: agent)
        #[arg(default_value = "agent")]
        name: String,
        /// terminal_only or full_access (default: terminal_only)
        #[arg(default_value = "terminal_only")]
        scope: String,
        /// Session duration in hours, 5–72 (default: 6)
        #[arg(default_value_t = 6.0)]
        hours: f64,
        /// Why you want access — free text, words joined (quote it if it has dashes)
        #[arg(trailing_var_arg = true)]
        reason: Vec<String>,
    },
    /// Poll a request or session by its id (auto-detects which)
    Status {
        /// A request id (req_...) or session id (ses_...)
        id: String,
    },
    /// Run a command inside an approved session. e.g. frtrol agent exec ses_x ls -la
    Exec {
        /// The session id (ses_...)
        session: String,
        /// Command and its arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
        /// Hard timeout in milliseconds (default 30000)
        #[arg(long, default_value_t = 30000)]
        timeout_ms: u64,
    },
    /// Read a file (full_access only). e.g. frtrol agent read ses_x /tmp/app.log
    Read {
        session: String,
        path: String,
    },
    /// Write a file (full_access only). e.g. frtrol agent write ses_x /tmp/f.txt "hello world"
    /// No content given → reads stdin (pipe friendly)
    Write {
        session: String,
        path: String,
        /// Plain text content (UTF-8)
        content: Option<String>,
        /// Base64 content (binary-safe)
        #[arg(long)]
        b64: Option<String>,
    },
    /// List a directory (full_access only). e.g. frtrol agent ls ses_x /tmp
    Ls {
        session: String,
        /// Directory to list (default: .)
        #[arg(default_value = ".")]
        path: String,
    },
    /// List processes (full_access only). e.g. frtrol agent ps ses_x
    Ps {
        session: String,
    },
    /// Kill a process by pid (full_access only). e.g. frtrol agent kill ses_x 1234
    Kill {
        session: String,
        pid: i64,
        /// Use SIGKILL instead of SIGTERM
        #[arg(long)]
        force: bool,
    },
    /// Launch a detached app (full_access only). e.g. frtrol agent app ses_x sleep 300
    App {
        session: String,
        /// Command and its arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Take a screenshot (full_access + graphical session). e.g. frtrol agent shot ses_x
    Shot {
        session: String,
    },
    /// Type text into the desktop (full_access + graphical session)
    Type {
        session: String,
        /// Text to type (words joined)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        text: Vec<String>,
    },
    /// Revoke own session (agents can always give up access)
    Revoke {
        session: String,
    },
    /// Interactive terminal (PTY) in an approved session.
    /// e.g. frtrol agent term ses_x bash
    Term {
        /// The session id (ses_...)
        session: String,
        /// Command and its arguments
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    let code = run(cli).unwrap_or_else(|e| {
        // §66 (ADR-0022): a server-rejected owner action carries its wire code;
        // map it to the stable exit-code contract instead of a bare 1.
        if let Some(oe) = e.downcast_ref::<cli_admin::OwnerErr>() {
            eprintln!("ERROR: {oe}");
            std::process::exit(crate::error::exit_for(&oe.code));
        }
        // SC-02 (ADR-0023): a rejected config is a usage error — exit 2, not 1.
        let msg = format!("{e:#}");
        if msg.starts_with("config_invalid") {
            eprintln!("ERROR: {msg}");
            std::process::exit(2);
        }
        eprintln!("ERROR: {msg}");
        1
    });
    std::process::exit(code);
}

fn quick_guide() {
    println!("FARcontrol {} — the AI asks, you approve, access expires", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  you   : frtrol start                       (run it, that is all)");
    println!("  agent : frtrol agent request myai full_access 12 fix the nginx");
    println!("  you   : frtrol list   →   frtrol approve req_xxx");
    println!("  agent : frtrol agent exec ses_xxx ls -la");
    println!();
    println!("  frtrol status | frtrol deny req_xxx | frtrol revoke ses_xxx | frtrol audit");
    println!("  frtrol doctor | frtrol panic   (health checks / emergency stop)");
    println!("  frtrol agent ping | request | status | exec | term | read | write | ls | revoke");
    println!("  web console: the URL that 'frtrol start' prints — login with the admin token");
    println!();
    println!("  full help: frtrol --help");
}

fn run(cli: Cli) -> anyhow::Result<i32> {
    let data_dir = match cli.data_dir {
        Some(d) => d,
        None => config::default_data_dir()?,
    };
    match cli.cmd {
        None => {
            quick_guide();
            Ok(0)
        }
        // start auto-initializes — first run creates tokens+config, then just works
        // (init_quiet is idempotent: pre-existing config without state is completed)
        Some(Cmd::Start { bind, allow_root }) => {
            cli_admin::init_quiet(&data_dir)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(&data_dir, bind, allow_root)).map(|_| 0)
        }
        Some(Cmd::Init) => {
            cli_admin::init(&data_dir)?;
            Ok(0)
        }
        Some(Cmd::Status { json }) => cli_admin::status(&data_dir, json).map(|_| 0),
        Some(Cmd::List { json }) => cli_admin::list(&data_dir, json).map(|_| 0),
        Some(Cmd::Approve { id, hours }) => cli_admin::approve(&data_dir, &id, hours).map(|_| 0),
        Some(Cmd::Deny { id, reason }) => cli_admin::deny(&data_dir, &id, &reason).map(|_| 0),
        Some(Cmd::Revoke { id, reason }) => cli_admin::revoke(&data_dir, &id, &reason).map(|_| 0),
        Some(Cmd::Rotate) => cli_admin::rotate(&data_dir).map(|_| 0),
        Some(Cmd::Audit { limit }) => cli_admin::audit(&data_dir, limit).map(|_| 0),
        Some(Cmd::Panic { reason }) => cli_admin::panic_stop(&data_dir, &reason.unwrap_or_else(|| "owner panic".into())).map(|_| 0),
        Some(Cmd::Doctor) => cli_admin::doctor(&data_dir),
        Some(Cmd::Backup { out }) => {
            let out = out.unwrap_or_else(|| {
                let d = chrono::Local::now().format("%Y%m%d-%H%M%S");
                format!("farcontrol-backup-{d}.tar.gz")
            });
            cli_admin::backup(&data_dir, std::path::Path::new(&out)).map(|_| 0)
        }
        Some(Cmd::Restore { archive }) => {
            cli_admin::restore(&data_dir, std::path::Path::new(&archive)).map(|_| 0)
        }
        Some(Cmd::Agent { url, token, timeout_secs, raw, cmd }) => {
            agent_client::run(&data_dir, url, token, timeout_secs, raw, cmd)
        }
    }
}
