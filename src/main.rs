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
mod out;
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
    about = "FARcontrol 1.2.0 — approval-gated control plane for external AI agents (authentication ≠ authorization)"
)]
struct Cli {
    /// Data directory (state, config — the OWNER side). Default: ~/.farcontrol
    #[arg(long, global = true, env = "FARCONTROL_HOME", hide = true)]
    data_dir: Option<PathBuf>,

    /// Machine-readable JSON output (ADR-0026: every command, stable schema, no styling)
    #[arg(long, global = true, env = "FARCONTROL_JSON")]
    json: bool,

    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Start a FARcontrol session — prints the ephemeral credentials
    /// (device id + session password + web console + admin token).
    /// Everything shown dies when this process stops.
    Start {
        /// Override the agent-plane bind (e.g. 0.0.0.0:7788 for LAN access)
        #[arg(long)]
        bind: Option<String>,
        /// Override the root refusal (not recommended)
        #[arg(long)]
        allow_root: bool,
        /// Operator detail after the session box (binds, fingerprint, policy…)
        #[arg(long)]
        verbose: bool,
    },
    /// End the session — graceful shutdown; every credential from this run dies
    Stop,
    /// Initialize the data directory (optional — start does this automatically)
    Init,
    /// Show the current session: device id, uptime, connected agents, counts
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
    /// Rotate the session password + admin token mid-session (shown once).
    /// Connected agents keep working; new logins need the new password.
    Rotate,
    /// Print the daemon cert fingerprint (TOFU out-of-band verification)
    Fingerprint,
    /// Show recent audit events
    Audit {
        #[arg(long, default_value_t = 50)]
        limit: u32,
    },
    /// EMERGENCY STOP: revoke every session, kill terminals, rotate EVERY credential
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
    /// Hidden: the background agent runtime (spawned by `frtrol agent`,
    /// ADR-0030). Runs standalone for supervised deployments (systemd etc.).
    #[command(hide = true)]
    Agentd,
    /// Restore state from a backup (daemon must be STOPPED — old data kept as .bak)
    Restore {
        archive: String,
    },
    /// Agent-side — run where the AI agent runs. Bare `frtrol agent` connects
    /// (device id + session password, nothing else) and leaves a background
    /// runtime behind; subcommands use the saved connection.
    Agent {
        /// Base URL of the FARcontrol agent API [env: FARCONTROL_URL]
        /// (advanced — the connect flow finds localhost on its own)
        #[arg(long, env = "FARCONTROL_URL")]
        url: Option<String>,
        /// Device id (FAR-XXXX-XXXX) [env: FARCONTROL_DEVICE] — or the prompt asks
        #[arg(long, env = "FARCONTROL_DEVICE")]
        device: Option<String>,
        /// Read the session password from this file (0600) instead of a prompt
        #[arg(long)]
        password_file: Option<PathBuf>,
        /// Agent name shown to the owner (connect flow; audit display only)
        #[arg(long)]
        name: Option<String>,
        /// Agent home (connection + runtime state). Default: ~/.farcontrol-agent
        #[arg(long, global = false, env = "FARCONTROL_AGENT_HOME", hide = true)]
        home: Option<PathBuf>,
        /// HTTP timeout in seconds
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Print raw output (stdout for exec, file content for read)
        #[arg(long)]
        raw: bool,
        #[command(subcommand)]
        cmd: Option<AgentCmd>,
    },
}

#[derive(Subcommand)]
enum AgentCmd {
    /// Stop the background runtime + clear the saved connection (fail closed)
    Stop,
    /// No argument → background-runtime status (connected? reconnecting? expired?).
    /// With an id → poll a request (req_...) or session (ses_...).
    Status {
        /// A request id (req_...) or session id (ses_...) — omit for runtime status
        id: Option<String>,
    },
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
    println!("FARcontrol {} — start a session, give two lines to your AI agent, approve what it asks", env!("CARGO_PKG_VERSION"));
    println!();
    println!("  you   : frtrol start                (prints device id + session password)");
    println!("  agent : frtrol agent                (on the agent machine — asks for those two)");
    println!("  agent : frtrol agent request myai terminal_only 6 fix the nginx");
    println!("  you   : frtrol list   →   frtrol approve req_xxx");
    println!("  agent : frtrol agent exec ses_xxx ls -la");
    println!();
    println!("  the session (and everything it printed) ends at: frtrol stop");
    println!("  frtrol status | agent status | deny req_xxx | revoke ses_xxx | audit");
    println!("  frtrol doctor | frtrol panic   (health checks / emergency stop)");
    println!("  frtrol agent ping | request | status | exec | term | read | write | ls | stop");
    println!("  add --json to any command for machine-readable output");
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
        // start auto-initializes — first run creates config+db, then just works.
        // The daemon mints a fresh session (password + key + admin token) here.
        Some(Cmd::Start { bind, allow_root, verbose }) => {
            cli_admin::init_quiet(&data_dir)?;
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(server::run(&data_dir, bind, allow_root, verbose)).map(|_| 0)
        }
        Some(Cmd::Stop) => cli_admin::stop(&data_dir).map(|_| 0),
        Some(Cmd::Init) => {
            cli_admin::init(&data_dir)?;
            Ok(0)
        }
        Some(Cmd::Status { .. }) => cli_admin::status(&data_dir, cli.json).map(|_| 0),
        Some(Cmd::List { .. }) => cli_admin::list(&data_dir, cli.json).map(|_| 0),
        Some(Cmd::Approve { id, hours }) => cli_admin::approve(&data_dir, &id, hours).map(|_| 0),
        Some(Cmd::Deny { id, reason }) => cli_admin::deny(&data_dir, &id, &reason).map(|_| 0),
        Some(Cmd::Revoke { id, reason }) => cli_admin::revoke(&data_dir, &id, &reason).map(|_| 0),
        Some(Cmd::Rotate) => cli_admin::rotate(&data_dir).map(|_| 0),
        Some(Cmd::Fingerprint) => cli_admin::fingerprint(&data_dir, cli.json).map(|_| 0),
        Some(Cmd::Audit { limit }) => cli_admin::audit(&data_dir, limit, cli.json).map(|_| 0),
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
        Some(Cmd::Agent { url, device, password_file, name, home, timeout_secs, raw, cmd }) => {
            let home = match home { Some(h) => h, None => agent_client::default_agent_home()? };
            agent_client::run(&home, agent_client::AgentArgs { url, device, name, password_file, timeout_secs, raw, json: cli.json }, cmd)
        }
        Some(Cmd::Agentd) => agent_client::agentd_main(),
    }
}
