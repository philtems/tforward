use chrono::Local;
use clap::Parser;
use ipnet::Ipv4Net;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time;

const VERSION: &str = "1.0.0";
const YEAR: &str = "2026";
const AUTHOR: &str = "Philippe TEMESI";
const WEBSITE: &str = "https://www.tems.be";
const APP_NAME: &str = "tforward";

#[derive(Parser, Debug)]
#[command(name = APP_NAME, version = VERSION, about, long_about = None)]
struct Args {
    /// Forwarding rules in format "0.0.0.0:8080:192.168.1.10:80"
    #[arg(short, long, required = true)]
    rule: Vec<String>,

    /// File containing blacklist (IP or CIDR per line)
    #[arg(short, long)]
    blocklist: Option<PathBuf>,

    /// Blacklist reload interval in seconds (default: 300)
    #[arg(long, default_value = "300")]
    reload_interval: u64,

    /// Log level (info, debug, warn)
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Daemon mode: detach from terminal and run in background
    #[arg(long)]
    daemonize: bool,

    /// PID file for daemon mode
    #[arg(long, default_value = "/var/run/tforward.pid")]
    pid_file: PathBuf,

    /// Log file for daemon mode (default: stdout redirected to /var/log/tforward.log)
    #[arg(long, default_value = "/var/log/tforward.log")]
    log_file: PathBuf,
}

#[derive(Clone, Debug)]
struct Rule {
    listen: SocketAddrV4,
    dest: SocketAddrV4,
}

#[derive(Clone)]
struct Blacklist {
    ips: HashSet<Ipv4Addr>,
    nets: Vec<Ipv4Net>,
}

impl Blacklist {
    fn new() -> Self {
        Self {
            ips: HashSet::new(),
            nets: Vec::new(),
        }
    }

    fn contains(&self, ip: Ipv4Addr) -> bool {
        if self.ips.contains(&ip) {
            return true;
        }
        for net in &self.nets {
            if net.contains(&ip) {
                return true;
            }
        }
        false
    }

    fn load_from_file(path: &PathBuf) -> io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut blacklist = Blacklist::new();

        for line in reader.lines() {
            let line = line?.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if line.contains('/') {
                if let Ok(net) = line.parse::<Ipv4Net>() {
                    blacklist.nets.push(net);
                    log_info(&format!("Blacklist CIDR added: {}", net));
                } else {
                    log_warn(&format!("Line ignored (invalid CIDR): {}", line));
                }
            } else {
                if let Ok(ip) = line.parse::<Ipv4Addr>() {
                    blacklist.ips.insert(ip);
                    log_info(&format!("Blacklist IP added: {}", ip));
                } else {
                    log_warn(&format!("Line ignored (invalid IP): {}", line));
                }
            }
        }

        Ok(blacklist)
    }
}

// Thread-safe logger for daemon mode
struct Logger {
    file: Mutex<Option<File>>,
    daemon_mode: bool,
}

impl Logger {
    fn new() -> Self {
        Self {
            file: Mutex::new(None),
            daemon_mode: false,
        }
    }

    fn init_file(&self, path: &PathBuf) {
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let mut guard = self.file.lock().unwrap();
            *guard = Some(file);
            let _ = self.log_to_stdout(&format!("Logging to {}", path.display()));
        } else {
            let _ = self.log_to_stderr(&format!("Unable to open log file: {}", path.display()));
        }
    }

    fn set_daemon_mode(&mut self, enabled: bool) {
        self.daemon_mode = enabled;
    }

    fn log_to_stdout(&self, msg: &str) -> io::Result<()> {
        let stdout = io::stdout();
        let mut handle = stdout.lock();
        handle.write_all(msg.as_bytes())?;
        handle.write_all(b"\n")?;
        handle.flush()?;
        Ok(())
    }

    fn log_to_stderr(&self, msg: &str) -> io::Result<()> {
        let stderr = io::stderr();
        let mut handle = stderr.lock();
        handle.write_all(msg.as_bytes())?;
        handle.write_all(b"\n")?;
        handle.flush()?;
        Ok(())
    }

    fn log(&self, level: &str, msg: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S");
        let log_line = format!("[{}] {}  {}", timestamp, level, msg);
        
        // Write to file if available
        let mut guard = self.file.lock().unwrap();
        if let Some(file) = guard.as_mut() {
            let _ = file.write_all(log_line.as_bytes());
            let _ = file.write_all(b"\n");
            let _ = file.flush();
        }
        
        // In interactive mode, write to console
        if !self.daemon_mode {
            if level == "ERROR" {
                let _ = self.log_to_stderr(&log_line);
            } else {
                let _ = self.log_to_stdout(&log_line);
            }
        }
    }
}

lazy_static::lazy_static! {
    static ref LOGGER: Logger = Logger::new();
}

fn show_banner() {
    let banner = format!(
        "\
============================================
{} v{} - TCP Port Forwarder
Author: {}
Website: {}
Year: {}
============================================
",
        APP_NAME, VERSION, AUTHOR, WEBSITE, YEAR
    );
    log_info(&banner);
}

fn log_info(msg: &str) {
    LOGGER.log("INFO", msg);
}

fn log_error(msg: &str) {
    LOGGER.log("ERROR", msg);
}

fn log_warn(msg: &str) {
    LOGGER.log("WARN", msg);
}

fn log_debug(msg: &str) {
    LOGGER.log("DEBUG", msg);
}

async fn handle_connection(
    mut client_stream: TcpStream,
    client_addr: SocketAddrV4,
    dest_addr: SocketAddrV4,
    blacklist: Arc<RwLock<Blacklist>>,
    rule_idx: usize,
) -> io::Result<()> {
    let client_ip = *client_addr.ip();

    {
        let blacklist = blacklist.read().await;
        if blacklist.contains(client_ip) {
            log_warn(&format!(
                "[Rule #{}] Connection REJECTED from {} (blacklisted)",
                rule_idx, client_addr
            ));
            return Ok(());
        }
    }

    log_info(&format!(
        "[Rule #{}] New connection from {} -> {}",
        rule_idx, client_addr, dest_addr
    ));

    match TcpStream::connect(dest_addr).await {
        Ok(mut dest_stream) => {
            log_info(&format!(
                "[Rule #{}] Connected to {}, starting relay",
                rule_idx, dest_addr
            ));

            match copy_bidirectional(&mut client_stream, &mut dest_stream).await {
                Ok((from_client, from_dest)) => {
                    log_info(&format!(
                        "[Rule #{}] Connection closed: {}B client->dest, {}B dest->client",
                        rule_idx, from_client, from_dest
                    ));
                }
                Err(e) => {
                    log_error(&format!("[Rule #{}] Relay error: {}", rule_idx, e));
                }
            }
        }
        Err(e) => {
            log_error(&format!(
                "[Rule #{}] Unable to connect to {}: {}",
                rule_idx, dest_addr, e
            ));
        }
    }

    Ok(())
}

async fn reload_blacklist_task(
    blocklist_path: PathBuf,
    blacklist: Arc<RwLock<Blacklist>>,
    reload_interval: Duration,
) {
    let mut interval = time::interval(reload_interval);
    loop {
        interval.tick().await;
        log_info("Reloading blacklist...");
        match Blacklist::load_from_file(&blocklist_path) {
            Ok(new_blacklist) => {
                let mut blacklist = blacklist.write().await;
                *blacklist = new_blacklist;
                log_info("Blacklist reloaded successfully");
            }
            Err(e) => {
                log_error(&format!("Error reloading blacklist: {}", e));
            }
        }
    }
}

fn write_pid_file(pid_file: &PathBuf) -> io::Result<()> {
    let pid = std::process::id();
    let mut file = File::create(pid_file)?;
    write!(file, "{}", pid)?;
    log_info(&format!("PID {} written to {:?}", pid, pid_file));
    Ok(())
}

fn daemonize(args: &Args) -> io::Result<()> {
    // Check if already in daemon mode
    if args.daemonize {
        // Create command to relaunch
        let mut cmd = Command::new(std::env::current_exe()?);
        
        // Pass all arguments except --daemonize
        cmd.arg("--rule");
        for rule in &args.rule {
            cmd.arg(rule);
        }
        
        if let Some(blocklist) = &args.blocklist {
            cmd.arg("--blocklist");
            cmd.arg(blocklist);
        }
        
        cmd.arg("--reload-interval");
        cmd.arg(args.reload_interval.to_string());
        
        cmd.arg("--log-level");
        cmd.arg(&args.log_level);
        
        cmd.arg("--pid-file");
        cmd.arg(&args.pid_file);
        
        cmd.arg("--log-file");
        cmd.arg(&args.log_file);
        
        // Redirect stdout/stderr to log file
        let log_file = File::create(&args.log_file)?;
        cmd.stdout(log_file.try_clone()?);
        cmd.stderr(log_file);
        
        // Detach from terminal
        cmd.stdin(Stdio::null());
        
        // Launch child process
        match cmd.spawn() {
            Ok(child) => {
                println!("Daemon started with PID: {}", child.id());
                println!("Logs written to: {}", args.log_file.display());
                println!("PID file: {}", args.pid_file.display());
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("Error starting daemon: {}", e);
                std::process::exit(1);
            }
        }
    }
    
    Ok(())
}

async fn run_forwarder(rules: Vec<Rule>, blocklist_path: Option<PathBuf>, reload_interval: Duration) {
    log_info(&format!("Starting TCP forwarder with {} rule(s)", rules.len()));

    let blacklist = Arc::new(RwLock::new(if let Some(ref path) = blocklist_path {
        match Blacklist::load_from_file(path) {
            Ok(bl) => {
                log_info(&format!("Blacklist loaded from {}", path.display()));
                bl
            }
            Err(e) => {
                log_error(&format!("Error loading blacklist: {}, starting without blacklist", e));
                Blacklist::new()
            }
        }
    } else {
        Blacklist::new()
    }));

    if let Some(path) = blocklist_path {
        let blacklist_clone = blacklist.clone();
        tokio::spawn(async move {
            reload_blacklist_task(path, blacklist_clone, reload_interval).await;
        });
    }

    let mut handles = vec![];
    for (idx, rule) in rules.iter().enumerate() {
        let rule = rule.clone();
        let blacklist_clone = blacklist.clone();
        let listener = match TcpListener::bind(rule.listen).await {
            Ok(l) => {
                log_info(&format!(
                    "[Rule #{}] Listening on {} -> forwarding to {}",
                    idx, rule.listen, rule.dest
                ));
                l
            }
            Err(e) => {
                log_error(&format!(
                    "[Rule #{}] Unable to bind {}: {}",
                    idx, rule.listen, e
                ));
                continue;
            }
        };

        let handle = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let dest_addr = rule.dest;
                        let blacklist = blacklist_clone.clone();
                        let rule_idx = idx;

                        if let std::net::SocketAddr::V4(client_addr) = addr {
                            tokio::spawn(async move {
                                if let Err(e) = handle_connection(
                                    stream,
                                    client_addr,
                                    dest_addr,
                                    blacklist,
                                    rule_idx,
                                )
                                .await
                                {
                                    log_error(&format!(
                                        "[Rule #{}] Handler error: {}",
                                        rule_idx, e
                                    ));
                                }
                            });
                        } else {
                            log_warn(&format!(
                                "[Rule #{}] IPv6 connection ignored (IPv4 only)",
                                idx
                            ));
                        }
                    }
                    Err(e) => {
                        log_error(&format!("[Rule #{}] Accept error: {}", idx, e));
                    }
                }
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }
}

fn parse_rule(rule_str: &str) -> Result<Rule, String> {
    let parts: Vec<&str> = rule_str.split(':').collect();
    if parts.len() != 4 {
        return Err(format!(
            "Invalid format. Expected 'IP:PORT:DEST_IP:DEST_PORT', got '{}'",
            rule_str
        ));
    }

    let listen_ip = parts[0]
        .parse::<Ipv4Addr>()
        .map_err(|e| format!("Invalid listen IP: {}", e))?;
    let listen_port = parts[1]
        .parse::<u16>()
        .map_err(|e| format!("Invalid listen port: {}", e))?;
    let dest_ip = parts[2]
        .parse::<Ipv4Addr>()
        .map_err(|e| format!("Invalid destination IP: {}", e))?;
    let dest_port = parts[3]
        .parse::<u16>()
        .map_err(|e| format!("Invalid destination port: {}", e))?;

    Ok(Rule {
        listen: SocketAddrV4::new(listen_ip, listen_port),
        dest: SocketAddrV4::new(dest_ip, dest_port),
    })
}

#[tokio::main]
async fn main() -> io::Result<()> {
    let args = Args::parse();

    // Display banner on startup
    show_banner();

    // Daemon mode: relaunch in background
    if args.daemonize {
        daemonize(&args)?;
        // Parent process exits here
        return Ok(());
    }

    // Normal mode (daemon child or interactive)
    // Configure logger
    if args.pid_file.exists() {
        log_warn(&format!("PID file {} already exists, daemon may already be running", args.pid_file.display()));
    }
    
    // Initialize log file if necessary
    let is_daemon_child = args.log_file.exists() || true; // Simplified: child always has --log-file
    
    if is_daemon_child {
        // In daemon child mode, initialize log file
        LOGGER.init_file(&args.log_file);
    }
    
    write_pid_file(&args.pid_file)?;

    // Parse rules
    let mut rules = Vec::new();
    for rule_str in &args.rule {
        match parse_rule(rule_str) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                log_error(&e);
                std::process::exit(1);
            }
        }
    }

    if rules.is_empty() {
        log_error("No valid rules");
        std::process::exit(1);
    }

    let reload_interval = Duration::from_secs(args.reload_interval);

    log_info(&format!(
        "Blacklist reload interval: {} seconds",
        args.reload_interval
    ));

    // Clean up PID file on exit
    let pid_file = args.pid_file.clone();
    let _ = tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        log_info("Received SIGINT, shutting down daemon...");
        let _ = std::fs::remove_file(&pid_file);
        std::process::exit(0);
    });

    run_forwarder(rules, args.blocklist, reload_interval).await;

    Ok(())
}

