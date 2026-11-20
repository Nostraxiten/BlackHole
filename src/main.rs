use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

mod types;
mod probe;
mod executor;
mod network;
mod output;
mod probes;
mod deps;
pub mod cve;

use types::{AuditContext, AuditMode, Finding, Severity};
use probe::{Probe, ProbeResult};
use output::evidence_store::EvidenceStore;
use output::report::ReportGenerator;

#[derive(Parser, Debug)]
#[command(
    name = "blackhole",
    author = "BlackHole Offensive Security Core Team",
    version,
    about = "BlackHole - Advanced Offensive Reconnaissance and Attack Surface Orchestrator",
    long_about = "BlackHole orchestrates industry-standard offensive security binaries \
                  into an asynchronous DAG engine. Features multi-stage dependency barriers, \
                  zero-overhead XML/JSON stream parsing, and an append-only JSONL evidence store.\n\n\
                  MODES:\n  \
                  blackhole <TARGET>                  [External audit against domain or IP]\n  \
                  blackhole local [SUBNET]            [Internal LAN audit with RFC1918 enforcement]"
)]
struct Cli {
    /// Target domain or IP for external audit, or 'local' to initiate internal LAN discovery
    #[arg(value_name = "TARGET_OR_COMMAND")]
    target: String,

    /// Optional specific local subnet or IP when in 'local' mode (e.g. 192.168.1.0/24)
    #[arg(value_name = "SUBNET")]
    subnet: Option<String>,

    /// Directory path for persisted evidence (JSONL) and final audit reports
    #[arg(short, long, default_value = "./blackhole_output")]
    output: String,

    /// Custom wordlist file path for web fuzzing (falls back to embedded wordlist)
    #[arg(short, long)]
    wordlist: Option<String>,

    /// Proxy URL for evasive operations (e.g. socks5://127.0.0.1:9050 or http://127.0.0.1:8080)
    #[arg(short, long)]
    proxy: Option<String>,

    /// Path to external Kaisen vulnerability database file (JSON or SQLite)
    #[arg(long)]
    kaisen_db: Option<String>,

    /// Download and update official NVD CVE JSON feed before scanning
    #[arg(long)]
    update_db: bool,

    /// Maximum concurrent probe executions (global semaphore permits)
    #[arg(short, long, default_value_t = 8)]
    concurrency: usize,

    /// Enable verbose debug logging output
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Security Guardian: verify root project directory
    let cwd = std::env::current_dir().unwrap_or_default();
    let has_cargo = cwd.join("Cargo.toml").is_file();
    let has_src = cwd.join("src").is_dir();
    if !has_cargo || !has_src {
        eprintln!(
            "{}",
            "[!] SECURITY ABORT: BlackHole must be executed from its root project directory (Kali Linux required)."
                .red()
                .bold()
        );
        std::process::exit(1);
    }

    // Dependency verification and automatic installer
    deps::check_and_install_dependencies();

    let cli = Cli::parse();

    let filter = if cli.verbose {
        EnvFilter::new("blackhole=debug,info")
    } else {
        EnvFilter::new("blackhole=info,warn,error")
    };

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();

    info!("============================================================");
    info!("[*] BLACKHOLE - OFFENSIVE RECON & ATTACK SURFACE ORCHESTRATOR");
    info!("============================================================");

    if cli.update_db {
        info!("[*] Fetching official National Vulnerability Database (NVD) feeds...");
        if let Err(e) = cve::update_nvd_feed().await {
            warn!("[-] NVD feed update failed: {}. Continuing with cached/builtin database.", e);
        }
    }

    let (mode, resolved_target) = if cli.target.eq_ignore_ascii_case("local") {
        let target = match cli.subnet {
            Some(explicit_subnet) => {
                info!("[+] Local mode: specified target/subnet: {}", explicit_subnet);
                explicit_subnet
            }
            None => {
                info!("[*] Local mode: auto-discovering active local network interface...");
                let discovered = network::discover_local_subnet()?;
                info!("[+] Discovered active LAN CIDR: {}", discovered);
                discovered
            }
        };

        network::validate_local_target(&target)?;
        (AuditMode::Local, target)
    } else {
        let external_target = cli.target.trim().to_string();
        info!("[+] Target mode: external assessment against '{}'", external_target);
        (AuditMode::Target, external_target)
    };

    let mut ctx = AuditContext::new(mode, &resolved_target, &cli.output);
    if let Some(ref wl) = cli.wordlist {
        ctx.wordlist_path = Some(wl.clone());
    }
    if let Some(ref prx) = cli.proxy {
        info!("[*] Configured routing proxy: {}", prx);
        ctx.proxy = Some(prx.clone());
    }
    if let Some(ref kdb) = cli.kaisen_db {
        info!("[*] Configured external Kaisen database: {}", kdb);
        ctx.kaisen_db_path = Some(kdb.clone());
    }

    let session_id = ctx.session_id.to_string();
    info!("[*] Session ID: {}", session_id);
    info!("[*] Audit Mode: {:?}", ctx.mode);
    info!("[*] Active Target: {}", ctx.target);
    info!("[*] Concurrency Limit: {} simultaneous permits", cli.concurrency);

    let mut store = EvidenceStore::new(&cli.output, &session_id).await?;

    let ctx_arc = Arc::new(RwLock::new(ctx));
    let semaphore = Arc::new(Semaphore::new(cli.concurrency));
    let mut all_findings: Vec<Finding> = Vec::new();

    // =========================================================================
    // DAG STAGE 1: Fast Perimeter Sweep & Subdomain Reconnaissance
    // =========================================================================
    info!("[*] [DAG STAGE 1] Initiating concurrent perimeter sweep and recon...");
    let mut stage1_probes: Vec<Arc<dyn Probe>> = Vec::new();
    {
        let c = ctx_arc.read().await;
        if c.mode == AuditMode::Target {
            stage1_probes.push(Arc::new(probes::subfinder::SubfinderProbe::new(c.target.clone())));
            stage1_probes.push(Arc::new(probes::recon::WhoisProbe::new(c.target.clone())));
            stage1_probes.push(Arc::new(probes::recon::WafDetectProbe::new(c.target.clone())));
            stage1_probes.push(Arc::new(probes::recon::TracerouteProbe::new(c.target.clone())));
            stage1_probes.push(Arc::new(probes::masscan::MasscanProbe::new(c.target.clone())));
        } else {
            stage1_probes.push(Arc::new(probes::network::ArpScanProbe::new(c.target.clone())));
        }
    }
    execute_probe_stage(stage1_probes, ctx_arc.clone(), &semaphore, &mut store, &mut all_findings).await?;

    // =========================================================================
    // DAG STAGE 2: High-Density DNS Resolution & Zone Transfer Probing
    // =========================================================================
    info!("[*] [DAG STAGE 2] Resolving discovered hosts and auditing DNS infrastructure...");
    let mut stage2_probes: Vec<Arc<dyn Probe>> = Vec::new();
    {
        let c = ctx_arc.read().await;
        if c.mode == AuditMode::Target {
            stage2_probes.push(Arc::new(probes::dnsx::DnsxProbe::new(c.target.clone())));
            stage2_probes.push(Arc::new(probes::recon::DigProbe::new(c.target.clone())));
        }
    }
    if !stage2_probes.is_empty() {
        execute_probe_stage(stage2_probes, ctx_arc.clone(), &semaphore, &mut store, &mut all_findings).await?;
    }

    // =========================================================================
    // DAG STAGE 3: Port Enumeration, Deep Service Fingerprinting & Netcat Scalpel
    // =========================================================================
    info!("[*] [DAG STAGE 3] Port scanning and service version fingerprinting...");
    let has_open_ports = { ctx_arc.read().await.open_ports.len() > 0 };
    if !has_open_ports {
        let target = { ctx_arc.read().await.target.clone() };
        let disc_probe: Vec<Arc<dyn Probe>> = vec![Arc::new(probes::network::NmapDiscoveryProbe::new(target))];
        execute_probe_stage(disc_probe, ctx_arc.clone(), &semaphore, &mut store, &mut all_findings).await?;
    }

    let mut stage3_probes: Vec<Arc<dyn Probe>> = Vec::new();
    {
        let c = ctx_arc.read().await;
        stage3_probes.push(Arc::new(probes::network::NmapServicesProbe::new(c.target.clone())));
        stage3_probes.push(Arc::new(probes::network::TestSslProbe::new(c.target.clone())));
    }
    execute_probe_stage(stage3_probes, ctx_arc.clone(), &semaphore, &mut store, &mut all_findings).await?;

    // =========================================================================
    // DAG STAGE 4: Web Probing & Technology Detection
    // =========================================================================
    info!("[*] [DAG STAGE 4] Auditing active web endpoints and technology stacks...");
    let mut stage4_probes: Vec<Arc<dyn Probe>> = Vec::new();
    {
        let c = ctx_arc.read().await;
        stage4_probes.push(Arc::new(probes::web::HttpxProbe::new(c.target.clone())));
        stage4_probes.push(Arc::new(probes::web::CurlHeadersProbe::new(c.target.clone())));
    }
    execute_probe_stage(stage4_probes, ctx_arc.clone(), &semaphore, &mut store, &mut all_findings).await?;

    // =========================================================================
    // DAG STAGE 5: Evasive Directory Fuzzing & Web Misconfigurations
    // =========================================================================
    info!("[*] [DAG STAGE 5] Directory fuzzing with adaptive WAF evasion...");
    let mut stage5_probes: Vec<Arc<dyn Probe>> = Vec::new();
    {
        let c = ctx_arc.read().await;
        stage5_probes.push(Arc::new(probes::web::FfufProbe::new(c.target.clone())));
        stage5_probes.push(Arc::new(probes::web::NiktoProbe::new(c.target.clone())));
    }
    execute_probe_stage(stage5_probes, ctx_arc.clone(), &semaphore, &mut store, &mut all_findings).await?;

    // =========================================================================
    // DAG STAGE 6: Vulnerability Probing & Hybrid CVE Engine Matching
    // =========================================================================
    info!("[*] [DAG STAGE 6] Vulnerability auditing and hybrid CVE correlation...");
    let mut stage6_probes: Vec<Arc<dyn Probe>> = Vec::new();
    {
        let c = ctx_arc.read().await;
        stage6_probes.push(Arc::new(probes::vuln::NucleiProbe::new(c.target.clone())));
        stage6_probes.push(Arc::new(probes::vuln::CveMatcher::new(c.target.clone())));
        if c.mode == AuditMode::Local {
            stage6_probes.push(Arc::new(probes::vuln::Enum4linuxProbe::new(c.target.clone())));
            stage6_probes.push(Arc::new(probes::vuln::NetExecProbe::new(c.target.clone())));
        }
    }
    execute_probe_stage(stage6_probes, ctx_arc.clone(), &semaphore, &mut store, &mut all_findings).await?;

    // Finalize evidence store before report compilation
    store.finalize().await?;

    // Generate technical assessment report
    info!("[*] Compiling executive summary and technical Markdown report...");
    let audit_mode_str = match ctx_arc.read().await.mode {
        AuditMode::Target => "External Target Audit",
        AuditMode::Local => "Internal LAN Audit",
    };
    let reporter = ReportGenerator::new(&cli.output, &session_id);
    reporter.generate(&all_findings, &resolved_target, Some(audit_mode_str))?;

    info!("============================================================");
    info!("[+] Assessment completed successfully.");
    info!("[*] Total findings identified: {}", all_findings.len());
    info!("[*] Artifacts location: {}", cli.output);

    let critical = all_findings.iter().filter(|f| f.severity == Severity::Critical).count();
    let high = all_findings.iter().filter(|f| f.severity == Severity::High).count();
    let medium = all_findings.iter().filter(|f| f.severity == Severity::Medium).count();
    let low = all_findings.iter().filter(|f| f.severity == Severity::Low).count();
    let info_count = all_findings.iter().filter(|f| f.severity == Severity::Info).count();

    if critical > 0 {
        error!("[CRITICAL] Identifiers discovered: {}", critical);
    }
    if high > 0 {
        warn!("[HIGH] Identifiers discovered: {}", high);
    }
    info!(
        "[*] Metrics: Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
        critical, high, medium, low, info_count
    );
    info!("============================================================");

    Ok(())
}

/// Executes independent probes concurrently inside a Tokio JoinSet.
/// Each probe takes a shared read snapshot of the context and returns a ProbeResult.
/// As probes complete, the barrier safely merges their mutations into the global AuditContext.
async fn execute_probe_stage(
    probes: Vec<Arc<dyn Probe>>,
    ctx_arc: Arc<RwLock<AuditContext>>,
    semaphore: &Arc<Semaphore>,
    store: &mut EvidenceStore,
    all_findings: &mut Vec<Finding>,
) -> Result<()> {
    let mut join_set: JoinSet<Result<ProbeResult>> = JoinSet::new();

    let ctx_snapshot = {
        let c = ctx_arc.read().await;
        Arc::new(c.clone())
    };

    for probe in probes {
        if !probe.is_applicable(&ctx_snapshot) {
            info!("  [-] Skipping probe '{}' (inapplicable for context)", probe.name());
            continue;
        }

        let p = probe.clone();
        let sem = semaphore.clone();
        let ctx_ref = ctx_snapshot.clone();

        join_set.spawn(async move {
            let _permit = sem.acquire().await.map_err(|e| anyhow::anyhow!("Semaphore acquire error: {}", e))?;
            info!("  [>] Executing probe: [{}]", p.name());

            match p.run(&ctx_ref).await {
                Ok(result) => Ok(result),
                Err(e) => {
                    warn!("  [!] Probe [{}] reported error: {}", p.name(), e);
                    Ok(ProbeResult::failed(p.name(), e.to_string()))
                }
            }
        });
    }

    while let Some(res) = join_set.join_next().await {
        match res {
            Ok(Ok(probe_result)) => {
                let count = probe_result.findings.len();
                info!(
                    "  [+] Probe [{}] finished: {} (findings: {})",
                    probe_result.probe_name, probe_result.status, count
                );
                if count > 0 {
                    store.append_many(&probe_result.findings)?;
                    all_findings.extend(probe_result.findings.clone());
                }
                // Atomically merge all discovered ports, subdomains, IPs into the global context
                let mut c = ctx_arc.write().await;
                c.apply_probe_result(probe_result);
            }
            Ok(Err(e)) => {
                warn!("[-] Task internal execution failure: {}", e);
            }
            Err(join_err) => {
                error!("[-] Task panicked inside JoinSet runtime: {}", join_err);
            }
        }
    }

    Ok(())
}
