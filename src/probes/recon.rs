use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::{debug, error, info, warn};

use crate::executor::{check_tool_available, run_command, CommandOutput};
use crate::probe::{Probe, ProbeResult};
use crate::types::{AuditContext, AuditMode, DnsRecord, Finding, FindingKind, Severity};

// -----------------------------------------------------------------------------
// PROBE 1: WhoisProbe
// -----------------------------------------------------------------------------

pub struct WhoisProbe {
    pub target: String,
}

impl WhoisProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }

    fn parse_whois_output(&self, output: &str) -> serde_json::Value {
        let mut data = serde_json::Map::new();
        let mut nameservers: Vec<String> = Vec::new();
        let mut emails: Vec<String> = Vec::new();

        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            let (key, val) = match parts.as_slice() {
                [k, v] => (k.trim().to_lowercase(), v.trim().to_string()),
                _ => continue,
            };

            if val.is_empty() {
                continue;
            }

            match key.as_str() {
                k if k.contains("expir") => {
                    data.insert("expiry_date".to_string(), val.into());
                }
                k if k.contains("registrar") && !k.contains("url") && !k.contains("whois") => {
                    data.entry("registrar".to_string()).or_insert_with(|| val.clone().into());
                }
                k if k.contains("name server") || k == "nserver" => {
                    let ns = val.to_lowercase().trim_end_matches('.').to_string();
                    if !nameservers.contains(&ns) {
                        nameservers.push(ns);
                    }
                }
                k if k.contains("email") || k.contains("e-mail") => {
                    if val.contains('@') && !emails.contains(&val) {
                        emails.push(val);
                    }
                }
                k if k.contains("organization") || k.contains("tech org") => {
                    data.entry("organization".to_string()).or_insert_with(|| val.into());
                }
                k if k.contains("country") => {
                    data.entry("country".to_string()).or_insert_with(|| val.into());
                }
                _ => {}
            }
        }

        if !nameservers.is_empty() {
            data.insert(
                "nameservers".to_string(),
                serde_json::to_value(&nameservers).unwrap_or_default(),
            );
        }
        if !emails.is_empty() {
            data.insert(
                "emails".to_string(),
                serde_json::to_value(&emails).unwrap_or_default(),
            );
        }

        serde_json::Value::Object(data)
    }

    fn check_expiry_soon(&self, parsed: &serde_json::Value) -> bool {
        if let Some(expiry_str) = parsed.get("expiry_date").and_then(|v| v.as_str()) {
            let formats = [
                "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d",
                "%d-%b-%Y",
                "%Y/%m/%d",
            ];
            for fmt in &formats {
                if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(expiry_str, fmt) {
                    let now = chrono::Utc::now().naive_utc();
                    let diff = dt.signed_duration_since(now);
                    return diff.num_days() >= 0 && diff.num_days() < 30;
                }
                if let Ok(d) = chrono::NaiveDate::parse_from_str(expiry_str, fmt) {
                    let now = chrono::Utc::now().naive_utc().date();
                    let diff = d.signed_duration_since(now);
                    return diff.num_days() >= 0 && diff.num_days() < 30;
                }
            }
        }
        false
    }
}

#[async_trait]
impl Probe for WhoisProbe {
    fn name(&self) -> &str {
        "whois"
    }

    fn timeout_secs(&self) -> u64 {
        30
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.mode == AuditMode::Target
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("whois") {
            warn!("[-] whois not found in PATH — skipping WhoisProbe");
            return Ok(ProbeResult::skipped("whois", "whois binary not found"));
        }

        info!("[*] Running whois for {}", self.target);
        let output = run_command("whois", &[self.target.as_str()], self.timeout_secs()).await?;

        if output.stdout.trim().is_empty() {
            warn!("[-] whois returned empty output for {}", self.target);
            return Ok(ProbeResult::skipped("whois", "Empty whois response"));
        }

        let parsed = self.parse_whois_output(&output.stdout);
        debug!("[*] whois parsed data for {}: {:?}", self.target, parsed);

        let mut findings = Vec::new();

        findings.push(
            Finding::new(
                "whois",
                &self.target,
                FindingKind::DnsRecord,
                Severity::Info,
                "Whois Registration Data",
                format!(
                    "Domain registration information for {}. Registrar: {}. Expiry: {}.",
                    self.target,
                    parsed.get("registrar").and_then(|v| v.as_str()).unwrap_or("unknown"),
                    parsed.get("expiry_date").and_then(|v| v.as_str()).unwrap_or("unknown"),
                ),
                parsed.clone(),
                0.9,
            )
            .with_tags(vec!["recon".into(), "whois".into(), "dns".into()]),
        );

        if self.check_expiry_soon(&parsed) {
            let expiry = parsed
                .get("expiry_date")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            warn!("[!] Domain {} expires on {} — within 30 days!", self.target, expiry);
            findings.push(
                Finding::new(
                    "whois",
                    &self.target,
                    FindingKind::DnsRecord,
                    Severity::Medium,
                    "Domain Expiring Soon",
                    format!(
                        "Domain {} expires on {}. Risk of domain hijacking after expiry.",
                        self.target, expiry,
                    ),
                    parsed.clone(),
                    0.85,
                )
                .with_tags(vec!["recon".into(), "whois".into(), "expiry".into()]),
            );
        }

        if let Some(emails) = parsed.get("emails").and_then(|v| v.as_array()) {
            for email in emails {
                if let Some(e) = email.as_str() {
                    info!("[+] Email found in whois: {}", e);
                }
            }
        }

        if let Some(ns_arr) = parsed.get("nameservers").and_then(|v| v.as_array()) {
            for ns in ns_arr {
                if let Some(ns_str) = ns.as_str() {
                    findings.push(
                        Finding::new(
                            "whois",
                            &self.target,
                            FindingKind::DnsRecord,
                            Severity::Info,
                            format!("Nameserver: {}", ns_str),
                            format!(
                                "Authoritative nameserver for {}: {}",
                                self.target, ns_str
                            ),
                            serde_json::json!({ "nameserver": ns_str }),
                            0.95,
                        )
                        .with_tags(vec!["recon".into(), "ns".into(), "dns".into()]),
                    );
                }
            }
        }

        info!("[+] WhoisProbe produced {} findings for {}", findings.len(), self.target);
        Ok(ProbeResult::success("whois", findings))
    }
}

// -----------------------------------------------------------------------------
// PROBE 2: DigProbe
// -----------------------------------------------------------------------------

pub struct DigProbe {
    pub target: String,
}

impl DigProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }

    fn parse_dig_line(line: &str) -> Option<DnsRecord> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            return None;
        }

        if parts[0].starts_with(';') {
            return None;
        }

        let name = parts[0].trim_end_matches('.').to_string();
        let ttl: Option<u32> = parts[1].parse().ok();
        let record_type = parts[3].to_uppercase();
        let value = parts[4..].join(" ");

        Some(DnsRecord {
            record_type,
            name,
            value,
            ttl,
        })
    }

    fn collect_records_from_output(output: &str) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        for line in output.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with(';') {
                continue;
            }
            if let Some(rec) = Self::parse_dig_line(line) {
                records.push(rec);
            }
        }
        records
    }
}

#[async_trait]
impl Probe for DigProbe {
    fn name(&self) -> &str {
        "dig"
    }

    fn timeout_secs(&self) -> u64 {
        20
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.mode == AuditMode::Target
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("dig") {
            warn!("[-] dig not found in PATH — skipping DigProbe");
            return Ok(ProbeResult::skipped("dig", "dig binary not found"));
        }

        info!("[*] Running DigProbe for {}", self.target);
        let mut all_records: Vec<DnsRecord> = Vec::new();
        let mut findings: Vec<Finding> = Vec::new();

        // 1. ANY record
        {
            let out = run_command(
                "dig",
                &["+noall", "+answer", "+short", self.target.as_str(), "ANY"],
                self.timeout_secs(),
            )
            .await
            .unwrap_or_else(|e| {
                warn!("[-] dig ANY failed: {}", e);
                CommandOutput { stdout: String::new(), stderr: String::new(), exit_code: -1 }
            });
            all_records.extend(Self::collect_records_from_output(&out.stdout));
        }

        // 2. Targeted record types
        for &rtype in &["A", "AAAA", "MX", "TXT", "NS", "SOA"] {
            let out = run_command(
                "dig",
                &["+noall", "+answer", self.target.as_str(), rtype],
                self.timeout_secs(),
            )
            .await
            .unwrap_or_else(|e| {
                warn!("[-] dig {} failed: {}", rtype, e);
                CommandOutput { stdout: String::new(), stderr: String::new(), exit_code: -1 }
            });
            all_records.extend(Self::collect_records_from_output(&out.stdout));
        }

        all_records.dedup_by(|a, b| {
            a.name == b.name && a.record_type == b.record_type && a.value == b.value
        });

        let mut resolved_ips = Vec::new();
        for r in &all_records {
            if r.record_type == "A" || r.record_type == "AAAA" {
                if !resolved_ips.contains(&r.value) {
                    resolved_ips.push(r.value.clone());
                }
            }
        }

        let txt_records: Vec<&DnsRecord> = all_records
            .iter()
            .filter(|r| r.record_type == "TXT")
            .collect();

        let has_spf = txt_records.iter().any(|r| r.value.contains("v=spf1"));
        let has_dmarc = txt_records
            .iter()
            .any(|r| r.name.contains("_dmarc") || r.value.contains("v=DMARC1"));

        if !has_spf {
            warn!("[-] No SPF record found for {}", self.target);
            findings.push(
                Finding::new(
                    "dig",
                    &self.target,
                    FindingKind::DnsRecord,
                    Severity::Medium,
                    "Missing SPF Record",
                    format!(
                        "No SPF TXT record found for {}. Domain is susceptible to email spoofing.",
                        self.target
                    ),
                    serde_json::json!({ "check": "spf", "domain": self.target }),
                    0.9,
                )
                .with_tags(vec!["recon".into(), "dns".into(), "email-security".into(), "spf".into()]),
            );
        }

        if !has_dmarc {
            warn!("[-] No DMARC record found for {}", self.target);
            findings.push(
                Finding::new(
                    "dig",
                    &self.target,
                    FindingKind::DnsRecord,
                    Severity::Medium,
                    "Missing DMARC Record",
                    format!(
                        "No DMARC policy found for {}. Without DMARC, spoofed emails may reach recipients.",
                        self.target
                    ),
                    serde_json::json!({ "check": "dmarc", "domain": self.target }),
                    0.9,
                )
                .with_tags(vec!["recon".into(), "dns".into(), "email-security".into(), "dmarc".into()]),
            );
        }

        for rec in &all_records {
            findings.push(
                Finding::new(
                    "dig",
                    &self.target,
                    FindingKind::DnsRecord,
                    Severity::Info,
                    format!("{} DNS Record: {}", rec.record_type, rec.name),
                    format!(
                        "{} record for {}: {} (TTL: {})",
                        rec.record_type,
                        rec.name,
                        rec.value,
                        rec.ttl.map(|t| t.to_string()).unwrap_or_else(|| "?".into())
                    ),
                    serde_json::to_value(rec).unwrap_or(serde_json::Value::Null),
                    0.95,
                )
                .with_tags(vec!["recon".into(), "dns".into(), rec.record_type.to_lowercase()]),
            );
        }

        // Zone transfer attempt (AXFR)
        let first_ns = all_records
            .iter()
            .find(|r| r.record_type == "NS")
            .map(|r| r.value.trim_end_matches('.').to_string());

        if let Some(ns) = first_ns {
            info!("[*] Attempting AXFR zone transfer via NS: {}", ns);
            let ns_server_arg = format!("@{}", ns);
            let axfr_out = run_command(
                "dig",
                &[ns_server_arg.as_str(), self.target.as_str(), "AXFR"],
                self.timeout_secs(),
            )
            .await
            .unwrap_or_else(|e| {
                warn!("[-] AXFR attempt failed: {}", e);
                CommandOutput { stdout: String::new(), stderr: String::new(), exit_code: -1 }
            });

            let axfr_records = Self::collect_records_from_output(&axfr_out.stdout);
            let transfer_succeeded = !axfr_records.is_empty()
                && !axfr_out.stdout.contains("Transfer failed")
                && !axfr_out.stdout.contains("REFUSED")
                && axfr_out.exit_code == 0;

            if transfer_succeeded {
                error!(
                    "[CRITICAL] Zone transfer (AXFR) succeeded for {} via {}! {} records exposed.",
                    self.target,
                    ns,
                    axfr_records.len()
                );
                findings.push(
                    Finding::new(
                        "dig",
                        &self.target,
                        FindingKind::ZoneTransfer,
                        Severity::Critical,
                        "DNS Zone Transfer Allowed (AXFR)",
                        format!(
                            "Zone transfer succeeded for {} via nameserver {}. {} DNS records were exposed. \
                             This allows an attacker to enumerate all subdomains and internal hosts.",
                            self.target,
                            ns,
                            axfr_records.len()
                        ),
                        serde_json::json!({
                            "nameserver": ns,
                            "record_count": axfr_records.len(),
                            "records": axfr_records.iter()
                                .map(|r| serde_json::json!({
                                    "type": r.record_type,
                                    "name": r.name,
                                    "value": r.value,
                                    "ttl": r.ttl
                                }))
                                .collect::<Vec<_>>()
                        }),
                        1.0,
                    )
                    .with_tags(vec![
                        "recon".into(),
                        "dns".into(),
                        "zone-transfer".into(),
                        "critical".into(),
                    ]),
                );
            } else {
                info!("[*] AXFR refused or empty for {} via {}", self.target, ns);
            }
        }

        info!("[+] DigProbe produced {} findings for {}", findings.len(), self.target);
        Ok(
            ProbeResult::success("dig", findings)
                .with_dns_records(all_records)
                .with_resolved_ips(resolved_ips),
        )
    }
}

// -----------------------------------------------------------------------------
// PROBE 3: TracerouteProbe
// -----------------------------------------------------------------------------

pub struct TracerouteProbe {
    pub target: String,
}

impl TracerouteProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }

    fn parse_hop_line(line: &str, is_windows: bool) -> Option<(u32, Vec<String>)> {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            return None;
        }

        if is_windows {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }
            let hop: u32 = parts[0].parse().ok()?;
            let ips: Vec<String> = parts
                .iter()
                .filter(|&&p| {
                    p.parse::<std::net::Ipv4Addr>().is_ok() || p.parse::<std::net::Ipv6Addr>().is_ok()
                })
                .map(|&p| p.to_string())
                .collect();
            Some((hop, ips))
        } else {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.is_empty() {
                return None;
            }
            let hop: u32 = parts[0].parse().ok()?;
            let ips: Vec<String> = parts
                .iter()
                .filter(|&&p| {
                    let clean = p.trim_matches('(').trim_matches(')');
                    clean.parse::<std::net::Ipv4Addr>().is_ok()
                        || clean.parse::<std::net::Ipv6Addr>().is_ok()
                })
                .map(|&p| p.trim_matches('(').trim_matches(')').to_string())
                .collect();
            Some((hop, ips))
        }
    }
}

#[async_trait]
impl Probe for TracerouteProbe {
    fn name(&self) -> &str {
        "traceroute"
    }

    fn timeout_secs(&self) -> u64 {
        90
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.mode == AuditMode::Target
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        let is_windows = cfg!(target_os = "windows");

        let (program, args): (&str, Vec<&str>) = if is_windows {
            ("tracert", vec!["-d", "-h", "30", "-w", "2000", self.target.as_str()])
        } else {
            ("traceroute", vec!["-n", "-q", "2", "-w", "2", self.target.as_str()])
        };

        let tool_name = if is_windows { "tracert" } else { "traceroute" };
        if !check_tool_available(tool_name) {
            warn!("[-] {} not found in PATH — skipping TracerouteProbe", tool_name);
            return Ok(ProbeResult::skipped("traceroute", "traceroute binary not found"));
        }

        info!("[*] Running {} for {}", tool_name, self.target);
        let output = run_command(program, &args, self.timeout_secs()).await?;

        if output.stdout.trim().is_empty() {
            warn!("[-] traceroute returned empty output for {}", self.target);
            return Ok(ProbeResult::skipped("traceroute", "empty output received"));
        }

        let mut hops: Vec<serde_json::Value> = Vec::new();
        for line in output.stdout.lines() {
            if let Some((hop_num, ips)) = Self::parse_hop_line(line, is_windows) {
                debug!("[*] Hop {}: {:?}", hop_num, ips);
                hops.push(serde_json::json!({
                    "hop": hop_num,
                    "ips": ips,
                }));
            }
        }

        if hops.is_empty() {
            info!("[*] No traceroute hops parsed for {}", self.target);
            return Ok(ProbeResult::skipped("traceroute", "No hops resolved"));
        }

        info!(
            "[+] TracerouteProbe mapped {} hops to {}",
            hops.len(),
            self.target
        );

        let finding = Finding::new(
            "traceroute",
            &self.target,
            FindingKind::NetworkHost,
            Severity::Info,
            format!("Network Path to {}", self.target),
            format!(
                "Network route to {} traverses {} hops. Intermediate infrastructure mapped.",
                self.target,
                hops.len()
            ),
            serde_json::json!({
                "target": self.target,
                "hop_count": hops.len(),
                "path": hops,
                "raw_output": output.stdout,
            }),
            0.85,
        )
        .with_tags(vec!["recon".into(), "traceroute".into(), "network".into()]);

        Ok(ProbeResult::success("traceroute", vec![finding]))
    }
}

// -----------------------------------------------------------------------------
// PROBE 4: FierceProbe
// -----------------------------------------------------------------------------

pub struct FierceProbe {
    pub target: String,
}

impl FierceProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }

    fn parse_fierce_line(line: &str, target: &str) -> Option<(String, Option<String>)> {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("---")
            || trimmed.starts_with("Looking")
            || trimmed.starts_with("Testing")
            || trimmed.starts_with("Now")
            || trimmed.starts_with("Found")
        {
            return None;
        }

        let parts: Vec<&str> = trimmed.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }

        for (i, &token) in parts.iter().enumerate() {
            let clean = token.trim_end_matches('.');
            if clean.ends_with(target) && clean != target {
                let ip = parts.get(i + 1).and_then(|&next| {
                    if next.parse::<std::net::Ipv4Addr>().is_ok()
                        || next.parse::<std::net::Ipv6Addr>().is_ok()
                    {
                        Some(next.to_string())
                    } else {
                        None
                    }
                });
                return Some((clean.to_string(), ip));
            }
        }
        None
    }
}

#[async_trait]
impl Probe for FierceProbe {
    fn name(&self) -> &str {
        "fierce"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.mode == AuditMode::Target
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("fierce") {
            warn!("[-] fierce not found in PATH — skipping FierceProbe");
            return Ok(ProbeResult::skipped("fierce", "fierce binary not found"));
        }

        info!("[*] Running fierce subdomain enum for {}", self.target);
        let output = run_command(
            "fierce",
            &[
                "--domain",
                self.target.as_str(),
                "--threads",
                "10",
                "--dns-servers",
                "8.8.8.8",
            ],
            self.timeout_secs(),
        )
        .await?;

        if output.stdout.trim().is_empty() && output.stderr.trim().is_empty() {
            warn!("[-] fierce returned empty output for {}", self.target);
            return Ok(ProbeResult::skipped("fierce", "empty output received"));
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut discovered: HashMap<String, Option<String>> = HashMap::new();
        let mut discovered_subdomains = Vec::new();

        for line in output.stdout.lines().chain(output.stderr.lines()) {
            if let Some((subdomain, ip)) = Self::parse_fierce_line(line, &self.target) {
                if discovered.contains_key(&subdomain) {
                    continue;
                }
                info!("[+] Fierce found subdomain: {} {:?}", subdomain, ip);
                discovered.insert(subdomain.clone(), ip.clone());
                discovered_subdomains.push(subdomain.clone());

                findings.push(
                    Finding::new(
                        "fierce",
                        &self.target,
                        FindingKind::Subdomain,
                        Severity::Info,
                        format!("Subdomain Discovered: {}", subdomain),
                        format!(
                            "Discovered active subdomain {} via Fierce DNS enumeration (IP: {}).",
                            subdomain,
                            ip.as_deref().unwrap_or("unresolved")
                        ),
                        serde_json::json!({
                            "subdomain": subdomain,
                            "ip": ip,
                            "target": self.target,
                        }),
                        0.9,
                    )
                    .with_tags(vec!["recon".into(), "subdomain".into(), "fierce".into()]),
                );
            }
        }

        info!("[+] Fierce discovered {} subdomains", discovered_subdomains.len());
        Ok(ProbeResult::success("fierce", findings).with_subdomains(discovered_subdomains))
    }
}

// -----------------------------------------------------------------------------
// PROBE 5: WafDetectProbe (wafw00f)
// -----------------------------------------------------------------------------

pub struct WafDetectProbe {
    pub target: String,
}

impl WafDetectProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }

    fn parse_wafw00f_json(output: &str) -> Vec<WafEntry> {
        let cleaned = output.trim();
        if let Ok(entries) = serde_json::from_str::<Vec<WafEntry>>(cleaned) {
            return entries;
        }

        if let (Some(start), Some(end)) = (cleaned.find('['), cleaned.rfind(']')) {
            if start < end {
                let json_slice = &cleaned[start..=end];
                if let Ok(entries) = serde_json::from_str::<Vec<WafEntry>>(json_slice) {
                    return entries;
                }
            }
        }

        if let (Some(start), Some(end)) = (cleaned.find('{'), cleaned.rfind('}')) {
            if start < end {
                let json_slice = &cleaned[start..=end];
                if let Ok(single) = serde_json::from_str::<WafEntry>(json_slice) {
                    return vec![single];
                }
            }
        }

        Vec::new()
    }
}

#[derive(Debug, serde::Deserialize)]
struct WafEntry {
    url: String,
    detected: bool,
    firewall: Option<String>,
    manufacturer: Option<String>,
}

#[async_trait]
impl Probe for WafDetectProbe {
    fn name(&self) -> &str {
        "wafw00f"
    }

    fn timeout_secs(&self) -> u64 {
        60
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.mode == AuditMode::Target
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("wafw00f") {
            warn!("[-] wafw00f not found in PATH — skipping WafDetectProbe");
            return Ok(ProbeResult::skipped("wafw00f", "wafw00f binary not found"));
        }

        let target_url = ctx.get_url();
        info!("[*] Running wafw00f against {}", target_url);

        let output = run_command(
            "wafw00f",
            &["-a", "-f", "json", target_url.as_str()],
            self.timeout_secs(),
        )
        .await?;

        let combined_output = format!("{}\n{}", output.stdout, output.stderr);
        if combined_output.trim().is_empty() {
            warn!("[-] wafw00f returned empty output for {}", target_url);
            return Ok(ProbeResult::skipped("wafw00f", "empty output received"));
        }

        let entries = Self::parse_wafw00f_json(&combined_output);
        if entries.is_empty() {
            warn!("[-] Could not parse any WAF entries from wafw00f output");
            return Ok(ProbeResult::skipped("wafw00f", "Failed to parse json"));
        }

        let mut findings: Vec<Finding> = Vec::new();
        let mut waf_detected = false;
        let mut waf_name = None;

        for entry in &entries {
            if entry.detected {
                let firewall_name = entry
                    .firewall
                    .as_deref()
                    .unwrap_or("Unknown WAF");
                let manufacturer = entry
                    .manufacturer
                    .as_deref()
                    .unwrap_or("Unknown");

                info!("[!] WAF detected: {} (by {})", firewall_name, manufacturer);
                waf_detected = true;
                waf_name = Some(firewall_name.to_string());

                findings.push(
                    Finding::new(
                        "wafw00f",
                        &self.target,
                        FindingKind::WafDetected,
                        Severity::Medium,
                        format!("WAF Detected: {}", firewall_name),
                        format!(
                            "A Web Application Firewall ({}, by {}) was detected in front of {}. \
                             Exploitation may require WAF evasion techniques.",
                            firewall_name, manufacturer, entry.url
                        ),
                        serde_json::json!({
                            "url": entry.url,
                            "detected": true,
                            "firewall": firewall_name,
                            "manufacturer": manufacturer,
                        }),
                        0.9,
                    )
                    .with_tags(vec![
                        "recon".into(),
                        "waf".into(),
                        firewall_name.to_lowercase().replace(' ', "-"),
                    ]),
                );
            } else {
                info!("[*] No WAF detected for {}", entry.url);
                findings.push(
                    Finding::new(
                        "wafw00f",
                        &self.target,
                        FindingKind::WafDetected,
                        Severity::Info,
                        "No WAF Detected",
                        format!(
                            "wafw00f found no WAF protecting {}. Direct exploitation attempts \
                             may not be filtered.",
                            entry.url
                        ),
                        serde_json::json!({
                            "url": entry.url,
                            "detected": false,
                            "firewall": null,
                            "manufacturer": null,
                        }),
                        0.75,
                    )
                    .with_tags(vec!["recon".into(), "waf".into(), "no-waf".into()]),
                );
            }
        }

        info!(
            "[+] WafDetectProbe produced {} findings for {}",
            findings.len(),
            self.target
        );
        Ok(ProbeResult::success("wafw00f", findings).with_waf(waf_detected, waf_name))
    }
}
