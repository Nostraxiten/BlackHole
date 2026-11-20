use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use quick_xml::events::{BytesStart, Event};
use quick_xml::reader::Reader;
use std::io::Cursor;
use tempfile::NamedTempFile;
use tracing::{debug, info, warn};

use crate::executor::{check_tool_available, run_command};
use crate::probe::{Probe, ProbeResult};
use crate::types::{
    AuditContext, AuditMode, Finding, FindingKind,
    NmapScript, PortInfo, PortState, Severity, TlsInfo, TlsVuln,
};

fn clean_target_host(target: &str) -> &str {
    let t = target
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let t = t.split('/').next().unwrap_or(t);
    t.trim()
}

fn host_without_port(target: &str) -> &str {
    let host = clean_target_host(target);
    if let Some((h, _)) = host.rsplit_once(':') {
        if !h.contains(':') || (h.starts_with('[') && h.ends_with(']')) {
            return h.trim_matches('[').trim_matches(']');
        }
    }
    host
}

fn get_attribute(e: &BytesStart, key: &[u8]) -> Option<String> {
    for attr in e.attributes().flatten() {
        if attr.key.as_ref() == key {
            let val = attr
                .unescape_value()
                .map(|v| v.to_string())
                .unwrap_or_else(|_| String::from_utf8_lossy(&attr.value).to_string());
            return Some(val);
        }
    }
    None
}

fn handle_state_element(e: &BytesStart, current_port: &mut Option<PortInfo>) {
    if let Some(ref mut p) = current_port {
        if let Some(state_str) = get_attribute(e, b"state") {
            p.state = match state_str.as_str() {
                "open" => PortState::Open,
                "closed" => PortState::Closed,
                "filtered" => PortState::Filtered,
                "open|filtered" | "unfiltered" => PortState::OpenFiltered,
                _ => PortState::Closed,
            };
        }
    }
}

fn handle_service_element(e: &BytesStart, current_port: &mut Option<PortInfo>) {
    if let Some(ref mut p) = current_port {
        if let Some(name) = get_attribute(e, b"name") {
            p.service = Some(name);
        }
        if let Some(product) = get_attribute(e, b"product") {
            p.product = Some(product);
        }
        if let Some(version) = get_attribute(e, b"version") {
            p.version = Some(version);
        }
        if let Some(extrainfo) = get_attribute(e, b"extrainfo") {
            p.extra_info = Some(extrainfo);
        }
    }
}

pub fn parse_nmap_xml(xml: &str) -> Result<Vec<PortInfo>> {
    let trimmed = xml.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("Nmap XML output is empty"));
    }

    let mut reader = Reader::from_reader(Cursor::new(trimmed.as_bytes()));
    let mut buf = Vec::new();

    let mut found_nmaprun = false;
    let mut ports: Vec<PortInfo> = Vec::new();
    let mut current_port: Option<PortInfo> = None;
    let mut in_cpe = false;
    let mut current_cpe = String::new();
    let mut current_script: Option<NmapScript> = None;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                match e.name().as_ref() {
                    b"nmaprun" => {
                        found_nmaprun = true;
                    }
                    b"port" => {
                        let proto = get_attribute(e, b"protocol").unwrap_or_else(|| "tcp".to_string());
                        if let Some(portid) = get_attribute(e, b"portid").and_then(|p| p.parse::<u16>().ok()) {
                            current_port = Some(PortInfo {
                                port: portid,
                                protocol: proto,
                                state: PortState::Closed,
                                service: None,
                                version: None,
                                product: None,
                                extra_info: None,
                                cpe: Vec::new(),
                                scripts: Vec::new(),
                            });
                        }
                    }
                    b"state" => {
                        handle_state_element(e, &mut current_port);
                    }
                    b"service" => {
                        handle_service_element(e, &mut current_port);
                    }
                    b"cpe" => {
                        in_cpe = true;
                        current_cpe.clear();
                    }
                    b"script" => {
                        if let Some(id) = get_attribute(e, b"id") {
                            let output = get_attribute(e, b"output").unwrap_or_default();
                            current_script = Some(NmapScript { id, output });
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Empty(ref e)) => {
                match e.name().as_ref() {
                    b"nmaprun" => {
                        found_nmaprun = true;
                    }
                    b"port" => {
                        let proto = get_attribute(e, b"protocol").unwrap_or_else(|| "tcp".to_string());
                        if let Some(portid) = get_attribute(e, b"portid").and_then(|p| p.parse::<u16>().ok()) {
                            ports.push(PortInfo {
                                port: portid,
                                protocol: proto,
                                state: PortState::Closed,
                                service: None,
                                version: None,
                                product: None,
                                extra_info: None,
                                cpe: Vec::new(),
                                scripts: Vec::new(),
                            });
                        }
                    }
                    b"state" => {
                        handle_state_element(e, &mut current_port);
                    }
                    b"service" => {
                        handle_service_element(e, &mut current_port);
                    }
                    b"script" => {
                        if let Some(id) = get_attribute(e, b"id") {
                            let output = get_attribute(e, b"output").unwrap_or_default();
                            if let Some(ref mut p) = current_port {
                                p.scripts.push(NmapScript { id, output });
                            }
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Text(ref e)) => {
                let txt = e
                    .unescape()
                    .map(|v| v.to_string())
                    .unwrap_or_else(|_| String::from_utf8_lossy(e.as_ref()).to_string());

                if in_cpe {
                    current_cpe.push_str(txt.trim());
                } else if let Some(ref mut sc) = current_script {
                    let trimmed_txt = txt.trim();
                    if !trimmed_txt.is_empty() {
                        if sc.output.is_empty() {
                            sc.output = trimmed_txt.to_string();
                        } else {
                            sc.output.push('\n');
                            sc.output.push_str(trimmed_txt);
                        }
                    }
                }
            }
            Ok(Event::End(ref e)) => {
                match e.name().as_ref() {
                    b"cpe" => {
                        in_cpe = false;
                        let cpe_trimmed = current_cpe.trim();
                        if !cpe_trimmed.is_empty() {
                            if let Some(ref mut p) = current_port {
                                p.cpe.push(cpe_trimmed.to_string());
                            }
                        }
                        current_cpe.clear();
                    }
                    b"script" => {
                        if let Some(sc) = current_script.take() {
                            if let Some(ref mut p) = current_port {
                                p.scripts.push(sc);
                            }
                        }
                    }
                    b"port" => {
                        if let Some(p) = current_port.take() {
                            ports.push(p);
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => {
                return Err(anyhow!("Failed to parse Nmap XML: {}", e));
            }
            _ => {}
        }
        buf.clear();
    }

    if !found_nmaprun {
        return Err(anyhow!("Invalid Nmap XML: missing <nmaprun> root tag"));
    }

    Ok(ports)
}

#[derive(Debug, Clone)]
pub struct VulnersEntry {
    pub cve_id: String,
    pub cvss_score: f32,
    pub advisory_url: String,
    pub is_exploit: bool,
}

/// Parses the output of the Nmap vulners NSE script.
/// Example lines:
///   CVE-2021-41773   7.5   https://vulners.com/cve/CVE-2021-41773
///   SSV:99259        7.5   https://vulners.com/suit/SSV:99259   *EXPLOIT*
pub fn parse_vulners_script_output(output: &str) -> Vec<VulnersEntry> {
    let mut entries = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let tokens: Vec<&str> = line.split_whitespace().collect();
        if tokens.len() >= 2 {
            let id = tokens[0];
            if id.starts_with("CVE-") || id.starts_with("SSV:") || id.contains('-') {
                if let Ok(cvss) = tokens[1].parse::<f32>() {
                    let url = tokens.get(2).unwrap_or(&"").to_string();
                    let is_exploit = line.to_uppercase().contains("*EXPLOIT*");
                    entries.push(VulnersEntry {
                        cve_id: id.to_string(),
                        cvss_score: cvss,
                        advisory_url: url,
                        is_exploit,
                    });
                }
            }
        }
    }
    entries
}

fn service_severity(port: u16) -> Severity {
    match port {
        23 => Severity::Critical,
        21 => Severity::High,
        445 => Severity::High,
        3389 => Severity::High,
        22 => Severity::Medium,
        80 | 443 => Severity::Low,
        _ => Severity::Info,
    }
}

fn parse_tls_date(s: &str) -> Option<chrono::NaiveDateTime> {
    chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%b %d %H:%M:%S %Y GMT"))
        .or_else(|_| {
            chrono::NaiveDate::parse_from_str(s, "%Y-%m-%d")
                .map(|d| d.and_hms_opt(0, 0, 0).unwrap())
        })
        .ok()
}

// -------------------------------------------------------------------------
// PROBE 1: ArpScanProbe — LOCAL LAN DISCOVERY
// -------------------------------------------------------------------------
pub struct ArpScanProbe {
    pub target: String,
}

impl ArpScanProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for ArpScanProbe {
    fn name(&self) -> &str {
        "arp-scan"
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.mode == AuditMode::Local
    }

    fn timeout_secs(&self) -> u64 {
        60
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("arp-scan") {
            warn!("[-] arp-scan is not installed or available in PATH");
            return Ok(ProbeResult::skipped("arp-scan", "arp-scan binary not found"));
        }

        let output = run_command("arp-scan", &["--localnet", "--ignoredups"], self.timeout_secs()).await?;

        let mut findings = Vec::new();
        let mut discovered_ips = Vec::new();

        for line in output.stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = if line.contains('\t') {
                line.split('\t').map(|s| s.trim()).filter(|s| !s.is_empty()).collect()
            } else {
                line.split_whitespace().collect()
            };

            if parts.is_empty() {
                continue;
            }

            let ip_str = parts[0];
            if ip_str.parse::<std::net::IpAddr>().is_err() {
                continue;
            }

            let mac_str = parts.get(1).map(|s| s.to_string());
            let vendor_str = parts.get(2..).map(|v| v.join(" "));

            discovered_ips.push(ip_str.to_string());

            let mut title = format!("Local LAN Host Discovered: {}", ip_str);
            if let Some(ref v) = vendor_str {
                title.push_str(&format!(" ({})", v));
            }

            let raw_data = serde_json::json!({
                "ip": ip_str,
                "mac": mac_str,
                "vendor": vendor_str,
            });

            let finding = Finding::new(
                "arp-scan",
                ip_str,
                FindingKind::HostDiscovery,
                Severity::Info,
                title,
                format!("Discovered responsive local host at {} via ARP sweep", ip_str),
                raw_data,
                1.0,
            ).with_tags(vec![
                "lan".to_string(),
                "arp".to_string(),
                "host-discovery".to_string(),
            ]);

            findings.push(finding);
        }

        info!("[+] arp-scan discovered {} hosts on local network", discovered_ips.len());
        Ok(ProbeResult::success("arp-scan", findings).with_resolved_ips(discovered_ips))
    }
}

// -------------------------------------------------------------------------
// PROBE 2: NmapDiscoveryProbe — FAST PORT DISCOVERY & NETCAT SCALPEL
// -------------------------------------------------------------------------
pub struct NmapDiscoveryProbe {
    pub target: String,
}

impl NmapDiscoveryProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for NmapDiscoveryProbe {
    fn name(&self) -> &str {
        "nmap-discovery"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("nmap") {
            warn!("[-] nmap is not installed or available in PATH");
            return Ok(ProbeResult::skipped("nmap-discovery", "nmap binary not found"));
        }

        let target_clean = host_without_port(&self.target);
        let args = [
            "-sS",
            "-Pn",
            "-n",
            "--top-ports",
            "1000",
            "--open",
            "-T4",
            "--max-retries",
            "1",
            "-oX",
            "-",
            target_clean,
        ];

        let output = match run_command("nmap", &args, self.timeout_secs()).await {
            Ok(out) => out,
            Err(e) => {
                debug!("[-] Raw TCP SYN sweep failed (permission issue?), falling back to TCP Connect: {}", e);
                let fallback_args = [
                    "-sT",
                    "-Pn",
                    "-n",
                    "--top-ports",
                    "1000",
                    "--open",
                    "-T4",
                    "--max-retries",
                    "1",
                    "-oX",
                    "-",
                    target_clean,
                ];
                run_command("nmap", &fallback_args, self.timeout_secs()).await?
            }
        };

        if output.stdout.trim().is_empty() {
            return Err(anyhow!("Nmap discovery produced empty XML output"));
        }

        let parsed_ports = parse_nmap_xml(&output.stdout)?;
        let mut open_ports: Vec<PortInfo> = parsed_ports
            .iter()
            .filter(|p| p.state == PortState::Open)
            .cloned()
            .collect();

        let filtered_ports: Vec<PortInfo> = parsed_ports
            .into_iter()
            .filter(|p| p.state == PortState::Filtered || p.state == PortState::OpenFiltered)
            .collect();

        // Netcat Scalpel: double-check filtered ports
        if !filtered_ports.is_empty() {
            let nc_binary = if check_tool_available("nc") {
                Some("nc")
            } else if check_tool_available("ncat") {
                Some("ncat")
            } else {
                None
            };

            if let Some(nc) = nc_binary {
                info!("[*] Netcat Scalpel: Probing {} filtered ports with {}...", filtered_ports.len(), nc);
                for mut fp in filtered_ports {
                    let port_str = fp.port.to_string();
                    let nc_args = ["-zv", "-w", "2", target_clean, &port_str];
                    if let Ok(nc_res) = run_command(nc, &nc_args, 5).await {
                        let lower_err = nc_res.stderr.to_lowercase();
                        let lower_out = nc_res.stdout.to_lowercase();
                        let is_open = nc_res.exit_code == 0
                            || lower_err.contains("succeeded")
                            || lower_err.contains("open")
                            || lower_out.contains("succeeded")
                            || lower_out.contains("open");

                        if is_open {
                            info!("[+] Netcat confirmed Port {} is OPEN (previously marked filtered by Nmap)!", fp.port);
                            fp.state = PortState::Open;
                            open_ports.push(fp);
                        }
                    }
                }
            }
        }

        let mut findings = Vec::new();
        let mut discovered_port_nums = Vec::new();

        for p in &open_ports {
            discovered_port_nums.push(p.port);

            let severity = if p.port < 1024 {
                Severity::Medium
            } else {
                Severity::Low
            };

            let raw_data = serde_json::json!({
                "port": p.port,
                "protocol": p.protocol,
                "state": "open",
            });

            let finding = Finding::new(
                "nmap-discovery",
                &self.target,
                FindingKind::OpenPort,
                severity,
                format!("Open Port: {}/{}", p.port, p.protocol),
                format!("Port {}/{} is open on {}", p.port, p.protocol, self.target),
                raw_data,
                1.0,
            ).with_tags(vec![
                "nmap".to_string(),
                "open-port".to_string(),
                format!("port-{}", p.port),
            ]);

            findings.push(finding);
        }

        discovered_port_nums.sort();
        discovered_port_nums.dedup();

        info!("[+] nmap-discovery found {} open ports on {}", discovered_port_nums.len(), self.target);
        Ok(
            ProbeResult::success("nmap-discovery", findings)
                .with_ports(discovered_port_nums)
                .with_port_infos(open_ports),
        )
    }
}

// -------------------------------------------------------------------------
// PROBE 3: NmapServicesProbe — DEEP SERVICE ENUMERATION & NSE VULNERS
// -------------------------------------------------------------------------
pub struct NmapServicesProbe {
    pub target: String,
}

impl NmapServicesProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for NmapServicesProbe {
    fn name(&self) -> &str {
        "nmap-services"
    }

    fn timeout_secs(&self) -> u64 {
        900
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if ctx.open_ports.is_empty() {
            info!("[*] No open ports recorded in context; skipping nmap services scan");
            return Ok(ProbeResult::skipped("nmap-services", "No open ports to probe"));
        }

        if !check_tool_available("nmap") {
            warn!("[-] nmap is not installed or available in PATH");
            return Ok(ProbeResult::skipped("nmap-services", "nmap binary not found"));
        }

        let ports_csv = ctx.ports_as_csv();
        let target_host = host_without_port(&self.target);

        // Aggressive Service & Version scan with default scripts and NSE Vulners
        let args = [
            "-Pn",
            "-sV",
            "-sC",
            "--version-all",
            "--script",
            "vulners",
            "-p",
            &ports_csv,
            "-oX",
            "-",
            target_host,
        ];

        info!(
            "[*] Executing deep Nmap service & NSE vulners scan against {} on ports [{}]...",
            target_host, ports_csv
        );

        let output = run_command("nmap", &args, self.timeout_secs()).await?;
        if output.stdout.trim().is_empty() {
            return Err(anyhow!("Nmap services scan produced empty XML output"));
        }

        let parsed_ports = parse_nmap_xml(&output.stdout)?;
        let open_ports: Vec<PortInfo> = parsed_ports
            .into_iter()
            .filter(|p| p.state == PortState::Open)
            .collect();

        let mut findings = Vec::new();

        for p in &open_ports {
            let has_version_info = p.version.is_some() || p.product.is_some() || p.service.is_some();
            let svc_name = p.service.as_deref().unwrap_or("unknown");
            let product_str = p.product.as_deref().unwrap_or("");
            let version_str = p.version.as_deref().unwrap_or("");
            let extra_str = p.extra_info.as_deref().unwrap_or("");

            if has_version_info {
                let severity = service_severity(p.port);
                let title = if !product_str.is_empty() && !version_str.is_empty() {
                    format!("Service Identified: {} {} ({}) on port {}/{}", product_str, version_str, svc_name, p.port, p.protocol)
                } else if !product_str.is_empty() {
                    format!("Service Identified: {} ({}) on port {}/{}", product_str, svc_name, p.port, p.protocol)
                } else {
                    format!("Service Identified: {} on port {}/{}", svc_name, p.port, p.protocol)
                };

                let mut desc_parts = vec![format!("Port {}/{} service '{}'", p.port, p.protocol, svc_name)];
                if !product_str.is_empty() {
                    desc_parts.push(format!("Product: {}", product_str));
                }
                if !version_str.is_empty() {
                    desc_parts.push(format!("Version: {}", version_str));
                }
                if !extra_str.is_empty() {
                    desc_parts.push(format!("Extra: {}", extra_str));
                }
                let description = desc_parts.join(" | ");

                let raw_data = serde_json::json!({
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state.to_string(),
                    "service": p.service,
                    "product": p.product,
                    "version": p.version,
                    "extra_info": p.extra_info,
                    "cpe": p.cpe,
                    "scripts": p.scripts,
                });

                let mut finding = Finding::new(
                    "nmap-services",
                    target_host,
                    FindingKind::Service,
                    severity,
                    title,
                    description,
                    raw_data,
                    0.95,
                ).with_tags(vec![
                    "nmap".to_string(),
                    "service".to_string(),
                    svc_name.to_string(),
                    format!("port-{}", p.port),
                ]);

                for (idx, cpe_item) in p.cpe.iter().enumerate() {
                    finding = finding.with_metadata(format!("cpe_{}", idx), cpe_item);
                }
                if !p.cpe.is_empty() {
                    finding = finding.with_metadata("cpe", p.cpe.join(", "));
                }
                if let Some(ref ver) = p.version {
                    finding = finding.with_metadata("version", ver);
                }
                if let Some(ref prod) = p.product {
                    finding = finding.with_metadata("product", prod);
                }

                findings.push(finding);
            }

            // Extract and parse NSE Vulners script findings
            for script in &p.scripts {
                if script.id == "vulners" {
                    let vulns = parse_vulners_script_output(&script.output);
                    for vuln in vulns {
                        let severity = if vuln.cvss_score >= 9.0 {
                            Severity::Critical
                        } else if vuln.cvss_score >= 7.0 {
                            Severity::High
                        } else if vuln.cvss_score >= 4.0 {
                            Severity::Medium
                        } else {
                            Severity::Low
                        };

                        let exploit_tag = if vuln.is_exploit { " [EXPLOIT AVAILABLE]" } else { "" };
                        let title = format!(
                            "Nmap Vulners: {} (CVSS {:.1}) on port {}/{}{}",
                            vuln.cve_id, vuln.cvss_score, p.port, p.protocol, exploit_tag
                        );

                        let desc = format!(
                            "Nmap NSE script 'vulners' detected {} on port {}/{} ({}). CVSS Base Score: {:.1}. Advisory: {}",
                            vuln.cve_id,
                            p.port,
                            p.protocol,
                            svc_name,
                            vuln.cvss_score,
                            vuln.advisory_url
                        );

                        let raw_data = serde_json::json!({
                            "cve_id": vuln.cve_id,
                            "cvss_score": vuln.cvss_score,
                            "advisory_url": vuln.advisory_url,
                            "is_exploit": vuln.is_exploit,
                            "port": p.port,
                            "protocol": p.protocol,
                            "service": p.service,
                            "product": p.product,
                            "version": p.version,
                        });

                        let mut f = Finding::new(
                            "nmap-vulners",
                            target_host,
                            FindingKind::Vulnerability,
                            severity,
                            title,
                            desc,
                            raw_data,
                            0.95,
                        ).with_tags(vec![
                            "nmap".to_string(),
                            "vulners".to_string(),
                            "cve".to_string(),
                            vuln.cve_id.clone(),
                            format!("port-{}", p.port),
                        ]);

                        if vuln.is_exploit {
                            f = f.with_metadata("exploit_available", "true");
                        }
                        findings.push(f);
                    }
                }
            }
        }

        info!("[+] nmap-services generated {} findings (services + vulners)", findings.len());
        Ok(ProbeResult::success("nmap-services", findings).with_port_infos(open_ports))
    }
}

// -------------------------------------------------------------------------
// PROBE 4: TestSslProbe — DEEP TLS/SSL AUDIT
// -------------------------------------------------------------------------
pub struct TestSslProbe {
    pub target: String,
}

impl TestSslProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for TestSslProbe {
    fn name(&self) -> &str {
        "testssl"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        let tool = if check_tool_available("testssl.sh") {
            "testssl.sh"
        } else if check_tool_available("testssl") {
            "testssl"
        } else {
            warn!("[-] testssl.sh is not installed or available in PATH");
            return Ok(ProbeResult::skipped("testssl", "testssl.sh binary not found"));
        };

        let clean_host = host_without_port(&self.target);
        let target_spec = if self.target.contains(':') && !self.target.starts_with("http") {
            self.target.clone()
        } else {
            format!("{}:443", clean_host)
        };

        let tmp = NamedTempFile::new().context("Failed to create temporary file for testssl output")?;
        let tmp_path = tmp.path().to_str().ok_or_else(|| anyhow!("Invalid temporary file path"))?.to_string();

        let args = [
            "--jsonfile",
            &tmp_path,
            "--color",
            "0",
            &target_spec,
        ];

        let _ = run_command(tool, &args, self.timeout_secs()).await;

        let json_content = match std::fs::read_to_string(&tmp_path) {
            Ok(content) if !content.trim().is_empty() => {
                let _ = std::fs::remove_file(&tmp_path);
                content
            }
            _ => {
                let _ = std::fs::remove_file(&tmp_path);
                warn!("[-] testssl produced no JSON output at {}", tmp_path);
                return Ok(ProbeResult::skipped("testssl", "No JSON output produced"));
            }
        };

        let entries: Vec<serde_json::Value> = if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json_content) {
            if let Some(arr) = val.as_array() {
                arr.clone()
            } else if let Some(arr) = val.get("scanResult").and_then(|v| v.as_array()) {
                arr.clone()
            } else {
                Vec::new()
            }
        } else {
            json_content
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l.trim()).ok())
                .collect()
        };

        let mut cert_valid = true;
        let mut cert_expires = None;
        let mut cert_issuer = None;
        let mut cert_subject = None;
        let mut weak_ciphers = Vec::new();
        let mut vulnerabilities = Vec::new();
        let mut protocols = Vec::new();
        let mut findings = Vec::new();

        for entry in &entries {
            let id = entry.get("id").and_then(|v| v.as_str()).unwrap_or("").trim();
            let sev_str = entry.get("severity").and_then(|v| v.as_str()).unwrap_or("").trim();
            let finding_str = entry.get("finding").and_then(|v| v.as_str()).unwrap_or("").trim();

            if id.is_empty() {
                continue;
            }

            let sev_upper = sev_str.to_uppercase();
            let finding_lower = finding_str.to_lowercase();

            if id.eq_ignore_ascii_case("cert_notAfter") {
                cert_expires = Some(finding_str.to_string());
                if let Some(dt) = parse_tls_date(finding_str) {
                    let now = chrono::Utc::now().naive_utc();
                    let diff = dt.signed_duration_since(now);
                    let days = diff.num_days();
                    if days < 0 {
                        cert_valid = false;
                        findings.push(Finding::new(
                            "testssl",
                            &self.target,
                            FindingKind::TlsWeakness,
                            Severity::Critical,
                            "TLS Certificate Expired",
                            format!("Certificate expired {} days ago on {}", -days, finding_str),
                            entry.clone(),
                            1.0,
                        ).with_tags(vec!["tls".to_string(), "certificate".to_string(), "expired".to_string()]));
                    } else if days < 30 {
                        findings.push(Finding::new(
                            "testssl",
                            &self.target,
                            FindingKind::TlsWeakness,
                            Severity::High,
                            "TLS Certificate Expiring Soon",
                            format!("Certificate will expire in {} days on {}", days, finding_str),
                            entry.clone(),
                            1.0,
                        ).with_tags(vec!["tls".to_string(), "certificate".to_string(), "expiring-soon".to_string()]));
                    }
                }
            }

            if id.eq_ignore_ascii_case("cert_issuer") || id.eq_ignore_ascii_case("cert_caIssuers") {
                if cert_issuer.is_none() {
                    cert_issuer = Some(finding_str.to_string());
                }
            }

            if id.eq_ignore_ascii_case("cert_commonName") || id.eq_ignore_ascii_case("cert_subject") {
                if cert_subject.is_none() {
                    cert_subject = Some(finding_str.to_string());
                }
            }

            if id.eq_ignore_ascii_case("cert_expiration_status") && (finding_lower.contains("expired") || sev_upper == "CRITICAL") {
                cert_valid = false;
            }

            let is_proto = matches!(
                id,
                "SSLv2" | "SSLv3" | "TLS1" | "TLS1_1" | "TLS1_2" | "TLS1_3" | "TLS1_0"
            );
            if is_proto && (finding_lower.contains("offered") || finding_lower.contains("yes")) && !finding_lower.contains("not offered") {
                protocols.push(id.to_string());
            }

            if (id.eq_ignore_ascii_case("cipher_negotiated") || id.contains("cipher"))
                && (finding_str.contains("RC4") || finding_str.contains("DES") || finding_str.contains("NULL") || finding_str.contains("EXPORT"))
            {
                weak_ciphers.push(finding_str.to_string());
            }

            if sev_upper == "INFO" || sev_upper == "OK" || sev_upper == "DEBUG" || sev_upper.is_empty() {
                continue;
            }

            if finding_lower.contains("not offered")
                || finding_lower.contains("not vulnerable")
                || finding_lower.contains("no (ok)")
                || finding_lower.contains("no risk")
            {
                continue;
            }

            let severity = if (id == "SSLv2" || id == "SSLv3") && (finding_lower.contains("offered") || finding_lower.contains("yes")) {
                Severity::Critical
            } else if (id == "TLS1" || id == "TLS1_1" || id == "TLS1_0") && (finding_lower.contains("offered") || finding_lower.contains("yes")) {
                Severity::High
            } else if id == "BEAST" || id == "LUCKY13" || id == "SWEET32" {
                Severity::Medium
            } else if id.eq_ignore_ascii_case("cert_expired") || (id.starts_with("cert_") && finding_lower.contains("expired")) {
                cert_valid = false;
                Severity::Critical
            } else if id == "cipher_negotiated" && (finding_str.contains("RC4") || finding_str.contains("DES")) {
                Severity::High
            } else {
                match sev_upper.as_str() {
                    "CRITICAL" => Severity::Critical,
                    "HIGH" => Severity::High,
                    "MEDIUM" | "WARN" => Severity::Medium,
                    "LOW" => Severity::Low,
                    _ => Severity::Low,
                }
            };

            let vuln_entry = TlsVuln {
                id: id.to_string(),
                severity: sev_upper.clone(),
                finding: finding_str.to_string(),
            };
            vulnerabilities.push(vuln_entry);

            let finding = Finding::new(
                "testssl",
                &self.target,
                FindingKind::TlsWeakness,
                severity,
                format!("TLS Vulnerability: {} ({})", id, sev_upper),
                format!("{}: {}", id, finding_str),
                entry.clone(),
                0.9,
            ).with_tags(vec![
                "tls".to_string(),
                "testssl".to_string(),
                id.to_lowercase(),
                sev_upper.to_lowercase(),
            ]);

            findings.push(finding);
        }

        let tls_info = TlsInfo {
            target: self.target.clone(),
            cert_valid,
            cert_expires,
            cert_issuer,
            cert_subject,
            weak_ciphers,
            vulnerabilities,
            protocols,
        };

        info!("[+] testssl completed with {} TLS findings", findings.len());
        Ok(ProbeResult::success("testssl", findings).with_tls_info(tls_info))
    }
}
