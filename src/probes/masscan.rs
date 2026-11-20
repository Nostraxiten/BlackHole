use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fs;
use tempfile::NamedTempFile;
use tracing::{debug, info, warn};

use crate::executor::{check_tool_available, run_command};
use crate::probe::{Probe, ProbeResult};
use crate::types::{AuditContext, AuditMode, Finding, FindingKind, PortInfo, PortState, Severity};

pub struct MasscanProbe {
    pub target: String,
    pub ports: String,
}

impl MasscanProbe {
    pub fn new(target: String) -> Self {
        Self {
            target,
            ports: "1-65535".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MasscanRecord {
    pub ip: Option<String>,
    pub timestamp: Option<String>,
    #[serde(default)]
    pub ports: Vec<MasscanPortEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MasscanPortEntry {
    pub port: u16,
    #[serde(default = "default_proto")]
    pub proto: String,
    #[serde(default)]
    pub status: String,
    pub reason: Option<String>,
    pub ttl: Option<u8>,
}

fn default_proto() -> String {
    "tcp".to_string()
}

#[async_trait]
impl Probe for MasscanProbe {
    fn name(&self) -> &str {
        "masscan"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.mode == AuditMode::Target || ctx.target.contains('/')
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("masscan") {
            warn!("[-] Masscan binary not found in PATH - skipping high-speed port scan");
            return Ok(ProbeResult::skipped("masscan", "binary not found in PATH"));
        }

        // Adaptive rate: 10000 pkts/s for external targets, 1000 pkts/s for local/LAN to prevent flooding
        let rate = if ctx.is_local() { 1000 } else { 10000 };

        info!(
            "[*] Launching Masscan ultra-fast port scan against '{}' (rate: {} pkts/sec, ports: {})",
            self.target, rate, self.ports
        );

        let tmp = NamedTempFile::new().context("Failed to allocate tempfile for masscan output")?;
        let tmp_path = tmp.path().to_str().ok_or_else(|| anyhow!("Invalid tempfile path"))?.to_string();

        let rate_str = rate.to_string();
        let port_spec = format!("-p{}", self.ports);
        let args = [
            &port_spec,
            "--rate",
            &rate_str,
            "-oJ",
            &tmp_path,
            &self.target,
        ];

        let cmd_out = run_command("masscan", &args, self.timeout_secs()).await?;
        if cmd_out.exit_code != 0 && !cmd_out.stderr.is_empty() {
            debug!("Masscan exited with code {}: {}", cmd_out.exit_code, cmd_out.stderr);
        }

        let content = match fs::read_to_string(&tmp_path) {
            Ok(c) => {
                let _ = fs::remove_file(&tmp_path);
                c
            }
            Err(_) => {
                let _ = fs::remove_file(&tmp_path);
                warn!("[-] Masscan produced no output file at {}", tmp_path);
                return Ok(ProbeResult::failed("masscan", "missing output file"));
            }
        };

        if content.trim().is_empty() {
            info!("[*] Masscan finished: no open ports detected on {}", self.target);
            return Ok(ProbeResult::success("masscan", vec![]));
        }

        let parsed_records: Vec<MasscanRecord> = parse_masscan_json(&content);
        info!("[*] Masscan parsed {} host records", parsed_records.len());

        let mut discovered_ports: Vec<u16> = Vec::new();
        let mut discovered_port_infos: Vec<PortInfo> = Vec::new();
        let mut findings = Vec::new();

        for record in parsed_records {
            let host_ip = record.ip.unwrap_or_else(|| self.target.clone());
            for p in record.ports {
                if p.status.is_empty() || p.status.eq_ignore_ascii_case("open") {
                    if !discovered_ports.contains(&p.port) {
                        discovered_ports.push(p.port);
                    }

                    discovered_port_infos.push(PortInfo {
                        port: p.port,
                        protocol: p.proto.clone(),
                        state: PortState::Open,
                        service: None,
                        version: None,
                        product: None,
                        extra_info: p.reason.clone(),
                        cpe: Vec::new(),
                        scripts: Vec::new(),
                    });

                    let severity = if p.port < 1024 {
                        Severity::Medium
                    } else {
                        Severity::Low
                    };

                    let raw_data = serde_json::json!({
                        "host": host_ip,
                        "port": p.port,
                        "protocol": p.proto,
                        "status": p.status,
                        "reason": p.reason,
                        "ttl": p.ttl,
                        "discovered_by": "masscan",
                    });

                    findings.push(
                        Finding::new(
                            "masscan",
                            &self.target,
                            FindingKind::OpenPort,
                            severity,
                            format!("High-Speed Open Port: {}/{}", p.port, p.proto),
                            format!(
                                "Masscan detected open port {}/{} on {} (TTL: {:?}, Reason: {:?})",
                                p.port, p.proto, host_ip, p.ttl, p.reason
                            ),
                            raw_data,
                            0.95,
                        )
                        .with_tags(vec![
                            "masscan".into(),
                            "port".into(),
                            "fast-scan".into(),
                            format!("port-{}", p.port),
                        ])
                        .with_metadata("port", p.port.to_string())
                        .with_metadata("protocol", p.proto),
                    );
                }
            }
        }

        discovered_ports.sort();
        discovered_ports.dedup();

        if !discovered_ports.is_empty() {
            info!(
                "[+] Masscan identified {} open ports: {:?}",
                discovered_ports.len(),
                discovered_ports
            );
        }

        // Summary finding
        findings.push(
            Finding::new(
                "masscan",
                &self.target,
                FindingKind::OpenPort,
                Severity::Info,
                format!("Masscan Port Sweep Summary: {} Open Ports", discovered_ports.len()),
                format!(
                    "High-speed port scan completed. Identified {} open ports across range {}.",
                    discovered_ports.len(),
                    self.ports
                ),
                serde_json::json!({
                    "target": self.target,
                    "total_open_ports": discovered_ports.len(),
                    "ports": discovered_ports,
                    "rate": rate,
                }),
                1.0,
            )
            .with_tags(vec!["masscan".into(), "summary".into()]),
        );

        Ok(ProbeResult::success("masscan", findings)
            .with_ports(discovered_ports)
            .with_port_infos(discovered_port_infos))
    }
}

pub fn parse_masscan_json(content: &str) -> Vec<MasscanRecord> {
    let trimmed = content.trim();

    if trimmed.starts_with('[') && trimmed.ends_with(']') {
        if let Ok(records) = serde_json::from_str::<Vec<MasscanRecord>>(trimmed) {
            return records;
        }
    }

    let sanitized = trimmed
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim();

    let mut records = Vec::new();
    for block in sanitized.split("},") {
        let mut json_str = block.trim().to_string();
        if !json_str.ends_with('}') {
            json_str.push('}');
        }
        if let Ok(record) = serde_json::from_str::<MasscanRecord>(&json_str) {
            records.push(record);
        }
    }

    records
}
