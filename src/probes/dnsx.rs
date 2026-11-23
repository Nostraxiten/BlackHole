use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;
use tracing::{info, warn};

use crate::executor::{check_tool_available, run_command};
use crate::probe::{Probe, ProbeResult};
use crate::types::{AuditContext, DnsRecord, Finding, FindingKind, Severity};

pub struct DnsxProbe {
    pub target: String,
}

impl DnsxProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DnsxOutputLine {
    pub host: Option<String>,
    #[serde(default)]
    pub a: Vec<String>,
    #[serde(default)]
    pub aaaa: Vec<String>,
    #[serde(default)]
    pub cname: Vec<String>,
    pub status_code: Option<String>,
    pub resolver: Option<Vec<String>>,
}

#[async_trait]
impl Probe for DnsxProbe {
    fn name(&self) -> &str {
        "dnsx"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        !ctx.subdomains.is_empty() || ctx.target.parse::<std::net::IpAddr>().is_err()
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("dnsx") {
            warn!("[-] dnsx binary not found in PATH - skipping fast bulk DNS resolution");
            return Ok(ProbeResult::skipped("dnsx", "binary not found in PATH"));
        }

        let mut hosts_to_resolve: Vec<String> = ctx.subdomains.clone();
        if !hosts_to_resolve.contains(&self.target) {
            hosts_to_resolve.push(self.target.clone());
        }

        if hosts_to_resolve.is_empty() {
            info!("[*] No hosts or subdomains available for dnsx resolution");
            return Ok(ProbeResult::success("dnsx", vec![]));
        }

        info!(
            "[*] Launching dnsx bulk DNS resolution for {} hosts/subdomains...",
            hosts_to_resolve.len()
        );

        let mut list_file = NamedTempFile::new().context("Failed to allocate tempfile for dnsx input")?;
        for host in &hosts_to_resolve {
            writeln!(list_file, "{}", host)?;
        }
        let list_path = list_file.path().to_str().ok_or_else(|| anyhow!("Invalid tempfile path"))?.to_string();

        let tmp_out = NamedTempFile::new().context("Failed to allocate tempfile for dnsx output")?;
        let tmp_out_path = tmp_out.path().to_str().ok_or_else(|| anyhow!("Invalid tempfile path"))?.to_string();

        let args = [
            "-l",
            &list_path,
            "-json",
            "-silent",
            "-a",
            "-aaaa",
            "-cname",
            "-resp",
            "-t",
            "150",
            "-r",
            "1.1.1.1,8.8.8.8,9.9.9.9",
            "-o",
            &tmp_out_path,
        ];

        let dynamic_timeout = std::cmp::max(self.timeout_secs(), (hosts_to_resolve.len() as u64) / 100 + 60);
        let _ = run_command("dnsx", &args, dynamic_timeout).await?;

        let content = match fs::read_to_string(&tmp_out_path) {
            Ok(c) => {
                let _ = fs::remove_file(&tmp_out_path);
                c
            }
            Err(_) => {
                let _ = fs::remove_file(&tmp_out_path);
                warn!("[-] dnsx produced no output file at {}", tmp_out_path);
                return Ok(ProbeResult::failed("dnsx", "missing output file"));
            }
        };

        let mut findings = Vec::new();
        let mut resolved_ips: Vec<String> = Vec::new();
        let mut dns_records: Vec<DnsRecord> = Vec::new();
        let mut resolved_count = 0usize;

        let clean_content = crate::executor::strip_ansi_codes(&content);
        for line in clean_content.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<DnsxOutputLine>(line) {
                let host = entry.host.unwrap_or_default();
                if host.is_empty() {
                    continue;
                }

                for ip in &entry.a {
                    if !resolved_ips.contains(ip) {
                        resolved_ips.push(ip.clone());
                    }
                    dns_records.push(DnsRecord {
                        record_type: "A".to_string(),
                        name: host.clone(),
                        value: ip.clone(),
                        ttl: None,
                    });
                }

                for ip in &entry.aaaa {
                    if !resolved_ips.contains(ip) {
                        resolved_ips.push(ip.clone());
                    }
                    dns_records.push(DnsRecord {
                        record_type: "AAAA".to_string(),
                        name: host.clone(),
                        value: ip.clone(),
                        ttl: None,
                    });
                }

                if !entry.a.is_empty() || !entry.aaaa.is_empty() || !entry.cname.is_empty() {
                    resolved_count += 1;
                    let ips_str = entry.a.join(", ");
                    let cnames_str = entry.cname.join(", ");

                    findings.push(
                        Finding::new(
                            "dnsx",
                            &host,
                            FindingKind::DnsRecord,
                            Severity::Info,
                            format!("Live DNS Host: {} -> [{}]", host, ips_str),
                            format!(
                                "dnsx resolved live host {} to IPv4: [{}] / CNAME: [{}] (status: {:?})",
                                host, ips_str, cnames_str, entry.status_code
                            ),
                            serde_json::json!({
                                "host": host,
                                "a_records": entry.a,
                                "aaaa_records": entry.aaaa,
                                "cnames": entry.cname,
                                "status": entry.status_code,
                            }),
                            1.0,
                        )
                        .with_tags(vec!["dns".into(), "dnsx".into(), "resolved".into(), "live-host".into()])
                        .with_metadata("host", host),
                    );
                }
            }
        }

        resolved_ips.sort();
        resolved_ips.dedup();

        info!(
            "[+] dnsx confirmed {} live hosts across {} unique IP addresses",
            resolved_count,
            resolved_ips.len()
        );

        Ok(ProbeResult::success("dnsx", findings)
            .with_resolved_ips(resolved_ips)
            .with_dns_records(dns_records))
    }
}
