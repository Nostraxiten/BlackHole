use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::executor::{check_tool_available, run_command};
use crate::probe::{Probe, ProbeResult};
use crate::types::{AuditContext, AuditMode, Finding, FindingKind, Severity};

pub struct SubfinderProbe {
    pub target: String,
}

impl SubfinderProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SubfinderOutputLine {
    pub host: Option<String>,
    pub input: Option<String>,
    #[serde(default)]
    pub sources: Vec<String>,
}

#[async_trait]
impl Probe for SubfinderProbe {
    fn name(&self) -> &str {
        "subfinder"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        if ctx.mode != AuditMode::Target {
            return false;
        }
        let clean = self.target.trim();
        clean.parse::<std::net::IpAddr>().is_err() && !clean.contains('/')
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("subfinder") {
            warn!("[-] Subfinder binary not found in PATH - skipping passive subdomain discovery");
            return Ok(ProbeResult::skipped("subfinder", "binary not found in PATH"));
        }

        info!("[*] Launching Subfinder against '{}'...", self.target);

        let args = ["-d", &self.target, "-silent", "-json", "-all"];
        let cmd_out = run_command("subfinder", &args, self.timeout_secs()).await?;

        if cmd_out.stdout.trim().is_empty() {
            info!("[*] Subfinder produced no subdomain results for {}", self.target);
            return Ok(ProbeResult::success("subfinder", vec![]));
        }

        let mut discovered: Vec<String> = Vec::new();
        let mut findings = Vec::new();

        for line in cmd_out.stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(entry) = serde_json::from_str::<SubfinderOutputLine>(line) {
                if let Some(host) = entry.host {
                    let h_clean = host.trim().to_lowercase();
                    if !h_clean.is_empty() && !discovered.contains(&h_clean) {
                        discovered.push(h_clean.clone());

                        let sources_str = entry.sources.join(", ");
                        findings.push(
                            Finding::new(
                                "subfinder",
                                &h_clean,
                                FindingKind::Subdomain,
                                Severity::Info,
                                format!("Subdomain Discovered: {}", h_clean),
                                format!(
                                    "Passive reconnaissance via Subfinder discovered subdomain {}. Sources: [{}]",
                                    h_clean, sources_str
                                ),
                                serde_json::json!({
                                    "subdomain": h_clean,
                                    "root_domain": self.target,
                                    "sources": entry.sources,
                                }),
                                0.95,
                            )
                            .with_tags(vec!["subdomain".into(), "subfinder".into(), "recon".into()])
                            .with_metadata("domain", h_clean),
                        );
                    }
                }
            } else {
                let h_clean = line.to_lowercase();
                if !h_clean.is_empty() && !discovered.contains(&h_clean) && h_clean.contains('.') {
                    discovered.push(h_clean.clone());

                    findings.push(
                        Finding::new(
                            "subfinder",
                            &h_clean,
                            FindingKind::Subdomain,
                            Severity::Info,
                            format!("Subdomain Discovered: {}", h_clean),
                            format!("Subfinder discovered active subdomain {}", h_clean),
                            serde_json::json!({
                                "subdomain": h_clean,
                                "root_domain": self.target,
                            }),
                            0.90,
                        )
                        .with_tags(vec!["subdomain".into(), "subfinder".into(), "recon".into()]),
                    );
                }
            }
        }

        discovered.sort();
        discovered.dedup();

        info!(
            "[+] Subfinder discovered {} unique subdomains for {}",
            discovered.len(),
            self.target
        );

        Ok(ProbeResult::success("subfinder", findings).with_subdomains(discovered))
    }
}
