use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::info;

use crate::types::{Finding, FindingKind, Severity};

pub struct ReportGenerator {
    output_dir: PathBuf,
    session_id: String,
}

impl ReportGenerator {
    pub fn new(output_dir: &str, session_id: &str) -> Self {
        Self {
            output_dir: PathBuf::from(output_dir),
            session_id: session_id.to_string(),
        }
    }

    pub fn generate(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        self.generate_markdown(findings, target, mode)?;
        self.generate_json_summary(findings, target, mode)?;
        Ok(())
    }

    fn generate_markdown(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        let mut md = String::new();
        let audit_mode = mode.unwrap_or("Standard Security Audit");

        // 1. Header
        md.push_str("# BlackHole Offensive Security Assessment Report\n\n");
        md.push_str(&format!("- **Primary Target:** `{}`\n", target));
        md.push_str(&format!("- **Audit Mode:** `{}`\n", audit_mode));
        md.push_str(&format!("- **Session ID:** `{}`\n", self.session_id));
        md.push_str(&format!(
            "- **Timestamp:** `{}`\n\n",
            chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Group findings by severity
        let mut by_severity: HashMap<String, Vec<&Finding>> = HashMap::new();
        for f in findings {
            by_severity.entry(f.severity.to_string()).or_default().push(f);
        }

        let crit_count = by_severity.get("CRITICAL").map(|v| v.len()).unwrap_or(0);
        let high_count = by_severity.get("HIGH").map(|v| v.len()).unwrap_or(0);
        let med_count = by_severity.get("MEDIUM").map(|v| v.len()).unwrap_or(0);
        let low_count = by_severity.get("LOW").map(|v| v.len()).unwrap_or(0);
        let info_count = by_severity.get("INFO").map(|v| v.len()).unwrap_or(0);

        // 2. Executive Summary
        md.push_str("## 1. Executive Summary\n\n");
        md.push_str("| Risk Level | Finding Count | Remediation SLA |\n|---|---|---|\n");
        md.push_str(&format!("| `[CRITICAL]` | {} | Immediate emergency remediation required |\n", crit_count));
        md.push_str(&format!("| `[HIGH]` | {} | Prioritize patching within 24-48 hours |\n", high_count));
        md.push_str(&format!("| `[MEDIUM]` | {} | Address during standard maintenance cycle |\n", med_count));
        md.push_str(&format!("| `[LOW]` | {} | Defensive hardening and configuration review |\n", low_count));
        md.push_str(&format!("| `[INFO]` | {} | Informational reconnaissance context |\n\n", info_count));

        // 3. Attack Surface Mapping
        md.push_str("## 2. Attack Surface Mapping\n\n");

        // 3.1 Open Ports & Services
        let mut port_entries: Vec<(&Finding, String, String, String, String, String)> = Vec::new();
        for f in findings {
            if matches!(f.kind, FindingKind::OpenPort | FindingKind::Service) || f.raw_data.get("port").is_some() {
                let port = f.raw_data.get("port")
                    .map(|v| v.to_string())
                    .or_else(|| f.metadata.get("port").cloned())
                    .unwrap_or_else(|| "-".to_string());

                let proto = f.raw_data.get("protocol")
                    .and_then(|v| v.as_str())
                    .or_else(|| f.metadata.get("protocol").map(|s| s.as_str()))
                    .unwrap_or("tcp")
                    .to_string();

                let service = f.raw_data.get("service")
                    .and_then(|v| v.as_str())
                    .or_else(|| f.metadata.get("service").map(|s| s.as_str()))
                    .unwrap_or("unknown")
                    .to_string();

                let version = f.raw_data.get("version")
                    .and_then(|v| v.as_str())
                    .or_else(|| f.metadata.get("version").map(|s| s.as_str()))
                    .unwrap_or("-")
                    .to_string();

                let cpes = if let Some(cpe_arr) = f.raw_data.get("cpe").and_then(|v| v.as_array()) {
                    cpe_arr.iter().filter_map(|c| c.as_str()).collect::<Vec<&str>>().join(", ")
                } else {
                    f.metadata.get("cpe").cloned().unwrap_or_else(|| "-".to_string())
                };

                if port != "-" {
                    port_entries.push((f, port, proto, service, version, cpes));
                }
            }
        }

        // Deduplicate port entries by port/proto
        port_entries.sort_by(|a, b| a.1.cmp(&b.1));
        port_entries.dedup_by(|a, b| a.1 == b.1 && a.2 == b.2);

        if !port_entries.is_empty() {
            md.push_str("### 2.1 Discovered Ports & Services\n\n");
            md.push_str("| Port / Protocol | Service Name | Version / Product | Identified CPEs | Detection Tool |\n|---|---|---|---|---|\n");
            for (f, port, proto, service, version, cpes) in &port_entries {
                md.push_str(&format!(
                    "| `{}/{}` | {} | {} | `{}` | `{}` |\n",
                    port, proto, service, version, cpes, f.source_tool
                ));
            }
            md.push_str("\n");
        }

        // 3.2 Discovered Subdomains
        let mut subdomains: Vec<&str> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::Subdomain))
            .map(|f| f.target.as_str())
            .collect();
        subdomains.sort();
        subdomains.dedup();

        if !subdomains.is_empty() {
            md.push_str("### 2.2 Discovered Subdomains\n\n");
            md.push_str("| Subdomain Hostname | Scope Status |\n|---|---|\n");
            for sub in &subdomains {
                md.push_str(&format!("| `{}` | In-Scope |\n", sub));
            }
            md.push_str("\n");
        }

        // 3.3 Detected Web Technologies & WAF
        let mut tech_list = Vec::new();
        let mut waf_name = None;

        for f in findings {
            if matches!(f.kind, FindingKind::WebTechnology) {
                tech_list.push(f.title.trim_start_matches("Web Technology: ").to_string());
            }
            if matches!(f.kind, FindingKind::WafDetected) {
                waf_name = Some(f.title.clone());
            }
        }
        tech_list.sort();
        tech_list.dedup();

        md.push_str("### 2.3 Identified Technologies & Defensive Controls\n\n");
        if let Some(waf) = waf_name {
            md.push_str(&format!("- **Active WAF / Cloud Shield:** `{}`\n", waf));
        } else {
            md.push_str("- **Active WAF / Cloud Shield:** None detected (direct origin accessible)\n");
        }

        if !tech_list.is_empty() {
            md.push_str(&format!("- **Detected Stacks & Frameworks:** `{}`\n\n", tech_list.join("`, `")));
        } else {
            md.push_str("- **Detected Stacks & Frameworks:** No specific frameworks fingerprinted\n\n");
        }

        // 4. Vulnerability Findings (Sorted by Severity Descending)
        md.push_str("## 3. Vulnerability Findings & Security Deficiencies\n\n");

        let mut sorted_findings = findings.to_vec();
        sorted_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        let mut index = 1;
        for f in &sorted_findings {
            // Include findings of significance
            let sev_tag = format!("[{}]", f.severity.to_string());
            md.push_str(&format!("### 3.{} {} {}\n\n", index, sev_tag, f.title));
            md.push_str(&format!("- **Severity:** `{}`\n", f.severity));
            md.push_str(&format!("- **Target Asset:** `{}`\n", f.target));
            md.push_str(&format!("- **Detection Tool:** `{}`\n", f.source_tool));
            md.push_str(&format!("- **Category:** `{:?}`\n", f.kind));
            md.push_str(&format!("- **Confidence Score:** `{:.0}%`\n\n", f.confidence * 100.0));

            md.push_str("#### Technical Description\n");
            md.push_str(&format!("{}\n\n", f.description));

            // CVE Enrichment Block
            let cve_id = f.raw_data.get("cve_id").and_then(|v| v.as_str());
            let cvss_score = f.raw_data.get("cvss_score").and_then(|v| v.as_f64());
            let cvss_vector = f.raw_data.get("cvss_vector").and_then(|v| v.as_str());

            if let Some(id) = cve_id {
                md.push_str("#### CVE Vulnerability Reference\n");
                md.push_str(&format!("- **Vulnerability ID:** `{}`\n", id));
                if let Some(score) = cvss_score {
                    md.push_str(&format!("- **CVSS Base Score:** `{:.1}`\n", score));
                }
                if let Some(vec_str) = cvss_vector {
                    md.push_str(&format!("- **CVSS Vector:** `{}`\n", vec_str));
                }
                md.push_str(&format!("- **Recommended Mitigation:** {}\n\n", generate_mitigation_advice(id)));
            }

            // Raw Evidence Data Block
            md.push_str("#### Raw Evidence Data\n");
            md.push_str("```json\n");
            let raw_json_str = serde_json::to_string_pretty(&f.raw_data).unwrap_or_else(|_| "{}".to_string());
            md.push_str(&raw_json_str);
            md.push_str("\n```\n\n---\n\n");

            index += 1;
        }

        // 5. Legal Notice & Disclaimer
        md.push_str("## 4. Legal Notice & Disclaimer\n\n");
        md.push_str("This report contains sensitive technical assessment results, discovered assets, and potential vulnerability details. \
It is intended strictly and exclusively for authorized security personnel and client stakeholders with explicit prior written consent \
for penetration testing and vulnerability assessment. Unauthorized use, reproduction, distribution, or weaponization of the details \
contained in this report violates applicable national and international computer fraud and cybersecurity legislation.\n");

        let path = self.output_dir.join(format!("report_{}.md", self.session_id));
        fs::create_dir_all(&self.output_dir)?;
        fs::write(&path, &md)?;
        info!("[+] Technical Markdown audit report successfully written to: {}", path.display());
        Ok(())
    }

    fn generate_json_summary(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        let summary = serde_json::json!({
            "target": target,
            "session_id": self.session_id,
            "mode": mode.unwrap_or("Standard Security Audit"),
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "total_findings": findings.len(),
            "by_severity": {
                "critical": findings.iter().filter(|f| f.severity == Severity::Critical).count(),
                "high": findings.iter().filter(|f| f.severity == Severity::High).count(),
                "medium": findings.iter().filter(|f| f.severity == Severity::Medium).count(),
                "low": findings.iter().filter(|f| f.severity == Severity::Low).count(),
                "info": findings.iter().filter(|f| f.severity == Severity::Info).count(),
            },
            "findings": findings,
        });

        let path = self.output_dir.join(format!("summary_{}.json", self.session_id));
        fs::create_dir_all(&self.output_dir)?;
        fs::write(&path, serde_json::to_string_pretty(&summary)?)?;
        info!("[+] JSON summary written to: {}", path.display());
        Ok(())
    }
}

/// Generates technical mitigation advice based on CVE patterns
fn generate_mitigation_advice(cve_id: &str) -> &'static str {
    match cve_id {
        id if id.contains("2021-44228") => {
            "Immediately upgrade Apache Log4j to >= 2.17.1. Remove JndiLookup class from classpath (zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class) or set -Dlog4j2.formatMsgNoLookups=true as an interim mitigative measure."
        }
        id if id.contains("2017-0144") => {
            "Disable SMBv1 across all domain controllers and member workstations (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol). Ensure Microsoft security bulletin MS17-010 is applied immediately."
        }
        id if id.contains("2014-0160") => {
            "Upgrade OpenSSL to >= 1.0.1g or recompile with -DOPENSSL_NO_HEARTBEATS. Revoke and reissue all SSL/TLS private keys and certificates associated with this server."
        }
        id if id.contains("2021-26855") => {
            "Deploy Microsoft Exchange Server Cumulative Updates (CU) immediately. Restrict external ingress to Exchange ECP/OWA interfaces via WAF or VPN."
        }
        id if id.contains("2019-0708") => {
            "Enable Network Level Authentication (NLA) on all RDP instances. Block inbound TCP port 3389 at perimeter firewalls. Apply Microsoft KB4499175."
        }
        id if id.contains("2020-1938") => {
            "Disable the AJP connector on port 8009 if unused, or set requiredSecret attribute and bind connector explicitly to 127.0.0.1 in Tomcat conf/server.xml."
        }
        id if id.contains("2024-6387") => {
            "Update OpenSSH server packages immediately (>= 9.8p1). Set LoginGraceTime to 0 in sshd_config as temporary workaround to prevent signal handler race conditions."
        }
        id if id.contains("2021-41773") => {
            "Upgrade Apache HTTP Server to version 2.4.51 or later. Ensure directory configuration enforces 'Require all denied' on root filesystem directories."
        }
        id if id.contains("2022-22965") => {
            "Upgrade Spring Framework to 5.3.18+ or 5.2.20+. If on Apache Tomcat, upgrade to Tomcat >= 10.0.20, 9.0.62, or 8.5.78 to restrict class loader access."
        }
        _ => {
            "Apply vendor software security updates immediately. Enforce principle of least privilege, restrict network exposure via firewall segmentation, and implement IDS/IPS detection signatures."
        }
    }
}
