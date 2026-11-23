use anyhow::{Context, Result};
use async_trait::async_trait;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::cve;
use crate::executor::{check_tool_available, run_command};
use crate::probe::{Probe, ProbeResult};
use crate::types::{AuditContext, Finding, FindingKind, Severity};

// ============================================================================
// PROBE 1: NucleiProbe
// ============================================================================

pub struct NucleiProbe {
    pub target: String,
}

impl NucleiProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for NucleiProbe {
    fn name(&self) -> &str {
        "nuclei"
    }

    fn timeout_secs(&self) -> u64 {
        600
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("nuclei") {
            warn!("[-] nuclei not found in PATH — skipping");
            return Ok(ProbeResult::skipped("nuclei", "nuclei binary not found"));
        }

        let target_url = ctx.get_url();
        info!("[*] Running nuclei scan against {}", target_url);

        let args = [
            "-u",
            &target_url,
            "-json",
            "-silent",
            "-severity",
            "critical,high,medium",
            "-no-color",
            "-rl",
            "50",
        ];

        let output = match run_command("nuclei", &args, self.timeout_secs()).await {
            Ok(out) => out,
            Err(e) => {
                warn!("[-] nuclei execution failed or timed out: {}", e);
                return Ok(ProbeResult::failed("nuclei", e.to_string()));
            }
        };

        let mut findings = Vec::new();

        let clean_stdout = crate::executor::strip_ansi_codes(&output.stdout);
        for line in clean_stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let val: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(e) => {
                    debug!("[-] nuclei: failed to parse json line: {} — error: {}", line, e);
                    continue;
                }
            };

            let template_id = val
                .get("template-id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let info_obj = val.get("info");
            let name = info_obj
                .and_then(|i| i.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or(&template_id)
                .to_string();

            let severity_str = info_obj
                .and_then(|i| i.get("severity"))
                .and_then(|v| v.as_str())
                .unwrap_or("info")
                .to_lowercase();

            let (severity, confidence) = match severity_str.as_str() {
                "critical" => (Severity::Critical, 0.95),
                "high" => (Severity::High, 0.90),
                "medium" => (Severity::Medium, 0.85),
                "low" => (Severity::Low, 0.80),
                _ => (Severity::Info, 0.70),
            };

            let matched_at = val
                .get("matched-at")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let mut tags = vec!["nuclei".to_string(), severity_str.clone()];
            if let Some(tag_list) = info_obj.and_then(|i| i.get("tags")).and_then(|t| t.as_array()) {
                for t in tag_list {
                    if let Some(ts) = t.as_str() {
                        tags.push(ts.to_string());
                    }
                }
            }

            let title = format!("[Nuclei] {} ({})", name, template_id);
            let description = format!(
                "Nuclei template '{}' matched at {}. Severity: {}.",
                template_id, matched_at, severity_str
            );

            let mut finding = Finding::new(
                "nuclei",
                &self.target,
                FindingKind::Vulnerability,
                severity,
                title,
                description,
                val,
                confidence,
            )
            .with_tags(tags);

            if !matched_at.is_empty() {
                finding = finding.with_metadata("matched_at", matched_at);
            }
            finding = finding.with_metadata("template_id", template_id);

            findings.push(finding);
        }

        info!("[+] nuclei: found {} findings", findings.len());
        Ok(ProbeResult::success("nuclei", findings))
    }
}

// ============================================================================
// PROBE 2: CveMatcher (Hybrid Nmap + Kaisen + NVD Engine)
// ============================================================================

pub struct CveMatcher {
    pub target: String,
}

impl CveMatcher {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for CveMatcher {
    fn name(&self) -> &str {
        "cve-matcher"
    }

    fn timeout_secs(&self) -> u64 {
        30 // In-memory indexed query, zero external process overhead
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if ctx.open_port_infos.is_empty() {
            warn!("[-] cve-matcher: no port/service info available (run nmap-services first)");
            return Ok(ProbeResult::skipped("cve-matcher", "No port infos available for correlation"));
        }

        // Initialize Hybrid CVE database (NVD + Kaisen + Builtin)
        let db = cve::CveDatabase::load_hybrid(ctx.kaisen_db_path.as_deref(), None);

        let mut findings = Vec::new();

        for port_info in &ctx.open_port_infos {
            // Match by CPE
            for cpe in &port_info.cpe {
                let matches = db.match_cpe(cpe);
                for m in matches {
                    let cve_entry = m.entry;
                    info!(
                        "[+] CVE match [{}]: {} (CVSS {:.1}) on port {}/{} (confidence {:.0}%)",
                        m.match_type, cve_entry.id, cve_entry.cvss_score, port_info.port, port_info.protocol, m.confidence * 100.0
                    );

                    let title = format!(
                        "CVE Match: {} (CVSS {:.1}) on port {}/{}",
                        cve_entry.id, cve_entry.cvss_score, port_info.port, port_info.protocol
                    );

                    let remediation = format!(
                        "Mitigation: Upgrade or patch product '{}' associated with CPE '{}'. Review advisory at: {}",
                        port_info.product.as_deref().unwrap_or("service"),
                        cpe,
                        cve_entry.references.first().map(|s| s.as_str()).unwrap_or("https://nvd.nist.gov")
                    );

                    let description = format!(
                        "CPE '{}' on port {}/{} matches {}. CVSS Base Score: {:.1}.\nDescription: {}\n{}",
                        cpe,
                        port_info.port,
                        port_info.protocol,
                        cve_entry.id,
                        cve_entry.cvss_score,
                        cve_entry.description,
                        remediation
                    );

                    let raw_data = serde_json::json!({
                        "cve_id": cve_entry.id,
                        "cvss_score": cve_entry.cvss_score,
                        "cvss_vector": cve_entry.cvss_vector,
                        "matched_cpe": cpe,
                        "match_type": m.match_type,
                        "port": port_info.port,
                        "protocol": port_info.protocol,
                        "service": port_info.service,
                        "product": port_info.product,
                        "version": port_info.version,
                        "published": cve_entry.published,
                        "references": cve_entry.references,
                    });

                    findings.push(
                        Finding::new(
                            "cve-matcher",
                            &self.target,
                            FindingKind::CveMatch,
                            cve_entry.severity(),
                            title,
                            description,
                            raw_data,
                            m.confidence,
                        )
                        .with_tags(vec![
                            "cve".to_string(),
                            "vulnerability".to_string(),
                            cve_entry.id.clone(),
                            format!("port-{}", port_info.port),
                        ]),
                    );
                }
            }

            // Fallback: Product & Version fuzzy match if CPE list was empty
            if let (Some(product), Some(version)) = (&port_info.product, &port_info.version) {
                if port_info.cpe.is_empty() {
                    let fuzzy_matches = db.search_by_product_name(product, version);
                    for m in fuzzy_matches.iter().take(5) {
                        let cve_entry = m.entry;
                        let title = format!(
                            "CVE Fuzzy Match: {} (CVSS {:.1}) on port {}/{}",
                            cve_entry.id, cve_entry.cvss_score, port_info.port, port_info.protocol
                        );

                        let description = format!(
                            "Product '{}' version '{}' on port {}/{} fuzzy-matched {}. CVSS: {:.1}. Verify banner accuracy manually.\nDescription: {}",
                            product, version, port_info.port, port_info.protocol,
                            cve_entry.id, cve_entry.cvss_score, cve_entry.description
                        );

                        let raw_data = serde_json::json!({
                            "cve_id": cve_entry.id,
                            "cvss_score": cve_entry.cvss_score,
                            "matched_product": product,
                            "matched_version": version,
                            "port": port_info.port,
                            "match_type": "fuzzy",
                        });

                        findings.push(
                            Finding::new(
                                "cve-matcher",
                                &self.target,
                                FindingKind::CveMatch,
                                cve_entry.severity(),
                                title,
                                description,
                                raw_data,
                                m.confidence,
                            )
                            .with_tags(vec![
                                "cve".to_string(),
                                "fuzzy-match".to_string(),
                                cve_entry.id.clone(),
                                format!("port-{}", port_info.port),
                            ]),
                        );
                    }
                }
            }
        }

        info!("[+] cve-matcher generated {} vulnerability correlation findings", findings.len());
        Ok(ProbeResult::success("cve-matcher", findings))
    }
}

// ============================================================================
// PROBE 3: Enum4linuxProbe
// ============================================================================

pub struct Enum4linuxProbe {
    pub target: String,
}

impl Enum4linuxProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for Enum4linuxProbe {
    fn name(&self) -> &str {
        "enum4linux-ng"
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.is_local()
    }

    fn timeout_secs(&self) -> u64 {
        180
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        let tool = if check_tool_available("enum4linux-ng") {
            "enum4linux-ng"
        } else if check_tool_available("enum4linux") {
            "enum4linux"
        } else {
            warn!("[-] enum4linux-ng / enum4linux not found in PATH — skipping");
            return Ok(ProbeResult::skipped("enum4linux-ng", "enum4linux binary not found"));
        };

        let tmp_file = tempfile::NamedTempFile::new()
            .context("Failed to create temporary file for enum4linux output")?;
        let tmp_path = tmp_file.path().to_string_lossy().to_string();

        let args = ["-A", "-oJ", &tmp_path, &self.target];
        let _ = run_command(tool, &args, self.timeout_secs()).await;

        let json_path = if Path::new(&tmp_path).exists()
            && fs::metadata(&tmp_path).map(|m| m.len() > 0).unwrap_or(false)
        {
            tmp_path.clone()
        } else {
            let alt = format!("{}.json", tmp_path);
            if Path::new(&alt).exists() {
                alt
            } else {
                tmp_path.clone()
            }
        };

        let content = match fs::read_to_string(&json_path) {
            Ok(c) if !c.trim().is_empty() => c,
            _ => {
                debug!("[-] enum4linux: no output file generated at {}", json_path);
                return Ok(ProbeResult::skipped("enum4linux-ng", "No output file generated"));
            }
        };

        if json_path != tmp_path && Path::new(&json_path).exists() {
            let _ = fs::remove_file(&json_path);
        }

        let json_val: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                warn!("[-] enum4linux: failed to parse JSON output: {}", e);
                return Ok(ProbeResult::failed("enum4linux-ng", e.to_string()));
            }
        };

        let mut findings = Vec::new();

        // 1. Users
        if let Some(users) = json_val.get("users").and_then(|v| v.as_object()) {
            for (uid, user_info) in users {
                let username = user_info
                    .get("username")
                    .and_then(|v| v.as_str())
                    .unwrap_or(uid);
                let full_name = user_info
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                findings.push(
                    Finding::new(
                        "enum4linux-ng",
                        &self.target,
                        FindingKind::SmbShare,
                        Severity::Medium,
                        format!("SMB User Enumerated: {}", username),
                        format!(
                            "Enumerated SMB user account '{}' (UID: {}, Name: '{}') on {}",
                            username, uid, full_name, self.target
                        ),
                        user_info.clone(),
                        0.9,
                    )
                    .with_tags(vec!["smb".into(), "user-enum".into(), username.to_string()])
                    .with_metadata("username", username)
                    .with_metadata("uid", uid),
                );
            }
        }

        // 2. Shares
        if let Some(shares) = json_val.get("shares").and_then(|v| v.as_object()) {
            for (share_name, share_info) in shares {
                let access = share_info
                    .get("access")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_uppercase();
                let share_type = share_info
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("Disk");

                let is_administrative = share_name.eq_ignore_ascii_case("IPC$")
                    || share_name.eq_ignore_ascii_case("ADMIN$");

                let (severity, has_access) = if access.contains("WRITE") {
                    (Severity::Critical, true)
                } else if access.contains("READ") {
                    if is_administrative {
                        (Severity::Low, true)
                    } else {
                        (Severity::High, true)
                    }
                } else if !access.is_empty() && !access.contains("NO ACCESS") {
                    (Severity::Medium, true)
                } else {
                    (Severity::Info, false)
                };

                if has_access && !is_administrative {
                    findings.push(
                        Finding::new(
                            "enum4linux-ng",
                            &self.target,
                            FindingKind::SmbShare,
                            severity,
                            format!("Accessible SMB Share: {} [{}]", share_name, access),
                            format!(
                                "SMB Share '{}' ({}) is accessible with permissions '{}' on target {}",
                                share_name, share_type, access, self.target
                            ),
                            share_info.clone(),
                            0.9,
                        )
                        .with_tags(vec!["smb".into(), "share".into(), share_name.to_string()])
                        .with_metadata("share", share_name)
                        .with_metadata("access", access),
                    );
                }
            }
        }

        // 3. OS Info
        if let Some(os_info) = json_val.get("os_info") {
            let os_desc = os_info
                .get("OS")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown Windows OS");
            findings.push(
                Finding::new(
                    "enum4linux-ng",
                    &self.target,
                    FindingKind::Service,
                    Severity::Info,
                    format!("SMB OS Fingerprinted: {}", os_desc),
                    format!("Target OS identified via SMB as '{}'", os_desc),
                    os_info.clone(),
                    0.85,
                )
                .with_tags(vec!["smb".into(), "os-fingerprint".into()]),
            );
        }

        info!("[+] enum4linux-ng completed with {} findings", findings.len());
        Ok(ProbeResult::success("enum4linux-ng", findings))
    }
}

// ============================================================================
// PROBE 4: NetExecProbe
// ============================================================================

pub struct NetExecProbe {
    pub target: String,
}

impl NetExecProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[async_trait]
impl Probe for NetExecProbe {
    fn name(&self) -> &str {
        "netexec"
    }

    fn is_applicable(&self, ctx: &AuditContext) -> bool {
        ctx.is_local()
    }

    fn timeout_secs(&self) -> u64 {
        120
    }

    async fn run(&self, _ctx: &AuditContext) -> Result<ProbeResult> {
        let bin = if check_tool_available("nxc") {
            "nxc"
        } else if check_tool_available("netexec") {
            "netexec"
        } else {
            warn!("[-] nxc / netexec not found in PATH — skipping");
            return Ok(ProbeResult::skipped("netexec", "netexec binary not found"));
        };

        info!("[*] Running {} SMB enumeration on {}", bin, self.target);
        let output = match run_command(bin, &["smb", &self.target, "--shares"], self.timeout_secs()).await {
            Ok(out) => out,
            Err(e) => {
                warn!("[-] {} execution failed: {}", bin, e);
                return Ok(ProbeResult::failed("netexec", e.to_string()));
            }
        };

        let mut findings = Vec::new();
        let mut in_shares_table = false;

        let clean_stdout = crate::executor::strip_ansi_codes(&output.stdout);
        for line in clean_stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if line.contains("[*]") && (line.contains("Windows") || line.contains("name:") || line.contains("domain:")) {
                findings.push(
                    Finding::new(
                        "netexec",
                        &self.target,
                        FindingKind::Service,
                        Severity::Info,
                        "SMB Target Details Discovered",
                        line.to_string(),
                        serde_json::json!({ "raw_line": line }),
                        0.95,
                    )
                    .with_tags(vec!["smb".into(), "discovery".into()]),
                );
            }

            if line.contains("[+]") {
                let is_pwn3d = line.to_lowercase().contains("pwn3d");
                let sev = if is_pwn3d {
                    Severity::Critical
                } else {
                    Severity::High
                };

                findings.push(
                    Finding::new(
                        "netexec",
                        &self.target,
                        FindingKind::Vulnerability,
                        sev,
                        "Null Session Authentication Successful",
                        format!(
                            "NetExec successfully established authenticated SMB null session on {}: {}",
                            self.target, line
                        ),
                        serde_json::json!({
                            "raw_line": line,
                            "pwn3d": is_pwn3d,
                        }),
                        0.95,
                    )
                    .with_tags(vec!["smb".into(), "null-session".into(), "auth".into()]),
                );
            }

            if line.contains("Share") && line.contains("Permissions") {
                in_shares_table = true;
                continue;
            }

            if in_shares_table {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.is_empty() {
                    continue;
                }

                let mut share_idx = None;
                for (idx, p) in parts.iter().enumerate() {
                    if *p == "ADMIN$" || *p == "C$" || *p == "IPC$" || *p == "SYSVOL" || *p == "NETLOGON" {
                        share_idx = Some(idx);
                        break;
                    }
                }

                let (share_name, perm, remark) = if let Some(idx) = share_idx {
                    let s_name = parts[idx];
                    let s_perm = parts.get(idx + 1).copied().unwrap_or("");
                    let s_rem = parts[idx + 2..].join(" ");
                    (s_name, s_perm, s_rem)
                } else if parts.len() >= 6 && parts[0] == "SMB" {
                    let s_name = parts[4];
                    let s_perm = parts[5];
                    let s_rem = parts[6..].join(" ");
                    (s_name, s_perm, s_rem)
                } else if parts.len() >= 2 {
                    let s_name = parts[0];
                    let s_perm = parts[1];
                    let s_rem = parts[2..].join(" ");
                    (s_name, s_perm, s_rem)
                } else {
                    continue;
                };

                let perm_upper = perm.to_uppercase();
                if perm_upper.contains("WRITE") {
                    findings.push(
                        Finding::new(
                            "netexec",
                            &self.target,
                            FindingKind::SmbShare,
                            Severity::Critical,
                            format!("Writable SMB Share: {}", share_name),
                            format!(
                                "SMB Share '{}' on {} has write permissions ({})! Remark: {}",
                                share_name, self.target, perm, remark
                            ),
                            serde_json::json!({
                                "share": share_name,
                                "permissions": perm,
                                "remark": remark,
                            }),
                            0.9,
                        )
                        .with_tags(vec!["smb".into(), "share".into(), "writable".into(), share_name.to_string()])
                        .with_metadata("share", share_name)
                        .with_metadata("permissions", perm),
                    );
                } else if perm_upper.contains("READ") {
                    let is_standard_sys = share_name.eq_ignore_ascii_case("IPC$")
                        || share_name.eq_ignore_ascii_case("ADMIN$")
                        || share_name.eq_ignore_ascii_case("SYSVOL");

                    let sev = if is_standard_sys {
                        Severity::Low
                    } else {
                        Severity::High
                    };

                    findings.push(
                        Finding::new(
                            "netexec",
                            &self.target,
                            FindingKind::SmbShare,
                            sev,
                            format!("Readable SMB Share: {}", share_name),
                            format!(
                                "SMB Share '{}' on {} is readable. Remark: {}",
                                share_name, self.target, remark
                            ),
                            serde_json::json!({
                                "share": share_name,
                                "permissions": perm,
                                "remark": remark,
                            }),
                            0.9,
                        )
                        .with_tags(vec!["smb".into(), "share".into(), share_name.to_string()])
                        .with_metadata("share", share_name)
                        .with_metadata("permissions", perm),
                    );
                }
            }
        }

        info!("[+] netexec completed with {} findings", findings.len());
        Ok(ProbeResult::success("netexec", findings))
    }
}
