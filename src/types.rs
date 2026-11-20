use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use uuid::Uuid;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditMode {
    Target,
    Local,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    OpenPort,
    Service,
    Vulnerability,
    Subdomain,
    DnsRecord,
    TlsWeakness,
    HttpHeader,
    DirectoryFound,
    WafDetected,
    SmbShare,
    CveMatch,
    NetworkHost,
    ZoneTransfer,
    WebTechnology,
    MisconfiguredHeader,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub source_tool: String,
    pub target: String,
    pub kind: FindingKind,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub raw_data: serde_json::Value,
    pub confidence: f32,
    pub timestamp: DateTime<Utc>,
    pub tags: Vec<String>,
    pub metadata: HashMap<String, String>,
}

impl Finding {
    pub fn new(
        source_tool: impl Into<String>,
        target: impl Into<String>,
        kind: FindingKind,
        severity: Severity,
        title: impl Into<String>,
        description: impl Into<String>,
        raw_data: serde_json::Value,
        confidence: f32,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            source_tool: source_tool.into(),
            target: target.into(),
            kind,
            severity,
            title: title.into(),
            description: description.into(),
            raw_data,
            confidence,
            timestamp: Utc::now(),
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub version: Option<String>,
    pub product: Option<String>,
    pub extra_info: Option<String>,
    pub cpe: Vec<String>,
    pub scripts: Vec<NmapScript>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NmapScript {
    pub id: String,
    pub output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHost {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub ports: Vec<PortInfo>,
    pub os_guess: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub name: String,
    pub value: String,
    pub ttl: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub target: String,
    pub cert_valid: bool,
    pub cert_expires: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_subject: Option<String>,
    pub weak_ciphers: Vec<String>,
    pub vulnerabilities: Vec<TlsVuln>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsVuln {
    pub id: String,
    pub severity: String,
    pub finding: String,
}

#[derive(Debug, Clone)]
pub struct AuditContext {
    pub mode: AuditMode,
    pub target: String,
    pub base_url: Option<String>,
    pub open_ports: Vec<u16>,
    pub open_port_infos: Vec<PortInfo>,
    pub subdomains: Vec<String>,
    pub live_hosts: Vec<NetworkHost>,
    pub dns_records: Vec<DnsRecord>,
    pub tls_info: Option<TlsInfo>,
    pub waf_detected: bool,
    pub waf_name: Option<String>,
    pub technologies: Vec<String>,
    pub findings: Vec<Finding>,
    pub wordlist_path: Option<String>,
    pub proxy: Option<String>,
    pub kaisen_db_path: Option<String>,
    pub resolved_ips: Vec<String>,
    pub output_dir: String,
    pub session_id: Uuid,
    pub start_time: DateTime<Utc>,
}

impl AuditContext {
    pub fn new(mode: AuditMode, target: impl Into<String>, output_dir: impl Into<String>) -> Self {
        let target = target.into();
        let base_url = if target.starts_with("http://") || target.starts_with("https://") {
            Some(target.clone())
        } else {
            None
        };
        Self {
            mode,
            target,
            base_url,
            open_ports: Vec::new(),
            open_port_infos: Vec::new(),
            subdomains: Vec::new(),
            live_hosts: Vec::new(),
            dns_records: Vec::new(),
            tls_info: None,
            waf_detected: false,
            waf_name: None,
            technologies: Vec::new(),
            findings: Vec::new(),
            wordlist_path: None,
            proxy: None,
            kaisen_db_path: None,
            resolved_ips: Vec::new(),
            output_dir: output_dir.into(),
            session_id: Uuid::new_v4(),
            start_time: Utc::now(),
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn add_findings(&mut self, findings: Vec<Finding>) {
        self.findings.extend(findings);
    }

    pub fn get_url(&self) -> String {
        self.base_url.clone().unwrap_or_else(|| format!("https://{}", self.target))
    }

    pub fn ports_as_csv(&self) -> String {
        self.open_ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
    }

    pub fn is_local(&self) -> bool {
        self.mode == AuditMode::Local
    }
}
