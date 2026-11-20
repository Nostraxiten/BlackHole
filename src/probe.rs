use anyhow::Result;
use async_trait::async_trait;
use crate::types::{AuditContext, DnsRecord, Finding, PortInfo, TlsInfo};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeStatus {
    Success,
    Skipped(String),
    Warning(String),
    Failed(String),
}

impl std::fmt::Display for ProbeStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeStatus::Success => write!(f, "SUCCESS"),
            ProbeStatus::Skipped(reason) => write!(f, "SKIPPED: {}", reason),
            ProbeStatus::Warning(msg) => write!(f, "WARNING: {}", msg),
            ProbeStatus::Failed(err) => write!(f, "FAILED: {}", err),
        }
    }
}

/// Structured execution result of an individual probe.
/// Decouples execution findings and context mutations from shared mutable references,
/// enabling safe, lock-free parallel execution inside a JoinSet.
#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub probe_name: String,
    pub status: ProbeStatus,
    pub findings: Vec<Finding>,
    pub new_ports: Vec<u16>,
    pub new_port_infos: Vec<PortInfo>,
    pub new_subdomains: Vec<String>,
    pub new_resolved_ips: Vec<String>,
    pub new_dns_records: Vec<DnsRecord>,
    pub waf_detected: Option<bool>,
    pub waf_name: Option<String>,
    pub new_technologies: Vec<String>,
    pub tls_info: Option<TlsInfo>,
}

impl ProbeResult {
    pub fn success(probe_name: impl Into<String>, findings: Vec<Finding>) -> Self {
        Self {
            probe_name: probe_name.into(),
            status: ProbeStatus::Success,
            findings,
            new_ports: Vec::new(),
            new_port_infos: Vec::new(),
            new_subdomains: Vec::new(),
            new_resolved_ips: Vec::new(),
            new_dns_records: Vec::new(),
            waf_detected: None,
            waf_name: None,
            new_technologies: Vec::new(),
            tls_info: None,
        }
    }

    pub fn failed(probe_name: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            probe_name: probe_name.into(),
            status: ProbeStatus::Failed(error.into()),
            findings: Vec::new(),
            new_ports: Vec::new(),
            new_port_infos: Vec::new(),
            new_subdomains: Vec::new(),
            new_resolved_ips: Vec::new(),
            new_dns_records: Vec::new(),
            waf_detected: None,
            waf_name: None,
            new_technologies: Vec::new(),
            tls_info: None,
        }
    }

    pub fn skipped(probe_name: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            probe_name: probe_name.into(),
            status: ProbeStatus::Skipped(reason.into()),
            findings: Vec::new(),
            new_ports: Vec::new(),
            new_port_infos: Vec::new(),
            new_subdomains: Vec::new(),
            new_resolved_ips: Vec::new(),
            new_dns_records: Vec::new(),
            waf_detected: None,
            waf_name: None,
            new_technologies: Vec::new(),
            tls_info: None,
        }
    }

    pub fn with_ports(mut self, ports: Vec<u16>) -> Self {
        self.new_ports = ports;
        self
    }

    pub fn with_port_infos(mut self, port_infos: Vec<PortInfo>) -> Self {
        self.new_port_infos = port_infos;
        self
    }

    pub fn with_subdomains(mut self, subdomains: Vec<String>) -> Self {
        self.new_subdomains = subdomains;
        self
    }

    pub fn with_resolved_ips(mut self, ips: Vec<String>) -> Self {
        self.new_resolved_ips = ips;
        self
    }

    pub fn with_dns_records(mut self, records: Vec<DnsRecord>) -> Self {
        self.new_dns_records = records;
        self
    }

    pub fn with_waf(mut self, detected: bool, name: Option<String>) -> Self {
        self.waf_detected = Some(detected);
        self.waf_name = name;
        self
    }

    pub fn with_technologies(mut self, techs: Vec<String>) -> Self {
        self.new_technologies = techs;
        self
    }

    pub fn with_tls_info(mut self, tls: TlsInfo) -> Self {
        self.tls_info = Some(tls);
        self
    }
}

#[async_trait]
pub trait Probe: Send + Sync + 'static {
    fn name(&self) -> &str;
    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult>;

    fn is_applicable(&self, _ctx: &AuditContext) -> bool {
        true
    }

    fn timeout_secs(&self) -> u64 {
        300
    }
}

impl AuditContext {
    /// Merges mutated state and discoveries from a ProbeResult into the global context
    pub fn apply_probe_result(&mut self, res: ProbeResult) {
        for p in res.new_ports {
            if !self.open_ports.contains(&p) {
                self.open_ports.push(p);
            }
        }
        self.open_ports.sort();
        self.open_ports.dedup();

        for pi in res.new_port_infos {
            if let Some(existing) = self.open_port_infos.iter_mut().find(|p| p.port == pi.port && p.protocol == pi.protocol) {
                if pi.service.is_some() { existing.service = pi.service; }
                if pi.version.is_some() { existing.version = pi.version; }
                if pi.product.is_some() { existing.product = pi.product; }
                if pi.extra_info.is_some() { existing.extra_info = pi.extra_info; }
                for cpe in pi.cpe {
                    if !existing.cpe.contains(&cpe) { existing.cpe.push(cpe); }
                }
            } else {
                self.open_port_infos.push(pi);
            }
        }

        for s in res.new_subdomains {
            if !self.subdomains.contains(&s) {
                self.subdomains.push(s);
            }
        }
        self.subdomains.sort();
        self.subdomains.dedup();

        for ip in res.new_resolved_ips {
            if !self.resolved_ips.contains(&ip) {
                self.resolved_ips.push(ip);
            }
        }
        self.resolved_ips.sort();
        self.resolved_ips.dedup();

        for d in res.new_dns_records {
            self.dns_records.push(d);
        }

        if let Some(detected) = res.waf_detected {
            self.waf_detected = detected;
        }
        if let Some(name) = res.waf_name {
            self.waf_name = Some(name);
        }

        for t in res.new_technologies {
            if !self.technologies.contains(&t) {
                self.technologies.push(t);
            }
        }

        if let Some(tls) = res.tls_info {
            self.tls_info = Some(tls);
        }

        self.findings.extend(res.findings);
    }
}
