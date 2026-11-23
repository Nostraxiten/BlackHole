use anyhow::Result;
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
        fs::create_dir_all(&self.output_dir)?;
        self.generate_html(findings, target, mode)?;
        self.generate_markdown(findings, target, mode)?;
        self.generate_json_summary(findings, target, mode)?;
        Ok(())
    }

    fn generate_html(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        let audit_mode = mode.unwrap_or("Target Audit");
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        // ---- Severity counters ----
        let count_sev = |s: &Severity| findings.iter().filter(|f| &f.severity == s).count();
        let crit   = count_sev(&Severity::Critical);
        let high   = count_sev(&Severity::High);
        let med    = count_sev(&Severity::Medium);
        let low    = count_sev(&Severity::Low);
        let info_c = count_sev(&Severity::Info);
        let total  = findings.len();

        // Posture Score calculation (0 to 100, where 100 is pristine)
        let risk_penalty = (crit * 30) + (high * 15) + (med * 5) + (low * 2);
        let posture_score = if risk_penalty >= 100 { 0 } else { 100 - risk_penalty };
        let (posture_grade, posture_color) = match posture_score {
            90..=100 => ("A (LOW RISK)", "var(--info)"),
            75..=89  => ("B (MODERATE)", "var(--low)"),
            50..=74  => ("C (ELEVATED)", "var(--med)"),
            25..=49  => ("D (HIGH RISK)", "var(--high)"),
            _        => ("F (CRITICAL)", "var(--crit)"),
        };

        // ---- Open Ports & Services ----
        let mut ports: Vec<(u16, String, String, String, String)> = Vec::new(); // (port, proto, service, version, scripts)
        for f in findings {
            if matches!(f.kind, FindingKind::OpenPort | FindingKind::Service) || f.raw_data.get("port").is_some() {
                if let Some(p) = f.raw_data.get("port").and_then(|v| v.as_u64()) {
                    let proto   = f.raw_data.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
                    let service = f.raw_data.get("service").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                    let version = f.raw_data.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    let scripts = f.raw_data.get("scripts").map(|s| s.to_string()).unwrap_or_default();
                    ports.push((p as u16, proto, service, version, scripts));
                }
            }
        }
        ports.sort_by_key(|p| p.0);
        ports.dedup_by_key(|p| (p.0, p.1.clone()));

        // ---- Vulnerabilities / CVE matches ----
        let mut vuln_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind,
                FindingKind::Vulnerability | FindingKind::CveMatch |
                FindingKind::TlsWeakness | FindingKind::MisconfiguredHeader |
                FindingKind::ZoneTransfer | FindingKind::InsecureCookie |
                FindingKind::CorsMisconfiguration))
            .collect();
        vuln_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        // High & Critical priorities for Quick-Win table
        let important_findings: Vec<&Finding> = vuln_findings.iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .copied()
            .collect();

        // ---- Subdomains list ----
        let subdomains: Vec<&str> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::Subdomain))
            .map(|f| f.target.as_str())
            .collect();

        // ---- DNS Records ----
        let dns_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::DnsRecord))
            .collect();

        // ---- WAF Detection ----
        let waf_finding = findings.iter().find(|f| matches!(f.kind, FindingKind::WafDetected));
        let waf_name = waf_finding.and_then(|f| f.raw_data.get("firewall").and_then(|v| v.as_str()))
            .or_else(|| waf_finding.map(|f| f.title.trim_start_matches("WAF Detected: ")));

        // ---- TLS Issues ----
        let tls_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::TlsWeakness))
            .collect();

        // ---- Cookie Issues ----
        let cookie_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::InsecureCookie))
            .collect();

        // ---- Security Header Findings ----
        let header_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::MisconfiguredHeader | FindingKind::InformationDisclosure | FindingKind::CorsMisconfiguration))
            .collect();

        let sev_badge = |s: &Severity| match s {
            Severity::Critical => r#"<span class="badge crit">CRITICAL</span>"#,
            Severity::High     => r#"<span class="badge high">HIGH</span>"#,
            Severity::Medium   => r#"<span class="badge med">MEDIUM</span>"#,
            Severity::Low      => r#"<span class="badge low">LOW</span>"#,
            Severity::Info     => r#"<span class="badge info">INFO</span>"#,
        };

        let mut h = String::with_capacity(128 * 1024);

        // Header & CSS
        h.push_str(&format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BlackHole Security Audit — {target}</title>
<style>
  :root {{
    --bg: #090d16;
    --card-bg: #111827;
    --card-hover: #1e293b;
    --border: #1f2937;
    --text: #f3f4f6;
    --text-muted: #9ca3af;
    --accent: #38bdf8;
    --accent-glow: rgba(56, 189, 248, 0.25);
    --crit: #f43f5e;
    --high: #fb923c;
    --med: #c084fc;
    --low: #60a5fa;
    --info: #34d399;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  code {{
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.1);
    padding: 2px 6px;
    border-radius: 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
    font-size: 12px;
  }}
  header {{
    background: rgba(17, 24, 39, 0.9);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border);
    padding: 20px 32px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    position: sticky;
    top: 0;
    z-index: 100;
  }}
  .logo {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .logo-icon {{
    width: 32px;
    height: 32px;
    background: radial-gradient(circle, var(--accent) 0%, transparent 70%);
    border-radius: 50%;
    border: 2px solid var(--accent);
    box-shadow: 0 0 15px var(--accent-glow);
  }}
  .logo h1 {{
    font-size: 18px;
    font-weight: 800;
    letter-spacing: 1.5px;
    color: #fff;
  }}
  .logo span {{ color: var(--accent); font-weight: 400; font-size: 14px; }}
  .header-actions {{ display: flex; gap: 10px; align-items: center; }}
  .btn {{
    background: var(--card-bg);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 8px 14px;
    border-radius: 6px;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
  }}
  .btn:hover {{
    background: var(--card-hover);
    border-color: var(--accent);
    color: var(--accent);
  }}
  .btn-accent {{
    background: var(--accent);
    color: #000;
    border-color: var(--accent);
  }}
  .btn-accent:hover {{
    background: #7dd3fc;
    color: #000;
  }}
  /* Nav Tabs */
  .nav-tabs {{
    display: flex;
    gap: 4px;
    background: #0f172a;
    border-bottom: 1px solid var(--border);
    padding: 0 32px;
    overflow-x: auto;
  }}
  .tab-btn {{
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: var(--text-muted);
    padding: 14px 18px;
    font-size: 13px;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s ease;
    white-space: nowrap;
  }}
  .tab-btn:hover {{ color: var(--text); }}
  .tab-btn.active {{
    color: var(--accent);
    border-bottom-color: var(--accent);
    background: rgba(56, 189, 248, 0.05);
  }}
  .wrap {{ max-width: 1400px; margin: 0 auto; padding: 28px 32px; }}
  .tab-content {{ display: none; }}
  .tab-content.active {{ display: block; }}
  /* Grid & Cards */
  .grid-cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 16px;
    margin-bottom: 28px;
  }}
  .card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px;
    text-align: center;
    transition: transform 0.2s, border-color 0.2s;
  }}
  .card:hover {{ border-color: rgba(255,255,255,0.2); transform: translateY(-2px); }}
  .card .num {{ font-size: 38px; font-weight: 800; line-height: 1.1; margin-bottom: 4px; }}
  .card .lbl {{ font-size: 11px; font-weight: 700; letter-spacing: 0.08em; color: var(--text-muted); }}
  .num.crit {{ color: var(--crit); text-shadow: 0 0 12px rgba(244, 63, 94, 0.4); }}
  .num.high {{ color: var(--high); text-shadow: 0 0 12px rgba(251, 146, 60, 0.4); }}
  .num.med  {{ color: var(--med); }}
  .num.low  {{ color: var(--low); }}
  .num.info {{ color: var(--info); }}
  /* Posture Banner */
  .posture-banner {{
    background: linear-gradient(135deg, rgba(17,24,39,0.9), rgba(30,41,59,0.9));
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    margin-bottom: 28px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 20px;
  }}
  .posture-left {{ display: flex; align-items: center; gap: 20px; }}
  .posture-score {{
    width: 72px;
    height: 72px;
    border-radius: 50%;
    border: 4px solid {posture_color};
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 26px;
    font-weight: 800;
    color: {posture_color};
    box-shadow: 0 0 18px rgba(0,0,0,0.5);
  }}
  .posture-details h2 {{ font-size: 18px; font-weight: 700; margin-bottom: 4px; }}
  .posture-details p {{ font-size: 13px; color: var(--text-muted); }}
  /* Badges */
  .badge {{
    display: inline-block;
    padding: 3px 9px;
    border-radius: 12px;
    font-size: 10px;
    font-weight: 800;
    letter-spacing: 0.05em;
  }}
  .badge.crit {{ background: rgba(244,63,94,0.18); color: var(--crit); border: 1px solid rgba(244,63,94,0.3); }}
  .badge.high {{ background: rgba(251,146,60,0.18); color: var(--high); border: 1px solid rgba(251,146,60,0.3); }}
  .badge.med  {{ background: rgba(192,132,252,0.18); color: var(--med); border: 1px solid rgba(192,132,252,0.3); }}
  .badge.low  {{ background: rgba(96,165,250,0.18); color: var(--low); border: 1px solid rgba(96,165,250,0.3); }}
  .badge.info {{ background: rgba(52,211,153,0.18); color: var(--info); border: 1px solid rgba(52,211,153,0.3); }}
  /* Search & Controls */
  .filter-bar {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 12px;
    margin-bottom: 18px;
  }}
  .search-box {{
    flex: 1;
    min-width: 250px;
    max-width: 450px;
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 8px 14px;
    color: #fff;
    font-size: 13px;
    outline: none;
  }}
  .search-box:focus {{ border-color: var(--accent); box-shadow: 0 0 8px var(--accent-glow); }}
  .pill-group {{ display: flex; gap: 6px; flex-wrap: wrap; }}
  .pill {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 4px 12px;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
    color: var(--text-muted);
    transition: all 0.2s;
  }}
  .pill:hover {{ color: var(--text); border-color: var(--accent); }}
  .pill.active {{ background: var(--accent); color: #000; border-color: var(--accent); }}
  /* Tables */
  .table-card {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
    margin-bottom: 28px;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{
    background: rgba(0,0,0,0.3);
    color: var(--text-muted);
    text-align: left;
    padding: 12px 16px;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .port-num {{ font-family: monospace; font-size: 14px; font-weight: 800; color: var(--accent); }}
  /* Detail Accordion / Card */
  .finding-item {{
    background: var(--card-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 18px 22px;
    margin-bottom: 14px;
    transition: border-color 0.2s;
  }}
  .finding-item:hover {{ border-color: rgba(255,255,255,0.25); }}
  .finding-head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px; gap: 14px; }}
  .finding-title {{ font-size: 15px; font-weight: 700; color: #fff; }}
  .finding-meta {{ font-size: 12px; color: var(--text-muted); margin-bottom: 10px; display: flex; gap: 16px; flex-wrap: wrap; }}
  .finding-desc {{ font-size: 13px; line-height: 1.6; margin-bottom: 12px; }}
  .remediation-box {{
    background: rgba(56, 189, 248, 0.08);
    border-left: 3px solid var(--accent);
    padding: 10px 14px;
    border-radius: 0 6px 6px 0;
    font-size: 12px;
  }}
  .remediation-box strong {{ color: var(--accent); }}
  .chip {{
    display: inline-block;
    background: rgba(56,189,248,0.1);
    color: var(--accent);
    border: 1px solid rgba(56,189,248,0.2);
    border-radius: 4px;
    padding: 3px 8px;
    font-size: 11px;
    margin: 3px;
    font-family: monospace;
  }}
  footer {{
    text-align: center;
    padding: 32px;
    color: var(--text-muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 40px;
  }}
  /* Toast Notification */
  #toast {{
    visibility: hidden;
    min-width: 200px;
    background-color: var(--card-hover);
    color: var(--accent);
    text-align: center;
    border-radius: 6px;
    border: 1px solid var(--accent);
    padding: 10px 16px;
    position: fixed;
    z-index: 1000;
    left: 50%;
    bottom: 30px;
    transform: translateX(-50%);
    font-weight: 600;
    font-size: 13px;
  }}
  #toast.show {{ visibility: visible; animation: fadein 0.3s, fadeout 0.3s 2.5s; }}
  @keyframes fadein {{ from {{ bottom: 0; opacity: 0; }} to {{ bottom: 30px; opacity: 1; }} }}
  @keyframes fadeout {{ from {{ bottom: 30px; opacity: 1; }} to {{ bottom: 0; opacity: 0; }} }}
  @media print {{
    header, .nav-tabs, .header-actions, .filter-bar {{ display: none !important; }}
    .tab-content {{ display: block !important; margin-bottom: 40px; }}
    body {{ background: #fff !important; color: #000 !important; }}
    .card, .table-card, .finding-item {{ background: #fff !important; border-color: #ddd !important; color: #000 !important; }}
  }}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon"></div>
    <div>
      <h1>BLACKHOLE <span>/ SECURITY AUDIT</span></h1>
    </div>
  </div>
  <div class="header-actions">
    <button class="btn" onclick="copySessionId('{session}')">Copy Session ID</button>
    <button class="btn btn-accent" onclick="window.print()">Print / Export PDF</button>
  </div>
</header>

<div class="nav-tabs">
  <button class="tab-btn active" onclick="openTab('tab-overview', this)">Overview &amp; Posture</button>
  <button class="tab-btn" onclick="openTab('tab-ports', this)">Attack Surface ({port_count})</button>
  <button class="tab-btn" onclick="openTab('tab-vulns', this)">Vulnerabilities &amp; CVEs ({vuln_count})</button>
  <button class="tab-btn" onclick="openTab('tab-web', this)">Web &amp; Headers ({header_count})</button>
  <button class="tab-btn" onclick="openTab('tab-dns', this)">DNS &amp; OSINT ({dns_count})</button>
  <button class="tab-btn" onclick="openTab('tab-evidence', this)">Raw Evidence ({total_count})</button>
</div>

<div class="wrap">
"#,
            target = target,
            session = self.session_id,
            posture_color = posture_color,
            port_count = ports.len(),
            vuln_count = vuln_findings.len(),
            header_count = header_findings.len() + cookie_findings.len(),
            dns_count = dns_findings.len(),
            total_count = total,
        ));

        // =====================================================================
        // TAB 1: EXECUTIVE OVERVIEW & POSTURE
        // =====================================================================
        h.push_str(r#"<div id="tab-overview" class="tab-content active">"#);

        // Posture Banner
        h.push_str(&format!(r#"
<div class="posture-banner">
  <div class="posture-left">
    <div class="posture-score">{score}</div>
    <div class="posture-details">
      <h2>Security Posture Grade: {grade}</h2>
      <p>Target: <code>{target}</code> &nbsp;|&nbsp; Mode: <strong>{mode}</strong> &nbsp;|&nbsp; Audit Date: {ts}</p>
    </div>
  </div>
  <div>
    <strong>Session ID:</strong> <code>{session}</code>
  </div>
</div>
"#,
            score = posture_score,
            grade = posture_grade,
            target = html_escape(target),
            mode = audit_mode,
            ts = timestamp,
            session = self.session_id,
        ));

        // Severity Metric Cards
        h.push_str("<div class=\"grid-cards\">\n");
        h.push_str(&format!(r#"<div class="card"><div class="num crit">{crit}</div><div class="lbl">CRITICAL</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num high">{high}</div><div class="lbl">HIGH</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num med">{med}</div><div class="lbl">MEDIUM</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num low">{low}</div><div class="lbl">LOW</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num info">{info_c}</div><div class="lbl">INFORMATIONAL</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num" style="color:var(--text)">{total}</div><div class="lbl">TOTAL FINDINGS</div></div>"#));
        h.push_str("</div>\n");

        // Target Summary Property Table
        h.push_str(r#"<div class="table-card">
<table>
  <thead>
    <tr><th style="width: 240px">Audited Perimeter Attribute</th><th>Observed Configuration &amp; Status</th></tr>
  </thead>
  <tbody>"#);
        h.push_str(&format!("<tr><td>Primary Target Host</td><td><code>{}</code></td></tr>", html_escape(target)));
        h.push_str(&format!("<tr><td>Web Application Firewall (WAF)</td><td>{}</td></tr>",
            waf_name.map(|w| format!("<span style='color:var(--high); font-weight:700'>Detected: {}</span>", html_escape(w)))
                    .unwrap_or_else(|| "<span style='color:var(--info)'>None detected / Direct origin reachable</span>".to_string())));
        h.push_str(&format!("<tr><td>Open Ports Confirmed</td><td><code>{}</code> open listening ports discovered</td></tr>", ports.len()));
        h.push_str(&format!("<tr><td>Discovered Subdomains</td><td><code>{}</code> distinct subdomains recorded</td></tr>", subdomains.len()));
        h.push_str(&format!("<tr><td>TLS Weaknesses</td><td><code>{}</code> cipher/protocol/certificate findings</td></tr>", tls_findings.len()));
        h.push_str(&format!("<tr><td>Insecure Cookies</td><td><code>{}</code> session/tracking cookies missing security flags</td></tr>", cookie_findings.len()));
        h.push_str("</tbody></table></div>\n");

        // Top Priority Actionable Items
        if !important_findings.is_empty() {
            h.push_str("<h2>Top Priority Remediation Actions</h2><br>\n");
            for f in &important_findings {
                let cve_id = f.raw_data.get("cve_id").and_then(|v| v.as_str())
                    .or_else(|| f.raw_data.get("cve").and_then(|v| v.as_str()))
                    .unwrap_or("—");
                let cvss = f.raw_data.get("cvss_score").and_then(|v| v.as_f64());
                let advice = generate_mitigation_advice(cve_id);

                h.push_str(&format!(r#"
<div class="finding-item">
  <div class="finding-head">
    <div class="finding-title">{title}</div>
    {badge}
  </div>
  <div class="finding-meta">
    <span>Asset: <code>{tgt}</code></span>
    <span>Source: <code>{tool}</code></span>
    {cvss_part}
    {cve_part}
  </div>
  <div class="finding-desc">{desc}</div>
  <div class="remediation-box">
    <strong>Actionable Fix:</strong> {advice}
  </div>
</div>
"#,
                    title = html_escape(&f.title),
                    badge = sev_badge(&f.severity),
                    tgt = html_escape(&f.target),
                    tool = html_escape(&f.source_tool),
                    cvss_part = cvss.map(|s| format!("<span>CVSS: <strong>{:.1}</strong></span>", s)).unwrap_or_default(),
                    cve_part = if cve_id != "—" {
                        format!("<span>CVE: <a href='https://nvd.nist.gov/vuln/detail/{id}' target='_blank'><strong>{id}</strong></a></span>", id = html_escape(cve_id))
                    } else { String::new() },
                    desc = html_escape(&f.description),
                    advice = advice,
                ));
            }
        }

        h.push_str("</div>\n"); // End Tab 1

        // =====================================================================
        // TAB 2: ATTACK SURFACE & PORTS
        // =====================================================================
        h.push_str(r#"<div id="tab-ports" class="tab-content">"#);
        h.push_str(r#"
<div class="filter-bar">
  <input type="text" id="portSearch" class="search-box" placeholder="Filter ports, protocols, services, or versions..." onkeyup="filterTable('portSearch', 'portTable')">
  <div style="font-size:12px; color:var(--text-muted)">Showing all verified listening endpoints</div>
</div>
<div class="table-card">
<table id="portTable">
  <thead>
    <tr>
      <th style="width: 100px">Port</th>
      <th style="width: 100px">Protocol</th>
      <th style="width: 160px">Service</th>
      <th>Product &amp; Version Banner</th>
      <th>NSE Scripts / Extra Info</th>
    </tr>
  </thead>
  <tbody>
"#);
        if ports.is_empty() {
            h.push_str("<tr><td colspan='5' style='text-align:center; color:var(--text-muted); padding:24px'>No open ports detected on target.</td></tr>");
        } else {
            for (port, proto, service, version, scripts) in &ports {
                let scripts_html = if !scripts.is_empty() && scripts != "[]" {
                    format!("<code>{}</code>", html_escape(scripts))
                } else {
                    "—".to_string()
                };
                h.push_str(&format!(
                    "<tr><td><span class='port-num'>{port}</span></td><td>{proto}</td><td><strong>{svc}</strong></td><td>{ver}</td><td>{scripts}</td></tr>\n",
                    port = port,
                    proto = proto,
                    svc = html_escape(service),
                    ver = if version.is_empty() { "—" } else { version },
                    scripts = scripts_html,
                ));
            }
        }
        h.push_str("</tbody></table></div></div>\n"); // End Tab 2

        // =====================================================================
        // TAB 3: VULNERABILITIES & CVE MATRIX
        // =====================================================================
        h.push_str(r#"<div id="tab-vulns" class="tab-content">"#);
        h.push_str(r#"
<div class="filter-bar">
  <input type="text" id="vulnSearch" class="search-box" placeholder="Search vulnerabilities, CVE ID, keyword, or asset..." onkeyup="filterVulnCards()">
  <div class="pill-group">
    <button class="pill active" onclick="filterBySev('all', this)">All</button>
    <button class="pill" onclick="filterBySev('critical', this)">Critical</button>
    <button class="pill" onclick="filterBySev('high', this)">High</button>
    <button class="pill" onclick="filterBySev('medium', this)">Medium</button>
    <button class="pill" onclick="filterBySev('low', this)">Low</button>
  </div>
</div>
<div id="vulnList">
"#);
        if vuln_findings.is_empty() {
            h.push_str("<div class='card' style='padding:32px; color:var(--text-muted)'>No vulnerabilities or CVE matches identified.</div>");
        } else {
            for f in &vuln_findings {
                let cve_id = f.raw_data.get("cve_id").and_then(|v| v.as_str())
                    .or_else(|| f.raw_data.get("cve").and_then(|v| v.as_str()))
                    .unwrap_or("—");
                let cvss = f.raw_data.get("cvss_score").and_then(|v| v.as_f64());
                let sev_str = f.severity.to_string().to_lowercase();
                let advice = generate_mitigation_advice(cve_id);

                let is_exploit = f.raw_data.get("is_exploit").and_then(|v| v.as_bool()).unwrap_or(false)
                    || f.title.contains("EXPLOIT");

                let exploit_badge = if is_exploit {
                    r#"<span class="badge crit" style="margin-left:6px">EXPLOIT READY</span>"#
                } else {
                    ""
                };

                h.push_str(&format!(r#"
<div class="finding-item vuln-card" data-severity="{sev}">
  <div class="finding-head">
    <div class="finding-title">{title} {exploit_badge}</div>
    {badge}
  </div>
  <div class="finding-meta">
    <span>Asset: <code>{tgt}</code></span>
    <span>Tool: <code>{tool}</code></span>
    {cvss_part}
    {cve_part}
  </div>
  <div class="finding-desc">{desc}</div>
  <div class="remediation-box">
    <strong>Remediation Recommendation:</strong> {advice}
  </div>
</div>
"#,
                    sev = sev_str,
                    title = html_escape(&f.title),
                    exploit_badge = exploit_badge,
                    badge = sev_badge(&f.severity),
                    tgt = html_escape(&f.target),
                    tool = html_escape(&f.source_tool),
                    cvss_part = cvss.map(|s| format!("<span>CVSS: <strong>{:.1}</strong></span>", s)).unwrap_or_default(),
                    cve_part = if cve_id != "—" {
                        format!("<span>CVE: <a href='https://nvd.nist.gov/vuln/detail/{id}' target='_blank'><strong>{id}</strong></a></span>", id = html_escape(cve_id))
                    } else { String::new() },
                    desc = html_escape(&f.description),
                    advice = advice,
                ));
            }
        }
        h.push_str("</div></div>\n"); // End Tab 3

        // =====================================================================
        // TAB 4: WEB & HEADERS INTELLIGENCE
        // =====================================================================
        h.push_str(r#"<div id="tab-web" class="tab-content">"#);
        h.push_str("<h2>Web Infrastructure &amp; Security Headers</h2><br>\n");

        if header_findings.is_empty() && cookie_findings.is_empty() {
            h.push_str("<div class='card' style='padding:24px; color:var(--text-muted)'>No web services or HTTP headers recorded.</div>");
        } else {
            h.push_str(r#"<div class="table-card">
<table>
  <thead>
    <tr><th>Category</th><th>Finding / Header</th><th>Severity</th><th>Observed Value &amp; Impact</th></tr>
  </thead>
  <tbody>"#);
            for f in &header_findings {
                h.push_str(&format!(
                    "<tr><td><code>{tool}</code></td><td><strong>{title}</strong></td><td>{badge}</td><td>{desc}</td></tr>\n",
                    tool = html_escape(&f.source_tool),
                    title = html_escape(&f.title),
                    badge = sev_badge(&f.severity),
                    desc = html_escape(&f.description),
                ));
            }
            for f in &cookie_findings {
                h.push_str(&format!(
                    "<tr><td><code>Cookie</code></td><td><strong>{title}</strong></td><td>{badge}</td><td>{desc}</td></tr>\n",
                    title = html_escape(&f.title),
                    badge = sev_badge(&f.severity),
                    desc = html_escape(&f.description),
                ));
            }
            h.push_str("</tbody></table></div>\n");
        }

        // Subdomain cloud
        if !subdomains.is_empty() {
            h.push_str("<div style='display:flex; justify-content:space-between; align-items:center; margin-top:24px; margin-bottom:12px'>");
            h.push_str(&format!("<h2>Discovered Subdomains ({})</h2>", subdomains.len()));
            h.push_str("<button class=\"btn\" onclick=\"copySubdomains()\">Copy All Subdomains</button>");
            h.push_str("</div>\n<div class='table-card' style='padding:16px; line-height:2.2' id='subdomainsContainer'>\n");
            for sub in &subdomains {
                h.push_str(&format!("<span class='chip'>{}</span>", html_escape(sub)));
            }
            h.push_str("\n</div>\n");
        }

        h.push_str("</div>\n"); // End Tab 4

        // =====================================================================
        // TAB 5: DNS & OSINT
        // =====================================================================
        h.push_str(r#"<div id="tab-dns" class="tab-content">"#);
        h.push_str("<h2>DNS Infrastructure &amp; Mail Spoofing Defenses</h2><br>\n");

        if dns_findings.is_empty() {
            h.push_str("<div class='card' style='padding:24px; color:var(--text-muted)'>No DNS records or OSINT information recorded.</div>");
        } else {
            h.push_str(r#"<div class="table-card">
<table>
  <thead>
    <tr><th>Record Type</th><th>Host / Name</th><th>Resolved Value</th><th>Security Impact</th></tr>
  </thead>
  <tbody>"#);
            for f in &dns_findings {
                let rec_type = f.raw_data.get("record_type").and_then(|v| v.as_str())
                    .or_else(|| f.raw_data.get("type").and_then(|v| v.as_str()))
                    .unwrap_or("DNS");
                let rec_name = f.raw_data.get("name").and_then(|v| v.as_str()).unwrap_or(&f.target);
                let rec_val  = f.raw_data.get("value").and_then(|v| v.as_str()).unwrap_or(&f.description);

                h.push_str(&format!(
                    "<tr><td><span class='chip'>{}</span></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>\n",
                    html_escape(rec_type),
                    html_escape(rec_name),
                    html_escape(rec_val),
                    sev_badge(&f.severity),
                ));
            }
            h.push_str("</tbody></table></div>\n");
        }
        h.push_str("</div>\n"); // End Tab 5

        // =====================================================================
        // TAB 6: RAW EVIDENCE STORE & EXPORT
        // =====================================================================
        h.push_str(r#"<div id="tab-evidence" class="tab-content">"#);
        h.push_str("<div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:16px'>");
        h.push_str(&format!("<h2>Raw Evidence Stream ({} Findings)</h2>", total));
        h.push_str("<button class=\"btn\" onclick=\"copyRawJson()\">Copy Findings JSON</button>");
        h.push_str("</div>\n");

        h.push_str(r#"<div class="table-card" style="padding: 16px;">
<pre id="rawJsonBlock" style="max-height: 550px; overflow-y: auto; font-size: 12px; color: #a5f3fc; line-height: 1.5;">"#);
        let compact_json = serde_json::to_string_pretty(findings).unwrap_or_else(|_| "[]".to_string());
        h.push_str(&html_escape(&compact_json));
        h.push_str("</pre></div></div>\n"); // End Tab 6

        // Footer & Toast Notification
        h.push_str(&format!(r#"
</div>
<div id="toast">Copied to clipboard!</div>
<footer>
  BlackHole Advanced Attack Surface Orchestrator &nbsp;|&nbsp; Target: {target} &nbsp;|&nbsp; {ts}
  <br>Privileged security audit artifact. Strictly confidential.
</footer>

<script>
  function openTab(tabId, btn) {{
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
    const target = document.getElementById(tabId);
    if (target) target.classList.add('active');
    if (btn) btn.classList.add('active');
  }}

  function filterTable(inputId, tableId) {{
    const input = document.getElementById(inputId);
    const filter = input.value.toLowerCase();
    const rows = document.querySelectorAll('#' + tableId + ' tbody tr');
    rows.forEach(row => {{
      row.style.display = row.innerText.toLowerCase().includes(filter) ? '' : 'none';
    }});
  }}

  function filterVulnCards() {{
    const search = document.getElementById('vulnSearch').value.toLowerCase();
    const activePill = document.querySelector('.pill-group .pill.active');
    const selectedSev = activePill ? activePill.innerText.toLowerCase() : 'all';

    document.querySelectorAll('.vuln-card').forEach(card => {{
      const cardSev = card.getAttribute('data-severity');
      const textMatch = card.innerText.toLowerCase().includes(search);
      const sevMatch = (selectedSev === 'all') || (cardSev === selectedSev);
      card.style.display = (textMatch && sevMatch) ? '' : 'none';
    }});
  }}

  function filterBySev(sev, btn) {{
    document.querySelectorAll('.pill-group .pill').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    filterVulnCards();
  }}

  function showToast(msg) {{
    const toast = document.getElementById('toast');
    toast.innerText = msg;
    toast.className = 'show';
    setTimeout(() => {{ toast.className = toast.className.replace('show', ''); }}, 2800);
  }}

  function copySessionId(id) {{
    navigator.clipboard.writeText(id).then(() => showToast('Session ID copied!'));
  }}

  function copySubdomains() {{
    const chips = Array.from(document.querySelectorAll('#subdomainsContainer .chip')).map(c => c.innerText);
    navigator.clipboard.writeText(chips.join('\n')).then(() => showToast(chips.length + ' Subdomains copied!'));
  }}

  function copyRawJson() {{
    const block = document.getElementById('rawJsonBlock');
    if (block) {{
      navigator.clipboard.writeText(block.innerText).then(() => showToast('Findings JSON copied to clipboard!'));
    }}
  }}
</script>
</body>
</html>
"#, target = target, ts = timestamp));

        let path = self.output_dir.join(format!("report_{}.html", self.session_id));
        fs::write(&path, &h)?;
        info!("[+] Interactive HTML Executive Dashboard written to: {}", path.display());
        Ok(())
    }

    fn generate_markdown(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        let audit_mode = mode.unwrap_or("Target Audit");
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        let count_sev = |s: &Severity| findings.iter().filter(|f| &f.severity == s).count();
        let crit  = count_sev(&Severity::Critical);
        let high  = count_sev(&Severity::High);
        let med   = count_sev(&Severity::Medium);
        let low   = count_sev(&Severity::Low);
        let info_c = count_sev(&Severity::Info);
        let total = findings.len();

        let mut md = String::with_capacity(64 * 1024);

        md.push_str(&format!("# BlackHole Security Assessment Report\n\n"));
        md.push_str(&format!("- **Target:** `{}`\n", target));
        md.push_str(&format!("- **Audit Mode:** {}\n", audit_mode));
        md.push_str(&format!("- **Generated:** {}\n", timestamp));
        md.push_str(&format!("- **Session ID:** `{}`\n\n", self.session_id));
        md.push_str("---\n\n");

        md.push_str("## 1. Executive Risk Summary\n\n");
        md.push_str("| Metric | Count |\n");
        md.push_str("| :--- | :--- |\n");
        md.push_str(&format!("| **Critical Severity** | **{}** |\n", crit));
        md.push_str(&format!("| **High Severity** | **{}** |\n", high));
        md.push_str(&format!("| **Medium Severity** | {} |\n", med));
        md.push_str(&format!("| **Low Severity** | {} |\n", low));
        md.push_str(&format!("| **Informational** | {} |\n", info_c));
        md.push_str(&format!("| **Total Findings** | **{}** |\n\n", total));

        // Open Ports Table
        md.push_str("## 2. Attack Surface & Open Ports\n\n");
        let mut ports: Vec<(u16, String, String, String)> = Vec::new();
        for f in findings {
            if f.raw_data.get("port").is_some() {
                if let Some(p) = f.raw_data.get("port").and_then(|v| v.as_u64()) {
                    let proto   = f.raw_data.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
                    let service = f.raw_data.get("service").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                    let version = f.raw_data.get("version").and_then(|v| v.as_str()).unwrap_or("—").to_string();
                    ports.push((p as u16, proto, service, version));
                }
            }
        }
        ports.sort_by_key(|p| p.0);
        ports.dedup_by_key(|p| (p.0, p.1.clone()));

        if ports.is_empty() {
            md.push_str("*No open listening ports discovered on target.*\n\n");
        } else {
            md.push_str("| Port | Protocol | Service | Product / Version |\n");
            md.push_str("| :--- | :--- | :--- | :--- |\n");
            for (p, proto, svc, ver) in &ports {
                md.push_str(&format!("| **{}** | {} | {} | {} |\n", p, proto, svc, ver));
            }
            md.push_str("\n");
        }

        // Top Vulnerabilities & CVE Matches
        let mut vuln_findings: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind,
                FindingKind::Vulnerability | FindingKind::CveMatch |
                FindingKind::TlsWeakness | FindingKind::MisconfiguredHeader |
                FindingKind::ZoneTransfer | FindingKind::CorsMisconfiguration))
            .collect();
        vuln_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        md.push_str("## 3. Discovered Vulnerabilities & CVE Findings\n\n");
        if vuln_findings.is_empty() {
            md.push_str("*No security vulnerabilities identified.*\n\n");
        } else {
            for f in vuln_findings {
                let cve_id = f.raw_data.get("cve_id").and_then(|v| v.as_str())
                    .or_else(|| f.raw_data.get("cve").and_then(|v| v.as_str()))
                    .unwrap_or("—");
                let cvss = f.raw_data.get("cvss_score").and_then(|v| v.as_f64());
                let advice = generate_mitigation_advice(cve_id);

                md.push_str(&format!("### [{}] {}\n\n", f.severity, f.title));
                md.push_str(&format!("- **Asset:** `{}`\n", f.target));
                md.push_str(&format!("- **Tool:** `{}`\n", f.source_tool));
                if let Some(score) = cvss {
                    md.push_str(&format!("- **CVSS Base Score:** `{:.1}`\n", score));
                }
                if cve_id != "—" {
                    md.push_str(&format!("- **CVE:** [{id}](https://nvd.nist.gov/vuln/detail/{id})\n", id = cve_id));
                }
                md.push_str(&format!("\n> **Description:** {}\n\n", f.description));
                md.push_str(&format!("**Actionable Mitigation:** {}\n\n---\n\n", advice));
            }
        }

        // Subdomains
        let subdomains: Vec<&str> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::Subdomain))
            .map(|f| f.target.as_str())
            .collect();

        if !subdomains.is_empty() {
            md.push_str(&format!("## 4. Discovered Subdomains ({})\n\n", subdomains.len()));
            for sub in &subdomains {
                md.push_str(&format!("- `{}`\n", sub));
            }
            md.push_str("\n");
        }

        let path = self.output_dir.join(format!("report_{}.md", self.session_id));
        fs::write(&path, &md)?;
        info!("[+] Technical Markdown report written to: {}", path.display());
        Ok(())
    }

    fn generate_json_summary(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        let ports: Vec<serde_json::Value> = findings.iter()
            .filter(|f| f.raw_data.get("port").is_some())
            .map(|f| serde_json::json!({
                "port":     f.raw_data.get("port"),
                "protocol": f.raw_data.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp"),
                "service":  f.raw_data.get("service").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "version":  f.raw_data.get("version").and_then(|v| v.as_str()).unwrap_or(""),
            }))
            .collect();

        let cves: Vec<serde_json::Value> = findings.iter()
            .filter(|f| f.raw_data.get("cve_id").is_some() || f.raw_data.get("cve").is_some())
            .map(|f| serde_json::json!({
                "cve_id":    f.raw_data.get("cve_id").or_else(|| f.raw_data.get("cve")),
                "cvss":      f.raw_data.get("cvss_score"),
                "severity":  f.severity.to_string(),
                "title":     f.title,
                "tool":      f.source_tool,
            }))
            .collect();

        let summary = serde_json::json!({
            "target":       target,
            "session_id":   self.session_id,
            "mode":         mode.unwrap_or("Target Audit"),
            "generated_at": chrono::Utc::now().to_rfc3339(),
            "risk_summary": {
                "critical": findings.iter().filter(|f| f.severity == Severity::Critical).count(),
                "high":     findings.iter().filter(|f| f.severity == Severity::High).count(),
                "medium":   findings.iter().filter(|f| f.severity == Severity::Medium).count(),
                "low":      findings.iter().filter(|f| f.severity == Severity::Low).count(),
                "info":     findings.iter().filter(|f| f.severity == Severity::Info).count(),
                "total":    findings.len(),
            },
            "open_ports":   ports,
            "cve_matches":  cves,
        });

        let path = self.output_dir.join(format!("summary_{}.json", self.session_id));
        fs::write(&path, serde_json::to_string_pretty(&summary)?)?;
        info!("[+] Compact JSON summary written to: {}", path.display());
        Ok(())
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}

pub fn generate_mitigation_advice(cve_id: &str) -> &'static str {
    match cve_id {
        // Apache Ecosystem
        id if id.contains("2021-44228") => "Upgrade Log4j to >= 2.17.1 immediately. Disable JNDI lookups (log4j2.formatMsgNoLookups=true).",
        id if id.contains("2021-45046") => "Upgrade Log4j to >= 2.17.1. Remove JndiLookup.class from classpath if upgrading is delayed.",
        id if id.contains("2021-41773") => "Upgrade Apache HTTP Server to >= 2.4.51. Restrict Directory configuration <Directory /> Require all denied.",
        id if id.contains("2021-42013") => "Upgrade Apache HTTP Server to >= 2.4.51. Enforce strict URI path normalization in reverse proxies.",
        id if id.contains("2017-5638")  => "Upgrade Apache Struts to 2.3.32 or 2.5.10.1+. Restrict invalid Content-Type headers in WAF.",
        id if id.contains("2020-1938")  => "Disable Apache Tomcat AJP connector on port 8009 or bind to 127.0.0.1 with requiredSecret configured.",
        id if id.contains("2017-12615") => "Set readonly=true in Tomcat web.xml for DefaultServlet. Restrict HTTP PUT methods.",
        id if id.contains("2023-46604") => "Upgrade Apache ActiveMQ to 5.15.16, 5.16.7, 5.17.6, or 5.18.3+. Restrict OpenWire port 61616.",

        // Microsoft Windows / SMB / Exchange / IIS / RDP
        id if id.contains("2017-0144")  => "Disable SMBv1 across all endpoints (Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol). Apply MS17-010.",
        id if id.contains("2020-0796")  => "Disable SMBv3 compression via PowerShell: Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters' DisableCompression -Type DWORD -Value 1 -Force. Apply KB4551762.",
        id if id.contains("2020-1472")  => "Enforce secure RPC communication with Netlogon (FullEnforcement flag). Apply MS Zerologon patches.",
        id if id.contains("2021-36942") => "Disable NTLM on AD CS servers. Enable EPA (Extended Protection for Authentication) on Certificate Authority web enrollment.",
        id if id.contains("2021-26855") => "Apply latest Microsoft Exchange Server Cumulative Update. Restrict external exposure of ECP / OWA endpoints.",
        id if id.contains("2021-34473") => "Apply Exchange Server Security Updates (KB5001779). Deploy rewrite rules blocking /autodiscover/autodiscover.json.",
        id if id.contains("2022-41040") => "Apply November 2022 Exchange Security Updates. Enable IIS URL Rewrite rule blocking '.*autodiscover\\.json.*Powershell.*'.",
        id if id.contains("2019-0708")  => "Enable Network Level Authentication (NLA) on RDP. Block TCP 3389 at perimeter firewall. Apply KB4499175.",
        id if id.contains("2021-34527") => "Stop and disable the Print Spooler service on domain controllers (Stop-Service Spooler -PassThru | Set-Service -StartupType Disabled).",
        id if id.contains("2015-1635")  => "Apply MS15-034 security update. In IIS, disable kernel caching or restrict crafted Range headers via WAF.",

        // OpenSSH / OpenSSL / Cryptography
        id if id.contains("2024-6387")  => "Upgrade OpenSSH to >= 9.8p1 immediately. As temporary mitigation, set LoginGraceTime 0 in sshd_config.",
        id if id.contains("2023-48795") => "Upgrade OpenSSH to >= 9.6p1. Disable vulnerable ChaCha20-Poly1305 and *-etm CBC ciphers in sshd_config.",
        id if id.contains("2018-15473") => "Upgrade OpenSSH to >= 7.8. Disable password authentication in favor of public keys.",
        id if id.contains("2014-0160")  => "Upgrade OpenSSL to >= 1.0.1g. Revoke and reissue all SSL/TLS private keys and certificates.",
        id if id.contains("2014-3566")  => "Disable SSLv3 across all services. Enforce TLS 1.2 and TLS 1.3 only.",
        id if id.contains("2016-0800")  => "Disable SSLv2 protocol support and export cipher suites on all listening ports.",
        id if id.contains("2016-2183")  => "Disable 3DES, DES, RC4, and Blowfish 64-bit block cipher suites in TLS configuration.",
        id if id.contains("2014-6271")  => "Upgrade GNU Bash to patched version. Audit CGI scripts invoking subshells.",

        // Firewalls, Gateways & VPNs
        id if id.contains("2024-21762") => "Upgrade Fortinet FortiOS to 7.4.3, 7.2.7+, or 7.0.14+. Disable SSL-VPN if not strictly needed.",
        id if id.contains("2022-40684") => "Upgrade FortiOS to 7.0.7 or 7.2.2+. Block HTTPS administrative interface from public internet.",
        id if id.contains("2023-46805") => "Apply Ivanti mitigation XML package or update to patched firmware release immediately.",
        id if id.contains("2024-21887") => "Perform factory reset and apply latest Ivanti Connect Secure software update. Run Integrity Checker Tool.",
        id if id.contains("2024-3400")  => "Upgrade Palo Alto PAN-OS to 10.2.9-h1, 11.0.4-h1, or 11.1.2-h3. Apply Threat Prevention signatures.",
        id if id.contains("2023-4966")  => "Upgrade NetScaler ADC / Gateway to 13.1-49.15+, 14.1-8.50+. Terminate all active ICA and HTTP sessions.",
        id if id.contains("2020-3452")  => "Upgrade Cisco ASA / FTD software. Restrict WebVPN portal access via source IP allowlisting.",
        id if id.contains("2022-1388")  => "Upgrade F5 BIG-IP to 17.0.0, 16.1.2.2+, or 15.1.5.1+. Block iControl REST access through Self IPs.",

        // Web Frameworks, Applications & Databases
        id if id.contains("2022-22965") => "Upgrade Spring Framework to >= 5.3.18 or 5.2.20. Upgrade to Apache Tomcat >= 10.0.20 or 9.0.62.",
        id if id.contains("2022-26134") => "Upgrade Atlassian Confluence Server / Data Center to 7.18.1, 7.17.4, 7.15.3, or 7.13.7+.",
        id if id.contains("2023-22515") => "Upgrade Atlassian Confluence to >= 8.3.3, 8.4.3, or 8.5.2+. Restrict external access to /setup/*.",
        id if id.contains("2021-22205") => "Upgrade GitLab to 13.10.3, 13.9.6, or 13.8.8+. Upgrade ExifTool to >= 12.24.",
        id if id.contains("2024-23897") => "Upgrade Jenkins to >= 2.442 or LTS 2.426.3. As interim fix, disable CLI access via script console.",
        id if id.contains("2024-4577")  => "Upgrade PHP on Windows to 8.1.29, 8.2.20, or 8.3.8+. Discontinue use of legacy PHP-CGI handler.",
        id if id.contains("2021-25450") => "Purge compromised PHP 8.1.0-dev binary. Deploy official PHP release from trusted distribution mirrors.",
        id if id.contains("2018-7600")  => "Upgrade Drupal core to 7.58 or 8.5.1+. Implement WAF rules blocking malicious Form API payloads.",
        id if id.contains("2021-21972") => "Apply VMware vCenter Server 7.0 U1c, 6.7 U3l, or 6.5 U3n updates. Restrict TCP 443 access to management VLAN.",
        id if id.contains("2022-0543")  => "Upgrade Redis package via apt-get. Bind Redis exclusively to localhost (bind 127.0.0.1) and require strong auth.",
        id if id.contains("2015-1427")  => "Disable dynamic scripting in elasticsearch.yml (script.groovy.sandbox.enabled: false). Upgrade Elasticsearch.",

        _ => "Apply vendor security updates promptly. Restrict perimeter exposure to trusted IP addresses. Enable WAF/IDS signatures.",
    }
}
