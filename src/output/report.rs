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
        fs::create_dir_all(&self.output_dir)?;
        self.generate_html(findings, target, mode)?;
        self.generate_json_summary(findings, target, mode)?;
        Ok(())
    }

    fn generate_html(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        let audit_mode = mode.unwrap_or("Target Audit");
        let timestamp = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

        // ---- Severity counters ----
        let count_sev = |s: &Severity| findings.iter().filter(|f| &f.severity == s).count();
        let crit  = count_sev(&Severity::Critical);
        let high  = count_sev(&Severity::High);
        let med   = count_sev(&Severity::Medium);
        let low   = count_sev(&Severity::Low);
        let info_c = count_sev(&Severity::Info);
        let total  = findings.len();

        // ---- Ports ----
        let mut ports: Vec<(u16, String, String, String)> = Vec::new(); // (port, proto, service, version)
        for f in findings {
            if matches!(f.kind, FindingKind::OpenPort | FindingKind::Service)
                || f.raw_data.get("port").is_some()
            {
                if let Some(p) = f.raw_data.get("port").and_then(|v| v.as_u64()) {
                    let proto   = f.raw_data.get("protocol").and_then(|v| v.as_str()).unwrap_or("tcp").to_string();
                    let service = f.raw_data.get("service").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
                    let version = f.raw_data.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string();
                    ports.push((p as u16, proto, service, version));
                }
            }
        }
        ports.sort_by_key(|p| p.0);
        ports.dedup_by_key(|p| p.0);

        // ---- CVEs ----
        let cve_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.raw_data.get("cve_id").is_some()
                     || f.raw_data.get("cve").is_some()
                     || matches!(f.kind, FindingKind::CveMatch | FindingKind::Vulnerability)
                        && (f.raw_data.get("cve_id").is_some()
                            || f.title.starts_with("CVE-")))
            .collect();

        // ---- Subdomains sample (top 10 live) ----
        let subdomains: Vec<&str> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::Subdomain))
            .map(|f| f.target.as_str())
            .take(10)
            .collect();

        // ---- High/Critical findings for Quick-Win table ----
        let mut important: Vec<&Finding> = findings.iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .collect();
        important.sort_by(|a, b| b.severity.cmp(&a.severity));

        // ---- WAF ----
        let waf = findings.iter()
            .find(|f| matches!(f.kind, FindingKind::WafDetected))
            .map(|f| f.title.trim_start_matches("WAF Detected: ").to_string());

        // ---- TLS issues ----
        let tls_issues: Vec<&Finding> = findings.iter()
            .filter(|f| matches!(f.kind, FindingKind::TlsWeakness))
            .collect();

        // =========================================================
        //  HTML
        // =========================================================
        let sev_badge = |s: &Severity| match s {
            Severity::Critical => r#"<span class="badge crit">CRITICAL</span>"#,
            Severity::High     => r#"<span class="badge high">HIGH</span>"#,
            Severity::Medium   => r#"<span class="badge med">MEDIUM</span>"#,
            Severity::Low      => r#"<span class="badge low">LOW</span>"#,
            Severity::Info     => r#"<span class="badge info">INFO</span>"#,
        };

        let mut h = String::with_capacity(64 * 1024);
        h.push_str(&format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>BlackHole Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --card: #161b22; --border: #21262d;
    --text: #e6edf3; --muted: #8b949e;
    --crit: #ff6b6b; --high: #ffa657; --med: #d2a8ff;
    --low: #79c0ff; --info: #56d364;
    --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
  header {{ background: var(--card); border-bottom: 1px solid var(--border); padding: 20px 32px; display: flex; justify-content: space-between; align-items: center; }}
  header h1 {{ font-size: 20px; letter-spacing: 1px; color: var(--accent); }}
  header .meta {{ font-size: 12px; color: var(--muted); text-align: right; line-height: 1.8; }}
  .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px 32px; }}
  section {{ margin-bottom: 32px; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: .08em; color: var(--muted); border-bottom: 1px solid var(--border); padding-bottom: 8px; margin-bottom: 16px; }}
  /* Score cards */
  .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ flex: 1; min-width: 110px; background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .card .num {{ font-size: 36px; font-weight: 700; line-height: 1.1; }}
  .card .lbl {{ font-size: 11px; color: var(--muted); margin-top: 4px; letter-spacing: .05em; }}
  .num.crit {{ color: var(--crit); }}
  .num.high {{ color: var(--high); }}
  .num.med  {{ color: var(--med); }}
  .num.low  {{ color: var(--low); }}
  .num.info {{ color: var(--info); }}
  /* Tables */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: var(--card); color: var(--muted); text-align: left; padding: 8px 12px; font-weight: 600; border-bottom: 1px solid var(--border); }}
  td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,.03); }}
  code {{ background: rgba(255,255,255,.08); padding: 1px 5px; border-radius: 4px; font-family: 'Courier New', monospace; font-size: 12px; }}
  /* Badges */
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 700; letter-spacing: .04em; }}
  .badge.crit {{ background: rgba(255,107,107,.2); color: var(--crit); }}
  .badge.high {{ background: rgba(255,166,87,.2); color: var(--high); }}
  .badge.med  {{ background: rgba(210,168,255,.2); color: var(--med); }}
  .badge.low  {{ background: rgba(121,192,255,.2); color: var(--low); }}
  .badge.info {{ background: rgba(86,211,100,.2); color: var(--info); }}
  /* Port badge */
  .port-num {{ font-family: monospace; font-weight: 700; color: var(--accent); }}
  /* Alert bar */
  .alert-bar {{ background: rgba(255,107,107,.12); border: 1px solid rgba(255,107,107,.4); border-radius: 6px; padding: 12px 16px; margin-bottom: 24px; color: var(--crit); font-size: 13px; display: none; }}
  .alert-bar.show {{ display: block; }}
  /* Footer */
  footer {{ text-align: center; padding: 24px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); }}
  .chip {{ display: inline-block; background: rgba(88,166,255,.12); color: var(--accent); border-radius: 4px; padding: 1px 7px; font-size: 11px; margin: 1px; }}
</style>
</head>
<body>
<header>
  <h1>BLACKHOLE / SECURITY ASSESSMENT</h1>
  <div class="meta">
    <strong>Target:</strong> {target}<br>
    <strong>Mode:</strong> {audit_mode}<br>
    <strong>Generated:</strong> {timestamp}<br>
    <strong>Session:</strong> <code>{session}</code>
  </div>
</header>
<div class="wrap">
"#, target=target, audit_mode=audit_mode, timestamp=timestamp, session=self.session_id));

        // ----- Critical alert bar -----
        if crit > 0 {
            h.push_str(&format!(
                r#"<div class="alert-bar show">[!] CRITICAL RISK: {} critical-severity finding(s) require immediate remediation.</div>"#,
                crit
            ));
        }

        // ----- Score cards -----
        h.push_str("<section>\n<h2>Risk Summary</h2>\n<div class=\"cards\">\n");
        h.push_str(&format!(r#"<div class="card"><div class="num crit">{crit}</div><div class="lbl">CRITICAL</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num high">{high}</div><div class="lbl">HIGH</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num med">{med}</div><div class="lbl">MEDIUM</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num low">{low}</div><div class="lbl">LOW</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num info">{info_c}</div><div class="lbl">INFO</div></div>"#));
        h.push_str(&format!(r#"<div class="card"><div class="num" style="color:var(--text)">{total}</div><div class="lbl">TOTAL</div></div>"#));
        h.push_str("</div>\n</section>\n");

        // ----- WAF + TLS strip -----
        h.push_str("<section>\n<h2>Target Intelligence</h2>\n<table>\n<tr><th style='width:200px'>Property</th><th>Detail</th></tr>\n");
        h.push_str(&format!("<tr><td>Primary Target</td><td><code>{}</code></td></tr>", target));
        h.push_str(&format!("<tr><td>WAF / Shield</td><td>{}</td></tr>",
            waf.as_deref().unwrap_or("<span style='color:var(--info)'>None detected — direct origin accessible</span>")));
        h.push_str(&format!("<tr><td>Open Ports Found</td><td><code>{}</code></td></tr>", ports.len()));
        h.push_str(&format!("<tr><td>Subdomains Discovered</td><td><code>{}</code></td></tr>",
            findings.iter().filter(|f| matches!(f.kind, FindingKind::Subdomain)).count()));
        h.push_str(&format!("<tr><td>TLS Issues</td><td><code>{}</code></td></tr>", tls_issues.len()));
        h.push_str("</table>\n</section>\n");

        // ----- Open Ports -----
        if !ports.is_empty() {
            h.push_str("<section>\n<h2>Open Ports &amp; Services</h2>\n");
            h.push_str("<table>\n<tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version / Banner</th></tr>\n");
            for (port, proto, service, version) in &ports {
                h.push_str(&format!(
                    "<tr><td><span class='port-num'>{port}</span></td><td>{proto}</td><td>{service}</td><td>{ver}</td></tr>\n",
                    port=port, proto=proto, service=service, ver=if version.is_empty() { "—" } else { version }
                ));
            }
            h.push_str("</table>\n</section>\n");
        }

        // ----- CVE / Vulnerability findings -----
        let vuln_findings: Vec<&Finding> = {
            let mut v: Vec<&Finding> = findings.iter()
                .filter(|f| matches!(f.kind,
                    FindingKind::Vulnerability | FindingKind::CveMatch |
                    FindingKind::TlsWeakness | FindingKind::MisconfiguredHeader |
                    FindingKind::ZoneTransfer))
                .collect();
            v.sort_by(|a, b| b.severity.cmp(&a.severity));
            v
        };

        if !vuln_findings.is_empty() {
            h.push_str("<section>\n<h2>Vulnerabilities &amp; CVE Matches</h2>\n");
            h.push_str("<table>\n<tr><th>Severity</th><th>Title</th><th>Target Asset</th><th>CVE / Reference</th><th>Tool</th></tr>\n");
            for f in &vuln_findings {
                let cve_id = f.raw_data.get("cve_id")
                    .and_then(|v| v.as_str())
                    .or_else(|| f.raw_data.get("cve").and_then(|v| v.as_str()))
                    .unwrap_or("—");
                let cve_cell = if cve_id != "—" {
                    format!("<a href='https://nvd.nist.gov/vuln/detail/{id}' target='_blank' style='color:var(--accent)'>{id}</a>",
                        id=html_escape(cve_id))
                } else {
                    "—".to_string()
                };
                h.push_str(&format!(
                    "<tr><td>{badge}</td><td>{title}</td><td><code>{tgt}</code></td><td>{cve}</td><td><code>{tool}</code></td></tr>\n",
                    badge = sev_badge(&f.severity),
                    title = html_escape(&f.title),
                    tgt   = html_escape(&f.target),
                    cve   = cve_cell,
                    tool  = html_escape(&f.source_tool),
                ));
            }
            h.push_str("</table>\n</section>\n");
        }

        // ----- High / Critical quick-wins -----
        if !important.is_empty() {
            h.push_str("<section>\n<h2>Critical &amp; High Priority — Quick Detail</h2>\n");
            for f in &important {
                let cvss = f.raw_data.get("cvss_score").and_then(|v| v.as_f64());
                let cve_id = f.raw_data.get("cve_id").and_then(|v| v.as_str());
                h.push_str(&format!(r#"<div style="background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 18px;margin-bottom:12px">
  <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
    {badge}
    <strong>{title}</strong>
  </div>
  <div style="color:var(--muted);font-size:12px;margin-bottom:6px">
    Asset: <code>{tgt}</code> &nbsp;|&nbsp; Tool: <code>{tool}</code>{cvss_part}
  </div>
  <div style="font-size:13px">{desc}</div>{cve_part}
</div>
"#,
                    badge     = sev_badge(&f.severity),
                    title     = html_escape(&f.title),
                    tgt       = html_escape(&f.target),
                    tool      = html_escape(&f.source_tool),
                    cvss_part = cvss.map(|s| format!(" &nbsp;|&nbsp; CVSS: <strong>{:.1}</strong>", s)).unwrap_or_default(),
                    desc      = html_escape(&f.description),
                    cve_part  = cve_id.map(|id| format!(
                        "\n  <div style='margin-top:8px;font-size:12px'>CVE: <a href='https://nvd.nist.gov/vuln/detail/{id}' target='_blank' style='color:var(--accent)'>{id}</a> &nbsp; {mitigation}</div>",
                        id=id, mitigation=generate_mitigation_advice(id)
                    )).unwrap_or_default(),
                ));
            }
            h.push_str("</section>\n");
        }

        // ----- Subdomain sample -----
        if !subdomains.is_empty() {
            h.push_str("<section>\n<h2>Live Subdomains Sample (top 10)</h2>\n<div style='line-height:2'>\n");
            for sub in &subdomains {
                h.push_str(&format!("<span class='chip'>{}</span>", html_escape(sub)));
            }
            let total_subs = findings.iter().filter(|f| matches!(f.kind, FindingKind::Subdomain)).count();
            if total_subs > 10 {
                h.push_str(&format!(" <span style='color:var(--muted);font-size:12px'>... and {} more in evidence store</span>", total_subs - 10));
            }
            h.push_str("\n</div>\n</section>\n");
        }

        // ----- TLS issues -----
        if !tls_issues.is_empty() {
            h.push_str("<section>\n<h2>TLS / SSL Issues</h2>\n");
            h.push_str("<table>\n<tr><th>Severity</th><th>Finding</th><th>Asset</th></tr>\n");
            for f in &tls_issues {
                h.push_str(&format!(
                    "<tr><td>{badge}</td><td>{title}</td><td><code>{tgt}</code></td></tr>\n",
                    badge = sev_badge(&f.severity),
                    title = html_escape(&f.title),
                    tgt   = html_escape(&f.target),
                ));
            }
            h.push_str("</table>\n</section>\n");
        }

        // ----- Footer -----
        h.push_str(&format!(r#"
</div>
<footer>
  BlackHole Offensive Recon Framework &nbsp;|&nbsp; {target} &nbsp;|&nbsp; {ts}
  <br>Strictly confidential. Authorized security personnel only.
</footer>
</body>
</html>
"#, target=target, ts=timestamp));

        let path = self.output_dir.join(format!("report_{}.html", self.session_id));
        fs::write(&path, &h)?;
        info!("[+] HTML executive report written to: {}", path.display());
        Ok(())
    }

    fn generate_json_summary(&self, findings: &[Finding], target: &str, mode: Option<&str>) -> Result<()> {
        // Compact JSON: metadata + per-severity counts + ports + CVEs only (no raw 40k subdomain dump)
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
            .filter(|f| f.raw_data.get("cve_id").is_some())
            .map(|f| serde_json::json!({
                "cve_id":    f.raw_data.get("cve_id"),
                "cvss":      f.raw_data.get("cvss_score"),
                "severity":  f.severity.to_string(),
                "title":     f.title,
                "tool":      f.source_tool,
            }))
            .collect();

        let high_critical: Vec<serde_json::Value> = findings.iter()
            .filter(|f| f.severity == Severity::Critical || f.severity == Severity::High)
            .map(|f| serde_json::json!({
                "severity":    f.severity.to_string(),
                "title":       f.title,
                "target":      f.target,
                "tool":        f.source_tool,
                "description": f.description,
                "cve_id":      f.raw_data.get("cve_id"),
                "cvss":        f.raw_data.get("cvss_score"),
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
            "high_critical_findings": high_critical,
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

fn generate_mitigation_advice(cve_id: &str) -> &'static str {
    match cve_id {
        id if id.contains("2021-44228") => "Upgrade Log4j to >= 2.17.1 immediately.",
        id if id.contains("2017-0144")  => "Disable SMBv1. Apply MS17-010.",
        id if id.contains("2014-0160")  => "Upgrade OpenSSL >= 1.0.1g. Reissue certificates.",
        id if id.contains("2021-26855") => "Apply Exchange CUs. Restrict ECP/OWA from internet.",
        id if id.contains("2019-0708")  => "Enable NLA. Block TCP 3389. Apply KB4499175.",
        id if id.contains("2020-1938")  => "Disable AJP on 8009 or bind to 127.0.0.1.",
        id if id.contains("2024-6387")  => "Upgrade OpenSSH >= 9.8p1. Set LoginGraceTime 0.",
        id if id.contains("2021-41773") => "Upgrade Apache to >= 2.4.51.",
        id if id.contains("2022-22965") => "Upgrade Spring Framework >= 5.3.18.",
        _ => "Apply vendor security updates. Restrict network exposure. Enable IDS signatures.",
    }
}
