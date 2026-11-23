use anyhow::Result;
use async_trait::async_trait;
use rand::seq::SliceRandom;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use tempfile::NamedTempFile;
use tracing::{debug, info, warn};

use crate::executor::{check_tool_available, run_command};
use crate::probe::{Probe, ProbeResult};
use crate::types::{AuditContext, Finding, FindingKind, Severity};

pub const DEFAULT_WORDLIST: &str = "\
admin
login
api
wp-admin
.env
config
backup
test
uploads
static
phpmyadmin
console
dashboard
manager
portal
v1
v2
api/v1
api/v2
swagger
swagger-ui
openapi.json
health
status
metrics
robots.txt
sitemap.xml
.git
.git/config
.htaccess
web.config
server-status
server-info
backup.zip
backup.tar.gz
db.sql
phpinfo.php
info.php
shell.php
test.php
config.php
settings.php
wp-login.php
wp-config.php
xmlrpc.php
adminer.php
user
users
account
accounts
auth
authentication
register
password
reset
confirm
verify
token
secret
keys
credentials
logs
log
error
errors
debug
trace
cache
queue
jobs
workers
health-check
ping
echo
test
dev
development
staging
qa
temp
tmp
old
bak
_backup
archive
readme
changelog
license
";

pub const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/124.0.2478.80",
];

pub fn get_random_user_agent() -> &'static str {
    let mut rng = rand::thread_rng();
    USER_AGENTS.choose(&mut rng).unwrap_or(&USER_AGENTS[0])
}

// ============================================================================
// PROBE 1: CurlHeadersProbe
// ============================================================================

pub struct CurlHeadersProbe {
    pub target: String,
}

impl CurlHeadersProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[derive(Debug, Clone, Default)]
pub struct HttpParsedResponse {
    pub status_code: Option<u16>,
    pub http_version: Option<String>,
    pub status_text: Option<String>,
    pub headers: HashMap<String, String>,
    pub cookies: Vec<String>,
}

pub fn parse_headers(raw: &str) -> HashMap<String, String> {
    parse_http_response(raw).headers
}

pub fn parse_http_response(raw: &str) -> HttpParsedResponse {
    let clean = crate::executor::strip_ansi_codes(raw);
    let mut parsed = HttpParsedResponse::default();

    // When following redirects (-L), split into response blocks separated by empty lines
    let blocks: Vec<&str> = clean.split("\r\n\r\n")
        .flat_map(|b| b.split("\n\n"))
        .filter(|b| !b.trim().is_empty())
        .collect();

    // Use the final response block for headers, but collect cookies from all blocks
    let target_block = blocks.last().copied().unwrap_or(&clean);

    for block in &blocks {
        for line in block.lines() {
            let line = line.trim();
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("set-cookie") {
                    parsed.cookies.push(v.trim().to_string());
                }
            }
        }
    }

    for line in target_block.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Check for HTTP status line: "HTTP/1.1 200 OK" or "HTTP/2 200"
        if (line.starts_with("HTTP/1.") || line.starts_with("HTTP/2") || line.starts_with("HTTP/3")) && line.contains(' ') {
            let tokens: Vec<&str> = line.split_whitespace().collect();
            if tokens.len() >= 2 {
                parsed.http_version = Some(tokens[0].to_string());
                if let Ok(code) = tokens[1].parse::<u16>() {
                    parsed.status_code = Some(code);
                }
                if tokens.len() >= 3 {
                    parsed.status_text = Some(tokens[2..].join(" "));
                }
            }
            continue;
        }

        if let Some((key, val)) = line.split_once(':') {
            let k = key.trim().to_lowercase();
            let v = val.trim().to_string();
            parsed.headers.entry(k)
                .and_modify(|existing: &mut String| {
                    existing.push_str(", ");
                    existing.push_str(&v);
                })
                .or_insert(v);
        }
    }

    parsed
}

#[async_trait]
impl Probe for CurlHeadersProbe {
    fn name(&self) -> &str {
        "curl-headers"
    }

    fn timeout_secs(&self) -> u64 {
        30
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("curl") {
            warn!("[-] Tool 'curl' is not available in PATH; skipping CurlHeadersProbe");
            return Ok(ProbeResult::skipped("curl-headers", "curl binary not found"));
        }

        let url = if !self.target.is_empty() && (self.target.starts_with("http://") || self.target.starts_with("https://")) {
            self.target.clone()
        } else {
            ctx.get_url()
        };
        info!("[*] Running CurlHeadersProbe against {}", url);

        let random_ua = get_random_user_agent();
        let mut args = vec![
            "-s",
            "-i",
            "-k", // Insecure SSL (bypass self-signed / inspection firewalls)
            "--connect-timeout",
            "6",
            "--max-time",
            "15",
            "--retry",
            "2",
            "--retry-delay",
            "1",
            "--location",
            "--max-redirs",
            "5",
            "-A",
            random_ua,
        ];

        if let Some(ref prx) = ctx.proxy {
            args.push("--proxy");
            args.push(prx.as_str());
        }

        args.push(&url);

        let output = run_command("curl", &args, self.timeout_secs()).await?;
        let resp = parse_http_response(&output.stdout);
        let headers = &resp.headers;

        if headers.is_empty() && resp.status_code.is_none() {
            warn!("[-] No HTTP response headers returned from curl for {}", url);
            return Ok(ProbeResult::skipped("curl-headers", "No response headers received"));
        }

        let mut findings = Vec::new();
        let mut detected_techs = Vec::new();

        // 1. Missing Security Headers
        if !headers.contains_key("strict-transport-security") && url.starts_with("https://") {
            findings.push(
                Finding::new(
                    "curl",
                    &url,
                    FindingKind::MisconfiguredHeader,
                    Severity::Medium,
                    "Missing HSTS (Strict-Transport-Security)",
                    "Strict-Transport-Security header is absent. Communication is susceptible to SSL stripping and downgrade attacks.",
                    serde_json::json!({
                        "header": "Strict-Transport-Security",
                        "status": "missing"
                    }),
                    0.95,
                )
                .with_tags(vec!["headers".into(), "hsts".into(), "security".into()]),
            );
        }

        if !headers.contains_key("x-frame-options") && !headers.get("content-security-policy").map(|c| c.contains("frame-ancestors")).unwrap_or(false) {
            findings.push(
                Finding::new(
                    "curl",
                    &url,
                    FindingKind::MisconfiguredHeader,
                    Severity::Medium,
                    "Missing Clickjacking Protection (X-Frame-Options)",
                    "X-Frame-Options header and CSP frame-ancestors are absent, making the web page vulnerable to clickjacking attacks via iframes.",
                    serde_json::json!({
                        "header": "X-Frame-Options",
                        "status": "missing"
                    }),
                    0.95,
                )
                .with_tags(vec!["headers".into(), "clickjacking".into(), "security".into()]),
            );
        }

        if !headers.contains_key("x-content-type-options") {
            findings.push(
                Finding::new(
                    "curl",
                    &url,
                    FindingKind::MisconfiguredHeader,
                    Severity::Low,
                    "Missing MIME Sniffing Protection (X-Content-Type-Options)",
                    "X-Content-Type-Options: nosniff is absent. User-agents may incorrectly sniff content types, risking XSS.",
                    serde_json::json!({
                        "header": "X-Content-Type-Options",
                        "status": "missing"
                    }),
                    0.95,
                )
                .with_tags(vec!["headers".into(), "mime".into(), "security".into()]),
            );
        }

        if !headers.contains_key("content-security-policy") {
            findings.push(
                Finding::new(
                    "curl",
                    &url,
                    FindingKind::MisconfiguredHeader,
                    Severity::Medium,
                    "Missing Content Security Policy (CSP)",
                    "Content-Security-Policy header is absent. Cross-Site Scripting (XSS) and data injection mitigations are disabled.",
                    serde_json::json!({
                        "header": "Content-Security-Policy",
                        "status": "missing"
                    }),
                    0.95,
                )
                .with_tags(vec!["headers".into(), "csp".into(), "security".into()]),
            );
        }

        // 2. Cookie Security Analysis
        for cookie in &resp.cookies {
            let cookie_lower = cookie.to_lowercase();
            let mut issues = Vec::new();
            if !cookie_lower.contains("secure") && url.starts_with("https://") {
                issues.push("missing Secure flag");
            }
            if !cookie_lower.contains("httponly") {
                issues.push("missing HttpOnly flag");
            }
            if !cookie_lower.contains("samesite") {
                issues.push("missing SameSite attribute");
            }

            if !issues.is_empty() {
                let cookie_name = cookie.split('=').next().unwrap_or("cookie").trim();
                findings.push(
                    Finding::new(
                        "curl",
                        &url,
                        FindingKind::InsecureCookie,
                        Severity::Low,
                        format!("Insecure Cookie Flags: {}", cookie_name),
                        format!("Cookie '{}' has security weaknesses: {}. Cookies without flags risk theft via XSS or cleartext transmission.", cookie_name, issues.join(", ")),
                        serde_json::json!({
                            "cookie": cookie,
                            "issues": issues,
                        }),
                        0.90,
                    )
                    .with_tags(vec!["cookie".into(), "security".into()]),
                );
            }
        }

        // 3. CORS Misconfiguration Check
        if let Some(cors) = headers.get("access-control-allow-origin") {
            if cors == "*" {
                findings.push(
                    Finding::new(
                        "curl",
                        &url,
                        FindingKind::CorsMisconfiguration,
                        Severity::Medium,
                        "Overly Permissive CORS (Access-Control-Allow-Origin: *)",
                        "Access-Control-Allow-Origin is set to wildcard (*), allowing arbitrary third-party domains to read API responses.",
                        serde_json::json!({
                            "header": "Access-Control-Allow-Origin",
                            "value": cors,
                        }),
                        0.90,
                    )
                    .with_tags(vec!["cors".into(), "api".into(), "security".into()]),
                );
            }
        }

        // 4. Information Disclosure via Headers
        if let Some(server) = headers.get("server") {
            detected_techs.push(server.clone());
            findings.push(
                Finding::new(
                    "curl",
                    &url,
                    FindingKind::InformationDisclosure,
                    Severity::Low,
                    format!("Server Banner Disclosed: {}", server),
                    format!("Server header exposes technology banner: '{}'. Simplifies reconnaissance for targeted exploit selection.", server),
                    serde_json::json!({
                        "header": "Server",
                        "value": server
                    }),
                    0.95,
                )
                .with_tags(vec!["headers".into(), "information-disclosure".into(), "server".into()]),
            );
        }

        if let Some(powered_by) = headers.get("x-powered-by") {
            detected_techs.push(powered_by.clone());
            findings.push(
                Finding::new(
                    "curl",
                    &url,
                    FindingKind::InformationDisclosure,
                    Severity::Low,
                    format!("Technology Disclosed: X-Powered-By: {}", powered_by),
                    format!("X-Powered-By header explicitly advertises backend runtime: '{}'.", powered_by),
                    serde_json::json!({
                        "header": "X-Powered-By",
                        "value": powered_by
                    }),
                    0.95,
                )
                .with_tags(vec!["headers".into(), "information-disclosure".into(), "x-powered-by".into()]),
            );
        }

        // 5. Dangerous HTTP Methods
        if let Some(allow) = headers.get("allow") {
            let dangerous_methods: Vec<&str> = ["PUT", "DELETE", "TRACE", "CONNECT"]
                .iter()
                .filter(|&&m| allow.to_uppercase().contains(m))
                .copied()
                .collect();

            if !dangerous_methods.is_empty() {
                findings.push(
                    Finding::new(
                        "curl",
                        &url,
                        FindingKind::MisconfiguredHeader,
                        Severity::Medium,
                        format!("Insecure HTTP Methods Permitted: {}", dangerous_methods.join(", ")),
                        format!("HTTP OPTIONS response allows potentially insecure methods: '{}'. Review method restrictions.", allow),
                        serde_json::json!({
                            "header": "Allow",
                            "allowed": allow,
                            "flagged_methods": dangerous_methods
                        }),
                        0.95,
                    )
                    .with_tags(vec!["headers".into(), "http-methods".into()]),
                );
            }
        }

        // 6. Header summary finding
        let status_num = resp.status_code.unwrap_or(200);
        findings.push(
            Finding::new(
                "curl",
                &url,
                FindingKind::HttpHeader,
                Severity::Info,
                format!("HTTP Response: {} ({:?})", status_num, resp.status_text.as_deref().unwrap_or("")),
                format!("Extracted {} headers from {} (HTTP status {}). Protocol: {:?}", headers.len(), url, status_num, resp.http_version),
                serde_json::json!({
                    "status_code": resp.status_code,
                    "http_version": resp.http_version,
                    "status_text": resp.status_text,
                    "headers": headers,
                    "cookies": resp.cookies,
                }),
                1.0,
            )
            .with_tags(vec!["headers".into(), "summary".into()]),
        );

        info!("[+] curl-headers completed with {} findings", findings.len());
        Ok(
            ProbeResult::success("curl-headers", findings)
                .with_technologies(detected_techs),
        )
    }
}

// ============================================================================
// PROBE 2: HttpxProbe
// ============================================================================

pub struct HttpxProbe {
    pub target: String,
}

impl HttpxProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[derive(Debug, Deserialize)]
struct HttpxResult {
    #[serde(default)]
    url: Option<String>,
    #[serde(rename = "status_code", default)]
    status_code: Option<u16>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    tech: Option<Vec<String>>,
    #[serde(rename = "content_length", default)]
    _content_length: Option<u64>,
}

#[async_trait]
impl Probe for HttpxProbe {
    fn name(&self) -> &str {
        "httpx"
    }

    fn timeout_secs(&self) -> u64 {
        120
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("httpx") {
            warn!("[-] Tool 'httpx' is not available in PATH; skipping HttpxProbe");
            return Ok(ProbeResult::skipped("httpx", "httpx binary not found"));
        }

        let url = if !self.target.is_empty() && (self.target.starts_with("http://") || self.target.starts_with("https://")) {
            self.target.clone()
        } else {
            ctx.get_url()
        };
        info!("[*] Running HttpxProbe against target {}", url);

        let _sub_file_guard;
        let sub_path_string;
        let mut args: Vec<&str> = Vec::new();

        if !ctx.subdomains.is_empty() {
            let mut sub_file = NamedTempFile::new()?;
            for sub in &ctx.subdomains {
                writeln!(sub_file, "{}", sub)?;
            }
            let sub_path = sub_file.into_temp_path();
            sub_path_string = sub_path.to_string_lossy().to_string();
            _sub_file_guard = Some(sub_path);

            args.push("-l");
            args.push(&sub_path_string);
        } else {
            args.push("-u");
            args.push(&url);
        }

        let random_ua = get_random_user_agent();
        args.extend_from_slice(&[
            "-tech-detect",
            "-status-code",
            "-title",
            "-json",
            "-silent",
            "-no-color",
            "-user-agent",
            random_ua,
        ]);

        if let Some(ref prx) = ctx.proxy {
            args.push("-http-proxy");
            args.push(prx.as_str());
        }

        let output = run_command("httpx", &args, self.timeout_secs()).await?;

        let mut findings = Vec::new();
        let mut live_urls = Vec::new();
        let mut parsed_results = Vec::new();
        let mut discovered_techs = Vec::new();

        for line in output.stdout.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            if let Ok(res) = serde_json::from_str::<HttpxResult>(line) {
                let raw_val: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
                parsed_results.push(raw_val);

                let target_url = res.url.clone().unwrap_or_else(|| url.clone());
                live_urls.push(target_url.clone());

                if let Some(tech_list) = res.tech {
                    for tech in tech_list {
                        if !discovered_techs.contains(&tech) {
                            discovered_techs.push(tech.clone());
                        }

                        findings.push(
                            Finding::new(
                                "httpx",
                                &target_url,
                                FindingKind::WebTechnology,
                                Severity::Info,
                                format!("Web Technology: {}", tech),
                                format!("Detected web technology '{}' on host {}", tech, target_url),
                                serde_json::json!({
                                    "url": target_url,
                                    "technology": tech,
                                    "title": res.title,
                                    "status_code": res.status_code,
                                }),
                                0.9,
                            )
                            .with_tags(vec!["web".into(), "technology".into(), tech.to_lowercase()]),
                        );
                    }
                }
            }
        }

        findings.push(
            Finding::new(
                "httpx",
                &url,
                FindingKind::WebTechnology,
                Severity::Info,
                "HTTPX Live Hosts Probed Summary",
                format!("HTTPX probed {} live target endpoint(s) successfully", live_urls.len()),
                serde_json::json!({
                    "target": url,
                    "live_count": live_urls.len(),
                    "live_urls": live_urls,
                    "results": parsed_results,
                }),
                1.0,
            )
            .with_tags(vec!["httpx".into(), "summary".into()]),
        );

        info!("[+] httpx probed {} endpoints, found {} technologies", live_urls.len(), discovered_techs.len());
        Ok(
            ProbeResult::success("httpx", findings)
                .with_technologies(discovered_techs),
        )
    }
}

// ============================================================================
// PROBE 3: FfufProbe — DIRECTORY FUZZER (ADAPTIVE WAF EVASION & DIRECTED FUZZING)
// ============================================================================

pub struct FfufProbe {
    pub target: String,
}

impl FfufProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[derive(Debug, Deserialize)]
struct FfufOutput {
    #[serde(default)]
    results: Vec<FfufResult>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct FfufResult {
    #[serde(default)]
    url: String,
    #[serde(default)]
    status: u16,
    #[serde(default)]
    length: Option<u64>,
    #[serde(default)]
    words: Option<u64>,
    #[serde(default)]
    lines: Option<u64>,
}

#[async_trait]
impl Probe for FfufProbe {
    fn name(&self) -> &str {
        "ffuf"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        let (_embedded_wl_guard, wordlist_path) = match &ctx.wordlist_path {
            Some(path) if std::path::Path::new(path).is_file() => {
                info!("[*] Using custom external wordlist: {}", path);
                (None, path.clone())
            }
            Some(path) => {
                warn!(
                    "[-] Configured wordlist path '{}' does not exist! Falling back to embedded high-value wordlist.",
                    path
                );
                let mut temp_wl = NamedTempFile::new()?;
                temp_wl.write_all(DEFAULT_WORDLIST.as_bytes())?;
                let temp_path = temp_wl.into_temp_path();
                let path_str = temp_path.to_string_lossy().to_string();
                (Some(temp_path), path_str)
            }
            None => {
                debug!("[*] No custom wordlist provided. Using embedded high-value wordlist.");
                let mut temp_wl = NamedTempFile::new()?;
                temp_wl.write_all(DEFAULT_WORDLIST.as_bytes())?;
                let temp_path = temp_wl.into_temp_path();
                let path_str = temp_path.to_string_lossy().to_string();
                (Some(temp_path), path_str)
            }
        };

        if !check_tool_available("ffuf") {
            if check_tool_available("gobuster") {
                info!("[*] Tool 'ffuf' not found in PATH — falling back to 'gobuster'");
                return self.run_gobuster(ctx, &wordlist_path).await;
            } else {
                warn!("[-] Neither 'ffuf' nor 'gobuster' available in PATH; skipping web directory fuzzing");
                return Ok(ProbeResult::skipped("ffuf", "Neither ffuf nor gobuster found"));
            }
        }

        let base_url = if !self.target.is_empty() && (self.target.starts_with("http://") || self.target.starts_with("https://")) {
            self.target.trim_end_matches('/').to_string()
        } else {
            ctx.get_url().trim_end_matches('/').to_string()
        };
        let fuzz_url = format!("{}/FUZZ", base_url);
        info!("[*] Running FfufProbe against {}", fuzz_url);

        let temp_out = NamedTempFile::new()?;
        let temp_out_path = temp_out.into_temp_path();
        let out_path_string = temp_out_path.to_string_lossy().to_string();

        let threads = if ctx.stealth_mode || ctx.waf_detected {
            info!("[!] Stealth/WAF mode active: switching FFuF to low-profile mode (5 threads, 0.5-2.0s delay jitter, browser UA rotation)");
            "5"
        } else {
            "50"
        };

        let user_agent = get_random_user_agent();
        let ua_header = format!("User-Agent: {}", user_agent);

        let mut args = vec![
            "-u",
            &fuzz_url,
            "-w",
            &wordlist_path,
            "-e",
            ".php,.bak,.env,.git,.sql,.zip",
            "-mc",
            "200,204,301,302,307,401,403",
            "-ac", // Auto-calibrate false positive filters
            "-t",
            threads,
            "-H",
            &ua_header,
        ];

        if ctx.stealth_mode || ctx.waf_detected {
            args.push("-p");
            args.push("0.5-2.0");
        }

        if let Some(ref prx) = ctx.proxy {
            info!("[*] Routing FFuF traffic through proxy: {}", prx);
            args.push("-x");
            args.push(prx.as_str());
        }

        args.push("-of");
        args.push("json");
        args.push("-o");
        args.push(&out_path_string);

        let cmd_res = run_command("ffuf", &args, self.timeout_secs()).await;
        if cmd_res.is_err() && check_tool_available("gobuster") {
            warn!("[-] Ffuf execution failed or timed out — attempting Gobuster secondary fallback");
            return self.run_gobuster(ctx, &wordlist_path).await;
        }

        let mut findings = Vec::new();
        if let Ok(content) = fs::read_to_string(&temp_out_path) {
            if let Ok(ffuf_out) = serde_json::from_str::<FfufOutput>(&content) {
                for res in ffuf_out.results {
                    let (severity, note) = match res.status {
                        200 => (Severity::Medium, "Accessible endpoint discovered"),
                        401 => (Severity::Medium, "Authentication required endpoint discovered"),
                        403 => (Severity::Low, "Forbidden directory or endpoint exists"),
                        301 | 302 | 307 => (Severity::Info, "Redirect endpoint discovered"),
                        _ => (Severity::Info, "Endpoint discovered"),
                    };

                    let title = format!("Directory Found: {} (HTTP {})", res.url, res.status);
                    let description = format!(
                        "{}: {} returned HTTP status {} (length: {:?}, words: {:?}, lines: {:?})",
                        note, res.url, res.status, res.length, res.words, res.lines
                    );

                    let raw_data = serde_json::to_value(&res).unwrap_or_else(|_| {
                        serde_json::json!({
                            "url": res.url,
                            "status": res.status,
                        })
                    });

                    findings.push(
                        Finding::new(
                            "ffuf",
                            &res.url,
                            FindingKind::DirectoryFound,
                            severity,
                            title,
                            description,
                            raw_data,
                            0.95,
                        )
                        .with_tags(vec![
                            "ffuf".into(),
                            "directory".into(),
                            format!("status-{}", res.status),
                        ])
                        .with_metadata("status", res.status.to_string()),
                    );
                }
            } else {
                warn!("[-] Failed to parse ffuf JSON output from {}", out_path_string);
            }
        } else {
            warn!("[-] Ffuf output file not found or unreadable: {}", out_path_string);
        }

        info!("[+] ffuf discovered {} endpoints", findings.len());
        Ok(ProbeResult::success("ffuf", findings))
    }
}

impl FfufProbe {
    /// Gobuster fallback execution if FFuF is missing or fails
    async fn run_gobuster(&self, ctx: &AuditContext, wordlist_path: &str) -> Result<ProbeResult> {
        let base_url = ctx.get_url();
        info!("[*] Running Gobuster directory enumeration against {}", base_url);

        let temp_out = NamedTempFile::new()?;
        let temp_out_path = temp_out.into_temp_path();
        let out_path_string = temp_out_path.to_string_lossy().to_string();

        let threads = if ctx.waf_detected { "5" } else { "30" };
        let random_ua = get_random_user_agent();

        let mut args = vec![
            "dir",
            "-u",
            &base_url,
            "-w",
            wordlist_path,
            "-t",
            threads,
            "-a",
            random_ua,
            "-s",
            "200,204,301,302,307,401,403",
            "-q",
            "-o",
            &out_path_string,
        ];

        if let Some(ref prx) = ctx.proxy {
            args.push("--proxy");
            args.push(prx.as_str());
        }

        let _ = run_command("gobuster", &args, self.timeout_secs()).await?;

        let mut findings = Vec::new();
        if let Ok(content) = fs::read_to_string(&temp_out_path) {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = line.split_whitespace().collect();
                let path = parts.first().unwrap_or(&"");
                let status_code = parts.iter()
                    .position(|&p| p == "(Status:")
                    .and_then(|idx| parts.get(idx + 1))
                    .map(|s| s.trim_end_matches(')'))
                    .unwrap_or("200");

                let status_num = status_code.parse::<u16>().unwrap_or(200);
                let full_url = format!("{}{}", base_url.trim_end_matches('/'), path);

                let severity = match status_num {
                    200 => Severity::Medium,
                    401 => Severity::Medium,
                    403 => Severity::Low,
                    _ => Severity::Info,
                };

                findings.push(
                    Finding::new(
                        "gobuster",
                        &full_url,
                        FindingKind::DirectoryFound,
                        severity,
                        format!("Directory Found (Gobuster): {} (HTTP {})", path, status_code),
                        format!("Gobuster discovered endpoint {} with status {}", path, status_code),
                        serde_json::json!({
                            "url": full_url,
                            "path": path,
                            "status": status_num,
                            "raw_line": line,
                        }),
                        0.90,
                    )
                    .with_tags(vec!["gobuster".into(), "directory".into()]),
                );
            }
        }

        info!("[+] gobuster fallback discovered {} endpoints", findings.len());
        Ok(ProbeResult::success("gobuster", findings))
    }
}

// ============================================================================
// PROBE 4: NiktoProbe — WEB VULNERABILITY SCANNER (WITH WAF EVASION & PROXY)
// ============================================================================

pub struct NiktoProbe {
    pub target: String,
}

impl NiktoProbe {
    pub fn new(target: String) -> Self {
        Self { target }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NiktoReport {
    #[serde(default)]
    pub vulnerabilities: Vec<NiktoVulnerability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NiktoVulnerability {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(rename = "OSVDB", default)]
    pub osvdb: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub msg: Option<String>,
    #[serde(default)]
    pub references: Option<String>,
}

pub fn parse_nikto_json(content: &str) -> Vec<NiktoVulnerability> {
    let clean = crate::executor::strip_ansi_codes(content);
    let trimmed = clean.trim();
    if let Ok(report) = serde_json::from_str::<NiktoReport>(trimmed) {
        if !report.vulnerabilities.is_empty() {
            return report.vulnerabilities;
        }
    }
    if let Ok(reports) = serde_json::from_str::<Vec<NiktoReport>>(trimmed) {
        let vulns: Vec<NiktoVulnerability> = reports.into_iter().flat_map(|r| r.vulnerabilities).collect();
        if !vulns.is_empty() {
            return vulns;
        }
    }
    if let Ok(vulns) = serde_json::from_str::<Vec<NiktoVulnerability>>(trimmed) {
        if !vulns.is_empty() {
            return vulns;
        }
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if start < end {
            let slice = &trimmed[start..=end];
            if let Ok(report) = serde_json::from_str::<NiktoReport>(slice) {
                if !report.vulnerabilities.is_empty() {
                    return report.vulnerabilities;
                }
            }
        }
    }
    if let (Some(start), Some(end)) = (trimmed.find('['), trimmed.rfind(']')) {
        if start < end {
            let slice = &trimmed[start..=end];
            if let Ok(reports) = serde_json::from_str::<Vec<NiktoReport>>(slice) {
                let vulns: Vec<NiktoVulnerability> = reports.into_iter().flat_map(|r| r.vulnerabilities).collect();
                if !vulns.is_empty() {
                    return vulns;
                }
            }
            if let Ok(vulns) = serde_json::from_str::<Vec<NiktoVulnerability>>(slice) {
                return vulns;
            }
        }
    }
    Vec::new()
}

#[async_trait]
impl Probe for NiktoProbe {
    fn name(&self) -> &str {
        "nikto"
    }

    fn timeout_secs(&self) -> u64 {
        300
    }

    async fn run(&self, ctx: &AuditContext) -> Result<ProbeResult> {
        if !check_tool_available("nikto") {
            warn!("[-] Tool 'nikto' is not available in PATH; skipping NiktoProbe");
            return Ok(ProbeResult::skipped("nikto", "nikto binary not found"));
        }

        let url = if !self.target.is_empty() && (self.target.starts_with("http://") || self.target.starts_with("https://")) {
            self.target.clone()
        } else {
            ctx.get_url()
        };
        info!("[*] Running NiktoProbe against {}", url);

        let temp_out = NamedTempFile::new()?;
        let temp_out_path = temp_out.into_temp_path();
        let out_path_string = temp_out_path.to_string_lossy().to_string();

        let random_ua = get_random_user_agent();
        let mut args = vec![
            "-h",
            &url,
            "-Format",
            "json",
            "-o",
            &out_path_string,
            "-nointeractive",
            "-useragent",
            random_ua,
        ];

        if let Some(ref prx) = ctx.proxy {
            args.push("-useproxy");
            args.push(prx.as_str());
        }

        if ctx.stealth_mode || ctx.waf_detected {
            info!("[!] WAF/Stealth active: enabling Nikto evasion encoding (-evasion 1) and 1s pause");
            args.push("-evasion");
            args.push("1");
            args.push("-Pause");
            args.push("1");
        }

        let _cmd_output = run_command("nikto", &args, self.timeout_secs()).await?;

        let mut findings = Vec::new();
        if let Ok(content) = fs::read_to_string(&temp_out_path) {
            let vulns = parse_nikto_json(&content);
            for vuln in vulns {
                let osvdb = vuln.osvdb.as_deref().unwrap_or("0");
                let msg = vuln.msg.as_deref().unwrap_or("Unknown vulnerability reported by Nikto");
                let msg_lower = msg.to_lowercase();

                let severity = if osvdb != "0" && (msg_lower.contains("vulnerable") || msg_lower.contains("cve")) {
                    Severity::High
                } else if msg_lower.contains("default") || msg_lower.contains("credential") {
                    Severity::High
                } else if msg_lower.contains("header") || msg_lower.contains("missing") {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                let title = if let Some(id) = &vuln.id {
                    let short_msg = if msg.len() > 60 { &msg[..60] } else { msg };
                    format!("Nikto [{}]: {}", id, short_msg)
                } else {
                    let short_msg = if msg.len() > 60 { &msg[..60] } else { msg };
                    format!("Nikto: {}", short_msg)
                };

                let raw_data = serde_json::to_value(&vuln).unwrap_or_else(|_| {
                    serde_json::json!({
                        "msg": msg,
                        "id": vuln.id,
                        "osvdb": vuln.osvdb,
                    })
                });

                let mut finding = Finding::new(
                    "nikto",
                    &url,
                    FindingKind::Vulnerability,
                    severity,
                    title,
                    msg,
                    raw_data,
                    0.85,
                )
                .with_tags(vec!["nikto".into(), "vulnerability".into()]);

                if let Some(id) = &vuln.id {
                    finding = finding.with_metadata("nikto_id", id.clone());
                }
                if let Some(osvdb_val) = &vuln.osvdb {
                    if osvdb_val != "0" {
                        finding = finding.with_metadata("osvdb", osvdb_val.clone());
                    }
                }
                if let Some(refs) = &vuln.references {
                    finding = finding.with_metadata("references", refs.clone());
                }

                findings.push(finding);
            }
        } else {
            warn!("[-] Nikto output file not found or unreadable: {}", out_path_string);
        }

        info!("[+] nikto completed with {} findings", findings.len());
        Ok(ProbeResult::success("nikto", findings))
    }
}
