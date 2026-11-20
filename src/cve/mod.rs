use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::types::Severity;

/// Downloads official NVD recent feed JSON.gz, decompresses it and saves it locally.
pub async fn update_nvd_feed() -> Result<String> {
    let url = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz";
    info!("[*] Fetching official NVD recent feed from: {}", url);

    let client = reqwest::Client::builder()
        .user_agent("Mozilla/5.0 (X11; Linux x86_64; rv:109.0) BlackHole/0.1")
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let response = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("Failed to download NVD feed from {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!("NVD feed server responded with HTTP status {}", response.status());
    }

    let compressed_bytes = response.bytes().await?;
    info!("[*] Downloaded {} compressed bytes. Decompressing gzip archive...", compressed_bytes.len());

    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut decompressed_json = String::new();
    decoder
        .read_to_string(&mut decompressed_json)
        .context("Failed to decompress NVD gzip feed")?;

    let dest_dir = PathBuf::from("./blackhole_output/nvd");
    tokio::fs::create_dir_all(&dest_dir).await?;
    let dest_file = dest_dir.join("nvdcve-recent.json");

    tokio::fs::write(&dest_file, &decompressed_json)
        .await
        .with_context(|| format!("Failed to save decompressed NVD JSON to {}", dest_file.display()))?;

    let file_str = dest_file.to_string_lossy().to_string();
    info!("[+] NVD CVE database successfully updated and saved to: {}", file_str);
    Ok(file_str)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CveEntry {
    pub id: String,
    pub description: String,
    pub cvss_score: f32,
    pub cvss_vector: Option<String>,
    pub published: Option<String>,
    pub cpes: Vec<String>,
    pub references: Vec<String>,
}

impl CveEntry {
    /// Maps numeric CVSS base score directly to standardized Severity enum.
    pub fn severity(&self) -> Severity {
        cvss_to_severity(self.cvss_score)
    }
}

/// Helper converting CVSS score (0.0 - 10.0) to BlackHole Severity
pub fn cvss_to_severity(score: f32) -> Severity {
    match score {
        s if s >= 9.0 => Severity::Critical,
        s if s >= 7.0 => Severity::High,
        s if s >= 4.0 => Severity::Medium,
        s if s > 0.0 => Severity::Low,
        _ => Severity::Info,
    }
}

/// Discovers candidate paths for Kaisen database file
fn resolve_kaisen_path(explicit_path: Option<&str>) -> Option<PathBuf> {
    if let Some(p) = explicit_path {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }

    let local_paths = [
        "./kaisen/kaisen.db",
        "./kaisen/db.json",
        "./tools/kaisen.db",
    ];

    for p in &local_paths {
        let pb = PathBuf::from(p);
        if pb.exists() {
            return Some(pb);
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        let user_kaisen = PathBuf::from(home).join(".blackhole").join("kaisen.db");
        if user_kaisen.exists() {
            return Some(user_kaisen);
        }
    }

    None
}

/// Loads Kaisen Linux CVE database from JSON or text database format
pub fn load_kaisen_db(explicit_path: Option<&str>) -> Result<Vec<CveEntry>> {
    let path = match resolve_kaisen_path(explicit_path) {
        Some(p) => p,
        None => {
            debug!("[*] No Kaisen database found at candidate paths; skipping Kaisen feed");
            return Ok(Vec::new());
        }
    };

    info!("[*] Loading Kaisen vulnerability database from: {}", path.display());
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read Kaisen database file at {}", path.display()))?;

    // Attempt parsing as JSON array
    if let Ok(entries) = serde_json::from_str::<Vec<CveEntry>>(&content) {
        info!("[+] Successfully loaded {} CVE entries from Kaisen DB array", entries.len());
        return Ok(entries);
    }

    // Attempt parsing as JSON object/map { "CVE-XXXX": { ... } }
    if let Ok(map) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&content) {
        let mut entries = Vec::new();
        for (k, val) in map {
            let id = val.get("id").and_then(|v| v.as_str()).unwrap_or(&k).to_string();
            let description = val.get("description").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let cvss_score = val.get("cvss_score").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
            let cvss_vector = val.get("cvss_vector").and_then(|v| v.as_str()).map(|s| s.to_string());
            let published = val.get("published").and_then(|v| v.as_str()).map(|s| s.to_string());
            let cpes = val.get("cpes").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|c| c.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();
            let references = val.get("references").and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|r| r.as_str().map(|s| s.to_string())).collect())
                .unwrap_or_default();

            entries.push(CveEntry {
                id,
                description,
                cvss_score,
                cvss_vector,
                published,
                cpes,
                references,
            });
        }
        info!("[+] Successfully loaded {} CVE entries from Kaisen DB map", entries.len());
        return Ok(entries);
    }

    warn!("[-] Unrecognized format for Kaisen DB at {}; returning empty entries", path.display());
    Ok(Vec::new())
}

/// In-memory indexed CVE vulnerability database.
/// Provides O(1) indexed lookup by normalized vendor:product CPE keys.
pub struct CveDatabase {
    entries: Vec<CveEntry>,
    // Maps "vendor:product" -> Vec of entry indices in `entries`
    cpe_index: HashMap<String, Vec<usize>>,
}

#[derive(Debug, Clone)]
pub struct CveMatchResult<'a> {
    pub entry: &'a CveEntry,
    pub confidence: f32,
    pub match_type: &'static str,
    pub matched_cpe: Option<String>,
}

impl CveDatabase {
    /// Ingests an official NVD CVE JSON feed (1.1 format).
    pub fn load_from_nvd_file(path: &str) -> Result<Vec<CveEntry>> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read NVD JSON database at {}", path))?;

        let raw: serde_json::Value = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse NVD JSON structure from {}", path))?;

        let mut entries = Vec::new();

        if let Some(items) = raw.get("CVE_Items").and_then(|v| v.as_array()) {
            for item in items {
                if let Some(entry) = Self::parse_nvd_item(item) {
                    entries.push(entry);
                }
            }
        }

        info!("[+] Ingested {} CVE entries from NVD database at '{}'", entries.len(), path);
        Ok(entries)
    }

    fn parse_nvd_item(item: &serde_json::Value) -> Option<CveEntry> {
        let cve_id = item
            .get("cve")?
            .get("CVE_data_meta")?
            .get("ID")?
            .as_str()?
            .to_string();

        let description = item
            .get("cve")?
            .get("description")?
            .get("description_data")?
            .as_array()?
            .first()?
            .get("value")?
            .as_str()?
            .to_string();

        let cvss_score = item
            .get("impact")
            .and_then(|i| i.get("baseMetricV3"))
            .and_then(|m| m.get("cvssV3"))
            .and_then(|c| c.get("baseScore"))
            .and_then(|s| s.as_f64())
            .unwrap_or_else(|| {
                item.get("impact")
                    .and_then(|i| i.get("baseMetricV2"))
                    .and_then(|m| m.get("cvssV2"))
                    .and_then(|c| c.get("baseScore"))
                    .and_then(|s| s.as_f64())
                    .unwrap_or(0.0)
            }) as f32;

        let cvss_vector = item
            .get("impact")
            .and_then(|i| i.get("baseMetricV3"))
            .and_then(|m| m.get("cvssV3"))
            .and_then(|c| c.get("vectorString"))
            .and_then(|s| s.as_str())
            .map(|s| s.to_string())
            .or_else(|| {
                item.get("impact")
                    .and_then(|i| i.get("baseMetricV2"))
                    .and_then(|m| m.get("cvssV2"))
                    .and_then(|c| c.get("vectorString"))
                    .and_then(|s| s.as_str())
                    .map(|s| s.to_string())
            });

        let mut cpes = Vec::new();
        if let Some(config) = item.get("configurations") {
            Self::extract_cpes_from_config(config, &mut cpes);
        }

        let published = item
            .get("publishedDate")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut references = Vec::new();
        if let Some(ref_data) = item
            .get("cve")
            .and_then(|c| c.get("references"))
            .and_then(|r| r.get("reference_data"))
            .and_then(|v| v.as_array())
        {
            for r in ref_data {
                if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
                    references.push(url.to_string());
                }
            }
        }

        Some(CveEntry {
            id: cve_id,
            description,
            cvss_score,
            cvss_vector,
            published,
            cpes,
            references,
        })
    }

    fn extract_cpes_from_config(config: &serde_json::Value, cpes: &mut Vec<String>) {
        if let Some(nodes) = config.get("nodes").and_then(|v| v.as_array()) {
            for node in nodes {
                if let Some(matches) = node.get("cpe_match").and_then(|v| v.as_array()) {
                    for m in matches {
                        if let Some(cpe) = m.get("cpe23Uri").and_then(|v| v.as_str()) {
                            cpes.push(cpe.to_string());
                        }
                    }
                }
                if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
                    for child in children {
                        Self::extract_cpes_from_config(child, cpes);
                    }
                }
            }
        }
    }

    /// High-impact built-in CVE database covering prominent critical infrastructure vulnerabilities
    pub fn load_builtin() -> Self {
        let entries = Self::builtin_entries();
        let mut db = Self {
            entries,
            cpe_index: HashMap::new(),
        };
        db.build_index();
        db
    }

    pub fn builtin_entries() -> Vec<CveEntry> {
        vec![
            CveEntry {
                id: "CVE-2021-44228".to_string(),
                description: "Log4Shell: Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints. Unauthenticated Remote Code Execution.".to_string(),
                cvss_score: 10.0,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H".to_string()),
                published: Some("2021-12-10".to_string()),
                cpes: vec![
                    "cpe:2.3:a:apache:log4j:2.0:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-44228".to_string()],
            },
            CveEntry {
                id: "CVE-2017-0144".to_string(),
                description: "EternalBlue: SMBv1 in Microsoft Windows allows remote code execution via crafted packets. Exploited by WannaCry and NotPetya.".to_string(),
                cvss_score: 9.3,
                cvss_vector: Some("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                published: Some("2017-03-16".to_string()),
                cpes: vec![
                    "cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:o:microsoft:windows_server_2008:*:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:microsoft:smbv1:*:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2017-0144".to_string()],
            },
            CveEntry {
                id: "CVE-2014-0160".to_string(),
                description: "Heartbleed: OpenSSL TLS heartbeat extension memory disclosure bug. Allows remote unauthenticated reading of server private keys and memory.".to_string(),
                cvss_score: 7.5,
                cvss_vector: Some("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:N/A:N".to_string()),
                published: Some("2014-04-07".to_string()),
                cpes: vec![
                    "cpe:2.3:a:openssl:openssl:1.0.1:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:openssl:openssl:1.0.1f:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2014-0160".to_string()],
            },
            CveEntry {
                id: "CVE-2021-26855".to_string(),
                description: "ProxyLogon: Microsoft Exchange Server SSRF leading to Remote Code Execution without authentication.".to_string(),
                cvss_score: 9.8,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                published: Some("2021-03-02".to_string()),
                cpes: vec![
                    "cpe:2.3:a:microsoft:exchange_server:2013:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:microsoft:exchange_server:2016:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:microsoft:exchange_server:2019:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-26855".to_string()],
            },
            CveEntry {
                id: "CVE-2019-0708".to_string(),
                description: "BlueKeep: Unauthenticated remote code execution in Microsoft Remote Desktop Protocol (RDP) on port 3389.".to_string(),
                cvss_score: 9.8,
                cvss_vector: Some("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                published: Some("2019-05-16".to_string()),
                cpes: vec![
                    "cpe:2.3:o:microsoft:windows_7:*:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:o:microsoft:windows_server_2008:*:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:microsoft:remote_desktop_services:*:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2019-0708".to_string()],
            },
            CveEntry {
                id: "CVE-2020-1938".to_string(),
                description: "Ghostcat: Apache Tomcat AJP protocol file inclusion and remote code execution vulnerability on port 8009.".to_string(),
                cvss_score: 9.8,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                published: Some("2020-02-24".to_string()),
                cpes: vec![
                    "cpe:2.3:a:apache:tomcat:7.0.0:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:apache:tomcat:8.5.0:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:apache:tomcat:9.0.0:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2020-1938".to_string()],
            },
            CveEntry {
                id: "CVE-2024-6387".to_string(),
                description: "regreSSHion: OpenSSH unauthenticated remote code execution vulnerability in glibc-based Linux systems.".to_string(),
                cvss_score: 8.1,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                published: Some("2024-07-01".to_string()),
                cpes: vec![
                    "cpe:2.3:a:openbsd:openssh:8.5:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*".to_string(),
                    "cpe:2.3:a:openbsd:openssh:9.7:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2024-6387".to_string()],
            },
            CveEntry {
                id: "CVE-2021-41773".to_string(),
                description: "Apache HTTP Server 2.4.49 path traversal and remote code execution flaw via mod_cgi.".to_string(),
                cvss_score: 7.5,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N".to_string()),
                published: Some("2021-10-05".to_string()),
                cpes: vec![
                    "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2021-41773".to_string()],
            },
            CveEntry {
                id: "CVE-2022-22965".to_string(),
                description: "Spring4Shell: Spring Framework remote code execution via class loader manipulation on JDK 9+.".to_string(),
                cvss_score: 9.8,
                cvss_vector: Some("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".to_string()),
                published: Some("2022-04-01".to_string()),
                cpes: vec![
                    "cpe:2.3:a:vmware:spring_framework:5.3.0:*:*:*:*:*:*:*".to_string(),
                ],
                references: vec!["https://nvd.nist.gov/vuln/detail/CVE-2022-22965".to_string()],
            },
        ]
    }

    /// Hybrid loader merging Builtin entries, Kaisen Linux DB and official NVD feed
    pub fn load_hybrid(kaisen_path: Option<&str>, nvd_path: Option<&str>) -> Self {
        let mut entry_map: HashMap<String, CveEntry> = HashMap::new();

        // 1. Ingest built-in high-impact CVEs
        for entry in Self::builtin_entries() {
            entry_map.insert(entry.id.clone(), entry);
        }

        // 2. Ingest Kaisen Linux database if present
        if let Ok(kaisen_entries) = load_kaisen_db(kaisen_path) {
            for entry in kaisen_entries {
                entry_map.insert(entry.id.clone(), entry);
            }
        }

        // 3. Ingest NVD JSON feed if present
        let nvd_file = nvd_path
            .map(|p| p.to_string())
            .unwrap_or_else(|| "./blackhole_output/nvd/nvdcve-recent.json".to_string());

        if Path::new(&nvd_file).exists() {
            if let Ok(nvd_entries) = Self::load_from_nvd_file(&nvd_file) {
                for entry in nvd_entries {
                    entry_map.insert(entry.id.clone(), entry);
                }
            }
        }

        let total_count = entry_map.len();
        let entries: Vec<CveEntry> = entry_map.into_values().collect();

        let mut db = Self {
            entries,
            cpe_index: HashMap::new(),
        };
        db.build_index();
        info!("[+] Hybrid CVE Engine initialized with {} unique CVE entries", total_count);
        db
    }

    /// Indexes all CVE entries by normalized "vendor:product" key for O(1) matching.
    fn build_index(&mut self) {
        self.cpe_index.clear();
        for (idx, entry) in self.entries.iter().enumerate() {
            for cpe in &entry.cpes {
                if let Some(key) = extract_vendor_product_key(cpe) {
                    self.cpe_index.entry(key).or_default().push(idx);
                }
            }
        }
        debug!("[*] CVE index built with {} unique vendor:product keys", self.cpe_index.len());
    }

    /// Matches a target CPE against the indexed CVE database.
    /// Confidence:
    /// - 0.95 for exact version match
    /// - 0.70 for vendor:product match
    pub fn match_cpe<'a>(&'a self, target_cpe: &str) -> Vec<CveMatchResult<'a>> {
        let key = match extract_vendor_product_key(target_cpe) {
            Some(k) => k,
            None => return vec![],
        };

        let target_version = extract_cpe_version(target_cpe);

        if let Some(indices) = self.cpe_index.get(&key) {
            indices
                .iter()
                .filter_map(|&i| self.entries.get(i))
                .map(|entry| {
                    let mut confidence = 0.70f32; // Vendor + Product match
                    let mut match_type = "cpe_vendor_product";

                    // Check if any indexed CPE matches version specifically
                    if let Some(ref t_ver) = target_version {
                        for cpe in &entry.cpes {
                            if let Some(ref cpe_ver) = extract_cpe_version(cpe) {
                                if cpe_ver == t_ver {
                                    confidence = 0.95; // Exact version match
                                    match_type = "cpe_exact_version";
                                    break;
                                }
                            }
                        }
                    }

                    CveMatchResult {
                        entry,
                        confidence,
                        match_type,
                        matched_cpe: Some(target_cpe.to_string()),
                    }
                })
                .collect()
        } else {
            vec![]
        }
    }

    /// Fallback fuzzy matching by product and version strings when no CPE is present.
    pub fn search_by_product_name<'a>(&'a self, product: &str, version: &str) -> Vec<CveMatchResult<'a>> {
        let p_lower = product.to_lowercase();
        let v_lower = version.to_lowercase();

        self.entries
            .iter()
            .filter_map(|entry| {
                let matches_product = entry.cpes.iter().any(|cpe| {
                    let cpe_l = cpe.to_lowercase();
                    cpe_l.contains(&p_lower)
                }) || entry.description.to_lowercase().contains(&p_lower);

                if !matches_product {
                    return None;
                }

                let matches_version = !v_lower.is_empty() && (
                    entry.cpes.iter().any(|cpe| cpe.contains(&v_lower))
                    || entry.description.contains(&v_lower)
                );

                let confidence = if matches_version { 0.75 } else { 0.50 };

                Some(CveMatchResult {
                    entry,
                    confidence,
                    match_type: "fuzzy_product_name",
                    matched_cpe: None,
                })
            })
            .collect()
        }
}

/// Normalizes CPE string (both 2.3 and 2.2) into a "vendor:product" lookup key
pub fn extract_vendor_product_key(cpe: &str) -> Option<String> {
    let lower = cpe.to_lowercase();
    let parts: Vec<&str> = lower.split(':').collect();

    // CPE 2.3 format: "cpe:2.3:<part>:<vendor>:<product>:..."
    if lower.starts_with("cpe:2.3:") && parts.len() >= 5 {
        let vendor = parts[3].trim();
        let product = parts[4].trim();
        if !vendor.is_empty() && !product.is_empty() && vendor != "*" && product != "*" {
            return Some(format!("{}:{}", vendor, product));
        }
    }

    // CPE 2.2 / legacy format: "cpe:/<part>:<vendor>:<product>:..."
    if lower.starts_with("cpe:/") {
        let trimmed = lower.trim_start_matches("cpe:/");
        let parts2: Vec<&str> = trimmed.split(':').collect();
        if parts2.len() >= 3 {
            let vendor = parts2[1].trim();
            let product = parts2[2].trim();
            if !vendor.is_empty() && !product.is_empty() {
                return Some(format!("{}:{}", vendor, product));
            }
        }
    }

    None
}

/// Extracts version segment from CPE 2.3 string if not wildcard
pub fn extract_cpe_version(cpe: &str) -> Option<String> {
    let lower = cpe.to_lowercase();
    let parts: Vec<&str> = lower.split(':').collect();
    if lower.starts_with("cpe:2.3:") && parts.len() >= 6 {
        let ver = parts[5].trim();
        if !ver.is_empty() && ver != "*" && ver != "-" {
            return Some(ver.to_string());
        }
    }
    None
}
