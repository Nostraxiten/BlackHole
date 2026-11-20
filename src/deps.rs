use std::process::{Command, Stdio};
use tracing::{info, warn};
use colored::Colorize;
use crate::executor::check_tool_available;

pub const REQUIRED_TOOLS: &[&str] = &[
    "nmap",
    "masscan",
    "subfinder",
    "dnsx",
    "ffuf",
    "nuclei",
    "testssl.sh",
    "nikto",
    "curl",
    "dig",
    "whois",
    "traceroute",
    "wafw00f",
    "enum4linux-ng",
    "netexec",
];

/// Maps specific CLI tool names to Debian/Ubuntu/Kali package names
fn map_tool_to_pkg(tool: &str) -> &str {
    match tool {
        "dig" => "dnsutils",
        "testssl.sh" => "testssl.sh",
        "wafw00f" => "wafw00f",
        "enum4linux-ng" => "enum4linux-ng",
        "netexec" => "netexec",
        other => other,
    }
}

/// Verifies presence of all required binary dependencies.
/// If any tool is absent from PATH and local candidate paths, attempts automatic installation via apt-get.
pub fn check_and_install_dependencies() {
    println!("{}", "[*] Verifying system binary dependencies...".cyan());

    for &tool in REQUIRED_TOOLS {
        if check_tool_available(tool) {
            info!("[+] Dependency verified: {}", tool);
            continue;
        }

        let pkg = map_tool_to_pkg(tool);
        println!(
            "{}",
            format!(
                "[!] Missing dependency: '{}'. Attempting automatic installation via apt-get (package: '{}')...",
                tool, pkg
            )
            .yellow()
        );

        // Attempt installation via apt-get with inherited stdio for sudo prompt
        let status = Command::new("sudo")
            .args(["apt-get", "install", "-y", pkg])
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status();

        match status {
            Ok(s) if s.success() => {
                println!(
                    "{}",
                    format!("[+] Successfully installed dependency: '{}'", tool).green()
                );
            }
            Ok(s) => {
                warn!(
                    "[-] Package manager returned exit code {:?} for '{}'. Associated probes may be skipped.",
                    s.code(),
                    pkg
                );
            }
            Err(e) => {
                warn!(
                    "[-] Failed to execute apt-get for '{}': {}. Associated probes will be skipped.",
                    pkg, e
                );
            }
        }
    }
}
