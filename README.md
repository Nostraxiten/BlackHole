# BlackHole - Advanced Offensive Reconnaissance & Audit Framework

BlackHole is an asynchronous, aggressive, and modular security reconnaissance and attack surface orchestration engine written purely in Rust. Designed specifically for Kali Linux, it acts as an offensive orchestrator that absorbs industry-standard security binaries into a structured Directed Acyclic Graph (DAG) pipeline, parses raw XML and JSON outputs into structured evidence streams, and persists all findings into an append-only JSONL Evidence Store.

---

## Architecture Overview

```
                      +-----------------------------+
                      |       BlackHole CLI         |
                      |   [Target Mode | Local Mode] |
                      +--------------+--------------+
                                     |
                                     v
                       +---------------------------+
                       |    Asynchronous DAG       |
                       | (Tokio JoinSet Execution) |
                       +-------------+-------------+
                                     |
       +-----------------------------+-----------------------------+
       |                             |                             |
       v                             v                             v
[DAG STAGE 1]                 [DAG STAGE 2]                 [DAG STAGE 3]
Perimeter Sweep               DNS Resolution                Port Enumeration
- Subfinder                   - Dnsx                        - Masscan
- Whois                       - Dig (Records & AXFR)        - Nmap Discovery
- Wafw00f                                                   - Netcat Scalpel
- Traceroute                                                - Nmap Phase 2 (Vulners)
- Arp-scan (Local)                                          - TestSSL.sh
       |                             |                             |
       +-----------------------------+-----------------------------+
                                     |
       +-----------------------------+-----------------------------+
       |                             |                             |
       v                             v                             v
[DAG STAGE 4]                 [DAG STAGE 5]                 [DAG STAGE 6]
Web Probing                   Evasive Directory Fuzzing     Vulnerability Audit
- Httpx                       - FFuF (Adaptive Rate Limit)  - Nuclei
- Curl Header Analysis        - Nikto (WAF Evasion)         - Hybrid CVE Matcher
                                                            - Enum4linux-ng (Local)
                                                            - NetExec (Local)
                                     |
                                     v
                      +-----------------------------+
                      |   Append-Only JSONL Store   |
                      |   & Markdown Report Engine  |
                      +-----------------------------+
```

### Core Design Principles
1. **Strict Operational Modes**:
   - **Target Mode**: Executed as `blackhole <domain_or_ip>`. Audits external targets, performing subdomain harvesting, DNS sweeps, and perimeter probing.
   - **Local Mode**: Executed as `blackhole local [SUBNET]`. Automatically discovers active private subnets via local interfaces or ARP sweeps. Enforces strict RFC1918 validation: scanning public IP addresses in local mode immediately triggers a security abort.
2. **Lock-Free Concurrency & Shared State**:
   - Independent probes execute concurrently inside a `tokio::task::JoinSet`.
   - Each probe consumes an immutable `Arc<AuditContext>` snapshot and returns a `ProbeResult`.
   - Results are applied to the global context at stage barriers without race conditions.
3. **Adaptive WAF Evasion**:
   - Dynamic User-Agent rotation selecting authentic browser signatures (Chrome, Firefox, Safari, Edge, Googlebot).
   - Automatic throttling in FFuF: switches from 50 threads to 5 threads with 0.5s–2.0s randomized inter-request delay when a WAF is detected.
   - Full SOCKS5 and HTTP proxy redirection across tools.
4. **Hybrid CVE Correlation Engine**:
   - Combines NIST NVD gzip feeds, Kaisen Linux databases, and built-in vulnerability definitions.
   - Matches CPE banners discovered by Nmap with exact version (0.95 confidence) and vendor/product (0.70 confidence) metrics.

---

## System Requirements
- **Operating System**: Kali Linux, Debian 12+, or Ubuntu 22.04+ (x86_64).
- **Permissions**: Root or sudo privileges (required for raw socket probes like Masscan and Nmap SYN sweeps).
- **Rust Toolchain**: Rust 1.75+ (automatically installed by `install.sh` if missing).

---

## Installation

Run the unified installer script from the root of the cloned repository:

```bash
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

The installer performs the following operations:
1. Verifies administrative privileges.
2. Updates apt repositories and installs binary dependencies:
   `nmap`, `masscan`, `subfinder`, `dnsx`, `ffuf`, `nuclei`, `testssl.sh`, `nikto`, `curl`, `dnsutils`, `whois`, `traceroute`, `wafw00f`, `enum4linux-ng`, `netexec`, `gobuster`.
3. Installs the official Rust stable toolchain via `rustup` if absent.
4. Compiles BlackHole in release mode (`cargo build --release`).
5. Creates a symlink `./blackhole` in the repository root.

---

## Usage

BlackHole requires execution from its root project directory to enforce workspace integrity.

### 1. External Target Assessment
```bash
# Standard external audit
sudo ./blackhole example.com

# External audit through SOCKS5 Tor proxy with 12 concurrent workers
sudo ./blackhole example.com --proxy socks5://127.0.0.1:9050 -c 12

# External audit with NVD feed update and custom wordlist
sudo ./blackhole target.org --update-db -w /usr/share/wordlists/dirb/common.txt
```

### 2. Internal LAN Assessment
```bash
# Automatic interface and subnet discovery
sudo ./blackhole local

# Explicit subnet targeting
sudo ./blackhole local 192.168.1.0/24

# Specific host targeting
sudo ./blackhole local 10.0.0.15
```

### CLI Options

| Flag | Long Option | Description | Default |
|---|---|---|---|
| `-o` | `--output` | Destination directory for evidence and reports | `./blackhole_output` |
| `-c` | `--concurrency` | Semaphore permit limit for concurrent executions | `8` |
| `-w` | `--wordlist` | Path to custom wordlist for directory fuzzing | Embedded list |
| `-p` | `--proxy` | Proxy URL (`socks5://...` or `http://...`) | None |
| | `--kaisen-db` | Path to external Kaisen vulnerability database | Auto-detected |
| | `--update-db` | Download and update official NVD CVE JSON feed | `false` |
| `-v` | `--verbose` | Enable debug logging output | `false` |

---

## Output Artifacts

All outputs are saved to the designated directory (default `./blackhole_output/`):
- `evidence_<SESSION_ID>.jsonl`: Append-only, newline-delimited JSON stream capturing every finding, raw tool output, and metadata in real time.
- `report_<SESSION_ID>.md`: Formatted technical Markdown assessment report containing executive summary metrics, attack surface tables, and prioritized findings with mitigation advice.
- `summary_<SESSION_ID>.json`: Machine-readable audit summary including finding distributions and severity metrics.

---

## Uninstallation

To clean build files, caches, or completely purge installed tools:

```bash
# Basic cleanup (removes target/, Cargo.lock, and ./blackhole_output/)
./uninstall.sh

# Complete purge (removes BlackHole artifacts and uninstalls all apt dependencies)
sudo ./uninstall.sh --purge-deps

# Deep purge (removes BlackHole, dependencies, and uninstalls the Rust toolchain)
sudo ./uninstall.sh --purge-deps --purge-rust
```

---

## Legal Disclaimer

BlackHole is designed exclusively for authorized penetration testing, vulnerability assessment, and defensive security auditing. Usage of BlackHole against targets without prior explicit written authorization is illegal. The developers assume no liability for misuse or damage caused by this software.
