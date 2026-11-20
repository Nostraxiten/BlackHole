#!/usr/bin/env bash
# ==============================================================================
# BlackHole - Complete Automated Installer for Kali Linux
# Architecture: Asynchronous DAG Offensive Security Reconnaissance Engine
# ==============================================================================

set -e
trap 'echo "[-] Error encountered at line $LINENO. Installation aborted."; exit 1' ERR

echo "[*] Initiating BlackHole environment setup and dependency verification..."

# 1. Privilege Verification
if [ "$EUID" -ne 0 ]; then
    if ! command -v sudo &>/dev/null; then
        echo "[-] ERROR: Root privileges or sudo required to install system packages."
        exit 1
    fi
    SUDO="sudo"
else
    SUDO=""
fi

echo "[+] Privileges verified."

# 2. Package Index Update
echo "[*] Updating package repositories..."
$SUDO apt-get update -y

# 3. System Binary Dependencies
PACKAGES=(
    "build-essential"
    "pkg-config"
    "libssl-dev"
    "curl"
    "git"
    "nmap"
    "masscan"
    "subfinder"
    "dnsx"
    "ffuf"
    "nuclei"
    "testssl.sh"
    "nikto"
    "dnsutils"
    "whois"
    "traceroute"
    "wafw00f"
    "enum4linux-ng"
    "netexec"
    "gobuster"
)

echo "[*] Installing required binary utilities and build dependencies..."
for pkg in "${PACKAGES[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        echo "[+] Package '$pkg' is already installed."
    else
        echo "[*] Installing '$pkg'..."
        $SUDO apt-get install -y "$pkg" || echo "[-] Warning: Package '$pkg' failed or unavailable in current repo; continuing."
    fi
done

# 4. Rust Toolchain Installation & Verification
echo "[*] Checking Rust toolchain..."
if ! command -v cargo &>/dev/null; then
    echo "[!] Rust toolchain not detected. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    
    # Source Rust environment for current session
    if [ -f "$HOME/.cargo/env" ]; then
        # shellcheck disable=SC1091
        source "$HOME/.cargo/env"
    elif [ -f "/root/.cargo/env" ]; then
        # shellcheck disable=SC1091
        source "/root/.cargo/env"
    fi
else
    echo "[+] Rust (cargo) is already installed: $(cargo --version)"
fi

# Ensure cargo is accessible in path
if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
fi

# 5. Project Directory Verification
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -f "Cargo.toml" ] || [ ! -d "src" ]; then
    echo "[-] ERROR: Cargo.toml or src directory missing from $SCRIPT_DIR."
    exit 1
fi

# 6. Compilation of BlackHole
echo "[*] Compiling BlackHole in release mode (aggressive optimizations)..."
cargo build --release

# 7. Symlink Creation
BINARY_PATH="$SCRIPT_DIR/target/release/blackhole"
if [ -f "$BINARY_PATH" ]; then
    echo "[+] Binary successfully compiled at: $BINARY_PATH"
    
    # Create local shortcut
    ln -sf "$BINARY_PATH" "$SCRIPT_DIR/blackhole"
    chmod +x "$BINARY_PATH" "$SCRIPT_DIR/blackhole"
    echo "[+] Local executable link created: $SCRIPT_DIR/blackhole"
else
    echo "[-] ERROR: Compilation finished but binary was not found at $BINARY_PATH."
    exit 1
fi

echo "============================================================"
echo "[+] BlackHole Installation Completed Successfully."
echo "[*] IMPORTANT: Due to security root directory enforcement,"
echo "    BlackHole must be run from this directory ($SCRIPT_DIR)."
echo ""
echo "    Usage Examples:"
echo "      $SUDO ./blackhole example.com"
echo "      $SUDO ./blackhole local"
echo "      $SUDO ./blackhole local 192.168.1.0/24"
echo "============================================================"
