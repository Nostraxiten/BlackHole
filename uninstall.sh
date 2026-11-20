#!/usr/bin/env bash
# ==============================================================================
# BlackHole - Complete Deep Uninstaller
# Cleans build artifacts, output evidence, and optionally purges dependencies
# ==============================================================================

set -e
trap 'echo "[-] Error encountered during cleanup at line $LINENO."; exit 1' ERR

PURGE_DEPS=false
PURGE_RUST=false

for arg in "$@"; do
    case "$arg" in
        --purge-deps)
            PURGE_DEPS=true
            ;;
        --purge-rust)
            PURGE_RUST=true
            ;;
        --help|-h)
            echo "BlackHole Deep Uninstaller"
            echo "Usage: ./uninstall.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --purge-deps   Purge all system CLI tools installed for BlackHole (apt-get purge)"
            echo "  --purge-rust   Remove the Rust compiler toolchain (~/.cargo and ~/.rustup)"
            echo "  --help, -h     Show this help message"
            exit 0
            ;;
        *)
            echo "[-] Unknown option: $arg"
            echo "    Use --help for usage information."
            exit 1
            ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "[*] Initiating BlackHole cleanup process..."

# 1. Clean Compilation Artifacts and Binaries
echo "[*] Removing build artifacts and local symlinks..."
rm -rf "$SCRIPT_DIR/target"
rm -f "$SCRIPT_DIR/Cargo.lock"
rm -f "$SCRIPT_DIR/blackhole"
echo "[+] Build artifacts removed."

# 2. Clean Evidence Store and Output Artifacts
echo "[*] Cleaning output evidence and scan sessions..."
rm -rf "$SCRIPT_DIR/blackhole_output"
rm -rf "$SCRIPT_DIR/kaisen"
rm -rf "$SCRIPT_DIR/nvd"
rm -rf "$SCRIPT_DIR/tmp"
rm -f "$SCRIPT_DIR"/*.tmp
rm -f "$SCRIPT_DIR"/*.json
rm -f "$SCRIPT_DIR"/*.xml
echo "[+] Output artifacts cleaned."

# 3. Optional: Purge System Binary Dependencies
if [ "$PURGE_DEPS" = true ]; then
    echo "[!] --purge-deps specified. Purging system security binaries..."
    
    if [ "$EUID" -ne 0 ]; then
        if ! command -v sudo &>/dev/null; then
            echo "[-] ERROR: Root privileges or sudo required to purge system packages."
            exit 1
        fi
        SUDO="sudo"
    else
        SUDO=""
    fi

    PACKAGES=(
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

    for pkg in "${PACKAGES[@]}"; do
        if dpkg -s "$pkg" &>/dev/null; then
            echo "[*] Purging package: $pkg..."
            $SUDO apt-get remove --purge -y "$pkg" || true
        fi
    done

    echo "[*] Running autoremove..."
    $SUDO apt-get autoremove -y
    $SUDO apt-get clean
    echo "[+] Dependencies successfully purged."
fi

# 4. Optional: Purge Rust Toolchain
if [ "$PURGE_RUST" = true ]; then
    echo "[!] --purge-rust specified. Removing Rust compiler and toolchains..."
    if command -v rustup &>/dev/null; then
        rustup self uninstall -y || true
    fi
    rm -rf "$HOME/.cargo"
    rm -rf "$HOME/.rustup"
    rm -rf "/root/.cargo"
    rm -rf "/root/.rustup"
    echo "[+] Rust toolchain successfully removed."
fi

echo "============================================================"
echo "[+] BlackHole Deep Uninstallation Completed."
echo "[*] Workspace directory reset to pristine repository state."
echo "============================================================"
