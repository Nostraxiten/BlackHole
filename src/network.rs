use anyhow::{bail, Context, Result};
use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::str::FromStr;
use tracing::{debug, info, warn};

/// Validates that the provided target is strictly a private, RFC1918, loopback, or link-local address.
/// Rejects any public IP address, public CIDR range, or public domain resolution.
pub fn validate_local_target(target: &str) -> Result<()> {
    let clean = target.trim();
    if clean.is_empty() {
        bail!("Local mode target cannot be empty");
    }

    // Case 1: CIDR notation (e.g., "192.168.1.0/24")
    if clean.contains('/') {
        let net = IpNet::from_str(clean).with_context(|| {
            format!("Invalid CIDR notation '{}' specified for local audit", clean)
        })?;

        let network_ip = net.network();
        let broadcast_ip = net.broadcast();

        if !is_private_ip(&network_ip) || !is_private_ip(&broadcast_ip) {
            bail!(
                "SECURITY ABORT: CIDR range '{}' includes public IP addresses! \
                 Local mode is strictly restricted to RFC1918 / private networks.",
                clean
            );
        }
        info!("Validated local CIDR range: {}", clean);
        return Ok(());
    }

    // Case 2: Single IP address (e.g., "192.168.1.50")
    if let Ok(ip) = IpAddr::from_str(clean) {
        if !is_private_ip(&ip) {
            bail!(
                "SECURITY ABORT: IP address '{}' is a PUBLIC internet address! \
                 Local mode strictly forbids scanning public assets. \
                 Use 'blackhole {}' without 'local' for external audits.",
                clean, clean
            );
        }
        info!("Validated local private IP: {}", clean);
        return Ok(());
    }

    // Case 3: Hostname or Domain (e.g., "localhost", "my-router.local", or "google.com")
    // In local mode, resolve the hostname and ensure ALL resolved IPs are private.
    debug!("Resolving hostname '{}' for RFC1918 verification", clean);
    match dns_lookup_ips(clean) {
        Ok(ips) if !ips.is_empty() => {
            for ip in &ips {
                if !is_private_ip(ip) {
                    bail!(
                        "SECURITY ABORT: Hostname '{}' resolved to PUBLIC IP {}! \
                         Local mode strictly forbids public scanning. Aborting.",
                        clean, ip
                    );
                }
            }
            info!("Hostname '{}' resolved exclusively to private IP(s): {:?}", clean, ips);
            Ok(())
        }
        Ok(_) => {
            bail!("Could not resolve hostname '{}' to any IP address", clean);
        }
        Err(e) => {
            // If it's a mDNS/local name that failed DNS, check if it ends with .local or is localhost
            if clean.eq_ignore_ascii_case("localhost") || clean.ends_with(".local") {
                warn!("Local name '{}' could not be resolved via standard DNS, proceeding under local assumption", clean);
                Ok(())
            } else {
                bail!("Failed to resolve target '{}': {}. Aborting local mode.", clean, e);
            }
        }
    }
}

/// Helper to resolve hostname to IP addresses synchronously
fn dns_lookup_ips(host: &str) -> Result<Vec<IpAddr>> {
    use std::net::ToSocketAddrs;
    let formatted = format!("{}:80", host);
    let addrs = formatted.to_socket_addrs().with_context(|| format!("DNS lookup failed for {}", host))?;
    Ok(addrs.map(|sa| sa.ip()).collect())
}

/// Checks if an IP is an RFC1918 private address, loopback, or link-local address.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // 10.0.0.0/8 (RFC1918)
            o[0] == 10
            // 172.16.0.0/12 (RFC1918)
            || (o[0] == 172 && (16..=31).contains(&o[1]))
            // 192.168.0.0/16 (RFC1918)
            || (o[0] == 192 && o[1] == 168)
            // 127.0.0.0/8 (Loopback RFC1122)
            || o[0] == 127
            // 169.254.0.0/16 (Link-Local RFC3927)
            || (o[0] == 169 && o[1] == 254)
            // 100.64.0.0/10 (Carrier-Grade NAT RFC6598)
            || (o[0] == 100 && (64..=127).contains(&o[1]))
        }
        IpAddr::V6(v6) => {
            // ::1 (Loopback)
            v6.is_loopback()
            // Unspecified ::
            || v6.is_unspecified()
            // Unique Local Address (fc00::/7, RFC4193)
            || ((v6.segments()[0] & 0xfe00) == 0xfc00)
            // Link-Local (fe80::/10, RFC4291)
            || ((v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

/// Automatically discovers the active local network interface and determines
/// the local CIDR range (e.g. "192.168.1.0/24") without sending internet traffic.
///
/// Uses OS kernel routing table query via a disconnected UDP socket to a public endpoint.
pub fn discover_local_subnet() -> Result<String> {
    info!("Auto-discovering active local network interface...");

    // Connecting a UDP socket queries the OS routing table to determine which
    // local adapter would route traffic to an external destination, without sending packets.
    let socket = UdpSocket::bind("0.0.0.0:0")
        .context("Failed to bind UDP socket for route discovery")?;

    // We target a well-known public DNS IP to trigger route selection
    socket.connect(SocketAddr::from(([8, 8, 8, 8], 53)))
        .or_else(|_| socket.connect(SocketAddr::from(([1, 1, 1, 1], 53))))
        .context("Failed to query OS routing table for active outbound interface")?;

    let local_addr = socket.local_addr()
        .context("Failed to retrieve local address from socket")?;

    let local_ip = local_addr.ip();
    info!("Identified active local host IP: {}", local_ip);

    if !is_private_ip(&local_ip) {
        bail!(
            "Auto-discovered host IP {} is NOT a private IP. Refusing to guess local subnet.",
            local_ip
        );
    }

    match local_ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Default to standard class C /24 subnet for the local LAN
            let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
            info!("Inferred active local subnet CIDR: {}", subnet);
            Ok(subnet)
        }
        IpAddr::V6(_) => {
            // For IPv6, use link-local or loopback
            Ok(format!("{}/64", local_ip))
        }
    }
}
