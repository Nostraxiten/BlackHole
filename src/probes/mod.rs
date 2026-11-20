pub mod recon;
pub mod network;
pub mod web;
pub mod vuln;
pub mod masscan;
pub mod subfinder;
pub mod dnsx;

use crate::probe::Probe;
use crate::types::{AuditContext, AuditMode};

#[allow(dead_code)]
pub fn build_pipeline(ctx: &AuditContext) -> Vec<Box<dyn Probe>> {
    let mut probes: Vec<Box<dyn Probe>> = Vec::new();

    // High speed recon & subdomains
    if ctx.mode == AuditMode::Target {
        probes.push(Box::new(subfinder::SubfinderProbe::new(ctx.target.clone())));
        probes.push(Box::new(recon::WhoisProbe::new(ctx.target.clone())));
        probes.push(Box::new(recon::DigProbe::new(ctx.target.clone())));
        probes.push(Box::new(dnsx::DnsxProbe::new(ctx.target.clone())));
        probes.push(Box::new(recon::TracerouteProbe::new(ctx.target.clone())));
        probes.push(Box::new(recon::WafDetectProbe::new(ctx.target.clone())));
        probes.push(Box::new(masscan::MasscanProbe::new(ctx.target.clone())));
    }

    if ctx.mode == AuditMode::Local {
        probes.push(Box::new(network::ArpScanProbe::new(ctx.target.clone())));
    }

    // Network port scanning & deep services
    probes.push(Box::new(network::NmapDiscoveryProbe::new(ctx.target.clone())));
    probes.push(Box::new(network::NmapServicesProbe::new(ctx.target.clone())));
    probes.push(Box::new(network::TestSslProbe::new(ctx.target.clone())));

    // Web probes
    probes.push(Box::new(web::CurlHeadersProbe::new(ctx.target.clone())));
    probes.push(Box::new(web::HttpxProbe::new(ctx.target.clone())));
    probes.push(Box::new(web::FfufProbe::new(ctx.target.clone())));
    probes.push(Box::new(web::NiktoProbe::new(ctx.target.clone())));

    // Vulnerability scanning & CVE matching
    probes.push(Box::new(vuln::NucleiProbe::new(ctx.target.clone())));
    probes.push(Box::new(vuln::CveMatcher::new(ctx.target.clone())));

    if ctx.mode == AuditMode::Local {
        probes.push(Box::new(vuln::Enum4linuxProbe::new(ctx.target.clone())));
        probes.push(Box::new(vuln::NetExecProbe::new(ctx.target.clone())));
    }

    probes
}
