use anyhow::{anyhow, Context, Result};
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::timeout;
use tracing::{debug, error, info};

#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

impl CommandOutput {
    pub fn is_success(&self) -> bool {
        self.exit_code == 0
    }
}

/// Resolves a binary by prioritizing local repository directories before querying system PATH.
pub fn resolve_binary_path(program: &str) -> String {
    let candidate_paths = [
        format!("./tools/{}", program),
        format!("./{}/{}", program, program),
        format!("./nmap/{}", program),
        format!("./kaisen/{}", program),
        format!("../{}/{}", program, program),
        format!("./{}", program),
    ];

    for path_str in &candidate_paths {
        let p = Path::new(path_str);
        if p.is_file() {
            debug!("[+] Resolved local binary path: {}", path_str);
            return path_str.clone();
        }
    }

    // Default to binary name for system PATH lookup
    program.to_string()
}

/// Executes a system command asynchronously with strict timeouts,
/// enforced process termination on drop (`kill_on_drop(true)`), and full stdout/stderr capture.
/// Checks repository-local binary paths prior to standard system PATH resolution.
pub async fn run_command(
    program: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<CommandOutput> {
    let resolved_program = resolve_binary_path(program);
    info!("[*] Executing: {} {}", resolved_program, args.join(" "));

    let fut = async {
        let mut cmd = Command::new(&resolved_program);
        cmd.args(args)
            .kill_on_drop(true)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());

        let output = cmd.output().await.with_context(|| {
            format!(
                "Failed to spawn binary '{}'. Ensure it is installed or present in local repo paths.",
                resolved_program
            )
        })?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        if !stdout.is_empty() {
            debug!("[{}] stdout: {} bytes", resolved_program, stdout.len());
        }
        if !stderr.is_empty() {
            debug!(
                "[{}] stderr (exit {}): {}",
                resolved_program,
                exit_code,
                &stderr[..stderr.len().min(400)]
            );
        }

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code,
        })
    };

    match timeout(Duration::from_secs(timeout_secs), fut).await {
        Ok(result) => result,
        Err(_) => {
            error!(
                "[-] Execution timed out after {}s for command: {} {}",
                timeout_secs,
                resolved_program,
                args.join(" ")
            );
            Err(anyhow!(
                "Command '{}' timed out after {} seconds. Child process was terminated.",
                resolved_program,
                timeout_secs
            ))
        }
    }
}

/// Checks if a tool is available either in local repo paths or system PATH.
pub fn check_tool_available(tool: &str) -> bool {
    let resolved = resolve_binary_path(tool);
    if Path::new(&resolved).is_file() {
        return true;
    }

    let check_cmd = if cfg!(target_os = "windows") { "where" } else { "which" };
    std::process::Command::new(check_cmd)
        .arg(tool)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Asynchronous version of tool availability check.
pub async fn check_tool_available_async(tool: &str) -> bool {
    let resolved = resolve_binary_path(tool);
    if Path::new(&resolved).is_file() {
        return true;
    }

    let check_cmd = if cfg!(target_os = "windows") { "where" } else { "which" };
    match Command::new(check_cmd)
        .arg(tool)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
    {
        Ok(status) => status.success(),
        Err(_) => false,
    }
}
