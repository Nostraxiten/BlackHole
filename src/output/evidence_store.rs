use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio::task::JoinHandle;
use tracing::{debug, error, info};
use crate::types::Finding;

/// Asynchronous, non-blocking evidence store.
/// Decouples finding collection from filesystem I/O using a dedicated Tokio background worker
/// and an unbounded MPSC channel. Guarantees that neither probes nor the orchestrator
/// block waiting for disk synchronization.
pub struct EvidenceStore {
    path: PathBuf,
    sender: Option<UnboundedSender<Finding>>,
    worker_handle: Option<JoinHandle<Result<()>>>,
}

impl EvidenceStore {
    /// Initializes the evidence store file and spawns the background disk writer task.
    pub async fn new(output_dir: &str, session_id: &str) -> Result<Self> {
        let dir = PathBuf::from(output_dir);
        tokio::fs::create_dir_all(&dir).await.with_context(|| {
            format!("Failed to create output directory: {}", dir.display())
        })?;

        let path = dir.join(format!("evidence_{}.jsonl", session_id));
        info!("Evidence Store initialized at: {}", path.display());

        // Ensure file can be opened for writing
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .await
            .with_context(|| format!("Cannot open evidence store at {}", path.display()))?;

        let (tx, rx) = mpsc::unbounded_channel::<Finding>();

        // Spawn dedicated asynchronous writer worker
        let worker_path = path.clone();
        let worker_handle = tokio::spawn(async move {
            Self::disk_writer_loop(rx, file, worker_path).await
        });

        Ok(Self {
            path,
            sender: Some(tx),
            worker_handle: Some(worker_handle),
        })
    }

    /// Background event loop consuming findings from the MPSC channel and appending to JSONL.
    async fn disk_writer_loop(
        mut rx: UnboundedReceiver<Finding>,
        mut file: tokio::fs::File,
        path: PathBuf,
    ) -> Result<()> {
        let mut count = 0usize;
        while let Some(finding) = rx.recv().await {
            match serde_json::to_string(&finding) {
                Ok(line) => {
                    let mut payload = line.into_bytes();
                    payload.push(b'\n');

                    if let Err(e) = file.write_all(&payload).await {
                        error!("Failed to write finding {} to {}: {}", finding.id, path.display(), e);
                    } else {
                        count += 1;
                    }
                }
                Err(e) => {
                    error!("Failed to serialize finding {}: {}", finding.id, e);
                }
            }
        }

        // Flush all buffered writes to persistent storage upon closing
        if let Err(e) = file.flush().await {
            error!("Failed to flush evidence file {}: {}", path.display(), e);
        }

        debug!("Evidence store worker finalized. Total persisted findings: {}", count);
        Ok(())
    }

    /// Non-blocking append of a single finding to the store.
    pub fn append(&self, finding: &Finding) -> Result<()> {
        if let Some(ref tx) = self.sender {
            tx.send(finding.clone())
                .context("Failed to dispatch finding to evidence writer worker (channel closed)")?;
        }
        Ok(())
    }

    /// Non-blocking append of multiple findings.
    pub fn append_many(&self, findings: &[Finding]) -> Result<()> {
        for f in findings {
            self.append(f)?;
        }
        Ok(())
    }

    /// Closes the channel and gracefully awaits the background worker task, ensuring all
    /// pending findings are fully synced to disk before reports are compiled.
    pub async fn finalize(&mut self) -> Result<()> {
        // Dropping the sender signals EOF to the receiver loop
        self.sender.take();

        if let Some(handle) = self.worker_handle.take() {
            handle.await
                .context("Evidence store worker thread panicked")?
                .context("Evidence store worker failed writing to disk")?;
        }

        info!("Evidence Store safely synced and closed: {}", self.path.display());
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
