//! Access logging in the Common/Combined Log Format.
//!
//! Each [`HttpBlock`](crate::config::HttpBlock) gets an
//! [`AccessLogger`](crate::logging::AccessLogger) writing to its configured
//! `access_log` path. The logger is cheap to [`Clone`] (it shares one file
//! handle behind an `Arc<Mutex<…>>`) and offers
//! [`reopen`](crate::logging::AccessLogger::reopen) for logrotate-style
//! `SIGHUP` handling.
//!
//! # Security
//!
//! URIs and user-agents are attacker-controlled, so control characters are
//! stripped from both before they reach the log line — closing the classic
//! log-injection / terminal-escape hole (Invariant 51).

use anyhow::{Context, Result};
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// An append-only access-log writer for one server block.
///
/// Cloning shares the same underlying file handle, so all clones write to the
/// same log and a single [`reopen`](Self::reopen) affects them all.
pub struct AccessLogger {
    path: String,
    file: Arc<Mutex<Option<std::fs::File>>>,
}

impl AccessLogger {
    /// Open (creating as needed) the log file at `path`, also creating any
    /// missing parent directories.
    ///
    /// # Errors
    ///
    /// Returns an error if the parent directory or the file cannot be created
    /// or opened for appending.
    pub fn new(path: &str) -> Result<Self> {
        if let Some(parent) = Path::new(path).parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create log directory: {}", parent.display()))?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("Failed to open access log: {}", path))?;

        Ok(Self {
            path: path.to_string(),
            file: Arc::new(Mutex::new(Some(file))),
        })
    }

    /// Append one request line in Combined Log Format.
    ///
    /// Control characters in `uri` and `user_agent` are stripped before
    /// writing (Invariant 51). Write errors are intentionally swallowed: a
    /// failing log must never take down request serving.
    pub fn log(&self, remote_addr: &str, method: &str, uri: &str, status: u16, bytes_sent: usize, user_agent: &str) {
        let timestamp = Local::now().format("%d/%b/%Y:%H:%M:%S %z");
        // Invariant 51: strip control characters to prevent log injection
        let safe_uri = uri.chars()
            .filter(|c| !(c.is_control() && *c != '\t'))
            .collect::<String>();
        let safe_ua = user_agent.chars()
            .filter(|c| !(c.is_control() && *c != '\t'))
            .collect::<String>();
        let entry = format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"-\" \"{}\"\n",
            remote_addr, timestamp, method, safe_uri, status, bytes_sent, safe_ua
        );

        if let Ok(mut guard) = self.file.lock() {
            if let Some(ref mut file) = *guard {
                let _ = file.write_all(entry.as_bytes());
                let _ = file.flush();
            }
        }
    }

    /// Reopen the log file at its original path, swapping in the new handle.
    ///
    /// This is the logrotate handshake: rename the old file, then call this so
    /// subsequent writes land in a freshly created file.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be reopened; the previous handle is
    /// left in place in that case.
    pub fn reopen(&self) -> Result<()> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .with_context(|| format!("Failed to reopen access log: {}", self.path))?;

        if let Ok(mut guard) = self.file.lock() {
            *guard = Some(file);
        }

        Ok(())
    }
}

impl Clone for AccessLogger {
    fn clone(&self) -> Self {
        Self {
            path: self.path.clone(),
            file: Arc::clone(&self.file),
        }
    }
}
