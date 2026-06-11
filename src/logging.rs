use anyhow::{Context, Result};
use chrono::Local;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

pub struct AccessLogger {
    path: String,
    file: Arc<Mutex<Option<std::fs::File>>>,
}

impl AccessLogger {
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
