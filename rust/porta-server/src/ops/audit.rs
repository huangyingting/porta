//! Append-only audit log of administrative changes, sign-ins and tunnel
//! connections, as rotated JSON lines.

use parking_lot::Mutex;
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

const MAX_BYTES: u64 = 10 << 20;
const KEEP_ROTATED: usize = 5;
const MAX_RECENT: usize = 1000;

/// Who performed an audited action.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Actor {
    /// `token` (break-glass), `admin`, `sso`, `client` or `system`.
    pub kind: &'static str,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
}

impl Actor {
    pub fn system() -> Self {
        Self {
            kind: "system",
            id: String::new(),
            name: String::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    #[serde(with = "time::serde::rfc3339")]
    pub time: OffsetDateTime,
    pub actor: Actor,
    /// For example `client.update`, `admin.sign_in` or `tunnel.connect`.
    pub action: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// `ok`, `denied` or `failed`.
    pub outcome: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "serde_json::Value::is_null")]
    pub detail: serde_json::Value,
}

impl AuditEvent {
    pub fn new(actor: Actor, action: impl Into<String>, target: impl Into<String>) -> Self {
        Self {
            time: OffsetDateTime::now_utc(),
            actor,
            action: action.into(),
            target: target.into(),
            outcome: "ok",
            address: None,
            detail: serde_json::Value::Null,
        }
    }

    pub fn outcome(mut self, outcome: &'static str) -> Self {
        self.outcome = outcome;
        self
    }

    pub fn address(mut self, address: Option<impl ToString>) -> Self {
        self.address = address.map(|address| address.to_string());
        self
    }

    pub fn detail(mut self, detail: serde_json::Value) -> Self {
        self.detail = detail;
        self
    }
}

pub struct AuditLog {
    path: PathBuf,
    file: Mutex<Option<File>>,
}

impl AuditLog {
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let file = open_append(&path)?;
        Ok(Self {
            path,
            file: Mutex::new(Some(file)),
        })
    }

    /// Appends `event`. Failures are logged rather than failing the action
    /// they describe.
    pub fn record(&self, event: AuditEvent) {
        let mut line = match serde_json::to_vec(&event) {
            Ok(line) => line,
            Err(error) => {
                tracing::error!(%error, "could not encode an audit event");
                return;
            }
        };
        line.push(b'\n');
        let mut file = self.file.lock();
        if let Err(error) = self.append(&mut file, &line) {
            tracing::error!(%error, path = %self.path.display(), "could not write the audit log");
        }
    }

    fn append(&self, file: &mut Option<File>, line: &[u8]) -> std::io::Result<()> {
        let size = std::fs::metadata(&self.path).map_or(0, |metadata| metadata.len());
        if size + line.len() as u64 > MAX_BYTES {
            *file = None;
            for index in (1..KEEP_ROTATED).rev() {
                let from = rotated(&self.path, index);
                if from.exists() {
                    std::fs::rename(&from, rotated(&self.path, index + 1))?;
                }
            }
            std::fs::rename(&self.path, rotated(&self.path, 1))?;
        }
        if file.is_none() {
            *file = Some(open_append(&self.path)?);
        }
        let current = file.as_mut().expect("audit log is open");
        current.write_all(line)?;
        current.flush()
    }

    /// The newest `limit` events, newest first.
    pub fn recent(&self, limit: usize) -> Vec<serde_json::Value> {
        let limit = limit.clamp(1, MAX_RECENT);
        let mut events = Vec::new();
        for path in std::iter::once(self.path.clone())
            .chain((1..=KEEP_ROTATED).map(|index| rotated(&self.path, index)))
        {
            let Ok(file) = File::open(&path) else {
                continue;
            };
            let mut lines = BufReader::new(file)
                .lines()
                .map_while(Result::ok)
                .filter_map(|line| serde_json::from_str::<serde_json::Value>(&line).ok())
                .collect::<Vec<_>>();
            lines.reverse();
            events.extend(lines);
            if events.len() >= limit {
                break;
            }
        }
        events.truncate(limit);
        events
    }

    /// Every retained event, oldest first, as JSON lines.
    pub fn export(&self) -> Vec<u8> {
        let _file = self.file.lock();
        let mut output = Vec::new();
        for index in (1..=KEEP_ROTATED).rev() {
            if let Ok(data) = std::fs::read(rotated(&self.path, index)) {
                output.extend_from_slice(&data);
            }
        }
        if let Ok(data) = std::fs::read(&self.path) {
            output.extend_from_slice(&data);
        }
        output
    }
}

fn rotated(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(format!(".{index}"));
    PathBuf::from(name)
}

fn open_append(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_append_read_back_newest_first_and_export_in_order() {
        let directory = tempfile::tempdir().unwrap();
        let log = AuditLog::open(directory.path().join("audit.log")).unwrap();
        let admin = Actor {
            kind: "admin",
            id: "a1".into(),
            name: "alice".into(),
        };
        log.record(AuditEvent::new(admin.clone(), "client.create", "c1"));
        log.record(
            AuditEvent::new(admin, "client.delete", "c1")
                .outcome("denied")
                .address(Some("192.0.2.1"))
                .detail(serde_json::json!({"status": 403})),
        );
        let recent = log.recent(10);
        assert_eq!(recent.len(), 2);
        assert_eq!(recent[0]["action"], "client.delete");
        assert_eq!(recent[0]["outcome"], "denied");
        assert_eq!(recent[0]["actor"]["name"], "alice");
        assert_eq!(recent[0]["address"], "192.0.2.1");
        assert_eq!(recent[1]["action"], "client.create");
        let export = String::from_utf8(log.export()).unwrap();
        assert!(export.find("client.create").unwrap() < export.find("client.delete").unwrap());
        assert_eq!(
            std::fs::metadata(directory.path().join("audit.log"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    use std::os::unix::fs::PermissionsExt;
}
