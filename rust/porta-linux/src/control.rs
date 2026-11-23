//! Requests to the root `porta-client --daemon` service over its Unix
//! socket: one JSON line out, one JSON line back.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{json, Value};

pub const DEFAULT_SOCKET: &str = "/run/porta-client/control.sock";
const TIMEOUT: Duration = Duration::from_secs(10);
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;

/// The control socket: `PORTA_CONTROL_SOCKET` or the service default.
pub fn socket_path() -> PathBuf {
    std::env::var_os("PORTA_CONTROL_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SOCKET))
}

/// Sends `request` and returns the service's snapshot.
pub fn request(socket: &Path, request: &Value) -> Result<Value, String> {
    let mut stream = UnixStream::connect(socket).map_err(|error| unavailable(socket, &error))?;
    stream
        .set_read_timeout(Some(TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(TIMEOUT)))
        .map_err(|error| error.to_string())?;
    let mut line = serde_json::to_vec(request).map_err(|error| error.to_string())?;
    line.push(b'\n');
    stream
        .write_all(&line)
        .map_err(|error| unavailable(socket, &error))?;
    let mut response = String::new();
    BufReader::new(std::io::Read::take(&stream, MAX_RESPONSE))
        .read_line(&mut response)
        .map_err(|error| unavailable(socket, &error))?;
    let mut response: Value = serde_json::from_str(&response)
        .map_err(|error| format!("invalid response from the Porta service: {error}"))?;
    if let Some(error) = response.get("error").and_then(Value::as_str) {
        return Err(error.to_owned());
    }
    response
        .get_mut("snapshot")
        .map(Value::take)
        .ok_or_else(|| "the Porta service returned no state".to_owned())
}

fn unavailable(socket: &Path, error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::PermissionDenied => format!(
            "permission denied for {}: add your user to the porta-client group and sign in again",
            socket.display()
        ),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => format!(
            "the Porta service is not running: sudo systemctl enable --now porta-client ({})",
            socket.display()
        ),
        _ => format!("cannot reach the Porta service: {error}"),
    }
}

/// What the window shows while the service cannot be reached.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn unavailable_snapshot(error: &str) -> Value {
    json!({
        "platform": "linux",
        "version": env!("CARGO_PKG_VERSION"),
        "profiles": [],
        "selectedProfileId": "",
        "activeProfileId": "",
        "status": "Service unavailable",
        "detail": error,
        "tone": "danger",
        "running": false,
        "connected": false,
        "restoring": false,
        "disconnecting": false,
        "recoveryAvailable": false,
        "startupBlocked": true,
        "address": "",
        "transport": "",
        "mtu": 0,
        "connectedAt": "",
        "bytesUploaded": 0,
        "bytesDownloaded": 0,
        "uploadRate": 0,
        "downloadRate": 0,
        "accountExpiresAt": 0,
        "quotaBytes": 0,
        "quotaUsedBytes": null,
        "rateLimitKbps": 0,
        "accountDenial": "",
        "splitRoutes": [],
        "splitDnsDomains": [],
        "activity": [],
    })
}

/// Writes the activity log of `snapshot` to a new file in `directory`.
#[cfg_attr(not(feature = "gui"), allow(dead_code))]
pub fn save_activity(directory: &Path, snapshot: &Value) -> Result<PathBuf, String> {
    std::fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    let path = directory.join(format!("porta-activity-{stamp}.log"));
    let mut text = snapshot
        .get("activity")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>()
        .join("\n");
    text.push('\n');
    std::fs::write(&path, text).map_err(|error| error.to_string())?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read as _;
    use std::os::unix::net::UnixListener;

    #[test]
    fn requests_are_one_json_line_and_errors_are_reported() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("control.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = std::thread::spawn(move || {
            for reply in [
                r#"{"snapshot":{"status":"Connected"}}"#,
                r#"{"error":"choose a profile first"}"#,
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut line = Vec::new();
                let mut byte = [0];
                while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
                    line.push(byte[0]);
                }
                let request: Value = serde_json::from_slice(&line).unwrap();
                assert!(request.get("command").is_some());
                stream.write_all(reply.as_bytes()).unwrap();
                stream.write_all(b"\n").unwrap();
            }
        });
        let snapshot = request(&socket, &json!({"command": "snapshot"})).unwrap();
        assert_eq!(snapshot["status"], "Connected");
        assert_eq!(
            request(&socket, &json!({"command": "connect", "id": ""})).unwrap_err(),
            "choose a profile first"
        );
        server.join().unwrap();
        let missing = request(
            &directory.path().join("absent"),
            &json!({"command": "snapshot"}),
        )
        .unwrap_err();
        assert!(missing.contains("not running"), "{missing}");
    }

    #[test]
    fn unavailable_state_blocks_actions_and_logs_save_to_a_file() {
        let snapshot = unavailable_snapshot("service down");
        assert_eq!(snapshot["startupBlocked"], true);
        assert_eq!(snapshot["detail"], "service down");
        let directory = tempfile::tempdir().unwrap();
        let path = save_activity(
            directory.path(),
            &json!({"activity": ["12:00:00  Connected", "12:00:05  Disconnected"]}),
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            "12:00:00  Connected\n12:00:05  Disconnected\n"
        );
    }
}
