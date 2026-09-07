use super::session::{FileResponse, RequestContext, Response};
use std::fs::File;
use std::os::fd::{FromRawFd, RawFd};
use std::path::Path;
use std::time::UNIX_EPOCH;

pub const CLIENT_DOWNLOAD_PREFIX: &str = "/download/";

pub const CLIENT_DOWNLOAD_TYPES: &[(&str, &str)] = &[
    ("porta-client-linux-amd64", "application/octet-stream"),
    ("porta-client-linux-arm64", "application/octet-stream"),
    ("porta-client-windows-amd64.zip", "application/zip"),
    (
        "porta-android-arm64-v8a.apk",
        "application/vnd.android.package-archive",
    ),
    (
        "porta-android-armeabi-v7a.apk",
        "application/vnd.android.package-archive",
    ),
    (
        "porta-android-x86_64.apk",
        "application/vnd.android.package-archive",
    ),
    ("SHA256SUMS", "text/plain; charset=utf-8"),
];

pub fn download_content_type(name: &str) -> Option<&'static str> {
    CLIENT_DOWNLOAD_TYPES
        .iter()
        .find_map(|(candidate, content_type)| (*candidate == name).then_some(*content_type))
}

pub struct DownloadService {
    directory: String,
}

impl DownloadService {
    pub fn new(directory: impl Into<String>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    pub fn handle(&self, request: &RequestContext) -> Option<Response> {
        if self.directory.is_empty() || !request.path.starts_with(CLIENT_DOWNLOAD_PREFIX) {
            return None;
        }
        let name = &request.path[CLIENT_DOWNLOAD_PREFIX.len()..];
        let Some(content_type) = download_content_type(name) else {
            return Some(Response::not_found());
        };
        if !request.is_get_or_head() {
            return Some(Response::not_found());
        }
        let mut file = match open_download_file(&self.directory, name) {
            Ok(file) => file,
            Err(_) => return Some(Response::not_found()),
        };
        let metadata = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            _ => return Some(Response::not_found()),
        };
        let size = metadata.len();
        let mut start = 0_u64;
        let mut end = size.saturating_sub(1);
        let mut status = 200;
        if let Some(range) = request.header("range") {
            match parse_single_range(range, size) {
                Some((range_start, range_end)) => {
                    start = range_start;
                    end = range_end;
                    status = 206;
                }
                None => {
                    let mut response = Response::new(416);
                    response.set_header("Content-Range", format!("bytes */{size}"));
                    return Some(response);
                }
            }
        }
        let content_length = if size == 0 { 0 } else { end - start + 1 };
        let mut response = Response::new(status);
        response.set_header("Content-Type", content_type);
        response.set_header(
            "Content-Disposition",
            format!("attachment; filename=\"{name}\""),
        );
        response.set_header("Cache-Control", "private, no-store");
        response.set_header("X-Content-Type-Options", "nosniff");
        response.set_header("Accept-Ranges", "bytes");
        response.set_header("Content-Length", content_length.to_string());
        if status == 206 {
            response.set_header("Content-Range", format!("bytes {start}-{end}/{size}"));
        }
        if let Ok(modified) = metadata.modified() {
            if let Ok(since_epoch) = modified.duration_since(UNIX_EPOCH) {
                response.set_header(
                    "X-Porta-Last-Modified-Unix",
                    since_epoch.as_secs().to_string(),
                );
            }
        }
        if request.method == "GET" && content_length > 0 {
            use std::io::{Seek, SeekFrom};
            if file.seek(SeekFrom::Start(start)).is_err() {
                return Some(Response::not_found());
            }
            response.file = Some(FileResponse {
                file,
                length: content_length,
            });
        }
        Some(response)
    }
}

fn parse_single_range(value: &str, size: u64) -> Option<(u64, u64)> {
    let value = value.strip_prefix("bytes=")?;
    if value.contains(',') || size == 0 {
        return None;
    }
    let (start, end) = value.split_once('-')?;
    if start.is_empty() {
        let suffix: u64 = end.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        let length = suffix.min(size);
        return Some((size - length, size - 1));
    }
    let start: u64 = start.parse().ok()?;
    if start >= size {
        return None;
    }
    let end = if end.is_empty() {
        size - 1
    } else {
        end.parse::<u64>().ok()?.min(size - 1)
    };
    (start <= end).then_some((start, end))
}

pub fn open_download_file(directory: &str, name: &str) -> std::io::Result<File> {
    if download_content_type(name).is_none() && name != "CLIENT_VERSION" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "download is not published",
        ));
    }
    let directory = std::ffi::CString::new(Path::new(directory).as_os_str().as_encoded_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let name = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let directory_fd = unsafe {
        libc::open(
            directory.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if directory_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file_fd: RawFd = unsafe {
        libc::openat(
            directory_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    unsafe {
        libc::close(directory_fd);
    }
    if file_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(file_fd) };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "download is not a regular file",
        ));
    }
    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn only_allowlisted_regular_files_are_served() {
        let directory = tempfile::tempdir().unwrap();
        fs::write(
            directory.path().join("porta-client-linux-amd64"),
            b"porta-client",
        )
        .unwrap();
        fs::write(directory.path().join("private"), b"secret").unwrap();
        let service = DownloadService::new(directory.path().to_string_lossy());
        let mut response = service
            .handle(&RequestContext::new(
                "GET",
                "/download/porta-client-linux-amd64",
            ))
            .unwrap();
        assert_eq!(response.status, 200);
        let mut body = Vec::new();
        response
            .file
            .take()
            .unwrap()
            .file
            .read_to_end(&mut body)
            .unwrap();
        assert_eq!(body, b"porta-client");
        for path in [
            "/download/",
            "/download/../private",
            "/download/private",
            "/download/porta-client-linux-amd64/extra",
        ] {
            assert_eq!(
                service
                    .handle(&RequestContext::new("GET", path))
                    .unwrap()
                    .status,
                404
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        symlink(outside.path(), directory.path().join("SHA256SUMS")).unwrap();
        let service = DownloadService::new(directory.path().to_string_lossy());
        assert_eq!(
            service
                .handle(&RequestContext::new("GET", "/download/SHA256SUMS"))
                .unwrap()
                .status,
            404
        );
    }

    #[test]
    fn requests_outside_prefix_fall_through() {
        let service = DownloadService::new(".");
        assert!(service.handle(&RequestContext::new("GET", "/")).is_none());
    }
}
