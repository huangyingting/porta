use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, DateTime, ZipWriter};

const REQUIRED_FILES: [&str; 3] = ["porta.exe", "porta-cli.exe", "wintun.dll"];

pub fn package_windows(output: &Path, input_directory: &Path) -> io::Result<()> {
    for name in REQUIRED_FILES {
        let path = input_directory.join(name);
        let metadata = fs::metadata(&path)
            .map_err(|error| contextual(error, format!("validate {}", path.display())))?;
        if !metadata.is_file() || metadata.len() == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} must be a non-empty regular file", path.display()),
            ));
        }
    }

    let output_directory = output.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(output_directory)?;
    let pending = pending_path(output)?;
    let result = (|| {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&pending)?;
        let mut archive = ZipWriter::new(file);
        let timestamp = DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let options = SimpleFileOptions::default()
            .compression_method(CompressionMethod::Deflated)
            .last_modified_time(timestamp)
            .unix_permissions(0o755);
        for name in REQUIRED_FILES {
            archive.start_file(name, options)?;
            let mut input = File::open(input_directory.join(name))?;
            io::copy(&mut input, &mut archive)?;
        }
        let mut file = archive.finish()?;
        file.flush()?;
        file.sync_all()?;
        drop(file);
        fs::rename(&pending, output)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result
}

fn pending_path(output: &Path) -> io::Result<PathBuf> {
    let file_name = output
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "output ZIP path is invalid"))?;
    for attempt in 0..1000_u16 {
        let candidate = output.with_file_name(format!(
            ".{}.tmp-{}-{attempt}",
            file_name.to_string_lossy(),
            std::process::id()
        ));
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a temporary ZIP path",
    ))
}

fn contextual(error: io::Error, context: String) -> io::Error {
    io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::io::Read as _;

    use super::*;

    #[test]
    fn creates_a_minimal_deterministic_archive() {
        let directory = tempfile::tempdir().unwrap();
        let input = directory.path().join("input");
        fs::create_dir(&input).unwrap();
        for (index, name) in REQUIRED_FILES.into_iter().enumerate() {
            fs::write(input.join(name), format!("file-{index}")).unwrap();
        }
        let first = directory.path().join("first.zip");
        let second = directory.path().join("second.zip");
        package_windows(&first, &input).unwrap();
        package_windows(&second, &input).unwrap();
        assert_eq!(fs::read(&first).unwrap(), fs::read(&second).unwrap());

        let mut archive = zip::ZipArchive::new(File::open(first).unwrap()).unwrap();
        assert_eq!(archive.len(), REQUIRED_FILES.len());
        for (index, expected_name) in REQUIRED_FILES.into_iter().enumerate() {
            let mut entry = archive.by_index(index).unwrap();
            assert_eq!(entry.name(), expected_name);
            assert_eq!(entry.unix_mode(), Some(0o100755));
            let mut contents = String::new();
            entry.read_to_string(&mut contents).unwrap();
            assert_eq!(contents, format!("file-{index}"));
        }
    }

    #[test]
    fn rejects_missing_and_empty_inputs_without_creating_output() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("output.zip");
        let error = package_windows(&output, directory.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(!output.exists());

        for name in REQUIRED_FILES {
            fs::write(directory.path().join(name), []).unwrap();
        }
        let error = package_windows(&output, directory.path()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!output.exists());
    }
}
