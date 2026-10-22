//! Read global/user configuration without blocking on special files.
//!
//! Shared with the standalone preload, so this module uses only std and libc.
//! Global and user configs may be symlinks managed by a dotfiles repository;
//! validate the opened target rather than rejecting the link itself.

use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Read a regular UTF-8 configuration file, following configuration symlinks.
pub fn read(path: &Path) -> io::Result<String> {
    read_with_metadata(path).map(|(content, _)| content)
}

/// `read`, also returning the metadata of the file that was read.
///
/// The buffer is sized from the validating `fstat`; `File::read_to_string`
/// would query the metadata again and seek before reading (#308). The final
/// empty read still detects a file that grew meanwhile.
pub fn read_with_metadata(path: &Path) -> io::Result<(String, std::fs::Metadata)> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "configuration is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    let expected = usize::try_from(metadata.len())
        .ok()
        .and_then(|len| len.checked_add(1))
        .ok_or_else(|| io::Error::new(io::ErrorKind::FileTooLarge, "configuration is too large"))?;
    bytes.try_reserve(expected).map_err(io::Error::other)?;
    // Take<&mut File> reads through the plain Read path, without the
    // metadata/seek size hint of File's own read_to_end.
    (&mut file).take(u64::MAX).read_to_end(&mut bytes)?;
    let content = String::from_utf8(bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok((content, metadata))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    #[test]
    fn reader_preserves_symlinked_configs_and_refuses_special_targets() {
        let fixture = tempfile::tempdir().unwrap();
        let regular = fixture.path().join("regular.toml");
        fs::write(&regular, "max_file_size_mb = 17\n").unwrap();
        let link = fixture.path().join("config.toml");
        symlink(&regular, &link).unwrap();
        assert_eq!(read(&link).unwrap(), "max_file_size_mb = 17\n");

        let fifo = fixture.path().join("fifo.toml");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let fifo_link = fixture.path().join("fifo-link.toml");
        symlink(&fifo, &fifo_link).unwrap();
        for path in [&fifo, &fifo_link, fixture.path()] {
            assert_eq!(read(path).unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
        fs::write(&regular, b"\xff").unwrap();
        assert_eq!(read(&link).unwrap_err().kind(), io::ErrorKind::InvalidData);

        // Contents of every size come back whole, with the target's metadata.
        for len in [0usize, 1, 31, 32, 33, 4095, 4096, 70_000] {
            let text = "x".repeat(len);
            fs::write(&regular, &text).unwrap();
            let (content, metadata) = read_with_metadata(&link).unwrap();
            assert_eq!(content, text);
            assert_eq!(metadata.len(), len as u64);
        }
    }
}
