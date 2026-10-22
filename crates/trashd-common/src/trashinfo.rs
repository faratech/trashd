use chrono::{DateTime, Local, NaiveDateTime};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

/// Read a regular metadata file without following symlinks or waiting for a
/// FIFO writer. Check the opened descriptor, so a replacement between lookup
/// and open cannot turn the read into a stream from a special file.
fn open_regular_metadata_file(path: &Path, limit: u64) -> io::Result<(fs::File, fs::Metadata)> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trash metadata is not a regular file",
        ));
    }
    // Metadata files are small; a huge one (crafted on removable media,
    // whose trash a user may own) is not metadata, and reading it whole made
    // every listing allocate its size (#335).
    if metadata.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trash metadata is too large",
        ));
    }
    Ok((file, metadata))
}

/// Largest .trashinfo sidecar accepted as metadata.
pub(crate) const MAX_SIDECAR_BYTES: u64 = 64 * 1024;

/// Read a regular metadata file of at most `limit` bytes.
pub(crate) fn read_regular_text_file(path: &Path, limit: u64) -> io::Result<String> {
    let (file, _) = open_regular_metadata_file(path, limit)?;
    let mut text = String::new();
    // Growth after the size check is bounded too.
    if file.take(limit + 1).read_to_string(&mut text)? as u64 > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trash metadata is too large",
        ));
    }
    Ok(text)
}

/// A sidecar's raw bytes (bounded like `read_sidecar`, no UTF-8 check), for
/// edits that must preserve every other byte.
pub(crate) fn read_sidecar_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let (file, _) = open_regular_metadata_file(path, MAX_SIDECAR_BYTES)?;
    let mut bytes = Vec::new();
    if file.take(MAX_SIDECAR_BYTES + 1).read_to_end(&mut bytes)? as u64 > MAX_SIDECAR_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trash metadata is too large",
        ));
    }
    Ok(bytes)
}

/// Read a .trashinfo sidecar. Special files and symlinks are invalid metadata,
/// including ones substituted while a listing or integrity check is running.
pub fn read_sidecar(path: &Path) -> io::Result<String> {
    read_regular_text_file(path, MAX_SIDECAR_BYTES)
}

/// Read exactly the opened sidecar's observed length and return that inode's
/// metadata with its contents. The caller must compare the path's final
/// version against this metadata before accepting the snapshot. Truncation
/// fails the read; growth or replacement is rejected by that version check.
/// Unlike File::read_to_string, this needs no extra metadata query, seek, or
/// EOF probe for every small sidecar in a large trash.
pub(crate) fn read_sidecar_snapshot(path: &Path) -> io::Result<(String, fs::Metadata)> {
    let (mut file, metadata) = open_regular_metadata_file(path, MAX_SIDECAR_BYTES)?;
    let text = read_text_exact(&mut file, metadata.len())?;
    Ok((text, metadata))
}

fn read_text_exact(file: &mut fs::File, len: u64) -> io::Result<String> {
    let len = usize::try_from(len)
        .map_err(|_| io::Error::new(io::ErrorKind::FileTooLarge, "trash metadata is too large"))?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(len).map_err(io::Error::other)?;
    // Take stops at the observed length without probing the file for EOF.
    // Let read_to_end initialize only bytes actually read: resizing up front
    // would touch the entire allocation even if a large file was truncated.
    file.take(len as u64).read_to_end(&mut bytes)?;
    if bytes.len() != len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "trash metadata was truncated while reading",
        ));
    }
    String::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

/// Reuse exact second-resolution timestamp conversions within one scan.
///
/// Construct with [`Default::default`] for each new scan and call [`Self::parse`]
/// for its sidecars. At most 256 exact dates are retained, with no process-global
/// cache. Discard the parser after the scan so later operations resolve their
/// local timezone independently. Exact keys retain Chrono's historical and DST
/// fold/gap handling rather than assuming one offset for a whole day or year.
#[derive(Default)]
pub struct TrashInfoParser {
    dates: HashMap<NaiveDateTime, Option<DateTime<Local>>>,
    #[cfg(test)]
    resolutions: usize,
}

const SCAN_DATE_CACHE_LIMIT: usize = 256;

impl TrashInfoParser {
    /// Parse a sidecar, reusing conversions first resolved during this scan.
    /// Metadata validation and first-occurrence handling match
    /// [`TrashInfo::from_trashinfo`]; standalone parsing remains uncached.
    pub fn parse(&mut self, content: &str) -> Option<TrashInfo> {
        TrashInfo::parse_with_resolver(content, |naive| {
            if self.dates.len() == SCAN_DATE_CACHE_LIMIT {
                if let Some(resolved) = self.dates.get(&naive) {
                    return *resolved;
                }
                self.dates.clear();
            }
            *self.dates.entry(naive).or_insert_with(|| {
                #[cfg(test)]
                {
                    self.resolutions += 1;
                }
                resolve_local_deletion_date(naive)
            })
        })
    }
}

fn resolve_local_deletion_date(naive: NaiveDateTime) -> Option<DateTime<Local>> {
    match naive.and_local_timezone(Local) {
        chrono::LocalResult::Single(dt) => Some(dt),
        chrono::LocalResult::Ambiguous(_, latest) => Some(latest),
        chrono::LocalResult::None => {
            // Preserve the existing gap recovery, including zones whose
            // transition is shorter or longer than an hour.
            let shifted = naive.checked_add_signed(chrono::Duration::hours(1))?;
            shifted.and_local_timezone(Local).earliest()
        }
    }
}

/// Represents a .trashinfo metadata file per FreeDesktop.org Trash spec.
#[derive(Debug, Clone)]
pub struct TrashInfo {
    pub original_path: PathBuf,
    pub deletion_date: DateTime<Local>,
    /// trashd extension: the command that caused deletion
    pub command: Option<String>,
    /// trashd extension: PID of the deleting process
    pub pid: Option<u32>,
    /// trashd extension: file size in bytes
    pub size: Option<u64>,
    /// trashd extension: SHA-256 of file contents (files only, not dirs)
    pub sha256: Option<String>,
    /// trashd extension: compression algorithm trashd applied to the stored
    /// data ("zstd"), or None if uncompressed. Restore decompresses ONLY when
    /// this is set — never by sniffing magic bytes, which would corrupt a
    /// user's genuine compressed file.
    pub compressed: Option<String>,
    /// trashd extension: the deletion instant in nanoseconds since the
    /// epoch. DeletionDate has one-second precision and sidecar mtimes come
    /// from the filesystem's coarse clock, so entries trashed together
    /// (`rm a b`) tied, and undo picked either (#345).
    pub deletion_ns: Option<u64>,
}

impl TrashInfo {
    /// True when trashd wrote this sidecar (it always records the PID and
    /// size); entries created by other FreeDesktop tools carry none of the
    /// `X-Trashd-*` fields.
    pub fn is_trashd_entry(&self) -> bool {
        self.pid.is_some() || self.size.is_some() || self.command.is_some() || self.sha256.is_some()
    }

    pub fn new(original_path: PathBuf) -> Self {
        let now = Local::now();
        Self {
            original_path,
            deletion_date: now,
            command: None,
            pid: None,
            size: None,
            sha256: None,
            compressed: None,
            deletion_ns: now
                .timestamp_nanos_opt()
                .and_then(|ns| u64::try_from(ns).ok()),
        }
    }

    /// Serialize to .trashinfo format (FreeDesktop.org Trash spec).
    pub fn to_trashinfo_string(&self) -> String {
        let encoded_path = encode_path(&self.original_path);
        let date_str = self.deletion_date.format("%Y-%m-%dT%H:%M:%S").to_string();

        let mut s = format!("[Trash Info]\nPath={encoded_path}\nDeletionDate={date_str}\n");

        if let Some(ref cmd) = self.command {
            // Strip control characters: a command containing a newline would
            // be parsed back as separate key=value lines (metadata injection).
            let sanitized: String = cmd.chars().filter(|c| !c.is_control()).collect();
            s.push_str(&format!("X-Trashd-Command={sanitized}\n"));
        }
        if let Some(pid) = self.pid {
            s.push_str(&format!("X-Trashd-PID={pid}\n"));
        }
        if let Some(size) = self.size {
            s.push_str(&format!("X-Trashd-Size={size}\n"));
        }
        if let Some(ref hash) = self.sha256 {
            // Use X-Trashd-Hash for new entries (algorithm-agnostic).
            // X-Trashd-SHA256 is still read for backward compatibility.
            s.push_str(&format!("X-Trashd-Hash={hash}\n"));
        }
        if let Some(ref algo) = self.compressed {
            s.push_str(&format!("X-Trashd-Compressed={algo}\n"));
        }
        if let Some(ns) = self.deletion_ns {
            s.push_str(&format!("X-Trashd-DeletedNs={ns}\n"));
        }

        s
    }

    /// Parse a .trashinfo file per FreeDesktop.org Trash spec.
    ///
    /// Spec requirements enforced:
    /// - First non-empty line MUST be exactly `[Trash Info]`
    /// - If `Path=` or `DeletionDate=` appears multiple times, first occurrence wins
    /// - Path value is NOT trimmed (percent-encoded spaces are meaningful)
    pub fn from_trashinfo(content: &str) -> Option<Self> {
        Self::parse_with_resolver(content, resolve_local_deletion_date)
    }

    fn parse_with_resolver(
        content: &str,
        mut resolve_date: impl FnMut(NaiveDateTime) -> Option<DateTime<Local>>,
    ) -> Option<Self> {
        // Spec: "First line MUST be: [Trash Info]"
        let first_line = content.lines().find(|l| !l.trim().is_empty())?;
        if first_line.trim() != "[Trash Info]" {
            return None;
        }

        let mut path: Option<PathBuf> = None;
        let mut date: Option<DateTime<Local>> = None;
        let mut command = None;
        let mut pid = None;
        let mut size = None;
        let mut sha256 = None;
        let mut compressed = None;
        let mut deletion_ns = None;

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed == "[Trash Info]" || trimmed.is_empty() {
                continue;
            }
            // split_once on '=' — the value is everything after the first '='
            // (handles '=' in filenames since Path values are percent-encoded).
            // Split the RAW line: the Path value must keep leading/trailing
            // literal whitespace byte-exact per this module's contract (only
            // the key is trimmed) (#112).
            if let Some((key, value)) = line.split_once('=') {
                match key.trim() {
                    // Spec: first occurrence wins for Path and DeletionDate
                    "Path" if path.is_none() => {
                        // Reject traversal lexically BEFORE decoding: the URL
                        // parser normalizes ".." silently — and even percent-
                        // encoded dot segments ("%2e%2e") — which would defeat
                        // restore's ParentDir guard and let a crafted
                        // .trashinfo restore to an arbitrary location (#27,
                        // encoded-form bypass). A segment is rejected when its
                        // percent-DECODED bytes are "." or "..", which covers
                        // "..", "%2e", ".%2E", "%2e.", and friends.
                        if value
                            .split('/')
                            .any(|seg| matches!(&decode_percent(seg)[..], b"." | b".."))
                        {
                            return None;
                        }
                        // Spec: Path value is percent-encoded bytes — don't trim
                        // (leading/trailing spaces in encoded form are meaningful)
                        let decoded = decode_path(value);
                        // An encoded slash (%2f) hides a separator from the
                        // per-segment check above: "%2e%2e%2fsecret" decodes
                        // to "../secret" (#256). Re-check the fully decoded
                        // components.
                        if decoded
                            .components()
                            .any(|c| c == std::path::Component::ParentDir)
                        {
                            return None;
                        }
                        path = Some(decoded);
                    }
                    "DeletionDate" if date.is_none() => {
                        if let Ok(naive) =
                            NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%dT%H:%M:%S")
                        {
                            date = resolve_date(naive);
                        }
                    }
                    // First occurrence wins for the extensions too: a later
                    // duplicate must never override e.g. the integrity-hash
                    // marker recorded at trash time (#30).
                    "X-Trashd-Command" if command.is_none() => {
                        command = Some(value.trim().to_string())
                    }
                    "X-Trashd-PID" if pid.is_none() => pid = value.trim().parse().ok(),
                    "X-Trashd-Size" if size.is_none() => size = value.trim().parse().ok(),
                    "X-Trashd-Hash" | "X-Trashd-SHA256" if sha256.is_none() => {
                        sha256 = Some(value.trim().to_string())
                    }
                    "X-Trashd-Compressed" if compressed.is_none() => {
                        compressed = Some(value.trim().to_string())
                    }
                    "X-Trashd-DeletedNs" if deletion_ns.is_none() => {
                        deletion_ns = value.trim().parse().ok()
                    }
                    _ => {}
                }
            }
        }

        Some(TrashInfo {
            original_path: path?,
            deletion_date: date?,
            command,
            pid,
            size,
            sha256,
            compressed,
            deletion_ns,
        })
    }
}

/// Percent-encode a path for .trashinfo (spec requirement).
///
/// Encodes the RAW byte representation (`OsStrExt::as_bytes`):
/// `to_string_lossy()` would replace invalid-UTF-8 filename bytes with
/// U+FFFD and the original name could never be reconstructed on restore (#15).
fn encode_path(path: &Path) -> String {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    let mut encoded = String::with_capacity(bytes.len());
    for byte in bytes {
        match *byte {
            // Safe chars: unreserved + /
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' => {
                encoded.push(*byte as char);
            }
            _ => {
                encoded.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    encoded
}

/// Decode a percent-encoded path from .trashinfo into raw bytes.
fn decode_percent(s: &str) -> Vec<u8> {
    // Exactly two ASCII hex digits: from_str_radix accepted a sign ("%+F"),
    // and consuming both bytes of an invalid escape swallowed a following
    // '%' (#223). Anything else stays literal.
    let bytes = s.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && bytes[i + 1].is_ascii_hexdigit()
            && bytes[i + 2].is_ascii_hexdigit()
        {
            let hex = |b: u8| (b as char).to_digit(16).unwrap() as u8;
            decoded.push(hex(bytes[i + 1]) << 4 | hex(bytes[i + 2]));
            i += 3;
        } else {
            decoded.push(bytes[i]);
            i += 1;
        }
    }
    decoded
}

/// Decode a percent-encoded path from .trashinfo.
///
/// Plain byte-level decoding — deliberately NOT the WHATWG URL parser, which
/// silently strips leading/trailing spaces from the whole URL (#112),
/// normalizes percent-encoded dot segments (#87), and invents paths out of
/// `file://host/...` forms (#25). Raw decoding does none of that; traversal
/// is rejected segment-wise at parse time (#27/#87) and restore re-checks the
/// decoded components on its side.
fn decode_path(s: &str) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    PathBuf::from(std::ffi::OsString::from_vec(decode_percent(s)))
}

#[cfg(test)]
mod tests {
    use super::*;

    // #385: a local timestamp near Chrono's limit can map outside its UTC
    // range. The gap-recovery hour must reject overflow instead of letting
    // one untrusted sidecar panic an entire scan. Re-exec for each timezone
    // so Local's cache and TZ never affect another harness test.
    #[test]
    fn extreme_dates_in_offset_zones_never_overflow() {
        const TEST: &str = "trashinfo::tests::extreme_dates_in_offset_zones_never_overflow";
        const CHILD: &str = "TRASHD_EXTREME_DATE_TZ_CHILD";
        if std::env::var_os(CHILD).is_none() {
            for zone in ["Etc/GMT+12", "Etc/GMT-14", "UTC0"] {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--test-threads=1", "--nocapture"])
                    .env(CHILD, "1")
                    .env("TZ", zone)
                    .env("TRASH_BYPASS", "1")
                    .status()
                    .unwrap();
                assert!(status.success(), "extreme date child failed for {zone}");
            }
            return;
        }
        let zone = std::env::var("TZ").unwrap();
        let mut parser = TrashInfoParser::default();
        for (date, valid) in [
            ("+262142-12-31T23:30:00", zone != "Etc/GMT+12"),
            ("-262143-01-01T00:30:00", zone != "Etc/GMT-14"),
            ("2026-10-22T12:30:00", true),
        ] {
            let sidecar = format!("[Trash Info]\nPath=/original\nDeletionDate={date}\n");
            assert_eq!(
                TrashInfo::from_trashinfo(&sidecar).is_some(),
                valid,
                "standalone conversion for {date} in {zone}"
            );
            for _ in 0..2 {
                assert_eq!(
                    parser.parse(&sidecar).is_some(),
                    valid,
                    "cached conversion for {date} in {zone}"
                );
            }
        }
    }

    #[test]
    fn scan_date_cache_reuses_exact_dates_and_has_bounded_memory() {
        let base =
            NaiveDateTime::parse_from_str("2026-10-20T00:00:00", "%Y-%m-%dT%H:%M:%S").unwrap();
        let content = |naive: NaiveDateTime| {
            format!(
                "[Trash Info]\nPath=/original\nDeletionDate={}\n",
                naive.format("%Y-%m-%dT%H:%M:%S")
            )
        };
        let mut parser = TrashInfoParser::default();
        let repeated = content(base);
        let expected = TrashInfo::from_trashinfo(&repeated).unwrap().deletion_date;
        for _ in 0..1000 {
            assert_eq!(parser.parse(&repeated).unwrap().deletion_date, expected);
        }
        assert_eq!(parser.resolutions, 1);
        for seconds in 1..1000 {
            let text = content(base + chrono::Duration::seconds(seconds));
            assert_eq!(
                parser.parse(&text).unwrap().deletion_date,
                TrashInfo::from_trashinfo(&text).unwrap().deletion_date
            );
            assert!(parser.dates.len() <= SCAN_DATE_CACHE_LIMIT);
        }
        let mut next_scan = TrashInfoParser::default();
        assert_eq!(next_scan.parse(&repeated).unwrap().deletion_date, expected);
        assert_eq!(
            next_scan.resolutions, 1,
            "a new scan must resolve its timezone independently"
        );
    }

    #[test]
    fn scan_date_cache_matches_dst_folds_gaps_and_historical_offsets() {
        const CHILD: &str = "TRASHD_DATE_CACHE_TZ_CHILD";
        if std::env::var_os(CHILD).is_none() {
            for zone in [
                "UTC0",
                "America/New_York",
                "Australia/Lord_Howe",
                "Pacific/Apia",
                "Europe/Kyiv",
            ] {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .arg("--exact")
                    .arg("trashinfo::tests::scan_date_cache_matches_dst_folds_gaps_and_historical_offsets")
                    .env(CHILD, "1")
                    .env("TZ", zone)
                    .env("TRASH_BYPASS", "1")
                    .status()
                    .unwrap();
                assert!(status.success(), "timezone child failed for {zone}");
            }
            return;
        }
        let mut parser = TrashInfoParser::default();
        for date in [
            "1883-11-18T12:01:00",
            "1990-07-01T01:30:00",
            "2011-12-30T12:30:00",
            "2019-03-10T02:30:00",
            "2019-11-03T01:30:00",
            "2019-04-07T01:45:00",
            "2019-10-06T02:15:00",
            "2026-01-01T00:00:00",
            "2026-07-01T00:00:00",
        ] {
            let text = format!("[Trash Info]\nPath=/original\nDeletionDate={date}\n");
            let expected = TrashInfo::from_trashinfo(&text).map(|info| info.deletion_date);
            for _ in 0..5 {
                assert_eq!(
                    parser.parse(&text).map(|info| info.deletion_date),
                    expected,
                    "conversion differs for {date}"
                );
            }
        }
        let text = "[Trash Info]\nPath=/original\nDeletionDate=2011-12-30T12:30:00\n";
        if std::env::var("TZ").as_deref() == Ok("Pacific/Apia") {
            assert!(
                parser.parse(text).is_none(),
                "a whole-day gap remains invalid after the existing one-hour recovery"
            );
        }
    }

    #[test]
    fn sidecar_reader_accepts_only_regular_files() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let fixture = tempfile::tempdir().unwrap();
        let regular = fixture.path().join("regular.trashinfo");
        fs::write(&regular, "metadata").unwrap();
        assert_eq!(read_sidecar(&regular).unwrap(), "metadata");
        let (content, metadata) = read_sidecar_snapshot(&regular).unwrap();
        assert_eq!(content, "metadata");
        assert_eq!(metadata.len(), 8);

        let fifo = fixture.path().join("fifo.trashinfo");
        let name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let socket = fixture.path().join("socket.trashinfo");
        let _listener = UnixListener::bind(&socket).unwrap();
        let link = fixture.path().join("link.trashinfo");
        symlink(&regular, &link).unwrap();
        for invalid in [&fifo, &socket, &link, fixture.path()] {
            assert!(read_sidecar(invalid).is_err(), "accepted {invalid:?}");
            assert!(
                read_sidecar_snapshot(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        // Arbitrary regular files keep the ordinary UTF-8 read contract.
        fs::write(&regular, b"\xff").unwrap();
        assert_eq!(
            read_sidecar(&regular).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_sidecar_snapshot(&regular).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn sidecar_snapshot_reads_observed_length_and_rejects_truncation() {
        use std::io::Write;
        let fixture = tempfile::tempdir().unwrap();
        let path = fixture.path().join("growing.trashinfo");
        fs::write(&path, "métadata").unwrap();
        let (mut input, metadata) = open_regular_metadata_file(&path, MAX_SIDECAR_BYTES).unwrap();
        let mut writer = fs::File::options().append(true).open(&path).unwrap();
        writer.write_all(b" appended").unwrap();
        assert_eq!(
            read_text_exact(&mut input, metadata.len()).unwrap(),
            "métadata"
        );
        assert_ne!(metadata.len(), writer.metadata().unwrap().len());
        // Other callers retain a full regular-file read. Only the snapshot
        // API stops at the captured length and requires version validation.
        assert_eq!(read_sidecar(&path).unwrap(), "métadata appended");

        let (mut input, metadata) = open_regular_metadata_file(&path, MAX_SIDECAR_BYTES).unwrap();
        writer.set_len(3).unwrap();
        assert_eq!(
            read_text_exact(&mut input, metadata.len())
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof,
        );
        fs::write(&path, b"").unwrap();
        assert_eq!(read_sidecar_snapshot(&path).unwrap().0, ""); // An oversized "sidecar" is not metadata (#335).
        fs::write(&path, vec![b'x'; MAX_SIDECAR_BYTES as usize + 1]).unwrap();
        assert_eq!(
            read_sidecar(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert!(read_sidecar_snapshot(&path).is_err());
        assert!(read_sidecar_bytes(&path).is_err());
    }

    // Regression (#223): from_str_radix accepts a sign ("%+F" decoded as
    // 0x0F), and an invalid escape swallowed the next '%' with it.
    // Regression (#256): an encoded slash hides a separator from the
    // per-segment dot check, so "%2e%2e%2f" must be rejected after decoding.
    #[test]
    fn encoded_slash_dot_segments_are_rejected() {
        for path in [
            "/tmp/%2e%2e%2fsecret",
            "/tmp/%2E%2E%2Fsecret",
            "/%2e%2e%2f%2e%2e%2fetc/passwd",
        ] {
            let content = format!("[Trash Info]\nPath={path}\nDeletionDate=2026-01-01T00:00:00\n");
            assert!(
                TrashInfo::from_trashinfo(&content).is_none(),
                "accepted traversal path {path}"
            );
        }
    }

    #[test]
    fn percent_decoding_takes_exactly_two_hex_digits() {
        assert_eq!(decode_percent("%+F"), b"%+F");
        assert_eq!(decode_percent("%A%41"), b"%AA");
        assert_eq!(decode_percent("%41%zz%"), b"A%zz%");
    }

    #[test]
    fn round_trip_simple_path() {
        let info = TrashInfo {
            original_path: PathBuf::from("/home/user/Documents/report.pdf"),
            deletion_date: Local::now(),
            command: Some("rm report.pdf".into()),
            pid: Some(1234),
            size: Some(4096),
            sha256: Some("abcdef1234567890".into()),
            compressed: None,
            deletion_ns: Some(1_792_642_099_123_456_789),
        };

        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).expect("should parse");

        assert_eq!(parsed.original_path, info.original_path);
        assert_eq!(parsed.command, info.command);
        assert_eq!(parsed.pid, info.pid);
        assert_eq!(parsed.size, info.size);
        assert_eq!(parsed.sha256, info.sha256);
    }

    #[test]
    fn round_trip_path_with_spaces() {
        let info = TrashInfo::new(PathBuf::from("/home/user/My Documents/file name.txt"));
        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn round_trip_path_with_unicode() {
        let info = TrashInfo::new(PathBuf::from("/home/user/文档/日本語ファイル.txt"));
        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn round_trip_path_with_equals() {
        let info = TrashInfo::new(PathBuf::from("/home/user/key=value.conf"));
        let serialized = info.to_trashinfo_string();

        // '=' should be percent-encoded so it doesn't break the key=value parser
        assert!(!serialized.contains("Path=/home/user/key=value"));
        assert!(serialized.contains("%3D"));

        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn round_trip_path_with_percent() {
        let info = TrashInfo::new(PathBuf::from("/home/user/100%done.txt"));
        let serialized = info.to_trashinfo_string();
        let parsed = TrashInfo::from_trashinfo(&serialized).unwrap();
        assert_eq!(parsed.original_path, info.original_path);
    }

    #[test]
    fn parse_minimal_trashinfo() {
        let content = "[Trash Info]\nPath=/tmp/test.txt\nDeletionDate=2026-03-20T14:30:00\n";
        let info = TrashInfo::from_trashinfo(content).unwrap();
        assert_eq!(info.original_path, PathBuf::from("/tmp/test.txt"));
        assert!(info.command.is_none());
        assert!(info.pid.is_none());
        assert!(info.size.is_none());
        assert!(info.sha256.is_none());
    }

    #[test]
    fn parse_with_extensions() {
        let content = "\
[Trash Info]
Path=/home/user/file.txt
DeletionDate=2026-03-20T14:30:00
X-Trashd-Command=rm -rf file.txt
X-Trashd-PID=42
X-Trashd-Size=1024
X-Trashd-SHA256=deadbeef
";
        let info = TrashInfo::from_trashinfo(content).unwrap();
        assert_eq!(info.command.as_deref(), Some("rm -rf file.txt"));
        assert_eq!(info.pid, Some(42));
        assert_eq!(info.size, Some(1024));
        assert_eq!(info.sha256.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn parse_missing_path_returns_none() {
        let content = "[Trash Info]\nDeletionDate=2026-03-20T14:30:00\n";
        assert!(TrashInfo::from_trashinfo(content).is_none());
    }

    // Regression (#87): percent-encoded dot segments normalize away inside the
    // URL parser, so the encoded value must be checked segment by segment.
    #[test]
    fn parse_rejects_encoded_dot_segments() {
        for path in [
            "/%2e%2e/%2e%2e/etc/evil",
            "/home/user/%2E%2e/etc/evil",
            "/x/%2e/%2e%2e/etc/evil",
            "../../etc/evil",
        ] {
            let content = format!("[Trash Info]\nPath={path}\nDeletionDate=2026-03-20T00:00:00\n");
            assert!(
                TrashInfo::from_trashinfo(&content).is_none(),
                "traversal path must be rejected: {path}"
            );
        }
    }

    // Regression (#112): the Path value must keep leading/trailing literal
    // whitespace byte-exact — only the KEY is trimmed. (trashd's own writer
    // percent-encodes spaces, so this only matters for foreign sidecars.)
    #[test]
    fn path_value_is_not_trimmed() {
        let content = "[Trash Info]\nPath=/home/user/trailing \nDeletionDate=2026-03-20T00:00:00\n";
        let info = TrashInfo::from_trashinfo(content).unwrap();
        assert_eq!(
            info.original_path,
            PathBuf::from("/home/user/trailing "),
            "trailing space must survive"
        );
    }

    #[test]
    fn parse_missing_date_returns_none() {
        let content = "[Trash Info]\nPath=/tmp/test.txt\n";
        assert!(TrashInfo::from_trashinfo(content).is_none());
    }

    #[test]
    fn encode_decode_path_preserves_special_chars() {
        let original = PathBuf::from("/path/to/file with spaces & symbols=yes!.txt");
        let encoded = encode_path(&original);
        let decoded = decode_path(&encoded);
        assert_eq!(decoded, original);
    }

    #[test]
    fn trashinfo_format_matches_spec() {
        let info = TrashInfo::new(PathBuf::from("/home/user/test.txt"));
        let s = info.to_trashinfo_string();

        assert!(s.starts_with("[Trash Info]\n"));
        assert!(s.contains("Path="));
        assert!(s.contains("DeletionDate="));
        // Date format: YYYY-MM-DDTHH:MM:SS (no timezone per spec)
        let date_line = s.lines().find(|l| l.starts_with("DeletionDate=")).unwrap();
        let date_val = date_line.strip_prefix("DeletionDate=").unwrap();
        assert_eq!(date_val.len(), 19); // "2026-03-20T14:30:00"
    }
}
