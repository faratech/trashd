use crate::util::*;
use colored::Colorize;

const GITHUB_REPO: &str = "faratech/trashd";

#[derive(serde::Deserialize)]
struct GhRelease {
    tag_name: String,
    #[allow(dead_code)]
    html_url: String,
    prerelease: bool,
    assets: Vec<GhAsset>,
}

#[derive(serde::Deserialize)]
struct GhAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

/// Path to the update check marker file.
fn update_check_marker() -> PathBuf {
    let cache_dir = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| "/tmp".into())).join(".cache")
        });
    cache_dir.join("trashd").join("last-update-check")
}

fn cached_update_check() -> Option<String> {
    let marker = update_check_marker();
    let meta = std::fs::metadata(&marker).ok()?;
    let age = meta.modified().ok()?.elapsed().ok()?;
    if age.as_secs() < 86400 {
        std::fs::read_to_string(&marker).ok()
    } else {
        None
    }
}

fn write_update_check_cache(version: &str) {
    let marker = update_check_marker();
    if let Some(parent) = marker.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::write(&marker, version);
}

pub fn run(check_only: bool) {
    let current = crate::VERSION;

    let release = if check_only {
        if let Some(cached) = cached_update_check() {
            if cached == current {
                println!(
                    "{} trashd {} is already the latest version.",
                    "Up to date:".green().bold(),
                    current,
                );
                return;
            }
            println!(
                "{} {} -> {}",
                "Update available:".yellow().bold(),
                current.dimmed(),
                cached.bold(),
            );
            println!("\nRun {} to install.", "trash self-update".bold());
            return;
        }
        fetch_release()
    } else {
        fetch_release()
    };

    let latest = release
        .tag_name
        .strip_prefix('v')
        .unwrap_or(&release.tag_name);

    if latest == current {
        println!(
            "{} trashd {} is already the latest version.",
            "Up to date:".green().bold(),
            current,
        );
        return;
    }

    println!(
        "{} {} -> {}",
        "Update available:".yellow().bold(),
        current.dimmed(),
        latest.bold(),
    );

    if release.prerelease {
        println!("  {}", "(pre-release)".yellow());
    }

    if check_only {
        println!("\nRun {} to install.", "trash self-update".bold());
        return;
    }

    // Find the right tarball for this architecture
    let arch = std::env::consts::ARCH;
    let tarball_arch = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64",
        other => fatal(format!("unsupported architecture: {other}")),
    };

    let tarball_prefix = format!("trashd-{latest}-linux-{tarball_arch}");
    let tarball_name = format!("{tarball_prefix}.tar.gz");
    let sha_name = format!("{tarball_name}.sha256");

    let tarball_asset = release.assets.iter().find(|a| a.name == tarball_name);
    let sha_asset = release.assets.iter().find(|a| a.name == sha_name);

    let tarball_asset = match tarball_asset {
        Some(a) => a,
        None => {
            eprintln!(
                "{} no release artifact for {tarball_arch}",
                "trash: error:".red().bold(),
            );
            eprintln!("Expected: {tarball_name}");
            eprintln!(
                "Available: {}",
                release
                    .assets
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            std::process::exit(1);
        }
    };

    if !confirm(&format!(
        "Download and install trashd {latest} ({})? [y/N] ",
        format_size(tarball_asset.size),
    )) {
        println!("{}", "Cancelled.".dimmed());
        return;
    }

    // The checksum is REQUIRED — we run install.sh as root below, so refuse to
    // proceed with an unverifiable artifact rather than silently skipping.
    let sha_asset = match sha_asset {
        Some(a) => a,
        None => fatal(format!(
            "release is missing checksum asset {sha_name}; refusing to install unverified"
        )),
    };

    // Download to a PRIVATE temp dir. install.sh is executed from here under
    // sudo, so a co-located local user must not be able to pre-create/symlink
    // the path or read its contents. Rather than remove_dir_all-then-create a
    // GUESSABLE path (which invites a squatting race), create a fresh dir with
    // an unpredictable name, exclusively and at 0700 atomically (mkdir applies
    // the mode at creation and fails if the path already exists).
    use std::os::unix::fs::DirBuilderExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    let tmp_base = std::env::temp_dir();
    let tmp_dir = {
        let mut chosen = None;
        for attempt in 0..128u32 {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let candidate = tmp_base.join(format!(
                "trashd-update-{latest}-{}-{nanos}-{attempt}",
                std::process::id()
            ));
            match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => {
                    chosen = Some(candidate);
                    break;
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => fatal(format!("create temp dir: {e}")),
            }
        }
        chosen.unwrap_or_else(|| fatal("could not create a private temp directory"))
    };

    let tarball_path = tmp_dir.join(&tarball_name);

    // Download tarball (size-capped to the advertised size + slack)
    eprint!("Downloading {}... ", tarball_name);
    if let Err(e) = download_file(
        &tarball_asset.browser_download_url,
        &tarball_path,
        tarball_asset.size + (1 << 20),
    ) {
        eprintln!("{}", "failed".red());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        fatal(e);
    }
    eprintln!("{}", "done".green());

    // Verify checksum (mandatory)
    eprint!("Verifying checksum... ");
    let sha_path = tmp_dir.join(&sha_name);
    if let Err(e) = download_file(&sha_asset.browser_download_url, &sha_path, 1 << 20) {
        eprintln!("{}", "failed".red());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        fatal(format!("download checksum: {e}"));
    }
    if let Err(e) = verify_sha256(&tarball_path, &sha_path) {
        eprintln!("{}", "FAILED".red().bold());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        fatal(e);
    }
    eprintln!("{}", "ok".green());

    // Extract tarball
    eprint!("Extracting... ");
    if let Err(e) = extract_tarball(&tarball_path, &tmp_dir) {
        eprintln!("{}", "failed".red());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        fatal(e);
    }
    eprintln!("{}", "done".green());

    // Run install.sh from the extracted directory
    let install_dir = tmp_dir.join(&tarball_prefix);
    let install_script = install_dir.join("install.sh");
    if !install_script.exists() {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        fatal("install.sh not found in release tarball");
    }

    println!("\n{}", "Running installer...".bold());
    // install.sh expects to run as root and performs its privileged writes
    // directly (it never calls sudo itself), so the only question is how we get
    // to root from here.
    let status = if unsafe { libc::geteuid() } == 0 {
        // Already root — invoke the installer directly. Going through sudo would
        // be pointless *and* actively broken: when the calling shell runs under
        // the seccomp supervisor (trashd-exec, the primary layer for
        // interactive shells), that supervisor sets PR_SET_NO_NEW_PRIVS, which
        // is inherited by every descendant and can never be cleared. The setuid
        // sudo binary then refuses to escalate ("the 'no new privileges' flag
        // is set"). Running bash directly needs no privilege transition.
        std::process::Command::new("bash")
            .arg(&install_script)
            .env("TRASH_BYPASS", "1")
            .current_dir(&install_dir)
            .status()
    } else if no_new_privs_set() {
        // Non-root and escalation is blocked by no_new_privs (same seccomp cause
        // as above). sudo/su are setuid and cannot work here — fail with a clear
        // message instead of sudo's cryptic container-oriented one.
        let _ = std::fs::remove_dir_all(&tmp_dir);
        fatal(
            "cannot install the update: privilege escalation is blocked because \
             the 'no new privileges' flag is set on this process.\n  \
             This shell is running under the trashd seccomp supervisor, which \
             sets the flag for all descendants, so sudo/su cannot become root \
             from here.\n  \
             Re-run `trash self-update` from a root shell that is not wrapped by \
             the supervisor.",
        )
    } else {
        // Non-root: escalate via sudo as before.
        std::process::Command::new("sudo")
            .arg("env")
            .arg("TRASH_BYPASS=1")
            .arg("bash")
            .arg(&install_script)
            .current_dir(&install_dir)
            .status()
    };

    let _ = std::fs::remove_dir_all(&tmp_dir);

    match status {
        Ok(s) if s.success() => {
            println!(
                "\n{} trashd updated to {}",
                "Success:".green().bold(),
                latest.bold(),
            );
        }
        Ok(s) => fatal(format!("installer exited with {s}")),
        Err(e) => fatal(format!("run installer: {e}")),
    }
}

/// Returns true if the `no_new_privs` flag is set on this process (e.g. because
/// the shell is running under the seccomp supervisor). Setuid escalation via
/// sudo/su is impossible while this flag is set.
fn no_new_privs_set() -> bool {
    // PR_GET_NO_NEW_PRIVS returns 1 when set, 0 otherwise, -1 on error.
    unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 }
}

fn fetch_release() -> GhRelease {
    eprint!("Checking for updates... ");
    match fetch_latest_release() {
        Ok(r) => {
            eprintln!("{}", "done".green());
            let v = r
                .tag_name
                .strip_prefix('v')
                .unwrap_or(&r.tag_name)
                .to_string();
            write_update_check_cache(&v);
            r
        }
        Err(e) => {
            eprintln!("{}", "failed".red());
            fatal(e);
        }
    }
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(30)))
        .build()
        .new_agent()
}

fn fetch_latest_release() -> Result<GhRelease, String> {
    let url = format!("https://api.github.com/repos/{GITHUB_REPO}/releases/latest");
    let resp = http_agent()
        .get(&url)
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "trashd-self-update")
        .call()
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let release: GhRelease = resp
        .into_body()
        .read_json()
        .map_err(|e| format!("parse release JSON: {e}"))?;
    Ok(release)
}

fn download_file(url: &str, dest: &std::path::Path, max_bytes: u64) -> Result<(), String> {
    // Only ever fetch over TLS — never silently downgrade to a plaintext URL
    // returned in the release JSON.
    if !url.starts_with("https://") {
        return Err(format!("refusing non-HTTPS download URL: {url}"));
    }

    let resp = http_agent()
        .get(url)
        .header("User-Agent", "trashd-self-update")
        .call()
        .map_err(|e| format!("download failed: {e}"))?;

    use std::io::Read;
    // Bound the body so a malicious/oversized response can't fill the temp
    // filesystem. ureq's reader is unbounded by default.
    let mut reader = resp.into_body().into_reader().take(max_bytes);
    let mut file = std::fs::File::create(dest).map_err(|e| format!("create file: {e}"))?;
    let written = std::io::copy(&mut reader, &mut file).map_err(|e| format!("write file: {e}"))?;
    if written >= max_bytes {
        let _ = std::fs::remove_file(dest);
        return Err(format!(
            "download exceeded the expected size ({max_bytes} bytes)"
        ));
    }
    Ok(())
}

fn verify_sha256(tarball: &std::path::Path, sha_file: &std::path::Path) -> Result<(), String> {
    let content =
        std::fs::read_to_string(sha_file).map_err(|e| format!("read checksum file: {e}"))?;
    let expected = content
        .split_whitespace()
        .next()
        .ok_or("empty checksum file")?
        .to_lowercase();

    use std::io::Read;
    let mut file = std::fs::File::open(tarball).map_err(|e| format!("open tarball: {e}"))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("read tarball: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let actual = hasher.hexdigest();

    if actual != expected {
        return Err(format!(
            "checksum mismatch\n  expected: {expected}\n  actual:   {actual}",
        ));
    }
    Ok(())
}

fn extract_tarball(tarball: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    let file = std::fs::File::open(tarball).map_err(|e| format!("open tarball: {e}"))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    archive.unpack(dest).map_err(|e| format!("extract: {e}"))?;
    Ok(())
}

/// Minimal SHA-256 implementation (avoids adding a crypto dependency).
struct Sha256 {
    state: [u32; 8],
    buf: Vec<u8>,
    total_len: u64,
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: Vec::new(),
            total_len: 0,
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += data.len() as u64;
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 64 {
            let block: [u8; 64] = self.buf[..64].try_into().unwrap();
            self.compress(&block);
            self.buf.drain(..64);
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes(block[i * 4..i * 4 + 4].try_into().unwrap());
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(Self::K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn hexdigest(mut self) -> String {
        let bit_len = self.total_len * 8;
        self.buf.push(0x80);
        while self.buf.len() % 64 != 56 {
            self.buf.push(0);
        }
        self.buf.extend_from_slice(&bit_len.to_be_bytes());
        let remaining = self.buf.clone();
        for chunk in remaining.chunks(64) {
            let block: [u8; 64] = chunk.try_into().unwrap();
            self.compress(&block);
        }
        self.state.iter().map(|s| format!("{s:08x}")).collect()
    }
}
