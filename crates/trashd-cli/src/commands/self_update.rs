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

    // Numeric comparison — string equality alone would offer "updates" to
    // older releases (or split 0.1.10 vs 0.1.9 lexicographically).
    if !is_newer(latest, current) {
        println!(
            "{} trashd {} is up to date (latest release: {}).",
            "Up to date:".green().bold(),
            current.dimmed(),
            latest.bold(),
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
    use sha2::Digest;
    let content =
        std::fs::read_to_string(sha_file).map_err(|e| format!("read checksum file: {e}"))?;
    let expected = content
        .split_whitespace()
        .next()
        .ok_or("empty checksum file")?
        .to_lowercase();

    use std::io::Read;
    let mut file = std::fs::File::open(tarball).map_err(|e| format!("open tarball: {e}"))?;
    let mut hasher = sha2::Sha256::new();
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
    let actual: String = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    if actual != expected {
        return Err(format!(
            "checksum mismatch\n  expected: {expected}\n  actual:   {actual}",
        ));
    }
    Ok(())
}

/// Numeric dot-component comparison: true when `candidate` is NEWER than
/// `current`. Plain string equality alone would offer "downgrades" whenever
/// the published tag differs at all (e.g. re-releases, v0.1.10 vs 0.1.9).
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        v.split('.')
            .map(|p| p.trim().parse().unwrap_or(0))
            .collect()
    }
    let (c, u) = (parts(candidate), parts(current));
    for i in 0..3.max(c.len().max(u.len())) {
        let a = c.get(i).copied().unwrap_or(0);
        let b = u.get(i).copied().unwrap_or(0);
        if a != b {
            return a > b;
        }
    }
    false
}

fn extract_tarball(tarball: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    let file = std::fs::File::open(tarball).map_err(|e| format!("open tarball: {e}"))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    archive.unpack(dest).map_err(|e| format!("extract: {e}"))?;
    Ok(())
}
