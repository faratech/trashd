use crate::util::*;
use colored::Colorize;
use std::ffi::{CString, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

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

/// Path to the update check marker file. The cache is optional: when neither
/// XDG_CACHE_HOME nor HOME is available, do not fall back to a shared location.
fn update_check_marker() -> Option<PathBuf> {
    update_check_marker_from(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))
}

fn update_check_marker_from(
    xdg_cache_home: Option<OsString>,
    home: Option<OsString>,
) -> Option<PathBuf> {
    let cache_dir = xdg_cache_home
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            home.filter(|value| !value.is_empty())
                .map(PathBuf::from)
                .map(|path| path.join(".cache"))
        })?;
    Some(cache_dir.join("trashd").join("last-update-check"))
}

fn cached_update_check() -> Option<String> {
    let marker = update_check_marker()?;
    validate_cache_parent(marker.parent()?).ok()?;

    // O_NOFOLLOW rejects a marker symlink instead of reading an attacker-chosen
    // target. Limit the tiny cache record so a corrupted file cannot allocate
    // arbitrary memory during an update check.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&marker)
        .ok()?;
    let meta = file.metadata().ok()?;
    if !meta.is_file() || meta.uid() != unsafe { libc::geteuid() } {
        return None;
    }
    let age = meta.modified().ok()?.elapsed().ok()?;
    if age.as_secs() >= 86400 {
        return None;
    }

    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(256)
        .read_to_end(&mut bytes)
        .ok()?;
    String::from_utf8(bytes).ok()
}

fn write_update_check_cache(version: &str) {
    let Some(marker) = update_check_marker() else {
        return;
    };
    let _ = write_update_check_cache_at(&marker, version);
}

/// Validate the application-owned cache directory before using it. A symlink
/// here could redirect a privileged invocation into an attacker-selected tree.
fn validate_cache_parent(parent: &Path) -> std::io::Result<()> {
    let uid = unsafe { libc::geteuid() };
    let mut current = parent;
    loop {
        let meta = fs::symlink_metadata(current)?;
        let mode = meta.permissions().mode();
        let is_app_dir = current == parent;
        if !meta.file_type().is_dir()
            || meta.file_type().is_symlink()
            || (is_app_dir && meta.uid() != uid)
            || (!is_app_dir && meta.uid() != 0 && meta.uid() != uid)
            || (is_app_dir && mode & 0o022 != 0)
            || (!is_app_dir && mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "update cache path has an unsafe owner, mode, or symlink ancestor",
            ));
        }
        match current.parent() {
            Some(next) if next != current => current = next,
            _ => break,
        }
    }
    Ok(())
}

/// Create a cache parent by walking from a pinned root/cwd descriptor. Each
/// component is opened with O_NOFOLLOW before the next one is created, so an
/// attacker cannot redirect recursive creation through a raced symlink.
fn ensure_cache_parent(path: &Path) -> std::io::Result<()> {
    use std::path::Component;

    let uid = unsafe { libc::geteuid() };
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let components: Vec<_> = absolute
        .components()
        .filter_map(|component| match component {
            Component::RootDir | Component::CurDir => None,
            Component::Normal(name) => Some(Ok(name)),
            Component::ParentDir | Component::Prefix(_) => Some(Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "unsafe update cache path",
            ))),
        })
        .collect::<std::io::Result<_>>()?;

    let root = CString::new("/").expect("static CString");
    let root_fd = unsafe {
        libc::open(
            root.as_ptr(),
            libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut directory = unsafe { fs::File::from_raw_fd(root_fd) };

    for (index, component) in components.iter().enumerate() {
        let component = CString::new(component.as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let open_component = || unsafe {
            libc::openat(
                directory.as_raw_fd(),
                component.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };

        let mut child_fd = open_component();
        if child_fd < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ELOOP) | Some(libc::ENOTDIR)
            ) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "update cache path contains a symlink or non-directory component",
                ));
            }
            if error.raw_os_error() != Some(libc::ENOENT) {
                return Err(error);
            }
            let created =
                unsafe { libc::mkdirat(directory.as_raw_fd(), component.as_ptr(), 0o700) };
            if created != 0 {
                let mkdir_error = std::io::Error::last_os_error();
                if mkdir_error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(mkdir_error);
                }
            }
            child_fd = open_component();
            if child_fd < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ELOOP) | Some(libc::ENOTDIR)
                ) {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "update cache path contains a raced symlink or non-directory component",
                    ));
                }
                return Err(error);
            }
        }

        let child = unsafe { fs::File::from_raw_fd(child_fd) };
        let meta = child.metadata()?;
        let mode = meta.permissions().mode();
        let is_app_dir = index + 1 == components.len();
        if !meta.is_dir()
            || (is_app_dir && meta.uid() != uid)
            || (!is_app_dir && meta.uid() != 0 && meta.uid() != uid)
            || (is_app_dir && mode & 0o022 != 0)
            || (!is_app_dir && mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "update cache path has an unsafe owner or mode",
            ));
        }
        directory = child;
    }

    // The descriptor walk establishes that every name is stable against other
    // users. Keep the ordinary path validator as a final defense before the
    // tempfile API reopens the application directory by name.
    validate_cache_parent(&absolute)
}

fn write_update_check_cache_at(marker: &Path, version: &str) -> std::io::Result<()> {
    let parent = marker.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "cache marker has no parent",
        )
    })?;

    ensure_cache_parent(parent)?;

    // Write beside the marker and atomically rename it into place. rename(2)
    // replaces a marker symlink itself; it never follows the symlink and writes
    // through to its target.
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary
        .as_file_mut()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(version.as_bytes())?;
    temporary.as_file_mut().sync_all()?;
    temporary.persist(marker).map_err(|error| error.error)?;
    Ok(())
}

pub fn run(check_only: bool, allow_unverified: bool) {
    let current = crate::VERSION;

    let release = if check_only {
        if let Some(cached) = cached_update_check() {
            // Apply the same is_newer guard as the fresh-fetch path: a cached
            // version that is not strictly newer (equal, or older — e.g. this
            // binary is a dev build newer than the latest release) must be
            // reported as up to date, never as a pending "update" (#95).
            let comparable = versions_comparable(&cached, current);
            if comparable && !is_newer(&cached, current) {
                println!(
                    "{} trashd {} is already the latest version.",
                    "Up to date:".green().bold(),
                    current,
                );
                return;
            }
            print_update_offer(current, &cached, comparable);
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
    // older releases (or split 0.1.10 vs 0.1.9 lexicographically). Cross-scheme
    // versions are never silently ordered (#154).
    let comparable = versions_comparable(latest, current);
    if comparable && !is_newer(latest, current) {
        println!(
            "{} trashd {} is up to date (latest release: {}).",
            "Up to date:".green().bold(),
            current.dimmed(),
            latest.bold(),
        );
        return;
    }

    print_update_offer(current, latest, comparable);

    if release.prerelease {
        println!("  {}", "(pre-release)".yellow());
    }

    if check_only {
        println!("\nRun {} to install.", "trash self-update".bold());
        return;
    }

    // Decide where to install before downloading anything (#199).
    let prefix = match detect_install_prefix() {
        InstallPrefix::Default => None,
        InstallPrefix::Custom(prefix) => Some(prefix),
        InstallPrefix::Refused(reason) => fatal(format!("cannot self-update: {reason}")),
    };

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

    // The checksum comes from the same release as the tarball; only the
    // build attestation shows where the artifact came from (#214).
    eprint!("Verifying provenance... ");
    let provenance = verify_provenance(&tarball_path);
    if let Err(refusal) = provenance_gate(provenance, allow_unverified) {
        eprintln!("{}", "not verified".red().bold());
        let _ = std::fs::remove_dir_all(&tmp_dir);
        fatal(refusal);
    }

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
        let mut cmd = std::process::Command::new("bash");
        cmd.arg(&install_script)
            .env("TRASH_BYPASS", "1")
            .current_dir(&install_dir);
        if let Some(prefix) = &prefix {
            cmd.env("PREFIX", prefix);
        }
        cmd.status()
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
        let mut cmd = std::process::Command::new("sudo");
        cmd.arg("env").arg("TRASH_BYPASS=1");
        if let Some(prefix) = &prefix {
            cmd.arg(format!("PREFIX={}", prefix.display()));
        }
        cmd.arg("bash")
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

/// Where a self-update may reinstall. The installer runs as root and puts the
/// preload into /etc/ld.so.preload (loaded by every process) and the profile
/// hook into root logins, so only a prefix nobody but root can write is
/// acceptable (#199).
enum InstallPrefix {
    /// install.sh's default (/usr/local), or not an installed layout.
    Default,
    /// The same custom PREFIX the running binary was installed with (#101).
    Custom(PathBuf),
    /// Refuse the update, with the reason.
    Refused(String),
}

/// The prefix this binary is installed under (…/bin/trash → …), so a
/// self-update reinstalls to the SAME location instead of silently
/// reverting a custom PREFIX to /usr/local (#101).
fn detect_install_prefix() -> InstallPrefix {
    match std::fs::read_link("/proc/self/exe") {
        Ok(exe) => install_prefix_for(&exe),
        Err(_) => InstallPrefix::Default,
    }
}

fn install_prefix_for(exe: &Path) -> InstallPrefix {
    let (Some(bin), Some(prefix)) = (exe.parent(), exe.parent().and_then(Path::parent)) else {
        return InstallPrefix::Default;
    };
    if !bin.ends_with("bin") || prefix == Path::new("/") || prefix == Path::new("/usr/local") {
        return InstallPrefix::Default;
    }
    if prefix == Path::new("/usr") {
        return InstallPrefix::Refused(
            "trashd in /usr belongs to your package manager; update it with the package manager"
                .into(),
        );
    }
    let root_controlled = prefix.ancestors().all(|dir| {
        fs::symlink_metadata(dir)
            .is_ok_and(|meta| meta.is_dir() && meta.uid() == 0 && meta.mode() & 0o022 == 0)
    });
    if !root_controlled {
        return InstallPrefix::Refused(format!(
            "{} can be modified by users other than root, and a system-wide install there \
             would let them replace the library every process loads. Reinstall with \
             `sudo ./install.sh` (default prefix /usr/local) instead",
            prefix.display()
        ));
    }
    InstallPrefix::Custom(prefix.to_path_buf())
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

/// The tarball download needs its own budget: ureq 3.x enforces the global
/// deadline on transport reads while the body streams, so sharing the API
/// agent's 30 s cap would abort a multi-MB release mid-download on any slow
/// link (#155). The size bound in download_file still caps total bytes.
fn download_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(std::time::Duration::from_secs(15 * 60)))
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

    let resp = download_agent()
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

/// Result of checking a release tarball's GitHub build attestation.
enum Provenance {
    Verified,
    /// Could not be verified, with the reason (gh missing, not logged in,
    /// no attestation, or a failed verification).
    Unverified(String),
}

fn verify_provenance(tarball: &std::path::Path) -> Provenance {
    match std::process::Command::new("gh")
        .args(["attestation", "verify"])
        .arg(tarball)
        .args(["--repo", "faratech/trashd"])
        .output()
    {
        Ok(output) if output.status.success() => Provenance::Verified,
        Ok(output) => Provenance::Unverified(format!(
            "gh attestation verify failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Provenance::Unverified("the GitHub CLI (gh) is not installed".into())
        }
        Err(error) => Provenance::Unverified(format!("could not run gh: {error}")),
    }
}

/// install.sh runs as root, so an artifact of unproven origin needs the
/// user's explicit consent (#214).
fn provenance_gate(provenance: Provenance, allow_unverified: bool) -> Result<(), String> {
    match provenance {
        Provenance::Verified => {
            eprintln!("{}", "ok".green());
            Ok(())
        }
        Provenance::Unverified(reason) if allow_unverified => {
            eprintln!("{} ({reason}); continuing as requested", "skipped".yellow());
            Ok(())
        }
        Provenance::Unverified(reason) => Err(format!(
            "cannot verify the release's build attestation: {reason}.\n  \
             Install and log in to the GitHub CLI (`gh auth login`) so the \
             attestation can be checked, or re-run with --allow-unverified \
             to install without it"
        )),
    }
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
/// Pre-release/build suffixes ("-rc1", "+build") are stripped before the
/// comparison so "0.2.0-rc1" compares as its base release, not as 0.
fn is_newer(candidate: &str, current: &str) -> bool {
    fn parts(v: &str) -> Vec<u64> {
        // Strip pre-release/build metadata at the first '-' or '+'.
        let core = v.split(['-', '+']).next().unwrap_or(v);
        core.split('.')
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

/// Print the "update available" line, flagging cross-scheme versions where
/// no ordering could be determined (#154).
fn print_update_offer(current: &str, latest: &str, comparable: bool) {
    if comparable {
        println!(
            "{} {} -> {}",
            "Update available:".yellow().bold(),
            current.dimmed(),
            latest.bold(),
        );
    } else {
        println!(
            "{} {} -> {} {}",
            "Update available:".yellow().bold(),
            current.dimmed(),
            latest.bold(),
            "(cannot compare version schemes — verify the release before installing)".yellow(),
        );
    }
}

/// Date-scheme versions are the release workflow's default YYYY.MM.DD tags.
/// Numeric comparison ACROSS schemes is meaningless — `is_newer("0.2.0",
/// "2026.09.29")` hides a real update and the inverse offers an apparent
/// downgrade (#154) — so callers must never silently order cross-scheme
/// versions.
fn is_date_scheme(version: &str) -> bool {
    let core = version.split(['-', '+']).next().unwrap_or(version);
    let comps: Vec<&str> = core.split('.').collect();
    comps.len() == 3
        && comps[0].len() == 4
        && comps
            .iter()
            .all(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()))
}

fn versions_comparable(a: &str, b: &str) -> bool {
    is_date_scheme(a) == is_date_scheme(b)
}

fn extract_tarball(tarball: &std::path::Path, dest: &std::path::Path) -> Result<(), String> {
    let file = std::fs::File::open(tarball).map_err(|e| format!("open tarball: {e}"))?;
    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);
    archive.unpack(dest).map_err(|e| format!("extract: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn update_cache_has_no_shared_tmp_fallback() {
        assert_eq!(update_check_marker_from(None, None), None);
        assert_eq!(
            update_check_marker_from(None, Some(OsString::from("/home/alice"))),
            Some(PathBuf::from("/home/alice/.cache/trashd/last-update-check"))
        );
        assert_eq!(
            update_check_marker_from(
                Some(OsString::from("/var/cache/alice")),
                Some(OsString::from("/home/alice")),
            ),
            Some(PathBuf::from("/var/cache/alice/trashd/last-update-check"))
        );
    }

    // Regression (#95): a cached marker that is not strictly newer than the
    // running binary must read as up to date, and suffixes must not skew the
    // numeric comparison.
    #[test]
    fn cached_and_suffixed_versions_never_offer_downgrades() {
        // Plain ordering.
        assert!(is_newer("0.2.0", "0.1.9"));
        assert!(is_newer("0.1.10", "0.1.9"));
        assert!(!is_newer("0.1.9", "0.1.9"));
        assert!(
            !is_newer("0.1.5", "0.2.0"),
            "cached downgrade must not read as an update"
        );
        // Pre-release/build suffixes compare as their base release.
        assert!(!is_newer("0.2.0-rc1", "0.2.0"));
        assert!(is_newer("0.2.1-rc1", "0.2.0"));
        assert!(!is_newer("0.2.0+build.5", "0.2.0"));
    }

    // Regression (#154): cross-scheme versions must never be silently
    // ordered — numeric comparison hides semver updates after a date-based
    // release and offers apparent downgrades in the inverse cache case.
    #[test]
    fn cross_scheme_versions_are_flagged_incomparable() {
        assert!(versions_comparable("0.1.9", "0.2.0"));
        assert!(versions_comparable("2026.09.29", "2026.10.01"));
        assert!(!versions_comparable("0.2.0", "2026.09.29"));
        assert!(!versions_comparable("2026.09.29", "0.2.0"));
        assert!(is_date_scheme("2026.09.29"));
        assert!(!is_date_scheme("0.2.0"));
        // pre-release suffixes are stripped before the scheme check, matching
        // is_newer's core comparison
        assert!(is_date_scheme("2026.09.29-rc1"));
        // a 4-digit-major semver would be misread as a date scheme, but the
        // failure mode is only "treated as comparable", same as today
        assert!(is_date_scheme("2026.1.2"));
    }

    // Regression (#101): the detected prefix must match an installed layout
    // (…/bin/trash) and must never fire for the default /usr/local install,
    // a bare root path, or a non-installed (dev-tree) binary.
    #[test]
    fn install_prefix_detection_follows_proc_self_exe() {
        // Whatever this test binary is, detection must be total (no panic) and
        // must reject anything whose parent chain is not an installed layout.
        if let InstallPrefix::Custom(prefix) = detect_install_prefix() {
            assert!(prefix.is_absolute());
            assert_ne!(prefix, Path::new("/usr/local"));
        }
    }

    // Regression (#214): the checksum comes from the same release as the
    // tarball, so only the build attestation shows where an artifact that
    // install.sh runs as root came from. Unverifiable releases need consent.
    #[test]
    fn provenance_gate_requires_attestation_or_consent() {
        assert!(provenance_gate(Provenance::Verified, false).is_ok());
        let unverified = || Provenance::Unverified("gh is not installed".into());
        let refusal = provenance_gate(unverified(), false).unwrap_err();
        assert!(refusal.contains("--allow-unverified") && refusal.contains("gh"));
        assert!(provenance_gate(unverified(), true).is_ok());
    }

    // Regression (#199): self-update reinstalls system-wide as root into the
    // running binary's prefix. A prefix other users can write (~/.cargo, /tmp)
    // would hand them the library every process loads; /usr belongs to the
    // package manager.
    #[test]
    fn install_prefix_must_be_root_controlled() {
        assert!(matches!(
            install_prefix_for(Path::new("/usr/local/bin/trash")),
            InstallPrefix::Default
        ));
        assert!(matches!(
            install_prefix_for(Path::new("/usr/bin/trash")),
            InstallPrefix::Refused(_)
        ));
        let user = tempfile::tempdir().unwrap();
        assert!(matches!(
            install_prefix_for(&user.path().join("bin/trash")),
            InstallPrefix::Refused(_)
        ));
        assert!(matches!(
            install_prefix_for(Path::new("/usr/lib/bin/trash")),
            InstallPrefix::Custom(prefix) if prefix == Path::new("/usr/lib")
        ));
    }

    #[test]
    fn cache_write_replaces_marker_symlink_without_touching_target() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("cache").join("trashd");
        fs::create_dir_all(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();

        let victim = temp.path().join("victim");
        fs::write(&victim, "do not replace").unwrap();
        let marker = parent.join("last-update-check");
        symlink(&victim, &marker).unwrap();

        write_update_check_cache_at(&marker, "9.9.9").unwrap();

        assert_eq!(fs::read_to_string(&victim).unwrap(), "do not replace");
        assert_eq!(fs::read_to_string(&marker).unwrap(), "9.9.9");
        assert!(fs::symlink_metadata(&marker).unwrap().file_type().is_file());
        assert_eq!(
            fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn cache_write_rejects_symlinked_application_directory() {
        let temp = tempfile::tempdir().unwrap();
        let redirected = temp.path().join("redirected");
        fs::create_dir(&redirected).unwrap();
        let cache_dir = temp.path().join("trashd");
        symlink(&redirected, &cache_dir).unwrap();

        let marker = cache_dir.join("last-update-check");
        let error = write_update_check_cache_at(&marker, "9.9.9").unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(!redirected.join("last-update-check").exists());
    }

    #[test]
    fn cache_write_rejects_symlinked_missing_path_ancestor() {
        let temp = tempfile::tempdir().unwrap();
        let redirected = temp.path().join("redirected");
        fs::create_dir(&redirected).unwrap();
        let link = temp.path().join("cache-link");
        symlink(&redirected, &link).unwrap();
        let marker = link.join("new").join("trashd").join("last-update-check");

        assert!(write_update_check_cache_at(&marker, "9.9.9").is_err());
        assert!(!redirected.join("new").exists());
    }
}
