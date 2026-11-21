//! never_trash/only_trash pattern rules shared by trashd-common's loader and
//! the standalone preload, which `#[path]`-includes this file: the two kept
//! separate copies, and the preload's missed the empty-pattern rule (#402,
//! cross-layer-2). Standard library only.

use std::path::{Path, PathBuf};

/// The pattern as the matcher should see it, or why it cannot be used.
///
/// Matched paths are normalized: absolute, without `.` or `..` components,
/// repeated slashes or a trailing slash. A pattern written like a directory
/// (`src/`, `~/projects/`) or relative to `.` (`./build/*`) therefore
/// matched nothing, and in only_trash a whitelist that matches nothing makes
/// every delete permanent (common-policy-5). So `dir/` means everything
/// under `dir` (`dir/*`) and leading `./` segments go. What still cannot
/// match, or would match everything only because of that rewrite (`/`,
/// `~/`), is refused.
pub fn normalize_pattern(pattern: &str) -> Result<String, &'static str> {
    let mut pattern = pattern;
    while let Some(rest) = pattern.strip_prefix("./") {
        pattern = rest.trim_start_matches('/');
    }
    if pattern.is_empty() {
        return Err("it is empty and would match nothing");
    }
    if pattern.contains(['{', '}']) {
        return Err("brace expansion is not supported");
    }
    let directory = pattern.trim_end_matches('/');
    let pattern = if directory.len() == pattern.len() {
        pattern.to_owned()
    } else if directory.is_empty() || directory == "~" {
        return Err("as a directory it would match every path below it");
    } else {
        format!("{directory}/*")
    };
    let unmatchable = pattern
        .split('/')
        .enumerate()
        .any(|(index, part)| part == "." || part == ".." || (part.is_empty() && index > 0));
    if unmatchable {
        return Err("a '.', '..' or empty path component never matches a path");
    }
    Ok(pattern)
}

/// Whether the matcher can honour `pattern` once normalized.
pub fn pattern_is_supported(pattern: &str) -> bool {
    normalize_pattern(pattern).is_ok()
}

/// Normalize a configured list, dropping what cannot be used with a warning
/// for each: a pattern that silently matches nothing would, in only_trash,
/// real-delete everything (#4, #402).
pub fn sanitize_patterns(list: &[String], what: &str, mut warn: impl FnMut(String)) -> Vec<String> {
    list.iter()
        .filter_map(|pattern| match normalize_pattern(pattern) {
            Ok(normalized) => Some(normalized),
            Err(reason) => {
                warn(format!("dropping {what} pattern '{pattern}': {reason}"));
                None
            }
        })
        .collect()
}

/// `~/rest` expanded against `home` as given and, where it differs, against
/// its canonical form. Policy paths have canonical parents, so a home
/// reached through a symlink (`/home/u` -> `/data/u`) never matched its
/// own `~/` patterns: an only_trash whitelist then real-deleted everything
/// (common-policy-6). Both spellings match, so configs written either way
/// keep working.
pub fn expand_home(rest: &str, home: &Path) -> (String, Option<String>) {
    let raw = home.join(rest).to_string_lossy().into_owned();
    let canonical = canonical_home(home)
        .filter(|canonical| canonical != home)
        .map(|canonical| canonical.join(rest).to_string_lossy().into_owned());
    (raw, canonical)
}

/// The canonical form of `home`, remembered for the last home seen: every
/// `~/` pattern of every delete asked for it. The lock is only tried and
/// never held across a syscall, so a fork from another thread cannot leave
/// a child waiting on it; it then just resolves again.
fn canonical_home(home: &Path) -> Option<PathBuf> {
    use std::sync::Mutex;
    static CACHE: Mutex<Option<(PathBuf, Option<PathBuf>)>> = Mutex::new(None);
    if let Ok(cache) = CACHE.try_lock()
        && let Some((raw, canonical)) = cache.as_ref()
        && raw == home
    {
        return canonical.clone();
    }
    let canonical = std::fs::canonicalize(home).ok();
    if let Ok(mut cache) = CACHE.try_lock() {
        *cache = Some((home.to_path_buf(), canonical.clone()));
    }
    canonical
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directory_and_dot_relative_patterns_are_normalized() {
        for (written, normalized) in [
            ("src/", "src/*"),
            ("src//", "src/*"),
            ("~/projects/", "~/projects/*"),
            ("/var/log/", "/var/log/*"),
            ("./build/*", "build/*"),
            ("././build/", "build/*"),
            (".//build/*", "build/*"),
            ("*.rs", "*.rs"),
            ("~", "~"),
            ("*/", "*/*"),
        ] {
            assert_eq!(
                normalize_pattern(written).as_deref(),
                Ok(normalized),
                "{written}"
            );
        }
    }

    #[test]
    fn patterns_that_cannot_match_or_would_match_everything_are_refused() {
        for pattern in [
            "", "./", "/", "~/", "~//", "*.{c,h}", "a//b", "a/./b", "a/../b", "/a/.", "./..",
        ] {
            assert!(normalize_pattern(pattern).is_err(), "{pattern:?}");
            assert!(!pattern_is_supported(pattern), "{pattern:?}");
        }
    }

    #[test]
    fn sanitizing_warns_for_each_dropped_pattern() {
        let mut warnings = Vec::new();
        let kept = sanitize_patterns(
            &["".into(), "src/".into(), "*.{a,b}".into(), "*.py".into()],
            "only_trash",
            |warning| warnings.push(warning),
        );
        assert_eq!(kept, ["src/*", "*.py"]);
        assert_eq!(warnings.len(), 2, "{warnings:?}");
        assert!(
            warnings[0].contains("only_trash pattern ''"),
            "{warnings:?}"
        );
        assert!(warnings[1].contains("brace expansion"), "{warnings:?}");
    }

    #[test]
    fn home_expands_to_both_spellings_through_a_symlink() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let canonical = std::fs::canonicalize(&real).unwrap();
        let (raw, resolved) = expand_home("docs/*", &link);
        assert_eq!(raw, link.join("docs/*").to_string_lossy());
        assert_eq!(
            resolved.as_deref(),
            Some(&*canonical.join("docs/*").to_string_lossy())
        );
        // A canonical home has nothing to add.
        assert_eq!(expand_home("docs/*", &canonical).1, None);
    }
}
