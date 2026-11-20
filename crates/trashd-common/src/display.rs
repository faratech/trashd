//! Escaping for human output of names and sidecar fields.

/// `s` for human output, with control and bidi-override characters escaped:
/// names and sidecar fields come from the filesystem, and could otherwise
/// move the cursor, clear the screen, or reorder a line (#230). Shared by
/// the CLI and the store's warnings, which print the same untrusted text
/// (cli-2).
pub fn printable(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control()
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            out.extend(c.escape_unicode());
        } else {
            out.push(c);
        }
    }
    out
}

/// A path for human output; see [`printable`].
pub fn printable_path(path: &std::path::Path) -> String {
    printable(&path.to_string_lossy())
}
