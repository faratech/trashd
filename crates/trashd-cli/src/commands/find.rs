use crate::util::*;
use colored::Colorize;
use trashd_common::TrashStore;

/// Glob introducers recognised by `simple_glob_match`; `[` opens a
/// character class, which `ls` already honoured but `find` did not (#257).
pub(crate) fn has_glob_chars(query: &str) -> bool {
    query.contains(['*', '?', '['])
}

pub fn run(store: &TrashStore, query: &str) {
    let has_glob = has_glob_chars(query);
    let matches = match store.list_for_query(|entry| matches_query(entry, query, has_glob)) {
        Ok(entries) => entries,
        Err(error) => fatal(error),
    };

    if matches.is_empty() {
        println!("{}", format!("No matches for '{query}'.").dimmed());
        return;
    }

    with_buffered_stdout(|out| {
        for entry in &matches {
            let date = entry.info.deletion_date.format("%Y-%m-%d %H:%M");
            let size = entry
                .info
                .size
                .map(format_size)
                .unwrap_or_else(|| "?".into());
            writeln!(
                out,
                "{:<20} {:>10} {} {}",
                date,
                size,
                printable_path(&entry.info.original_path),
                printable(&entry.id).dimmed(),
            )?;
        }
        writeln!(out, "\n{} matches", matches.len())
    });
}

fn matches_query(entry: &trashd_common::store::TrashEntry, query: &str, has_glob: bool) -> bool {
    let path = entry.info.original_path.to_string_lossy();
    if has_glob {
        let name = entry
            .info
            .original_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy();
        trashd_common::store::simple_glob_match(query, &name)
            || trashd_common::store::simple_glob_match(query, &path)
    } else {
        path.contains(query) || entry.id.contains(query)
    }
}

#[cfg(test)]
mod tests {
    use super::has_glob_chars;

    #[test]
    fn filtered_queries_match_the_existing_full_listing_predicates() {
        use super::matches_query;
        use std::fs;
        let fixture = tempfile::tempdir().unwrap();
        let mut config = trashd_common::Config::default();
        config.never_trash.clear();
        let store = trashd_common::TrashStore::open_isolated(&fixture.path().join("Trash"), config)
            .unwrap();
        for name in ["alpha", "beta", "a[1].txt"] {
            let source = fixture.path().join(name);
            fs::write(&source, b"data").unwrap();
            store.trash(&source, None).unwrap();
        }
        let listed = store.list(None).unwrap();
        for query in ["alpha", "a*", "[ab]*", "*.txt", "missing", ""] {
            let has_glob = has_glob_chars(query);
            let expected = listed
                .iter()
                .filter(|entry| matches_query(entry, query, has_glob))
                .map(|entry| entry.trashed_path.clone())
                .collect::<Vec<_>>();
            let actual = store
                .list_for_query(|entry| matches_query(entry, query, has_glob))
                .unwrap();
            assert_eq!(
                actual
                    .iter()
                    .map(|entry| entry.trashed_path.clone())
                    .collect::<Vec<_>>(),
                expected,
                "{query:?}"
            );
        }
    }

    // Regression (#257): `[a].txt` took the substring path and never matched.
    #[test]
    fn character_class_counts_as_glob() {
        assert!(has_glob_chars("[a].txt"));
        assert!(has_glob_chars("*.txt"));
        assert!(has_glob_chars("a?.txt"));
        assert!(!has_glob_chars("plain.txt"));
        assert!(trashd_common::store::simple_glob_match("[a].txt", "a.txt"));
    }
}
