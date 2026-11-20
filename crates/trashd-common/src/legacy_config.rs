//! How a configuration layer is read, shared with the standalone preload:
//! compatibility with releases that shipped root settings under
//! [retention], and keys of the wrong type dropped one by one.

pub fn normalize(contents: &str) -> Result<toml::Value, toml::de::Error> {
    let mut value: toml::Value = toml::from_str(contents)?;
    if let Some(root) = value.as_table_mut() {
        for key in [
            "never_trash",
            "only_trash",
            "bypass_processes",
            "bypass_paths",
            "max_file_size_mb",
            "max_dir_size_mb",
            "sha256_max_size_mb",
            "auto_purge_interval_secs",
            "hash_algorithm",
        ] {
            let legacy = root
                .get_mut("retention")
                .and_then(toml::Value::as_table_mut)
                .and_then(|retention| retention.remove(key));
            if let Some(legacy) = legacy {
                // An explicit root setting always takes precedence.
                if root.get(key).is_none() {
                    // A misplaced key SILENTLY applied is the worst failure
                    // direction for a whitelist like only_trash (real
                    // deletes); bc1a5f5 originally rejected these outright.
                    // Keep the legacy compatibility, but stay loud (#150).
                    // Through the including crate: inside the preload this
                    // runs in arbitrary host processes (#208).
                    crate::report_note(&format!(
                        "trashd: note: '{key}' applied from [retention] (legacy layout); \
                         move it to the top level to silence this"
                    ));
                    root.insert(key.to_owned(), legacy);
                }
            }
        }
    }
    Ok(value)
}

/// A parse or type error of `contents` for a diagnostic: where it is and
/// what it is, never the error's own `Display`. That rendering quotes the
/// whole source line it stopped at, and a configuration file may be a
/// symlink: a setuid-root program loading the preload printed root's line
/// of /etc/shadow to the terminal of whoever pointed `XDG_CONFIG_HOME` at
/// it (preload-1, common-policy-4).
pub fn describe(error: &toml::de::Error, contents: &str) -> String {
    let Some(span) = error.span() else {
        return error.message().to_owned();
    };
    let before = &contents.as_bytes()[..span.start.min(contents.len())];
    let line_start = before
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let line = before.iter().filter(|byte| **byte == b'\n').count() + 1;
    let column = String::from_utf8_lossy(&before[line_start..])
        .chars()
        .count()
        + 1;
    format!("line {line}, column {column}: {}", error.message())
}

/// A normalized configuration layer as `T`, without each top-level key
/// whose value has the wrong type: `dropped` reports it, and the rest of
/// the layer still applies. Rejecting the whole layer over one key that
/// only some loaders read (`sha256_max_size_mb = 0.5`) left the layers on
/// different policies: the preload applied the layer's never_trash,
/// whitelist and size caps, trashd-common used none of them
/// (cross-layer-7). Both loaders read their layers through this.
pub fn layer<T: serde::de::DeserializeOwned>(
    mut value: toml::Value,
    mut dropped: impl FnMut(&str, &toml::de::Error),
) -> Result<T, toml::de::Error> {
    let error = match value.clone().try_into::<T>() {
        Ok(layer) => return Ok(layer),
        Err(error) => error,
    };
    let Some(table) = value.as_table_mut() else {
        return Err(error);
    };
    let keys: Vec<String> = table.keys().cloned().collect();
    for key in keys {
        let mut alone = toml::Table::new();
        alone.insert(key.clone(), table[&key].clone());
        if let Err(error) = toml::Value::Table(alone).try_into::<T>() {
            dropped(&key, &error);
            table.remove(&key);
        }
    }
    value.try_into::<T>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_settings_are_promoted_without_overriding_root_values() {
        let value = normalize(
            r#"
max_file_size_mb = 8
[retention]
max_age_days = 7
max_file_size_mb = 16
only_trash = ["*.txt"]
auto_purge_interval_secs = 90
"#,
        )
        .unwrap();
        assert_eq!(value["max_file_size_mb"].as_integer(), Some(8));
        assert_eq!(value["auto_purge_interval_secs"].as_integer(), Some(90));
        assert_eq!(value["only_trash"][0].as_str(), Some("*.txt"));
        assert_eq!(value["retention"]["max_age_days"].as_integer(), Some(7));
        assert!(value["retention"].get("only_trash").is_none());
    }

    // preload-1, common-policy-4: a diagnostic names where parsing stopped
    // and why, and never quotes the file. A setuid-root program reading a
    // symlinked "config" printed root's line of /etc/shadow that way.
    #[test]
    fn diagnostics_never_quote_the_configuration() {
        for contents in [
            "root:SECRETMARKER:19000:0:99999:7:::\n",
            "a = 1\nPATH=/SECRETMARKER/bin\u{0}HOME=/root",
            "a = 1\n\né = [\"SECRETMARKER\"\n",
        ] {
            let error = normalize(contents).unwrap_err();
            let rendered = error.to_string();
            assert!(rendered.contains("SECRETMARKER"), "{rendered}");
            // The position the parser's own rendering heads its quote with.
            let position = rendered
                .lines()
                .next()
                .and_then(|line| line.strip_prefix("TOML parse error at "))
                .expect("a parse error has a position");
            let described = describe(&error, contents);
            assert!(!described.contains("SECRETMARKER"), "{described}");
            assert_eq!(
                described,
                format!("{position}: {}", error.message()),
                "{rendered}"
            );
            assert!(!described.contains('\n'), "{described}");
        }
        // A type error has no position: its message alone.
        #[derive(Debug, serde::Deserialize)]
        struct Layer {
            #[serde(rename = "limit")]
            _limit: Option<u64>,
        }
        let contents = "limit = [1]\n";
        let error = normalize(contents)
            .unwrap()
            .try_into::<Layer>()
            .unwrap_err();
        assert_eq!(error.span(), None);
        assert_eq!(describe(&error, contents), error.message());
    }
}
