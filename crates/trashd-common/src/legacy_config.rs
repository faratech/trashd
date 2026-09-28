//! Compatibility with releases that shipped root settings under [retention].

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
                root.entry(key.to_owned()).or_insert(legacy);
            }
        }
    }
    Ok(value)
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
}
