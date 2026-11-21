//! Scan trash roots and resolve selectors while preserving entry snapshots.
//! Mutation, accounting, and shared entry types live in the parent module.

use super::*;

impl TrashStore {
    /// List all items across all trash directories, newest first.
    pub fn list(&self, pattern: Option<&str>) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_with(pattern, ScanMetadata::MUTATION)
    }

    /// `list` for display: entries carry no data identity (`identity` is
    /// None), which only mutations verify. Listing statted every entry's
    /// data for nothing (#353).
    pub fn list_for_display(&self, pattern: Option<&str>) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_with(pattern, ScanMetadata::DISPLAY)
    }

    /// Mutation listing with an info-level prefilter applied BEFORE the
    /// per-entry data stat: rejected entries never pay for (or retain) a
    /// data identity they will not use. Accepted entries are full mutation
    /// snapshots, identical to `list`.
    pub fn list_mutation_filtered(
        &self,
        keep: impl Fn(&TrashInfo) -> bool,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        let mut entries = Vec::new();
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(dir, _)| dir)
            .collect();
        self.visit_roots_for_id_filtered(
            &roots,
            None,
            None,
            ScanMetadata::MUTATION,
            Some(&keep),
            &mut |entry, _| entries.push(entry),
        )?;
        newest_first(&mut entries);
        Ok(entries)
    }

    /// A read-only query: preserve sidecar freshness checks, omit data
    /// identities, and retain/sort only the entries the predicate accepts.
    /// Mutation callers must use `list` or selected mutation snapshots.
    pub fn list_for_query(
        &self,
        keep: impl FnMut(&TrashEntry) -> bool,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_filtered_with(None, ScanMetadata::QUERY, keep)
    }

    /// Display listing with a filter applied after orphan bookkeeping and
    /// before collecting/sorting entries, for example a deletion-date range.
    pub fn list_for_display_filtered(
        &self,
        pattern: Option<&str>,
        keep: impl FnMut(&TrashEntry) -> bool,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_filtered_with(pattern, ScanMetadata::DISPLAY, keep)
    }

    fn list_with(
        &self,
        pattern: Option<&str>,
        metadata: ScanMetadata,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        self.list_filtered_with(pattern, metadata, |_| true)
    }

    fn list_filtered_with(
        &self,
        pattern: Option<&str>,
        metadata: ScanMetadata,
        mut keep: impl FnMut(&TrashEntry) -> bool,
    ) -> Result<Vec<TrashEntry>, TrashError> {
        let mut entries = Vec::new();
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(dir, _)| dir)
            .collect();
        self.visit_roots_for_id(&roots, pattern, None, metadata, &mut |entry, _| {
            if keep(&entry) {
                entries.push(entry);
            }
        })?;
        newest_first(&mut entries);
        Ok(entries)
    }

    fn scanned_data_metadata(&self, path: &Path, metadata: ScanMetadata) -> Option<fs::Metadata> {
        if !metadata.data {
            return None;
        }
        #[cfg(test)]
        self.scan_data_stats.set(self.scan_data_stats.get() + 1);
        fs::symlink_metadata(path).ok()
    }

    /// List one trash root, newest first.
    pub fn list_root(&self, root: &Path) -> Result<Vec<TrashEntry>, TrashError> {
        let mut entries = Vec::new();
        self.list_roots(&[root.to_path_buf()], None, &mut entries)?;
        newest_first(&mut entries);
        Ok(entries)
    }

    /// List several roots. One unreadable non-home root (a broken USB stick)
    /// is skipped with a warning instead of failing ls/restore/purge for
    /// every other root (#221); the home root still fails loudly, so a broken
    /// trash never reads as an empty one (#147).
    pub(super) fn list_roots(
        &self,
        roots: &[PathBuf],
        pattern: Option<&str>,
        entries: &mut Vec<TrashEntry>,
    ) -> Result<(), TrashError> {
        self.visit_roots(roots, pattern, &mut |entry, _| entries.push(entry))
    }

    /// Visit entries with the data metadata already needed for their identity.
    /// Status can aggregate each snapshot immediately instead of retaining a
    /// sorted listing and statting every entry for a second time.
    pub(super) fn visit_roots(
        &self,
        roots: &[PathBuf],
        pattern: Option<&str>,
        visitor: &mut impl FnMut(TrashEntry, Option<fs::Metadata>),
    ) -> Result<(), TrashError> {
        self.visit_roots_for_id(roots, pattern, None, ScanMetadata::MUTATION, visitor)
            .map(|_| ())
    }

    /// A name-only prefilter still traverses every directory entry, preserving
    /// scan errors, while exact selectors need only open their own sidecars.
    fn visit_roots_for_id(
        &self,
        roots: &[PathBuf],
        pattern: Option<&str>,
        only_id: Option<&OsStr>,
        metadata: ScanMetadata,
        visitor: &mut impl FnMut(TrashEntry, Option<fs::Metadata>),
    ) -> Result<Vec<(PathBuf, TrashError)>, TrashError> {
        self.visit_roots_for_id_filtered(roots, pattern, only_id, metadata, None, visitor)
    }

    fn visit_roots_for_id_filtered(
        &self,
        roots: &[PathBuf],
        pattern: Option<&str>,
        only_id: Option<&OsStr>,
        metadata: ScanMetadata,
        info_filter: Option<&dyn Fn(&TrashInfo) -> bool>,
        visitor: &mut impl FnMut(TrashEntry, Option<fs::Metadata>),
    ) -> Result<Vec<(PathBuf, TrashError)>, TrashError> {
        let mut parser = crate::trashinfo::TrashInfoParser::default();
        let mut deferred_warnings: Vec<(PathBuf, TrashError)> = Vec::new();
        for root in roots {
            if let Err(e) = self.visit_in_dir(
                root,
                pattern,
                only_id,
                metadata,
                info_filter,
                &mut parser,
                visitor,
            ) {
                if *root == self.home {
                    for (root, error) in deferred_warnings {
                        Self::warn_unreadable_root(&root, error);
                    }
                    return Err(e);
                }
                if only_id.is_some() {
                    // A missing exact ID falls back to a complete scan. Let
                    // that scan report failures once, without duplicate
                    // warnings from its preliminary name-only pass.
                    deferred_warnings.push((root.clone(), e));
                } else {
                    Self::warn_unreadable_root(root, e);
                }
            }
        }
        Ok(deferred_warnings)
    }

    pub(super) fn warn_unreadable_root(root: &Path, error: TrashError) {
        crate::report_note(&format!(
            "trashd: warning: skipping unreadable trash {}: {error}",
            root.display()
        ));
    }

    #[cfg(test)]
    pub(super) fn list_in_dir(
        &self,
        trash_dir: &Path,
        pattern: Option<&str>,
        entries: &mut Vec<TrashEntry>,
    ) -> Result<(), TrashError> {
        self.visit_in_dir(
            trash_dir,
            pattern,
            None,
            ScanMetadata::MUTATION,
            None,
            &mut crate::trashinfo::TrashInfoParser::default(),
            &mut |entry, _| entries.push(entry),
        )
    }

    /// Visit items in a single trash directory.
    #[allow(clippy::too_many_arguments)]
    fn visit_in_dir(
        &self,
        trash_dir: &Path,
        pattern: Option<&str>,
        only_id: Option<&OsStr>,
        metadata: ScanMetadata,
        info_filter: Option<&dyn Fn(&TrashInfo) -> bool>,
        parser: &mut crate::trashinfo::TrashInfoParser,
        visitor: &mut impl FnMut(TrashEntry, Option<fs::Metadata>),
    ) -> Result<(), TrashError> {
        // Orphan detection below must compare against ids from THIS directory
        // only: visitors may aggregate across all trash roots, so an
        // orphaned files/<id> in root B would otherwise be hidden by a real
        // entry with the same id in root A.
        let info_dir = trash_dir.join("info");
        let files_dir = trash_dir.join("files");
        // A topdir root (removable or network media, a FUSE mount) is read
        // through descriptors of its files/ and info/ that follow no symlink
        // and stay on the root's device: by path, a server could answer each
        // lookup with a symlink to /etc, whose files were then listed as
        // orphans and purged (security-1). Reads go through the descriptors'
        // /proc/self/fd views; entries keep their real paths. The home trash
        // is this user's alone.
        let pinned = if trash_dir == self.home {
            None
        } else {
            Some(PinnedStoreDirs::open(trash_dir)?)
        };
        let (read_info, read_files) = match &pinned {
            Some(pinned) => (pinned.info_view(), pinned.files_view()),
            None => (Some(info_dir.clone()), Some(files_dir.clone())),
        };

        // A missing info/ directory must not hide the data: every files/
        // entry then has no readable sidecar and is reported as an orphan,
        // so list/empty/purge still see the stranded data (#403). Other
        // read failures still fail the scan loudly.
        let info_entries = match read_info.as_ref().map(fs::read_dir) {
            Some(Ok(entries)) => Some(entries),
            None => None,
            Some(Err(e)) if e.kind() == std::io::ErrorKind::NotFound => None,
            Some(Err(e)) => return Err(e.into()),
        };

        // IDs with a readable sidecar, recorded BEFORE the pattern filter:
        // orphan detection must know every real entry in this directory, or a
        // filtered-out entry's own files/<id> would be re-synthesized as a
        // fake "orphaned" copy of itself (#144).
        let mut seen_ids = std::collections::HashSet::new();

        for entry in info_entries.into_iter().flatten() {
            let entry = entry?;
            let raw_filename = entry.file_name();
            // Compare raw stems: a lossy ID can collapse distinct filenames,
            // and even the unusual ".trashinfo" leaf has file_stem semantics
            // that must agree with the full scan below.
            if let Some(id) = only_id
                && Path::new(&raw_filename).file_stem() != Some(id)
            {
                continue;
            }
            let filename = raw_filename.to_string_lossy().into_owned();
            if !filename.ends_with(".trashinfo") {
                continue;
            }
            // The on-disk stem in raw bytes: the String ID is lossy for
            // non-UTF-8 names, and paths built from it point nowhere (#247).
            let raw_stem = entry
                .path()
                .file_stem()
                .map(|s| s.to_os_string())
                .unwrap_or_default();
            // Read through the (pinned) directory; record the real path.
            let sidecar_path = entry.path();
            let info_path = info_dir.join(&raw_filename);

            let id = filename
                .strip_suffix(".trashinfo")
                .unwrap_or(&filename)
                .to_string();
            #[cfg(test)]
            self.sidecar_reads.set(self.sidecar_reads.get() + 1);
            let (content, sidecar_metadata) =
                match crate::trashinfo::read_sidecar_snapshot(&sidecar_path) {
                    Ok(snapshot) => snapshot,
                    Err(_) => continue,
                };
            let sidecar_version = Some(SidecarVersion::from_metadata(&sidecar_metadata));
            // Confirm the path still names what was read. A display listing
            // skips it: every mutation re-checks the version under the lock
            // (#354).
            if metadata.verify_sidecar && sidecar_version != self::sidecar_version(&sidecar_path) {
                continue;
            }

            let mut info = match parser.parse(&content) {
                Some(i) => i,
                None => continue,
            };
            seen_ids.insert(raw_stem.clone());

            // Spec: topdir trash may store relative paths. Resolve to absolute
            // using the topdir (parent of the trash directory).
            if !info.original_path.is_absolute() {
                let topdir = Self::topdir_for_trash(trash_dir);
                info.original_path = topdir.join(&info.original_path);
            }

            // Apply pattern filter
            if let Some(pat) = pattern {
                let name = info
                    .original_path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if !simple_glob_match(pat, &name)
                    && !simple_glob_match(pat, &info.original_path.to_string_lossy())
                {
                    continue;
                }
            }

            // Info-level prefilter: skip the data stat (and identity) for
            // entries the caller will discard anyway (e.g. too young for
            // an age-based purge). seen_ids was already updated above, so
            // orphan detection is unaffected.
            if let Some(filter) = info_filter
                && !filter(&info)
            {
                continue;
            }

            let trashed_path = files_dir.join(&raw_stem);
            let data_metadata = read_files.as_ref().and_then(|read_files| {
                self.scanned_data_metadata(&read_files.join(&raw_stem), metadata)
            });
            let identity = data_metadata
                .as_ref()
                .map(|metadata| (metadata.dev(), metadata.ino()));
            visitor(
                TrashEntry {
                    identity,
                    sidecar_version,
                    id,
                    info,
                    trashed_path,
                    info_path,
                    trash_root: trash_dir.to_path_buf(),
                    orphaned: false,
                },
                data_metadata,
            );
        }

        #[cfg(test)]
        if let Some(hook) = self.between_scan_passes.borrow_mut().take() {
            hook();
        }

        // Spec: "If info file corresponding to file in $trash/files is unavailable,
        // this is emergency case and MUST be presented as such."
        // Scan files/ for entries without matching .trashinfo.
        if let Some(read_files) = read_files.as_ref().filter(|read_files| read_files.exists()) {
            let known_ids = seen_ids;
            if let Ok(file_entries) = fs::read_dir(read_files) {
                for fe in file_entries.flatten() {
                    let raw_name = fe.file_name();
                    if let Some(id) = only_id
                        && raw_name != id
                    {
                        continue;
                    }
                    if !known_ids.contains(&raw_name) {
                        let name = raw_name.to_string_lossy().into_owned();
                        // Apply pattern filter to orphans too
                        if let Some(pat) = pattern
                            && !simple_glob_match(pat, &name)
                        {
                            continue;
                        }
                        // Real on-disk paths in raw bytes (#247); reads go
                        // through the (pinned) directories.
                        let trashed_path = files_dir.join(&raw_name);
                        let data_path = fe.path();
                        let mut raw_info_name = raw_name.clone();
                        raw_info_name.push(".trashinfo");
                        let info_path = info_dir.join(&raw_info_name);
                        let sidecar_path = read_info
                            .as_ref()
                            .map(|read_info| read_info.join(&raw_info_name));
                        // Writers publish the sidecar before the data, so one
                        // created after the info/ pass read past it (or
                        // rewritten while it was read) parses now: the entry
                        // is live, never an orphan (store-metadata-1). One
                        // that cannot be parsed is still listed.
                        if sidecar_path.as_deref().is_some_and(sidecar_parses) {
                            continue;
                        }
                        let data_metadata = self.scanned_data_metadata(&data_path, metadata);
                        let identity = data_metadata
                            .as_ref()
                            .map(|metadata| (metadata.dev(), metadata.ino()));
                        // An orphan's true deletion time is unknowable without
                        // its sidecar, but a synthetic "now" would make it age
                        // zero forever and never expire by retention (#404).
                        // Age it from when the data arrived in files/: rename
                        // and the cross-device copy both set its ctime. Its
                        // mtime alone (the last content edit) made an old file
                        // trashed just now look long deleted, and retention
                        // purged it (store-metadata-1, store-core-5). Stat
                        // even display scans here: orphans are the spec's
                        // emergency case, and one stat per orphan keeps aging
                        // correct.
                        let arrived = data_metadata
                            .clone()
                            .or_else(|| fs::symlink_metadata(&data_path).ok())
                            .and_then(|metadata| {
                                let changed = chrono::DateTime::from_timestamp(
                                    metadata.ctime(),
                                    metadata.ctime_nsec() as u32,
                                );
                                let modified = metadata
                                    .modified()
                                    .ok()
                                    .map(chrono::DateTime::<chrono::Utc>::from);
                                changed.max(modified)
                            })
                            .map(|time| time.with_timezone(&chrono::Local));
                        let info = if let Some(deletion_date) = arrived {
                            TrashInfo {
                                original_path: PathBuf::from(format!("(orphaned: {name})")),
                                deletion_date,
                                command: None,
                                pid: None,
                                size: None,
                                sha256: None,
                                compressed: None,
                                deletion_ns: None,
                            }
                        } else {
                            TrashInfo::new(PathBuf::from(format!("(orphaned: {name})")))
                        };
                        if let Some(filter) = info_filter
                            && !filter(&info)
                        {
                            continue;
                        }
                        visitor(
                            TrashEntry {
                                identity,
                                sidecar_version: sidecar_path.as_deref().and_then(sidecar_snapshot),
                                id: name.clone(),
                                info,
                                trashed_path,
                                info_path,
                                trash_root: trash_dir.to_path_buf(),
                                orphaned: true,
                            },
                            data_metadata,
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// The selector (trashed path) of the entry whose original file name is
    /// exactly `raw`. IDs are built from lossy names, so a non-UTF-8 name
    /// must never reach ID matching through a lossy conversion: it matched
    /// another entry's ID exactly, and purge deleted the wrong file (#209).
    pub fn selector_for_raw_name(&self, raw: &OsStr) -> Result<String, TrashError> {
        let entries = self.list(None)?;
        let matching: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| e.info.original_path.file_name() == Some(raw))
            .collect();
        let lossy = raw.to_string_lossy().into_owned();
        match matching.as_slice() {
            [entry] => entry
                .trashed_path
                .to_str()
                .map(str::to_owned)
                .ok_or(TrashError::EntryNotFound(lossy)),
            [] => Err(TrashError::EntryNotFound(lossy)),
            _ => Err(TrashError::AmbiguousMatch {
                pattern: lossy,
                count: matching.len(),
            }),
        }
    }

    /// Resolve a trash entry by exact ID (or filename fallback), refusing
    /// ambiguity when the same ID exists in more than one trash root — the
    /// same resolution rules restore/purge apply, so `trash info` can never
    /// describe a different copy than the one restore would publish (#148).
    pub fn find_entry(&self, id_or_pattern: &str) -> Result<TrashEntry, TrashError> {
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(dir, _)| dir)
            .collect();
        self.find_entry_in_roots(&roots, id_or_pattern)
    }

    /// Resolve a command's selector once, retaining the snapshots needed for
    /// ambiguity output and mutation. Raw names never pass through lossy IDs.
    /// With `every_copy`, exact IDs include every original-filename copy and
    /// the glob fallback also matches complete original paths (restore --all).
    pub fn select_entries(
        &self,
        selector: &OsStr,
        every_copy: bool,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        if let Some(selector) = selector.to_str() {
            return self.select_utf8_in_roots(&roots, selector, every_copy, every_copy);
        }
        let mut entries = Vec::new();
        self.list_roots(&roots, None, &mut entries)?;
        newest_first(&mut entries);
        if Path::new(selector).is_absolute()
            && let Some(entry) = entries
                .iter()
                .find(|entry| entry.trashed_path == Path::new(selector))
        {
            return Ok(Some((MatchTier::TrashedPath, vec![entry.clone()])));
        }
        entries.retain(|entry| entry.info.original_path.file_name() == Some(selector));
        Ok((!entries.is_empty()).then_some((MatchTier::FileName, entries)))
    }

    pub(super) fn find_entry_in_roots(
        &self,
        roots: &[PathBuf],
        selector: &str,
    ) -> Result<TrashEntry, TrashError> {
        match self.select_utf8_in_roots(roots, selector, false, false)? {
            Some((_, mut entries)) if entries.len() == 1 => Ok(entries.remove(0)),
            Some((_, entries)) => Err(TrashError::AmbiguousMatch {
                pattern: selector.into(),
                count: entries.len(),
            }),
            None => Err(TrashError::EntryNotFound(selector.into())),
        }
    }

    fn select_utf8_in_roots(
        &self,
        roots: &[PathBuf],
        id_or_pattern: &str,
        every_copy: bool,
        original_path_glob: bool,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        let selector = Path::new(id_or_pattern);
        // Replacement characters may stand for multiple non-UTF-8 raw names.
        // Filename/glob fallbacks also need the complete listing. Ordinary
        // exact IDs and selectors within a known files/ directory can filter
        // raw names before reading sidecars, without changing their snapshots.
        let ordinary_leaf = |name: &str| {
            !name.is_empty()
                && name != "."
                && name != ".."
                && !name.contains(['/', '\0', '\u{fffd}', '*', '?', '[', ']'])
        };
        let only_id = if ordinary_leaf(id_or_pattern) {
            Some(OsStr::new(id_or_pattern))
        } else if selector.is_absolute()
            && roots
                .iter()
                .any(|root| selector.parent() == Some(root.join("files").as_path()))
        {
            selector
                .file_name()
                .filter(|name| name.to_str().is_some_and(ordinary_leaf))
        } else {
            None
        };

        if let Some(id) = only_id.filter(|_| !every_copy) {
            let mut entries = Vec::new();
            let warnings = self.visit_roots_for_id(
                roots,
                None,
                Some(id),
                ScanMetadata::MUTATION,
                &mut |entry, _| entries.push(entry),
            )?;
            let matched = if selector.is_absolute() {
                entries.iter().any(|entry| entry.trashed_path == selector)
            } else {
                entries.iter().any(|entry| entry.id == id_or_pattern)
            };
            if matched {
                for (root, error) in warnings {
                    Self::warn_unreadable_root(&root, error);
                }
                newest_first(&mut entries);
                return Ok(Self::selected_entries(entries, id_or_pattern, false, false));
            }
        }

        let mut entries = Vec::new();
        self.list_roots(roots, None, &mut entries)?;
        newest_first(&mut entries);
        Ok(Self::selected_entries(
            entries,
            id_or_pattern,
            every_copy,
            original_path_glob,
        ))
    }

    #[cfg(test)]
    pub(super) fn resolve_listed_entry(
        entries: &[TrashEntry],
        id_or_pattern: &str,
    ) -> Result<TrashEntry, TrashError> {
        match Self::matching_tier(entries, id_or_pattern, false) {
            Some((_, matches)) if matches.len() == 1 => Ok(matches[0].clone()),
            Some((_, matches)) => Err(TrashError::AmbiguousMatch {
                pattern: id_or_pattern.into(),
                count: matches.len(),
            }),
            None => Err(TrashError::EntryNotFound(id_or_pattern.into())),
        }
    }

    /// The entries a selector names, by the same tiers `find_entry` uses:
    /// for reporting an ambiguous selector, and for acting on all of them.
    /// Listing the selector as a glob instead named other entries whenever
    /// an exact name contained glob syntax (`a[1].txt` -> `a1.txt`, #328).
    pub fn matching_entries(
        &self,
        id_or_pattern: &str,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        self.matching_entries_with(id_or_pattern, false)
    }

    /// The entries `--all` acts on: those of `matching_entries`, except that
    /// an exact ID also selects every entry trashed under that file name
    /// (`foo`, `foo.2`, `foo.3`). The ID tier alone restored one of three
    /// copies that listing the name had selected (#340).
    pub fn matching_entries_all(
        &self,
        id_or_pattern: &str,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        self.matching_entries_with(id_or_pattern, true)
    }

    fn matching_entries_with(
        &self,
        id_or_pattern: &str,
        every_copy: bool,
    ) -> Result<Option<(MatchTier, Vec<TrashEntry>)>, TrashError> {
        let roots: Vec<PathBuf> = self
            .all_trash_dirs()
            .into_iter()
            .map(|(root, _)| root)
            .collect();
        self.select_utf8_in_roots(&roots, id_or_pattern, every_copy, false)
    }

    fn selected_entries(
        entries: Vec<TrashEntry>,
        selector: &str,
        every_copy: bool,
        original_path_glob: bool,
    ) -> Option<(MatchTier, Vec<TrashEntry>)> {
        let selected = Self::matching_tier(&entries, selector, every_copy);
        if original_path_glob
            && selected
                .as_ref()
                .is_none_or(|(tier, _)| *tier == MatchTier::Glob)
        {
            let matches = entries
                .iter()
                .filter(|entry| {
                    let name = entry
                        .info
                        .original_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy();
                    if entry.orphaned {
                        simple_glob_match(selector, &entry.id)
                    } else {
                        simple_glob_match(selector, &name)
                            || simple_glob_match(
                                selector,
                                &entry.info.original_path.to_string_lossy(),
                            )
                    }
                })
                .cloned()
                .collect::<Vec<_>>();
            return (!matches.is_empty()).then_some((MatchTier::Glob, matches));
        }
        selected.map(|(tier, matches)| (tier, matches.into_iter().cloned().collect()))
    }

    /// The first selector tier with any match, and its matches. With
    /// `every_copy`, an ID match also takes the file-name matches.
    fn matching_tier<'a>(
        entries: &'a [TrashEntry],
        id_or_pattern: &str,
        every_copy: bool,
    ) -> Option<(MatchTier, Vec<&'a TrashEntry>)> {
        // An entry's trashed path is unique even when two roots hold the
        // same ID, so it selects exactly one entry (#210).
        if id_or_pattern.starts_with('/')
            && let Some(entry) = entries
                .iter()
                .find(|e| e.trashed_path == Path::new(id_or_pattern))
        {
            return Some((MatchTier::TrashedPath, vec![entry]));
        }

        // Exact ID match. IDs are unique WITHIN one trash dir, but two
        // partitions can hold entries with the same ID (same filename trashed
        // on two mounts); picking either nondeterministically could restore
        // or purge the WRONG copy (#41). Distinct raw names can also share a
        // lossy display ID inside one root: an ID must select exactly one
        // entry before a restore or purge acts on it.
        let file_name = |e: &TrashEntry| {
            e.info
                .original_path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default()
        };
        if entries.iter().any(|e| e.id == id_or_pattern) {
            let exact: Vec<&TrashEntry> = entries
                .iter()
                .filter(|e| e.id == id_or_pattern || (every_copy && file_name(e) == id_or_pattern))
                .collect();
            return Some((MatchTier::Id, exact));
        }

        let filename_matches: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| file_name(e) == id_or_pattern)
            .collect();
        if !filename_matches.is_empty() {
            return Some((MatchTier::FileName, filename_matches));
        }

        let glob_matches: Vec<&TrashEntry> = entries
            .iter()
            .filter(|e| simple_glob_match(id_or_pattern, &file_name(e)))
            .collect();
        (!glob_matches.is_empty()).then_some((MatchTier::Glob, glob_matches))
    }
}

/// Newest first, by the instant of deletion (`deletion_instant`).
/// DeletionDate has one-second precision, so entries trashed within one
/// second kept directory-listing (hash) order and `undo` picked an arbitrary
/// one (#329). The recorded nanosecond deletion stamp orders them, or for
/// older entries the sidecar's mtime from when it was published: the
/// filesystem's coarse clock can tie those (#345).
pub(super) fn newest_first(entries: &mut [TrashEntry]) {
    entries.sort_by_key(|entry| {
        let published = entry.sidecar_version.map(|version| {
            i128::from(version.modified.0) * 1_000_000_000 + i128::from(version.modified.1)
        });
        std::cmp::Reverse((deletion_instant(&entry.info), published))
    });
}

/// When an entry was deleted, in nanoseconds since the epoch: the instant
/// `X-Trashd-DeletedNs` records, where there is one. DeletionDate is local
/// time without an offset, so read back after the system's time zone
/// changed, or inside the hour a DST fall-back repeats, it names another
/// instant; ordered by it first, with the stamp only breaking ties, `undo`
/// restored an entry that was not the last one deleted (store-metadata-7).
/// The stamp counts only close to the date it was written with (zones are
/// at most 26 hours apart): a sidecar whose date another tool rewrote, or a
/// forged stamp, is ordered by its date, as an entry without a stamp is.
fn deletion_instant(info: &TrashInfo) -> i128 {
    const SECOND: i128 = 1_000_000_000;
    const ZONE_SPREAD: i128 = 26 * 60 * 60 * SECOND;
    let dated = i128::from(info.deletion_date.timestamp()) * SECOND;
    match info.deletion_ns.map(i128::from) {
        // The date drops the stamp's fraction of a second.
        Some(stamp) if (stamp - dated).abs() <= ZONE_SPREAD + SECOND => stamp,
        _ => dated,
    }
}

/// A topdir root's files/ and info/, each opened following no symlink (in
/// the root or the child) and checked to be on the root's device, for an
/// unlocked listing (security-1). A missing child is None, as a missing
/// path was.
struct PinnedStoreDirs {
    files: Option<fs::File>,
    info: Option<fs::File>,
}

impl PinnedStoreDirs {
    fn open(root: &Path) -> Result<Self, TrashError> {
        let child = |name: &CStr| match open_store_child(root, name) {
            Ok(dir) => Ok(Some(dir)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(TrashError::Io(e)),
        };
        Ok(Self {
            files: child(c"files")?,
            info: child(c"info")?,
        })
    }

    /// The pinned directory's own `/proc/self/fd` path: every lookup below
    /// it starts at the pinned inode, never at a name.
    fn view(dir: &Option<fs::File>) -> Option<PathBuf> {
        dir.as_ref()
            .map(|dir| PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd())))
    }

    fn files_view(&self) -> Option<PathBuf> {
        Self::view(&self.files)
    }

    fn info_view(&self) -> Option<PathBuf> {
        Self::view(&self.info)
    }
}
