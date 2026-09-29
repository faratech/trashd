use crate::trashinfo::TrashInfo;
use rusqlite::{Connection, params};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Index location relative to a trash directory. Shared so every caller
/// (store, fsck rebuild) targets the SAME file and cannot drift.
pub const REL_PATH: &str = ".trashd/index.sqlite";

/// SQLite index for fast trash lookups.
pub struct TrashIndex {
    conn: Connection,
}

/// Surface a privacy-setup failure as the same kind of open error SQLite
/// itself would produce, so callers' existing "degrade to no-index" handling
/// keeps working.
fn cantopen(error: &std::io::Error) -> rusqlite::Error {
    rusqlite::Error::SqliteFailure(
        rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_CANTOPEN),
        Some(format!("cannot open trash index privately: {error}")),
    )
}

impl TrashIndex {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        // SQLite creates new database files with the process umask (typically
        // 0644), but the index records original paths and commands — private
        // metadata. Create/repair the file owner-only BEFORE SQLite touches
        // it, matching the .trashinfo sidecars and the operation log (#79).
        // The -wal/-shm side files stay protected by the 0700 trash directory
        // enforced around them.
        let db = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|e| cantopen(&e))?;
        if let Err(e) = db.set_permissions(std::fs::Permissions::from_mode(0o600)) {
            return Err(cantopen(&e));
        }
        drop(db);

        let conn = Connection::open(path)?;
        // A transient lock must never demote a protection layer to real `rm`:
        // wait for the lock instead of returning SQLITE_BUSY immediately.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        // WAL allows a reader and a writer to coexist; ignore if the
        // filesystem (e.g. some network mounts) refuses it.
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS trash_entries (
                id TEXT PRIMARY KEY,
                original_path TEXT NOT NULL,
                deletion_date TEXT NOT NULL,
                command TEXT,
                pid INTEGER,
                size INTEGER,
                sha256 TEXT,
                trash_dir TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_deletion_date ON trash_entries(deletion_date);
            CREATE INDEX IF NOT EXISTS idx_original_path ON trash_entries(original_path);",
        )?;

        // Add trash_dir column if upgrading from older schema
        let has_trash_dir: bool = conn
            .prepare(
                "SELECT COUNT(*) FROM pragma_table_info('trash_entries') WHERE name='trash_dir'",
            )?
            .query_row([], |row| row.get::<_, i64>(0))
            .unwrap_or(0)
            > 0;
        if !has_trash_dir {
            let _ = conn.execute("ALTER TABLE trash_entries ADD COLUMN trash_dir TEXT", []);
        }

        Ok(Self { conn })
    }

    pub fn insert(
        &self,
        id: &str,
        info: &TrashInfo,
        trash_dir: &Path,
    ) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "INSERT OR REPLACE INTO trash_entries (id, original_path, deletion_date, command, pid, size, sha256, trash_dir)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                id,
                info.original_path.to_string_lossy().as_ref(),
                info.deletion_date.format("%Y-%m-%dT%H:%M:%S").to_string(),
                info.command,
                info.pid.map(|p| p as i64),
                info.size.map(|s| s as i64),
                info.sha256,
                trash_dir.to_string_lossy().as_ref(),
            ],
        )?;
        Ok(())
    }

    pub fn delete(&self, id: &str) -> Result<(), rusqlite::Error> {
        self.conn
            .execute("DELETE FROM trash_entries WHERE id = ?1", params![id])?;
        Ok(())
    }

    pub fn delete_in(&self, id: &str, root: &Path) -> Result<(), rusqlite::Error> {
        self.conn.execute(
            "DELETE FROM trash_entries WHERE id = ?1 AND trash_dir = ?2",
            params![id, root.to_string_lossy().as_ref()],
        )?;
        Ok(())
    }

    /// Retire a restored batch with a single commit rather than N fsyncs.
    pub fn delete_many(
        &self,
        entries: &[(String, std::path::PathBuf)],
    ) -> Result<(), rusqlite::Error> {
        if entries.is_empty() {
            return Ok(());
        }
        let tx = self.conn.unchecked_transaction()?;
        for (id, root) in entries {
            self.delete_in(id, root)?;
        }
        tx.commit()
    }

    /// Number of rows currently in the index (test/diagnostic helper).
    #[cfg(test)]
    pub fn count(&self) -> Result<i64, rusqlite::Error> {
        self.conn
            .query_row("SELECT COUNT(*) FROM trash_entries", [], |r| r.get(0))
    }

    /// Drop all entries and rebuild from the provided list.
    pub fn rebuild(
        &self,
        entries: &[(String, TrashInfo, std::path::PathBuf)],
    ) -> Result<usize, rusqlite::Error> {
        // Wrap the whole rebuild in ONE transaction. Otherwise every insert
        // autocommits (and fsyncs) on its own, so recovering an index for a
        // large trash is O(entries) disk syncs instead of one. The transaction
        // rolls back automatically if any step fails (tx dropped without commit).
        let tx = self.conn.unchecked_transaction()?;
        self.conn.execute("DELETE FROM trash_entries", [])?;
        let mut count = 0;
        for (id, info, trash_dir) in entries {
            self.insert(id, info, trash_dir)?;
            count += 1;
        }
        tx.commit()?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trashinfo::TrashInfo;
    use std::path::PathBuf;

    // The database file must be owner-only no matter the ambient umask:
    // SQLite alone would create it 0644 (issue #79).
    #[test]
    fn index_file_is_private_regardless_of_umask() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("idx-mode-test")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("index.sqlite");

        {
            let idx = TrashIndex::open(&db_path).unwrap();
            idx.rebuild(&[(String::from("id"), TrashInfo::new(PathBuf::from("/x")), dir.clone())])
                .unwrap();
        }
        let mode = std::fs::symlink_metadata(&db_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "index must be 0600 (umask {:#o})", get_umask());

        // Reopening repairs an existing too-open file as well.
        std::fs::set_permissions(&db_path, std::fs::Permissions::from_mode(0o666)).unwrap();
        drop(TrashIndex::open(&db_path).unwrap());
        let mode = std::fs::symlink_metadata(&db_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn get_umask() -> u32 {
        // Read-only peek: set a new umask and restore the old one it returns.
        unsafe {
            let old = libc::umask(0o022);
            libc::umask(old);
            old as u32
        }
    }

    // rebuild() must commit every row in one transaction and be idempotent.
    #[test]
    fn rebuild_commits_all_rows() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("idx-test")
            .join(format!("{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let idx = TrashIndex::open(&dir.join("index.sqlite")).unwrap();

        let entries: Vec<(String, TrashInfo, PathBuf)> = (0..50)
            .map(|i| {
                (
                    format!("id{i}"),
                    TrashInfo::new(PathBuf::from(format!("/home/u/file{i}"))),
                    PathBuf::from("/home/u/.local/share/Trash"),
                )
            })
            .collect();

        assert_eq!(idx.rebuild(&entries).unwrap(), 50);
        assert_eq!(idx.count().unwrap(), 50, "all rows must be committed");

        // Re-running replaces the contents (DELETE + reinsert) atomically.
        assert_eq!(idx.rebuild(&entries[..10]).unwrap(), 10);
        assert_eq!(idx.count().unwrap(), 10);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
