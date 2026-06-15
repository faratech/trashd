use crate::trashinfo::TrashInfo;
use rusqlite::{params, Connection};
use std::path::Path;

/// Index location relative to a trash directory. Shared so every caller
/// (store, fsck rebuild) targets the SAME file and cannot drift.
pub const REL_PATH: &str = ".trashd/index.sqlite";

/// SQLite index for fast trash lookups.
pub struct TrashIndex {
    conn: Connection,
}

impl TrashIndex {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
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
