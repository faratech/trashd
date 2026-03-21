use crate::trashinfo::TrashInfo;
use rusqlite::{params, Connection};
use std::path::Path;

/// SQLite index for fast trash lookups.
pub struct TrashIndex {
    conn: Connection,
}

impl TrashIndex {
    pub fn open(path: &Path) -> Result<Self, rusqlite::Error> {
        let conn = Connection::open(path)?;
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

    /// Drop all entries and rebuild from the provided list.
    pub fn rebuild(
        &self,
        entries: &[(String, TrashInfo, std::path::PathBuf)],
    ) -> Result<usize, rusqlite::Error> {
        self.conn.execute("DELETE FROM trash_entries", [])?;
        let mut count = 0;
        for (id, info, trash_dir) in entries {
            self.insert(id, info, trash_dir)?;
            count += 1;
        }
        Ok(count)
    }
}
