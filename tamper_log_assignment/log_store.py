# log_store.py
import sqlite3
import hashlib
import json


def create_db(db_path: str):
    """Create the audit log table if it doesn't exist."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS log_entries (
            id INTEGER PRIMARY KEY,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            description TEXT,
            prev_hash TEXT,      -- hash of previous entry
            this_hash TEXT       -- hash of this entry
        )
        """
    )
    conn.commit()
    conn.close()


def compute_hash(entry_data: dict) -> str:
    """Compute SHA‑256 hash of a canonical JSON representation of the entry."""
    sorted_str = json.dumps(entry_data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(sorted_str.encode("utf-8")).hexdigest()
