# tamper_log.py
import sqlite3
import time
from typing import Optional
from log_store import compute_hash


def add_log_entry(db_path: str, event_type: str, description: str) -> int:
    """Add a new tamper‑evident log entry at the end of the chain."""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Get last entry (if any) to chain its hash
    cur.execute("SELECT id, this_hash FROM log_entries ORDER BY id DESC LIMIT 1")
    last = cur.fetchone()
    prev_hash: Optional[str] = last[1] if last else None

    # Build entry data (no id yet)
    entry_data = {
        "timestamp": timestamp,
        "event_type": event_type,
        "description": description,
        "prev_hash": prev_hash,
    }
    this_hash = compute_hash(entry_data)
    entry_data["this_hash"] = this_hash

    # Insert into DB
    cur.execute(
        """
        INSERT INTO log_entries
            (timestamp, event_type, description, prev_hash, this_hash)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            entry_data["timestamp"],
            entry_data["event_type"],
            entry_data["description"],
            entry_data["prev_hash"],
            entry_data["this_hash"],
        ),
    )
    new_id = cur.lastrowid
    conn.commit()
    conn.close()

    print(f"[+] Logged entry #{new_id} with hash {this_hash[:12]}...")
    return new_id


def verify_log_chain(db_path: str) -> (bool, list[int]):
    """Verify entire log chain; returns (is_ok, list of suspect IDs)."""
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute(
        """SELECT id, timestamp, event_type, description, prev_hash, this_hash
           FROM log_entries ORDER BY id"""
    )
    rows = cur.fetchall()
    conn.close()

    valid = True
    tampered_ids = []

    expected_prev_hash = None

    for row in rows:
        id_, timestamp, event_type, desc, prev_hash_db, this_hash_db = row
        entry_data = {
            "timestamp": timestamp,
            "event_type": event_type,
            "description": desc,
            "prev_hash": prev_hash_db,
        }

        # Recompute expected hash
        expected_this_hash = compute_hash(entry_data)

        # Check chain linkage
        if expected_prev_hash is not None and expected_prev_hash != prev_hash_db:
            print(f"[!] Tampering detected at id={id_}: prev_hash mismatch")
            valid = False
            tampered_ids.append(id_)

        # Check own hash
        if expected_this_hash != this_hash_db:
            print(f"[!] Tampering detected at id={id_}: this_hash mismatch")
            valid = False
            tampered_ids.append(id_)

        expected_prev_hash = this_hash_db

    return valid, tampered_ids
