"""
kx -- Diff Engine
SQLite-backed scan state. Compares current findings against previous scan.
Surfaces new JS files discovered and new findings since last run.
"""

import sqlite3
import json
import hashlib
import time
from pathlib import Path
from typing import Optional

from extractor import Finding

DEFAULT_DB = Path.home() / ".kx" / "state.db"
# Legacy path from when the tool was called wraith. Migrated on first run
# so users upgrading don't lose their scan history.
_LEGACY_DB = Path.home() / ".wraith" / "state.db"


def _fingerprint(f: Finding) -> str:
    key = f"{f.source_url}|{f.name}|{f.match[:80]}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _migrate_legacy_db_once():
    """If the old ~/.wraith/state.db exists and the new one doesn't, move it.

    Operator runs the same diff history without losing prior scans. We move
    (not copy) so we don't leave two copies drifting apart on subsequent
    scans, and we only do it once -- if the new path exists, hands off.
    """
    try:
        if _LEGACY_DB.exists() and not DEFAULT_DB.exists():
            DEFAULT_DB.parent.mkdir(parents=True, exist_ok=True)
            _LEGACY_DB.rename(DEFAULT_DB)
    except Exception:
        # Migration is a courtesy; never fatal.
        pass


class DiffEngine:
    def __init__(self, db_path: Path | str | None = None):
        if db_path is None:
            _migrate_legacy_db_once()
        self.db_path = Path(db_path) if db_path else DEFAULT_DB
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self):
        self._conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            target      TEXT NOT NULL,
            started_at  INTEGER NOT NULL,
            finished_at INTEGER,
            js_count    INTEGER DEFAULT 0,
            finding_count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS js_files (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            url         TEXT NOT NULL,
            first_seen  INTEGER NOT NULL,
            UNIQUE(scan_id, url)
        );

        CREATE TABLE IF NOT EXISTS findings (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id     INTEGER NOT NULL,
            fingerprint TEXT NOT NULL,
            source_url  TEXT NOT NULL,
            category    TEXT NOT NULL,
            name        TEXT NOT NULL,
            severity    TEXT NOT NULL,
            context     TEXT,
            match       TEXT,
            line        INTEGER,
            confidence  TEXT,
            first_seen  INTEGER NOT NULL,
            UNIQUE(scan_id, fingerprint)
        );
        """)
        self._conn.commit()

    # ── scan lifecycle ──────────────────────────────────────────────────

    def start_scan(self, target: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO scans (target, started_at) VALUES (?, ?)",
            (target, int(time.time())),
        )
        self._conn.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id: int, js_count: int, finding_count: int):
        self._conn.execute(
            "UPDATE scans SET finished_at=?, js_count=?, finding_count=? WHERE id=?",
            (int(time.time()), js_count, finding_count, scan_id),
        )
        self._conn.commit()

    def _last_scan_id(self, target: str, current_id: int) -> int | None:
        row = self._conn.execute(
            """SELECT id FROM scans
               WHERE target=? AND id != ? AND finished_at IS NOT NULL
               ORDER BY started_at DESC LIMIT 1""",
            (target, current_id),
        ).fetchone()
        return row[0] if row else None

    # ── recording ──────────────────────────────────────────────────────

    def record_js_files(self, scan_id: int, urls: list[str]):
        now = int(time.time())
        self._conn.executemany(
            "INSERT OR IGNORE INTO js_files (scan_id, url, first_seen) VALUES (?, ?, ?)",
            [(scan_id, url, now) for url in urls],
        )
        self._conn.commit()

    def record_findings(self, scan_id: int, findings: list[Finding]):
        now = int(time.time())
        rows = []
        for f in findings:
            fp = _fingerprint(f)
            rows.append((
                scan_id, fp, f.source_url, f.category,
                f.name, f.severity, f.context, f.match[:500],
                f.line, f.confidence, now,
            ))
        self._conn.executemany(
            """INSERT OR IGNORE INTO findings
               (scan_id, fingerprint, source_url, category, name,
                severity, context, match, line, confidence, first_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            rows,
        )
        self._conn.commit()

    # ── diffing ────────────────────────────────────────────────────────

    def diff(
        self,
        target: str,
        current_scan_id: int,
        current_findings: list[Finding],
        current_js_urls: list[str],
    ) -> dict:
        """
        Compare current scan against the previous finished scan.
        Returns a dict with new_findings, new_js_files, removed_js_files.
        """
        last_id = self._last_scan_id(target, current_scan_id)
        if last_id is None:
            return {
                "is_first_scan": True,
                "new_findings": current_findings,
                "new_js_files": current_js_urls,
                "removed_js_files": [],
            }

        # Previous fingerprints
        prev_fps = {
            row[0] for row in self._conn.execute(
                "SELECT fingerprint FROM findings WHERE scan_id=?", (last_id,)
            )
        }
        prev_js = {
            row[0] for row in self._conn.execute(
                "SELECT url FROM js_files WHERE scan_id=?", (last_id,)
            )
        }

        # Current fingerprints
        curr_fps = {_fingerprint(f) for f in current_findings}
        curr_js = set(current_js_urls)

        new_findings = [f for f in current_findings if _fingerprint(f) not in prev_fps]
        new_js = list(curr_js - prev_js)
        removed_js = list(prev_js - curr_js)

        return {
            "is_first_scan": False,
            "new_findings": new_findings,
            "new_js_files": new_js,
            "removed_js_files": removed_js,
        }

    def history(self, target: str, limit: int = 20) -> list[dict]:
        """
        Return previous scan rows for the same target, newest first.

        Used by the REPL's `history` command to let an operator see what
        they've already scanned and how findings counts have moved.
        """
        rows = self._conn.execute(
            """SELECT id, target, started_at, finished_at, js_count, finding_count
               FROM scans WHERE target=? ORDER BY started_at DESC LIMIT ?""",
            (target, limit),
        ).fetchall()
        return [
            {
                "id":            r[0],
                "target":        r[1],
                "started_at":    r[2],
                "finished_at":   r[3],
                "js_count":      r[4],
                "finding_count": r[5],
            }
            for r in rows
        ]

    def close(self):
        self._conn.close()
