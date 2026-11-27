import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from host_audit.schema import Finding


class AuditStore:
    def __init__(self, db_path: Path | str):
        self.db_path = Path(db_path)
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        self._init_db()

    def _init_db(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id INTEGER PRIMARY KEY AUTOINCREMENT,
                host TEXT NOT NULL,
                timestamp TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                domain TEXT NOT NULL,
                severity TEXT NOT NULL,
                priority_score INTEGER NOT NULL,
                title TEXT NOT NULL,
                target TEXT NOT NULL,
                evidence TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open'
            );

            CREATE INDEX IF NOT EXISTS idx_findings_host_status ON findings (host, status);
            """
        )
        self.conn.commit()

    def record_run(self, host: str, findings: list[Finding]) -> dict[str, list[Any]]:
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute("INSERT INTO runs (host, timestamp) VALUES (?, ?)", (host, now))

        existing_rows = self.conn.execute(
            "SELECT * FROM findings WHERE host = ? AND status = 'open'", (host,)
        ).fetchall()
        existing_open = {row["finding_id"]: dict(row) for row in existing_rows}

        current_ids: set[str] = set()
        diff: dict[str, list[Any]] = {
            "new": [],
            "persisting": [],
            "resolved_ids": [],
        }

        for f in findings:
            fid = f.finding_id
            current_ids.add(fid)

            if fid in existing_open:
                diff["persisting"].append(f)
                self.conn.execute(
                    """
                    UPDATE findings
                    SET last_seen = ?, priority_score = ?, severity = ?, title = ?, evidence = ?
                    WHERE finding_id = ?
                    """,
                    (now, f.priority_score, f.severity, f.title, f.evidence, fid),
                )
            else:
                diff["new"].append(f)
                # Check if this finding was previously recorded (e.g., reopened)
                prior = self.conn.execute(
                    "SELECT first_seen FROM findings WHERE finding_id = ?", (fid,)
                ).fetchone()
                first_seen = prior["first_seen"] if prior else now

                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO findings
                    (finding_id, host, rule_id, domain, severity, priority_score, title, target, evidence, first_seen, last_seen, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')
                    """,
                    (
                        fid, host, f.rule_id, f.domain, f.severity,
                        f.priority_score, f.title, f.target, f.evidence, first_seen, now,
                    ),
                )

        # Mark findings no longer observed as resolved
        for old_id in existing_open:
            if old_id not in current_ids:
                diff["resolved_ids"].append(old_id)
                self.conn.execute(
                    "UPDATE findings SET status = 'resolved', last_seen = ? WHERE finding_id = ?",
                    (now, old_id),
                )

        self.conn.commit()
        return diff

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "AuditStore":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
