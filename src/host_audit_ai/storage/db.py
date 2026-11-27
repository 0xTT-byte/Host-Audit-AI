"""SQLite persistence layer for host audit runs, snapshots, findings, and triage."""

from __future__ import annotations

import hashlib
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from host_audit_ai.models.report import AuditReport, RunRecord
from host_audit_ai.models.snapshot import HostSnapshot
from host_audit_ai.models.triage import TriageReport

SCHEMA_VERSION = 1


def resolve_db_path(db_path: Path | str | None = None) -> Path:
    """Resolve SQLite database path with deterministic precedence.

    Precedence:
      1. explicit db_path argument
      2. HOST_AUDIT_DB environment variable
      3. $XDG_DATA_HOME/host-audit-ai/audit.db
      4. ~/.local/share/host-audit-ai/audit.db
    """
    if db_path is not None:
        return Path(db_path).expanduser()

    env_db = os.environ.get("HOST_AUDIT_DB", "").strip()
    if env_db:
        return Path(env_db).expanduser()

    xdg_data = os.environ.get("XDG_DATA_HOME", "").strip()
    base_dir = Path(xdg_data).expanduser() if xdg_data else Path.home() / ".local" / "share"
    return base_dir / "host-audit-ai" / "audit.db"


class AuditStore:
    """SQLite-backed store for HostSnapshot, AuditReport, ExposureChain, and TriageReport."""

    def __init__(self, db_path: Path | str | None = None) -> None:
        self.db_path = resolve_db_path(db_path)

        db_existed = self.db_path.exists()
        missing_dirs: list[Path] = []
        cur = self.db_path.parent
        while not cur.exists():
            missing_dirs.append(cur)
            if cur.parent == cur:
                break
            cur = cur.parent

        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            for created_dir in missing_dirs:
                os.chmod(created_dir, 0o700)

        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row

        if not db_existed and os.name == "posix" and self.db_path.exists():
            os.chmod(self.db_path, 0o600)

        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.execute("PRAGMA journal_mode = WAL")
        self.init_schema()

    def init_schema(self) -> None:
        """Create and migrate SQLite schema idempotently using PRAGMA user_version."""
        row = self.conn.execute("PRAGMA user_version").fetchone()
        current_version = int(row[0]) if row is not None else 0

        if current_version < 1:
            self._migrate_to_v1()
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.conn.commit()

    def _migrate_to_v1(self) -> None:
        self.conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS hosts (
                host_id TEXT PRIMARY KEY,
                hostname TEXT NOT NULL,
                os_name TEXT,
                os_version TEXT,
                arch TEXT,
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                host_id TEXT NOT NULL REFERENCES hosts(host_id),
                hostname TEXT NOT NULL,
                created_at TEXT NOT NULL,
                baseline_name TEXT NOT NULL,
                degraded_mode INTEGER NOT NULL,
                snapshot_hash TEXT NOT NULL,
                total_findings INTEGER NOT NULL,
                exposure_chain_count INTEGER NOT NULL,
                report_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                run_id TEXT PRIMARY KEY REFERENCES runs(run_id) ON DELETE CASCADE,
                snapshot_hash TEXT NOT NULL,
                snapshot_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                fingerprint TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                target TEXT NOT NULL,
                drift_status TEXT,
                waiver_reason TEXT,
                finding_json TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_findings_run_fp
                ON findings (run_id, fingerprint);
            CREATE INDEX IF NOT EXISTS idx_findings_fp
                ON findings (fingerprint);

            CREATE TABLE IF NOT EXISTS exposure_chains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                chain_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                chain_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS triage_runs (
                triage_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                llm_model TEXT NOT NULL,
                created_at TEXT NOT NULL,
                triage_json TEXT NOT NULL
            );
            """
        )

    def _resolve_unique_run_id(self, report: AuditReport, created_iso: str) -> str:
        existing = self.conn.execute(
            "SELECT created_at FROM runs WHERE run_id = ?",
            (report.run_id,),
        ).fetchone()
        if existing is None or str(existing["created_at"]) == created_iso:
            return report.run_id

        suffix = 2
        while True:
            candidate = f"{report.run_id}-{suffix}"
            row = self.conn.execute(
                "SELECT created_at FROM runs WHERE run_id = ?",
                (candidate,),
            ).fetchone()
            if row is None:
                return candidate
            suffix += 1

    def save_run(self, report: AuditReport, snapshot: HostSnapshot | None = None) -> str:
        """Persist an AuditReport and optional HostSnapshot atomically."""
        created_iso = report.created_at.astimezone(UTC).isoformat()
        actual_run_id = self._resolve_unique_run_id(report, created_iso)
        persisted_report = (
            report
            if actual_run_id == report.run_id
            else report.model_copy(update={"run_id": actual_run_id})
        )

        os_name = snapshot.metadata.os_name if snapshot else None
        os_version = snapshot.metadata.os_version if snapshot else None
        arch = snapshot.metadata.architecture if snapshot else None

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO hosts (
                    host_id, hostname, os_name, os_version, arch, first_seen_at, last_seen_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(host_id) DO UPDATE SET
                    hostname = excluded.hostname,
                    os_name = COALESCE(excluded.os_name, hosts.os_name),
                    os_version = COALESCE(excluded.os_version, hosts.os_version),
                    arch = COALESCE(excluded.arch, hosts.arch),
                    last_seen_at = CASE
                        WHEN excluded.last_seen_at > hosts.last_seen_at
                        THEN excluded.last_seen_at
                        ELSE hosts.last_seen_at
                    END
                """,
                (
                    persisted_report.host_id,
                    persisted_report.hostname,
                    os_name,
                    os_version,
                    arch,
                    created_iso,
                    created_iso,
                ),
            )

            self.conn.execute(
                """
                INSERT OR REPLACE INTO runs (
                    run_id, host_id, hostname, created_at, baseline_name,
                    degraded_mode, snapshot_hash, total_findings,
                    exposure_chain_count, report_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    persisted_report.run_id,
                    persisted_report.host_id,
                    persisted_report.hostname,
                    created_iso,
                    persisted_report.baseline_name,
                    int(persisted_report.degraded_mode),
                    persisted_report.snapshot_hash,
                    persisted_report.summary.total_findings,
                    persisted_report.summary.exposure_chain_count,
                    persisted_report.model_dump_json(),
                ),
            )

            if snapshot is not None:
                self.conn.execute(
                    """
                    INSERT OR REPLACE INTO snapshots (run_id, snapshot_hash, snapshot_json)
                    VALUES (?, ?, ?)
                    """,
                    (
                        persisted_report.run_id,
                        persisted_report.snapshot_hash,
                        snapshot.model_dump_json(),
                    ),
                )

            self.conn.execute(
                "DELETE FROM findings WHERE run_id = ?",
                (persisted_report.run_id,),
            )
            if persisted_report.findings:
                self.conn.executemany(
                    """
                    INSERT INTO findings (
                        run_id, fingerprint, rule_id, severity, category,
                        target, drift_status, waiver_reason, finding_json
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            persisted_report.run_id,
                            f.fingerprint,
                            f.rule_id,
                            f.severity.value,
                            f.category,
                            f.target,
                            f.drift_status.value if f.drift_status is not None else None,
                            f.waiver_reason,
                            f.model_dump_json(),
                        )
                        for f in persisted_report.findings
                    ],
                )

            self.conn.execute(
                "DELETE FROM exposure_chains WHERE run_id = ?",
                (persisted_report.run_id,),
            )
            if persisted_report.exposure_chains:
                self.conn.executemany(
                    """
                    INSERT INTO exposure_chains (
                        run_id, chain_id, severity, title, chain_json
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            persisted_report.run_id,
                            c.chain_id,
                            c.severity.value,
                            c.title,
                            c.model_dump_json(),
                        )
                        for c in persisted_report.exposure_chains
                    ],
                )

        return persisted_report.run_id

    def get_run(self, run_id: str) -> AuditReport | None:
        """Retrieve a persisted AuditReport by run_id."""
        row = self.conn.execute(
            "SELECT report_json FROM runs WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return AuditReport.model_validate_json(str(row["report_json"]))

    def get_snapshot(self, run_id: str) -> HostSnapshot | None:
        """Retrieve a persisted HostSnapshot by run_id."""
        row = self.conn.execute(
            "SELECT snapshot_json FROM snapshots WHERE run_id = ?",
            (run_id,),
        ).fetchone()
        if row is None:
            return None
        return HostSnapshot.model_validate_json(str(row["snapshot_json"]))

    def list_runs(self, hostname: str | None = None, limit: int = 20) -> list[RunRecord]:
        """List persisted audit runs ordered newest-first."""
        if hostname is not None:
            rows = self.conn.execute(
                """
                SELECT run_id, host_id, hostname, created_at, baseline_name,
                       degraded_mode, snapshot_hash, total_findings, exposure_chain_count
                FROM runs
                WHERE hostname = ? OR host_id = ?
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (hostname, hostname, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT run_id, host_id, hostname, created_at, baseline_name,
                       degraded_mode, snapshot_hash, total_findings, exposure_chain_count
                FROM runs
                ORDER BY created_at DESC, rowid DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()

        return [
            RunRecord(
                run_id=str(r["run_id"]),
                host_id=str(r["host_id"]),
                hostname=str(r["hostname"]),
                created_at=datetime.fromisoformat(str(r["created_at"])),
                baseline_name=str(r["baseline_name"]),
                degraded_mode=bool(r["degraded_mode"]),
                snapshot_hash=str(r["snapshot_hash"]),
                total_findings=int(r["total_findings"]),
                exposure_chain_count=int(r["exposure_chain_count"]),
            )
            for r in rows
        ]

    def get_latest_runs_for_host(
        self, hostname_or_host_id: str, limit: int = 2
    ) -> list[AuditReport]:
        """Return up to `limit` latest AuditReports for a host, newest first."""
        rows = self.conn.execute(
            """
            SELECT report_json
            FROM runs
            WHERE hostname = ? OR host_id = ?
            ORDER BY created_at DESC, rowid DESC
            LIMIT ?
            """,
            (hostname_or_host_id, hostname_or_host_id, limit),
        ).fetchall()
        return [AuditReport.model_validate_json(str(r["report_json"])) for r in rows]

    def get_historical_fingerprints(
        self,
        host_id: str,
        before_created_at: datetime,
        exclude_run_id: str | None = None,
    ) -> set[str]:
        """Return all finding fingerprints seen on a host strictly before a timestamp."""
        before_iso = before_created_at.astimezone(UTC).isoformat()
        if exclude_run_id is not None:
            rows = self.conn.execute(
                """
                SELECT DISTINCT f.fingerprint
                FROM findings f
                JOIN runs r ON f.run_id = r.run_id
                WHERE r.host_id = ? AND r.created_at < ? AND r.run_id != ?
                """,
                (host_id, before_iso, exclude_run_id),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT DISTINCT f.fingerprint
                FROM findings f
                JOIN runs r ON f.run_id = r.run_id
                WHERE r.host_id = ? AND r.created_at < ?
                """,
                (host_id, before_iso),
            ).fetchall()
        return {str(r["fingerprint"]) for r in rows}

    def save_triage(self, report: TriageReport) -> str:
        """Persist a TriageReport linked to an existing run_id."""
        created_iso = report.created_at.astimezone(UTC).isoformat()
        digest = hashlib.sha256(
            f"{report.run_id}|{report.llm_model}|{created_iso}".encode()
        ).hexdigest()
        triage_id = f"triage-{digest[:16]}"

        with self.conn:
            self.conn.execute(
                """
                INSERT OR REPLACE INTO triage_runs (
                    triage_id, run_id, llm_model, created_at, triage_json
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    triage_id,
                    report.run_id,
                    report.llm_model,
                    created_iso,
                    report.model_dump_json(),
                ),
            )
        return triage_id

    def get_triage_runs(self, run_id: str) -> list[TriageReport]:
        """Retrieve all TriageReports associated with a run_id, newest first."""
        rows = self.conn.execute(
            """
            SELECT triage_json
            FROM triage_runs
            WHERE run_id = ?
            ORDER BY created_at DESC, rowid DESC
            """,
            (run_id,),
        ).fetchall()
        return [TriageReport.model_validate_json(str(r["triage_json"])) for r in rows]

    def close(self) -> None:
        """Close the underlying SQLite connection."""
        self.conn.close()

    def __enter__(self) -> AuditStore:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()
