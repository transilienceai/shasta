"""SQLite database schema and access for Shasta."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC
from pathlib import Path
from typing import Any

from shasta.evidence.models import Evidence, Finding, ScanResult, ScanSummary

DEFAULT_DB_PATH = Path("data/shasta.db")

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    region TEXT NOT NULL,
    domains_scanned TEXT NOT NULL,  -- JSON array
    started_at TEXT NOT NULL,
    completed_at TEXT,
    summary TEXT  -- JSON
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    check_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL,
    domain TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    region TEXT NOT NULL,
    account_id TEXT NOT NULL,
    remediation TEXT,
    details TEXT,  -- JSON
    soc2_controls TEXT,  -- JSON array
    timestamp TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    finding_id TEXT NOT NULL,
    evidence_type TEXT NOT NULL,
    description TEXT NOT NULL,
    data TEXT,  -- JSON
    collected_at TEXT NOT NULL,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);

CREATE TABLE IF NOT EXISTS risk_items (
    risk_id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    likelihood TEXT NOT NULL,
    impact TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL,
    owner TEXT,
    treatment TEXT NOT NULL,
    treatment_plan TEXT,
    status TEXT NOT NULL,
    soc2_controls TEXT,  -- JSON array
    related_finding TEXT,
    created_date TEXT NOT NULL,
    last_reviewed TEXT NOT NULL,
    review_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_risk_items_account ON risk_items(account_id);
CREATE INDEX IF NOT EXISTS idx_risk_items_status ON risk_items(status);
CREATE INDEX IF NOT EXISTS idx_risk_items_level ON risk_items(risk_level);

CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_domain ON findings(domain);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
"""


class ShastaDB:
    """SQLite database for storing scan results, findings, and evidence."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    @property
    def conn(self) -> sqlite3.Connection:
        if self._conn is None:
            self._conn = sqlite3.connect(str(self._db_path))
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        return self._conn

    def initialize(self) -> None:
        """Create tables if they don't exist."""
        self.conn.executescript(SCHEMA_SQL)
        self._migrate()

    def _migrate(self) -> None:
        """Run schema migrations for new columns."""
        cursor = self.conn.execute("PRAGMA table_info(findings)")
        columns = {row["name"] for row in cursor.fetchall()}
        if "cloud_provider" not in columns:
            self.conn.execute("ALTER TABLE findings ADD COLUMN cloud_provider TEXT DEFAULT 'aws'")
        cursor = self.conn.execute("PRAGMA table_info(scans)")
        columns = {row["name"] for row in cursor.fetchall()}
        if "cloud_provider" not in columns:
            self.conn.execute("ALTER TABLE scans ADD COLUMN cloud_provider TEXT DEFAULT 'aws'")
        self.conn.commit()

    def save_scan(self, scan: ScanResult) -> None:
        """Save a scan result and all its findings."""
        self.conn.execute(
            "INSERT OR REPLACE INTO scans (id, account_id, region, domains_scanned, started_at, completed_at, summary) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan.id,
                scan.account_id,
                scan.region,
                json.dumps([d.value for d in scan.domains_scanned]),
                scan.started_at.isoformat(),
                scan.completed_at.isoformat() if scan.completed_at else None,
                scan.summary.model_dump_json() if scan.summary else None,
            ),
        )

        for finding in scan.findings:
            self._save_finding(scan.id, finding)

        self.conn.commit()

    def _save_finding(self, scan_id: str, finding: Finding) -> None:
        self.conn.execute(
            "INSERT OR REPLACE INTO findings (id, scan_id, check_id, title, description, severity, status, domain, resource_type, resource_id, region, account_id, cloud_provider, remediation, details, soc2_controls, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                finding.id,
                scan_id,
                finding.check_id,
                finding.title,
                finding.description,
                finding.severity.value,
                finding.status.value,
                finding.domain.value,
                finding.resource_type,
                finding.resource_id,
                finding.region,
                finding.account_id,
                finding.cloud_provider.value,
                finding.remediation,
                json.dumps(finding.details),
                json.dumps(finding.soc2_controls),
                finding.timestamp.isoformat(),
            ),
        )

    def save_evidence(self, evidence: Evidence) -> None:
        """Save an evidence artifact."""
        self.conn.execute(
            "INSERT OR REPLACE INTO evidence (id, scan_id, finding_id, evidence_type, description, data, collected_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                evidence.id,
                evidence.scan_id,
                evidence.finding_id,
                evidence.evidence_type,
                evidence.description,
                json.dumps(evidence.data),
                evidence.collected_at.isoformat(),
            ),
        )
        self.conn.commit()

    def get_latest_scan(self, account_id: str | None = None) -> ScanResult | None:
        """Get the most recent scan, optionally filtered by account."""
        query = "SELECT * FROM scans"
        params: list[Any] = []
        if account_id:
            query += " WHERE account_id = ?"
            params.append(account_id)
        query += " ORDER BY started_at DESC LIMIT 1"

        row = self.conn.execute(query, params).fetchone()
        if not row:
            return None

        findings = self._get_findings_for_scan(row["id"])
        return ScanResult(
            id=row["id"],
            account_id=row["account_id"],
            region=row["region"],
            domains_scanned=json.loads(row["domains_scanned"]),
            findings=findings,
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            summary=ScanSummary.model_validate_json(row["summary"]) if row["summary"] else None,
        )

    def _get_findings_for_scan(self, scan_id: str) -> list[Finding]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE scan_id = ? ORDER BY severity, status", (scan_id,)
        ).fetchall()

        findings = []
        for row in rows:
            cloud = row["cloud_provider"] if "cloud_provider" in row.keys() else "aws"
            findings.append(
                Finding(
                    id=row["id"],
                    check_id=row["check_id"],
                    title=row["title"],
                    description=row["description"],
                    severity=row["severity"],
                    status=row["status"],
                    domain=row["domain"],
                    resource_type=row["resource_type"],
                    resource_id=row["resource_id"],
                    region=row["region"],
                    account_id=row["account_id"],
                    cloud_provider=cloud,
                    remediation=row["remediation"],
                    details=json.loads(row["details"]) if row["details"] else {},
                    soc2_controls=json.loads(row["soc2_controls"]) if row["soc2_controls"] else [],
                    timestamp=row["timestamp"],
                )
            )
        return findings

    def get_scan_history(self, account_id: str | None = None, limit: int = 10) -> list[dict]:
        """Get scan history with summaries."""
        query = "SELECT id, account_id, region, started_at, completed_at, summary FROM scans"
        params: list[Any] = []
        if account_id:
            query += " WHERE account_id = ?"
            params.append(account_id)
        query += " ORDER BY started_at DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]

    def save_risk_items(self, items: list, account_id: str) -> None:
        """Save risk register items to the database."""
        for item in items:
            self.conn.execute(
                "INSERT OR REPLACE INTO risk_items (risk_id, account_id, title, description, category, likelihood, impact, risk_score, risk_level, owner, treatment, treatment_plan, status, soc2_controls, related_finding, created_date, last_reviewed, review_notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    item.risk_id,
                    account_id,
                    item.title,
                    item.description,
                    item.category,
                    item.likelihood,
                    item.impact,
                    item.risk_score,
                    item.risk_level,
                    item.owner,
                    item.treatment,
                    item.treatment_plan,
                    item.status,
                    json.dumps(item.soc2_controls),
                    item.related_finding,
                    item.created_date,
                    item.last_reviewed,
                    item.review_notes,
                ),
            )
        self.conn.commit()

    def get_risk_items(self, account_id: str) -> list[dict]:
        """Get all risk items for an account."""
        rows = self.conn.execute(
            "SELECT * FROM risk_items WHERE account_id = ? ORDER BY risk_score DESC", (account_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def get_recent_scan(
        self, max_age_minutes: int = 60, account_id: str | None = None
    ) -> ScanResult | None:
        """Get the most recent scan if it's within max_age_minutes.

        Returns None if no scan exists or the latest is too old.
        Used by skills to avoid re-scanning when recent data exists.
        """
        from datetime import datetime, timedelta

        scan = self.get_latest_scan(account_id)
        if not scan or not scan.completed_at:
            return None

        completed = scan.completed_at
        if isinstance(completed, str):
            completed = datetime.fromisoformat(completed)
        if completed.tzinfo is None:
            completed = completed.replace(tzinfo=UTC)

        cutoff = datetime.now(UTC) - timedelta(minutes=max_age_minutes)
        if completed >= cutoff:
            return scan
        return None

    def get_last_review_date(self) -> str | None:
        """Get the date of the most recent access review from saved files.

        Checks data/reviews/ for the most recent review file.
        """
        from pathlib import Path

        review_dir = Path("data/reviews")
        if not review_dir.exists():
            return None

        reviews = sorted(review_dir.glob("access-review-*.md"), reverse=True)
        if not reviews:
            return None

        # Extract date from filename: access-review-ACCOUNT-YYYY-MM-DD.md
        name = reviews[0].stem  # access-review-470226123496-2026-04-03
        parts = name.split("-")
        if len(parts) >= 5:
            return f"{parts[-3]}-{parts[-2]}-{parts[-1]}"
        return None

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None
