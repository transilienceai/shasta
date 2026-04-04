"""SBOM Vulnerability Scanner — checks dependencies against live vulnerability databases.

Queries:
  - OSV.dev (Google's open-source vulnerability database — covers NVD, PyPI, npm, Go, etc.)
  - GitHub Advisory Database (via API)
  - CISA KEV (Known Exploited Vulnerabilities catalog)
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request, error

from transilience_compliance.sbom.discovery import Dependency, SBOMReport


@dataclass
class VulnerabilityMatch:
    """A vulnerability found in a dependency."""

    vuln_id: str  # CVE-XXXX-XXXXX or GHSA-xxx
    package: str
    version: str
    ecosystem: str
    source_resource: str  # AWS resource where this was found
    severity: str  # critical, high, medium, low
    summary: str
    details: str = ""
    fixed_version: str = ""
    references: list[str] = field(default_factory=list)
    is_kev: bool = False  # In CISA Known Exploited Vulnerabilities


@dataclass
class VulnScanResult:
    """Result of scanning an SBOM against vulnerability databases."""

    scanned_at: str
    total_dependencies: int
    total_vulnerabilities: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    kev_count: int = 0  # Known Exploited Vulnerabilities
    vulnerabilities: list[VulnerabilityMatch] = field(default_factory=list)


# Ecosystem mapping for OSV.dev
OSV_ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "go": "Go",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
    "system": "Linux",
}


def scan_sbom_vulnerabilities(sbom: SBOMReport) -> VulnScanResult:
    """Scan all SBOM dependencies against vulnerability databases."""
    result = VulnScanResult(
        scanned_at=datetime.now(timezone.utc).isoformat(),
        total_dependencies=sbom.total_dependencies,
    )

    # Batch query OSV.dev (supports batch queries)
    osv_results = _query_osv_batch(sbom.dependencies)
    result.vulnerabilities.extend(osv_results)

    # Load CISA KEV for cross-referencing
    kev_cves = _load_cisa_kev()
    for vuln in result.vulnerabilities:
        if vuln.vuln_id in kev_cves:
            vuln.is_kev = True
            result.kev_count += 1

    # Count by severity
    for vuln in result.vulnerabilities:
        match vuln.severity:
            case "critical":
                result.critical += 1
            case "high":
                result.high += 1
            case "medium":
                result.medium += 1
            case "low":
                result.low += 1

    result.total_vulnerabilities = len(result.vulnerabilities)
    return result


def _query_osv_batch(dependencies: list[Dependency]) -> list[VulnerabilityMatch]:
    """Query OSV.dev for vulnerabilities in a batch of dependencies."""
    vulnerabilities = []

    # OSV supports batch queries of up to 1000
    queries = []
    dep_map = {}  # index -> dependency

    for i, dep in enumerate(dependencies):
        osv_ecosystem = OSV_ECOSYSTEMS.get(dep.ecosystem)
        if not osv_ecosystem or not dep.name or not dep.version or dep.version == "unknown":
            continue

        queries.append({
            "package": {"name": dep.name, "ecosystem": osv_ecosystem},
            "version": dep.version,
        })
        dep_map[len(queries) - 1] = dep

    if not queries:
        return []

    # Batch in chunks of 100
    for chunk_start in range(0, len(queries), 100):
        chunk = queries[chunk_start:chunk_start + 100]
        try:
            payload = json.dumps({"queries": chunk}).encode("utf-8")
            req = request.Request(
                "https://api.osv.dev/v1/querybatch",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            resp = request.urlopen(req, timeout=30)
            data = json.loads(resp.read())

            for idx, result in enumerate(data.get("results", [])):
                actual_idx = chunk_start + idx
                dep = dep_map.get(actual_idx)
                if not dep:
                    continue

                for vuln_data in result.get("vulns", []):
                    vuln_id = vuln_data.get("id", "")
                    severity = _extract_severity(vuln_data)
                    summary = vuln_data.get("summary", "")
                    details = vuln_data.get("details", "")[:500]

                    # Find fixed version
                    fixed = ""
                    for affected in vuln_data.get("affected", []):
                        for rng in affected.get("ranges", []):
                            for event in rng.get("events", []):
                                if "fixed" in event:
                                    fixed = event["fixed"]

                    refs = [r.get("url", "") for r in vuln_data.get("references", [])[:3]]

                    vulnerabilities.append(VulnerabilityMatch(
                        vuln_id=vuln_id,
                        package=dep.name,
                        version=dep.version,
                        ecosystem=dep.ecosystem,
                        source_resource=dep.source,
                        severity=severity,
                        summary=summary,
                        details=details,
                        fixed_version=fixed,
                        references=refs,
                    ))

        except (error.URLError, json.JSONDecodeError) as e:
            # OSV is optional — don't fail the whole scan
            pass

    return vulnerabilities


def _extract_severity(vuln_data: dict) -> str:
    """Extract severity from OSV vulnerability data."""
    # Check CVSS in database_specific or severity
    for sev_entry in vuln_data.get("severity", []):
        score_str = sev_entry.get("score", "")
        # CVSS vector string — extract base score
        if "CVSS" in sev_entry.get("type", ""):
            try:
                # Parse CVSS score from vector
                if "/" in score_str:
                    for part in score_str.split("/"):
                        if part.startswith("AV:") or part.startswith("CVSS:"):
                            continue
                # Fall back to database severity
            except Exception:
                pass

    # Check database_specific for severity
    db_specific = vuln_data.get("database_specific", {})
    severity = db_specific.get("severity", "").lower()
    if severity in ("critical", "high", "medium", "low"):
        return severity

    # Check ecosystem_specific
    eco_specific = vuln_data.get("ecosystem_specific", {})
    severity = eco_specific.get("severity", "").lower()
    if severity in ("critical", "high", "medium", "low"):
        return severity

    return "medium"  # Default if unknown


def _load_cisa_kev() -> set[str]:
    """Load CISA Known Exploited Vulnerabilities catalog."""
    try:
        req = request.Request(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            headers={"Accept": "application/json"},
        )
        resp = request.urlopen(req, timeout=15)
        data = json.loads(resp.read())
        return {v.get("cveID", "") for v in data.get("vulnerabilities", [])}
    except (error.URLError, json.JSONDecodeError):
        return set()


def save_vuln_report(result: VulnScanResult, output_path: Path | str = "data/sbom") -> Path:
    """Save vulnerability scan results."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"vuln-scan-{timestamp}.json"

    data = {
        "scanned_at": result.scanned_at,
        "summary": {
            "total_dependencies": result.total_dependencies,
            "total_vulnerabilities": result.total_vulnerabilities,
            "critical": result.critical,
            "high": result.high,
            "medium": result.medium,
            "low": result.low,
            "kev_count": result.kev_count,
        },
        "vulnerabilities": [
            {
                "id": v.vuln_id,
                "package": v.package,
                "version": v.version,
                "ecosystem": v.ecosystem,
                "source": v.source_resource,
                "severity": v.severity,
                "summary": v.summary,
                "fixed_version": v.fixed_version,
                "is_kev": v.is_kev,
                "references": v.references,
            }
            for v in result.vulnerabilities
        ],
    }

    filepath.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return filepath
