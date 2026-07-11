"""Output / ground-truth contracts.

- `DependencyLabel` mirrors `dependency_labels.csv` (Section 4.5) — the
  generator's ground truth, read only by the eval harness.
- `DependencyFinding` / `AppRiskReport` / `AnalysisReport` are the analyzer's
  output (Section 9.1) — the canonical machine-readable report.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator

from .entities import (
    BusinessCriticality,
    CvssSeverity,
    Ecosystem,
    LicenseOutcome,
    UsageSignal,
)


# --------------------------------------------------------------------------- #
# Shared enumerations
# --------------------------------------------------------------------------- #
class RiskType(str, Enum):
    vulnerable = "vulnerable"
    transitive_vulnerable = "transitive_vulnerable"
    license_conflict = "license_conflict"
    unmaintained = "unmaintained"
    clean = "clean"


class Severity(str, Enum):
    """Severity band derived from the risk score (Section 7.3)."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


# --------------------------------------------------------------------------- #
# 4.5  dependency_labels.csv — GROUND TRUTH (generator output only)
# --------------------------------------------------------------------------- #
class DependencyLabel(BaseModel):
    dependency_id: str
    is_risk: bool
    risk_types: list[RiskType]  # stored pipe-separated in the CSV
    severity: Severity
    risk_score: float = Field(ge=0.0, le=100.0)
    explanation: str = ""

    @field_validator("risk_types", mode="before")
    @classmethod
    def _split_pipes(cls, v: object) -> object:
        """Accept the CSV's pipe-separated string form, e.g. 'vulnerable|unmaintained'."""
        if isinstance(v, str):
            return [part for part in v.split("|") if part]
        return v


# --------------------------------------------------------------------------- #
# 9.1  Analysis report (analyzer output)
# --------------------------------------------------------------------------- #
class MatchedVulnerability(BaseModel):
    """A CVE the analyzer matched to a dependency occurrence."""

    cve_id: str
    cvss_score: float
    cvss_severity: CvssSeverity
    affected_versions: str
    patch_available: bool
    fixed_version: str | None = None
    vulnerable_function: str = ""
    # True when the version matches the range but is a backported/safe build.
    is_false_positive: bool = False
    exploitability: UsageSignal | None = None
    # This CVE's contribution to base_vuln (worst-CVE-wins, Section 7.1).
    cve_score: float = 0.0


class AttackPath(BaseModel):
    """A resolved path App -> ... -> vulnerable library (Section 6.2)."""

    app_id: str
    path: list[str]  # ordered dependency_ids from app-root down to the vuln dep
    vulnerable_dependency_id: str
    cve_id: str | None = None
    narrative: str | None = None  # LLM-generated (Reasoner C), optional


class MaintenanceStatus(BaseModel):
    last_updated: date
    age_years: float = 0.0
    is_stale: bool = False  # age > 2 years (Section 5.4c / 7.1)
    maintenance_penalty: float = 0.0


class RemediationPlaybook(BaseModel):
    """LLM Reasoner D output (Section 8.5), with a deterministic fallback."""

    steps: list[str] = Field(default_factory=list)
    priority: Literal["P1", "P2", "P3"] = "P3"


class DependencyFinding(BaseModel):
    dependency_id: str
    app_id: str
    library_name: str
    version: str
    ecosystem: Ecosystem
    license: str = ""
    risk_score: float = Field(ge=0.0, le=100.0)
    severity: Severity
    risk_types: list[RiskType] = Field(default_factory=list)
    matched_cves: list[MatchedVulnerability] = Field(default_factory=list)
    license_outcome: LicenseOutcome = LicenseOutcome.ok
    maintenance: MaintenanceStatus | None = None
    attack_paths: list[AttackPath] = Field(default_factory=list)
    narrative: str | None = None
    remediation: RemediationPlaybook | None = None
    # True only when an LLM reasoner *successfully* contributed to this finding.
    # A finding in the LLM scope whose calls all failed stays False, so the report
    # never credits the model for text a deterministic fallback actually wrote.
    llm_enriched: bool = False

    @property
    def is_risk(self) -> bool:
        """True when any risk type other than `clean` was detected.

        Mirrors `DependencyLabel.is_risk` on the ground-truth side, so the
        report, the HTML view, and the API all agree on what "at risk" means.
        """
        return any(rt is not RiskType.clean for rt in self.risk_types)


class AppRiskReport(BaseModel):
    app_id: str
    name: str
    business_criticality: BusinessCriticality
    app_score: float = Field(ge=0.0, le=100.0)
    severity: Severity
    findings: list[DependencyFinding] = Field(default_factory=list)


class RiskyDependencyRef(BaseModel):
    """Compact reference used in the global top-N list."""

    dependency_id: str
    app_id: str
    library_name: str
    version: str
    risk_score: float
    severity: Severity


class GlobalSummary(BaseModel):
    totals_per_risk_type: dict[RiskType, int] = Field(default_factory=dict)
    top_riskiest: list[RiskyDependencyRef] = Field(default_factory=list)
    # e.g. shared vulnerable libs linked by (library, version) for blast radius.
    dedup_note: str = ""


class AnalysisReport(BaseModel):
    """The single canonical report object written to reports/analysis.json."""

    run_id: str
    generated_at: datetime
    # Provenance: how this run was produced. The eval harness reads these rather
    # than re-guessing from the environment, so the scorecard can never claim the
    # run was deterministic when an LLM actually touched it.
    llm_provider: str = "none"
    llm_affects_score: bool = False
    # How much the LLM actually contributed. `llm_provider != "none"` only says it
    # was *configured*; if every call 402s, `llm_calls == llm_fallbacks` and the
    # output is entirely deterministic. Both facts have to survive into the report.
    llm_calls: int = 0
    llm_fallbacks: int = 0
    apps: list[AppRiskReport] = Field(default_factory=list)
    summary: GlobalSummary = Field(default_factory=GlobalSummary)
