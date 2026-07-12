"""Output / ground-truth contracts.

- `DependencyLabel` mirrors `dependency_labels.csv` — the supplied ground truth,
  read only by the eval harness.
- `DependencyFinding` / `AppRiskReport` / `AnalysisReport` are the analyzer's
  output — the canonical machine-readable report.
"""

from __future__ import annotations

from datetime import date, datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .entities import (
    BusinessCriticality,
    CvssSeverity,
    DependencyType,
    Exploitability,
    LicenseOutcome,
)


# --------------------------------------------------------------------------- #
# Shared enumerations
# --------------------------------------------------------------------------- #
class RiskType(str, Enum):
    """The dataset's taxonomy, lowercased.

    `vulnerable_dependency` and `transitive_vulnerability` are distinguished by
    the dependency's OWN ``dependency_type``, not by graph traversal — verified
    against the labels: every one of the 122 `VULNERABLE_DEPENDENCY` rows is
    `direct`, and all 54 `TRANSITIVE_VULNERABILITY` rows are `transitive` rows
    that carry a CVE themselves. A dependency whose *child* is vulnerable is not
    flagged by this dataset at all.
    """

    vulnerable_dependency = "vulnerable_dependency"
    transitive_vulnerability = "transitive_vulnerability"
    license_conflict = "license_conflict"
    transitive_license_conflict = "transitive_license_conflict"
    license_unknown = "license_unknown"
    unmaintained = "unmaintained"
    none = "none"


# Worst-first. The label file records exactly one risk type per dependency, so
# the analyzer must pick a primary when several apply. This is that order.
RISK_PRECEDENCE: tuple[RiskType, ...] = (
    RiskType.vulnerable_dependency,
    RiskType.transitive_vulnerability,
    RiskType.license_conflict,
    RiskType.transitive_license_conflict,
    RiskType.license_unknown,
    RiskType.unmaintained,
    RiskType.none,
)


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


class VulnConfidence(str, Enum):
    """How strongly the evidence supports "this occurrence is vulnerable".

    Advisories in the wild are imprecise. An `affected_versions` list is what the
    vendor got round to enumerating — not a proof of what is safe. A library can
    be vulnerable in a build the advisory never lists (a backport, a distro
    rebuild, a vendor-specific patch level), and a scanner that only believes the
    enumerated versions will miss those silently.

    So a match is graded, not asserted:

    - ``confirmed`` — the version IS in the advisory's affected set. Full weight.
    - ``potential`` — the library matches, the version is not listed. Real enough
      to surface and triage, too weak to assert. Reduced weight, and rendered as
      *unconfirmed* everywhere, so the report never claims a vulnerability the
      advisory does not support.

    This is what lets the analyzer be right in both directions at once: it never
    cries wolf on an unverified match, and it never goes blind to one either.
    """

    confirmed = "confirmed"
    potential = "potential"


class VulnStatus(str, Enum):
    """The finding-level verdict, after adjudication.

    ``potential_vulnerable`` is the interesting one — it is the analyzer saying
    "the library is named in an advisory, but this exact version is not, and I am
    not going to pretend to know which way that falls." LLM Reasoner B can rule on
    those cases; with no LLM, they stay `potential` and are scored at reduced
    weight rather than silently dropped or silently promoted.
    """

    confirmed_vulnerable = "confirmed_vulnerable"
    potential_vulnerable = "potential_vulnerable"
    not_vulnerable = "not_vulnerable"
    # Reasoner B looked at the advisory and ruled this version out.
    dismissed = "dismissed"


# --------------------------------------------------------------------------- #
# dependency_labels.csv — GROUND TRUTH (eval harness only)
# --------------------------------------------------------------------------- #
class DependencyLabel(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    dependency_id: str = Field(alias="dep_id")
    app_id: str = Field(alias="application_id")
    library_name: str = Field(alias="library")
    version: str
    is_risk: bool = Field(alias="is_risky")
    risk_type: RiskType
    severity: Severity
    explanation: str = ""

    @field_validator("risk_type", "severity", mode="before")
    @classmethod
    def _lower(cls, v: object) -> object:
        return v.lower() if isinstance(v, str) else v


# --------------------------------------------------------------------------- #
# Analysis report (analyzer output)
# --------------------------------------------------------------------------- #
class MatchedVulnerability(BaseModel):
    """A CVE the analyzer matched to a dependency occurrence."""

    cve_id: str
    cvss_score: float
    cvss_severity: CvssSeverity
    affected_versions: list[str] = Field(default_factory=list)
    fixed_version: str | None = None
    patch_available: bool = False
    exploitability: Exploitability = Exploitability.medium
    confidence: VulnConfidence = VulnConfidence.potential
    description: str = ""
    # This CVE's contribution to base_vuln (worst-CVE-wins).
    cve_score: float = 0.0

    # --- Reasoner B (false-positive adjudication) ------------------------------
    # Only ever set on `potential` matches — a confirmed match needs no ruling.
    # `dismissed` means the model read the advisory and ruled this version out;
    # the CVE is then kept on the report (struck through) rather than deleted, so
    # the judgement is auditable instead of invisible.
    dismissed: bool = False
    adjudication: str | None = None  # why, in one sentence
    adjudicated_by_llm: bool = False  # false => deterministic fallback ruled

    @property
    def is_confirmed(self) -> bool:
        return self.confidence is VulnConfidence.confirmed

    @property
    def counts_as_risk(self) -> bool:
        """A CVE only contributes once it has survived adjudication."""
        return not self.dismissed


class AttackPath(BaseModel):
    """A resolved path App -> ... -> vulnerable library."""

    app_id: str
    path: list[str]  # ordered node ids, app root first
    vulnerable_dependency_id: str
    cve_id: str | None = None
    narrative: str | None = None  # LLM-generated, optional


class MaintenanceStatus(BaseModel):
    last_updated: date
    age_years: float = 0.0
    is_stale: bool = False  # age > 2 years
    maintenance_penalty: float = 0.0


class RemediationPlaybook(BaseModel):
    """LLM reasoner output, with a deterministic fallback."""

    steps: list[str] = Field(default_factory=list)
    priority: Literal["P1", "P2", "P3"] = "P3"


class TransitiveChild(BaseModel):
    """A library this dependency pulls in but which is not itself an SBOM row."""

    library_name: str
    version: str
    cve_ids: list[str] = Field(default_factory=list)


class DependencyFinding(BaseModel):
    dependency_id: str
    app_id: str
    library_name: str
    version: str
    license: str = ""
    dependency_type: DependencyType = DependencyType.direct
    risk_score: float = Field(ge=0.0, le=100.0)
    severity: Severity
    risk_types: list[RiskType] = Field(default_factory=list)
    # The single worst risk type, by RISK_PRECEDENCE. The label file records one
    # type per dependency, so this is the field the eval compares against.
    primary_risk_type: RiskType = RiskType.none
    matched_cves: list[MatchedVulnerability] = Field(default_factory=list)
    # The headline vulnerability verdict: confirmed / potential / dismissed / none.
    vuln_status: VulnStatus = VulnStatus.not_vulnerable
    license_outcome: LicenseOutcome = LicenseOutcome.ok
    maintenance: MaintenanceStatus | None = None
    # Libraries pulled in by this dependency. Graph structure only — these are
    # not SBOM rows and are never scored, but a vulnerable one is worth showing.
    transitive_children: list[TransitiveChild] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    narrative: str | None = None
    remediation: RemediationPlaybook | None = None
    # True only when an LLM reasoner *successfully* contributed to this finding.
    llm_enriched: bool = False

    @property
    def is_risk(self) -> bool:
        return any(rt is not RiskType.none for rt in self.risk_types)

    @property
    def confirmed_cves(self) -> list[MatchedVulnerability]:
        return [c for c in self.matched_cves if c.is_confirmed and not c.dismissed]

    @property
    def potential_cves(self) -> list[MatchedVulnerability]:
        return [c for c in self.matched_cves if not c.is_confirmed and not c.dismissed]

    @property
    def dismissed_cves(self) -> list[MatchedVulnerability]:
        return [c for c in self.matched_cves if c.dismissed]

    @property
    def is_flagged_vulnerable(self) -> bool:
        """Did the analyzer actually *call* this dependency vulnerable?

        Derived from `risk_types`, NOT from `vuln_status`. The two can disagree,
        and the disagreement matters: `vuln_status` describes the EVIDENCE (a
        potential match is still a potential match), while `risk_types` records the
        VERDICT — and under strict matching a potential match is evidence that does
        not amount to a verdict.

        Reading recall off the evidence and the false-positive rate off the verdict
        would let the same dependency count as caught for one metric and clean for
        the other. Both now read the verdict.
        """
        return any(
            rt
            in (RiskType.vulnerable_dependency, RiskType.transitive_vulnerability)
            for rt in self.risk_types
        )


class AppRiskReport(BaseModel):
    app_id: str
    name: str
    business_criticality: BusinessCriticality
    owner: str = ""
    environment: str = ""
    license_model: str = ""
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
    dedup_note: str = ""


class AnalysisReport(BaseModel):
    """The single canonical report object written to reports/analysis.json."""

    run_id: str
    generated_at: datetime
    llm_provider: str = "none"
    llm_affects_score: bool = False
    llm_calls: int = 0
    llm_fallbacks: int = 0
    apps: list[AppRiskReport] = Field(default_factory=list)
    summary: GlobalSummary = Field(default_factory=GlobalSummary)
