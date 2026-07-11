"""Input data contracts (Section 4.1–4.4).

These schemas are the contract between the generator, the loaders, and the
analyzer. The generator writes *exactly* these fields; the loaders validate
*exactly* these fields. If they drift, everything breaks silently.
"""

from __future__ import annotations

from datetime import date
from enum import Enum

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- #
# Enumerations (closed value sets from the brief)
# --------------------------------------------------------------------------- #
class BusinessCriticality(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Environment(str, Enum):
    production = "production"
    staging = "staging"
    internal = "internal"


class DependencyType(str, Enum):
    direct = "direct"
    transitive = "transitive"


class Ecosystem(str, Enum):
    npm = "npm"
    pypi = "pypi"
    maven = "maven"


class UsageSignal(str, Enum):
    """Simulated code-usage hint that drives exploitability (Section 7.2)."""

    calls_vulnerable_function = "calls_vulnerable_function"
    imports_only = "imports_only"
    not_referenced = "not_referenced"


class CvssSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class LicenseCategory(str, Enum):
    permissive = "permissive"
    copyleft_weak = "copyleft-weak"
    copyleft_strong = "copyleft-strong"
    copyleft_network = "copyleft-network"
    unknown = "unknown"


class BaseRisk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class LicenseOutcome(str, Enum):
    """Resolved license verdict from the compatibility matrix (Section 4.4)."""

    conflict = "conflict"
    review = "review"
    ok = "ok"


# --------------------------------------------------------------------------- #
# 4.1  applications.json — 10 records
# --------------------------------------------------------------------------- #
class Application(BaseModel):
    app_id: str
    name: str
    business_criticality: BusinessCriticality
    owner: str
    environment: Environment
    internet_facing: bool
    # True = shipped to external parties (matters for GPL / distribution).
    distributed: bool


# --------------------------------------------------------------------------- #
# 4.2  sbom_dependencies.csv — 500 rows (one row == one occurrence)
# --------------------------------------------------------------------------- #
class Dependency(BaseModel):
    dependency_id: str  # unique per row; this is the graph node key
    app_id: str
    library_name: str
    version: str  # PEP 440 / semver-clean, e.g. "2.14.1"
    # SPDX id (MIT, Apache-2.0, GPL-3.0, ...) or "" for unknown.
    license: str = ""
    dependency_type: DependencyType
    # "" for direct; else the dependency_id that pulled this one in (graph edge).
    parent_dependency_id: str = ""
    last_updated: date
    ecosystem: Ecosystem
    usage_signal: UsageSignal


# --------------------------------------------------------------------------- #
# 4.3  vulnerability_db.json — ~200 records (simulated NVD)
# --------------------------------------------------------------------------- #
class Vulnerability(BaseModel):
    cve_id: str
    library_name: str
    # SpecifierSet string, e.g. ">=2.0,<2.15.0". Never string-compare versions.
    affected_versions: str
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_severity: CvssSeverity
    patch_available: bool
    fixed_version: str | None = None  # null if no patch
    vulnerable_function: str = ""
    # FP trap: versions that match the range but are actually safe.
    backported_patch_builds: list[str] = Field(default_factory=list)
    description: str = ""


# --------------------------------------------------------------------------- #
# 4.4  license_rules.json — 15 records (one object with two sections)
# --------------------------------------------------------------------------- #
class LicenseInfo(BaseModel):
    category: LicenseCategory
    base_risk: BaseRisk


class CompatibilityRule(BaseModel):
    """Resolved outcome per distribution context for one license category."""

    distributed: LicenseOutcome
    internal: LicenseOutcome


class LicenseRules(BaseModel):
    """Top-level shape of `license_rules.json`."""

    # keyed by SPDX id (incl. "" for unknown)
    licenses: dict[str, LicenseInfo]
    # keyed by LicenseCategory
    compatibility: dict[LicenseCategory, CompatibilityRule]

    def resolve(self, spdx_id: str, distributed: bool) -> LicenseOutcome:
        """Resolve an SPDX id + distribution context to a license outcome.

        Deterministic lookup only (no LLM). Unknown ids fall back to the
        `unknown` category, mirroring the generator's convention.
        """
        info = self.licenses.get(spdx_id) or self.licenses.get("")
        category = info.category if info else LicenseCategory.unknown
        rule = self.compatibility[category]
        return rule.distributed if distributed else rule.internal


# Alias to match the singular name used in Section 3's file listing.
LicenseRule = LicenseRules
