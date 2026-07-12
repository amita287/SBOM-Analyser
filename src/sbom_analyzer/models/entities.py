"""Input data contracts.

These schemas are the contract between the supplied dataset and the analyzer.
The loaders validate *exactly* these fields; if they drift, everything breaks
silently.

The dataset ships with its own column names (``dep_id``, ``library``,
``criticality``, ...). Rather than rename those concepts through every module,
graph, API response and HTML template, each field is declared under the name the
rest of the codebase already speaks and given a validation *alias* for the name
on disk. One line of translation here beats a thousand renames downstream, and
the alias makes the mapping explicit and greppable.
"""

from __future__ import annotations

from datetime import date
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator


# --------------------------------------------------------------------------- #
# Enumerations (closed value sets)
# --------------------------------------------------------------------------- #
class BusinessCriticality(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Deployment(str, Enum):
    cloud = "cloud"
    on_prem = "on-prem"


class LicenseModel(str, Enum):
    proprietary = "proprietary"
    internal_only = "internal-only"


class DependencyType(str, Enum):
    direct = "direct"
    transitive = "transitive"


class CvssSeverity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class Exploitability(str, Enum):
    """How exploitable the advisory says the CVE is.

    In the previous dataset this was a *usage* signal on the dependency ("does
    our code call the vulnerable function?"). Here it is a property of the CVE
    itself, so it is modelled on :class:`Vulnerability`, not on
    :class:`Dependency`. Same name, different owner — worth being loud about.
    """

    high = "high"
    medium = "medium"
    low = "low"
    none = "none"


class LicenseRisk(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class LicenseOutcome(str, Enum):
    """Resolved licence verdict for a dependency in its application's context."""

    conflict = "conflict"  # viral licence inside a proprietary product
    unknown = "unknown"  # no licence declared
    ok = "ok"


def _lower(v: object) -> object:
    """The dataset shouts its enums (``HIGH``); we speak lowercase."""
    return v.lower() if isinstance(v, str) else v


# --------------------------------------------------------------------------- #
# applications.json
# --------------------------------------------------------------------------- #
class Application(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    app_id: str
    name: str
    language: str = ""
    business_criticality: BusinessCriticality = Field(alias="criticality")
    license_model: LicenseModel = LicenseModel.proprietary
    owner: str = Field(default="", alias="business_owner")
    department: str = ""
    environment: Deployment = Field(default=Deployment.cloud, alias="deployment")

    _norm_crit = field_validator("business_criticality", mode="before")(_lower)

    @property
    def distributed(self) -> bool:
        """True when the app ships as a proprietary product.

        This is what makes a viral (copyleft) licence a *conflict* rather than a
        footnote: an internal-only tool can use GPL freely, a proprietary product
        cannot. The old dataset carried an explicit `distributed` flag; here the
        same fact is expressed as ``license_model``.
        """
        return self.license_model is LicenseModel.proprietary


# --------------------------------------------------------------------------- #
# sbom_dependencies.csv
# --------------------------------------------------------------------------- #
class LibraryRef(BaseModel):
    """A ``library:version`` pair, as used by the transitive edge lists."""

    library_name: str
    version: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.library_name, self.version)


class Dependency(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    dependency_id: str = Field(alias="dep_id")
    app_id: str = Field(alias="application_id")
    app_name: str = Field(default="", alias="application_name")
    library_name: str = Field(alias="library")
    version: str
    license: str = ""
    dependency_type: DependencyType
    last_updated: date
    # Libraries this dependency pulls in. NOTE: these children are *not* rows in
    # this CSV — they are phantom nodes that exist only as edges (verified: all
    # 372 children are absent from the dependency table). They are graph
    # structure, not scored occurrences.
    transitive_children: list[LibraryRef] = Field(
        default_factory=list, alias="transitive_deps"
    )

    @field_validator("transitive_children", mode="before")
    @classmethod
    def _parse_children(cls, v: object) -> object:
        """Parse ``"lib:1.2.3;other:4.5.6"`` into refs.

        Split the version off the RIGHT: a library name may contain a colon in
        principle, a version never does.
        """
        if not isinstance(v, str):
            return v
        out: list[dict[str, str]] = []
        for token in v.split(";"):
            token = token.strip()
            if not token or ":" not in token:
                continue
            lib, _, ver = token.rpartition(":")
            out.append({"library_name": lib, "version": ver})
        return out


# --------------------------------------------------------------------------- #
# transitive_dependencies.json
# --------------------------------------------------------------------------- #
class TransitiveEdge(BaseModel):
    """One parent -> child edge, scoped to an application.

    Redundant with ``Dependency.transitive_children`` — the two were verified to
    describe an identical set of 372 edges. Both are loaded and cross-checked, so
    a future dataset where they disagree fails loudly instead of quietly picking
    a winner.
    """

    model_config = ConfigDict(populate_by_name=True)

    app_id: str = Field(alias="application_id")
    parent_library: str
    parent_version: str
    child_library: str
    child_version: str


# --------------------------------------------------------------------------- #
# vulnerability_db.json
# --------------------------------------------------------------------------- #
class Vulnerability(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    cve_id: str
    library_name: str = Field(alias="library")
    # A LIST of discrete affected versions — NOT a range, and NOT ordered
    # (`netty-all` ships `["4.3.0", "2.8.0"]`). Membership is therefore an exact
    # set lookup, never an ordering comparison, which keeps the project rule
    # "never string-compare versions" intact: we don't compare them at all.
    affected_versions: list[str] = Field(default_factory=list)
    fixed_version: str | None = None
    cvss_score: float = Field(ge=0.0, le=10.0)
    cvss_severity: CvssSeverity = Field(alias="severity")
    exploitability: Exploitability = Exploitability.medium
    patch_available: bool = False
    description: str = ""
    published_date: date | None = None

    _norm_sev = field_validator("cvss_severity", mode="before")(_lower)
    _norm_exp = field_validator("exploitability", mode="before")(_lower)


# --------------------------------------------------------------------------- #
# license_rules.json
# --------------------------------------------------------------------------- #
class LicenseRule(BaseModel):
    license: str
    spdx: str
    risk_level: LicenseRisk
    compatible_with_proprietary: bool
    viral: bool
    notes: str = ""

    _norm_risk = field_validator("risk_level", mode="before")(_lower)


# The dependency table and the rules table disagree on how to spell a licence:
# the SBOM says `GPL-3.0`, the rule book says `GPL-3.0-only`; the SBOM says
# `UNKNOWN`, the rule book says `NOASSERTION`. Left unmapped, every copyleft
# dependency silently falls through to "no rule found" and no conflict is ever
# raised — the licence half of the product goes dark without a single error.
LICENSE_ALIASES: dict[str, str] = {
    "GPL-2.0": "GPL-2.0-only",
    "GPL-3.0": "GPL-3.0-only",
    "AGPL-3.0": "AGPL-3.0-only",
    "LGPL-2.1": "LGPL-2.1-only",
    "LGPL-3.0": "LGPL-3.0-only",
    "UNKNOWN": "NOASSERTION",
}

# Spellings that mean "nobody declared a licence".
UNDECLARED: frozenset[str] = frozenset({"", "UNKNOWN", "NOASSERTION", "NONE"})


class LicenseRules(BaseModel):
    """The rule book, indexed by SPDX id."""

    rules: list[LicenseRule] = Field(default_factory=list)

    def _index(self) -> dict[str, LicenseRule]:
        # Later duplicates lose to earlier ones (the file lists MIT twice).
        idx: dict[str, LicenseRule] = {}
        for rule in self.rules:
            idx.setdefault(rule.spdx, rule)
        return idx

    def lookup(self, license_id: str) -> LicenseRule | None:
        """Find the rule for a licence as spelled in the SBOM."""
        idx = self._index()
        canonical = LICENSE_ALIASES.get(license_id, license_id)
        return idx.get(canonical)

    def resolve(self, license_id: str, *, distributed: bool) -> LicenseOutcome:
        """Resolve a licence to a verdict for this distribution context.

        - undeclared            -> ``unknown``
        - viral + proprietary   -> ``conflict``
        - anything else         -> ``ok``

        A licence with no matching rule (the dataset carries
        ``Dual-MIT/Commercial``, which the rule book never mentions) is *declared
        but unrecognised*. That is NOT the same as undeclared, and it is not a
        conflict: it resolves to ``ok``. Treating it as unknown would flag 66
        healthy dependencies and torch the false-positive rate.
        """
        if license_id.strip().upper() in UNDECLARED:
            return LicenseOutcome.unknown

        rule = self.lookup(license_id)
        if rule is None:
            return LicenseOutcome.ok
        if rule.viral and distributed:
            return LicenseOutcome.conflict
        return LicenseOutcome.ok
