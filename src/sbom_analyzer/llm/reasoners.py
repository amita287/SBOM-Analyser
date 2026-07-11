"""The four LLM reasoners, each with a deterministic fallback (Section 8).

  A. :func:`adjudicate_exploitability` — bounded to the 3 usage buckets.
  B. :func:`adjudicate_false_positive` — deterministic pre-check runs first.
  C. :func:`narrate_attack_path`       — the path is given; nothing is discovered.
  D. :func:`build_remediation`         — grounded in the concrete fix data.

Every reasoner is total: it *always* returns a valid result. If the LLM is off,
errors, times out, returns junk, or violates its schema, the deterministic
fallback is returned instead. Reasoners never raise, so the pipeline cannot be
taken down by the LLM.

A note on the metric boundary
-----------------------------
Reasoners C and D produce prose — they can never move a number. Reasoners A and
B *could*: exploitability feeds ``base_vuln``, and a false-positive verdict drops
a CVE entirely. CLAUDE.md's rule is "never use an LLM to produce numbers that
feed a metric", so by default their verdicts are **recorded but not applied** —
see ``Settings.llm_affects_score``. The fallbacks are exactly the Phase 4
deterministic answers, which is why ``LLM_PROVIDER=none`` reproduces the
deterministic pipeline bit for bit.
"""

from __future__ import annotations

from typing import Literal

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field

from ..analysis.vulnerabilities import is_backported_safe
from ..models.entities import Application, Dependency, UsageSignal, Vulnerability
from ..models.findings import RemediationPlaybook
from . import prompts
from .client import LLMClient


# --------------------------------------------------------------------------- #
# Output schemas — every reasoner reply is validated against one of these
# --------------------------------------------------------------------------- #
class ExploitabilityVerdict(BaseModel):
    """Section 8.2. The enum is the guardrail: only 3 buckets can ever parse."""

    exploitability: UsageSignal
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class FalsePositiveVerdict(BaseModel):
    """Section 8.3."""

    is_false_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


class AttackNarrative(BaseModel):
    """Section 8.4."""

    narrative: str


# Section 8.5 reuses `RemediationPlaybook` from models.findings.
Priority = Literal["P1", "P2", "P3"]


# --------------------------------------------------------------------------- #
# A. Exploitability adjudication
# --------------------------------------------------------------------------- #
def adjudicate_exploitability(
    client: LLMClient,
    *,
    dep: Dependency,
    app: Application,
    cve: Vulnerability,
) -> ExploitabilityVerdict:
    """Refine the static usage signal. Fallback = the raw ``usage_signal``."""
    fallback = ExploitabilityVerdict(
        exploitability=dep.usage_signal,
        confidence=1.0,
        reasoning="Deterministic: the SBOM's static usage signal, used as-is.",
    )
    if not client.enabled:
        return fallback

    verdict = client.complete_model(
        prompts.EXPLOITABILITY_SYSTEM,
        prompts.exploitability_user(
            library_name=dep.library_name,
            version=dep.version,
            app_name=app.name,
            environment=app.environment.value,
            internet_facing=app.internet_facing,
            usage_signal=dep.usage_signal.value,
            cve_id=cve.cve_id,
            cvss_score=cve.cvss_score,
            vulnerable_function=cve.vulnerable_function,
            description=cve.description,
        ),
        ExploitabilityVerdict,
    )
    # A parsed verdict is already bounded to the 3 buckets by the UsageSignal
    # enum — an invented bucket fails validation and lands us on the fallback.
    return verdict or fallback


# --------------------------------------------------------------------------- #
# B. False-positive adjudication
# --------------------------------------------------------------------------- #
def _is_ambiguous(dep: Dependency, cve: Vulnerability) -> bool:
    """Is this match genuinely debatable, i.e. worth an LLM call at all?

    Two shapes qualify:
      * the CVE is known to have backported builds, but *this* build is not one
        of them (so backporting is plausible but unlisted); or
      * the installed version is at/after the published ``fixed_version`` yet
        still inside the affected range — a self-contradictory advisory.
    Everything else is an unambiguous hit and never reaches the LLM.
    """
    if cve.backported_patch_builds:
        return True
    if not cve.fixed_version:
        return False
    try:
        return Version(dep.version) >= Version(cve.fixed_version)
    except InvalidVersion:
        return False


def adjudicate_false_positive(
    client: LLMClient,
    *,
    dep: Dependency,
    cve: Vulnerability,
) -> FalsePositiveVerdict:
    """Decide whether an in-range match is actually safe.

    The deterministic pre-check runs FIRST and settles the obvious case: a version
    listed in ``backported_patch_builds`` is a false positive, full stop — no LLM
    call, no confidence, no debate. The LLM is consulted only for the genuinely
    ambiguous remainder, and its fallback is the deterministic verdict.
    """
    if is_backported_safe(dep.version, cve.backported_patch_builds):
        return FalsePositiveVerdict(
            is_false_positive=True,
            confidence=1.0,
            reasoning=(
                f"Deterministic: {dep.version} is listed as a backported patched "
                f"build of {cve.cve_id}; the fix is already present."
            ),
        )

    deterministic = FalsePositiveVerdict(
        is_false_positive=False,
        confidence=1.0,
        reasoning=(
            f"Deterministic: {dep.version} is inside {cve.affected_versions} and is "
            "not a backported build."
        ),
    )
    if not client.enabled or not _is_ambiguous(dep, cve):
        return deterministic

    verdict = client.complete_model(
        prompts.FALSE_POSITIVE_SYSTEM,
        prompts.false_positive_user(
            library_name=dep.library_name,
            version=dep.version,
            cve_id=cve.cve_id,
            affected_versions=cve.affected_versions,
            fixed_version=cve.fixed_version,
            backported_patch_builds=list(cve.backported_patch_builds),
            description=cve.description,
        ),
        FalsePositiveVerdict,
    )
    return verdict or deterministic


# --------------------------------------------------------------------------- #
# C. Attack-chain narrative
# --------------------------------------------------------------------------- #
def _deterministic_narrative(
    *, app_name: str, path_labels: list[str], library_name: str, version: str,
    cve_id: str, cvss_severity: str, cvss_score: float, hop_distance: int,
) -> str:
    chain = " -> ".join(path_labels)
    return (
        f"{app_name} reaches {library_name} {version} through {chain} "
        f"({hop_distance} hop(s)). That version matches {cve_id} "
        f"({cvss_severity}, CVSS {cvss_score})."
    )


def narrate_attack_path(
    client: LLMClient,
    *,
    app: Application,
    path_labels: list[str],
    library_name: str,
    version: str,
    cve: Vulnerability,
    hop_distance: int,
) -> str:
    """Narrate an already-resolved path. Fallback = a deterministic sentence.

    ``path_labels`` is the resolved chain (app, then each library@version down to
    the vulnerable one). The LLM is told the exact path — it discovers nothing.
    """
    fallback = _deterministic_narrative(
        app_name=app.name,
        path_labels=path_labels,
        library_name=library_name,
        version=version,
        cve_id=cve.cve_id,
        cvss_severity=cve.cvss_severity.value,
        cvss_score=cve.cvss_score,
        hop_distance=hop_distance,
    )
    if not client.enabled:
        return fallback

    result = client.complete_model(
        prompts.NARRATIVE_SYSTEM,
        prompts.narrative_user(
            app_name=app.name,
            path_description=" -> ".join(path_labels),
            library_name=library_name,
            version=version,
            cve_id=cve.cve_id,
            cvss_score=cve.cvss_score,
            cvss_severity=cve.cvss_severity.value,
            description=cve.description,
            hop_distance=hop_distance,
        ),
        AttackNarrative,
    )
    return result.narrative.strip() if result and result.narrative.strip() else fallback


# --------------------------------------------------------------------------- #
# D. Remediation playbook
# --------------------------------------------------------------------------- #
def _deterministic_playbook(
    *,
    library_name: str,
    version: str,
    risk_score: float,
    risk_types: list[str],
    cve_id: str | None,
    fixed_version: str | None,
    license_id: str,
    license_outcome: str,
    is_stale: bool,
    internet_facing: bool,
) -> RemediationPlaybook:
    steps: list[str] = []
    if cve_id:
        if fixed_version:
            steps.append(
                f"Upgrade {library_name} {version} -> {fixed_version} to remediate {cve_id}."
            )
        else:
            steps.append(
                f"No patch is published for {cve_id}. Pin {library_name} {version}, "
                "isolate the vulnerable code path, or replace the library."
            )
    if "transitive_vulnerable" in risk_types:
        steps.append(
            "This dependency is on a path to a vulnerable descendant — bump the "
            "direct parent that pulls it in, or override the transitive pin."
        )
    if license_outcome == "conflict":
        steps.append(
            f"License {license_id or 'unknown'} conflicts with distribution. Replace "
            "the library, or seek a commercial/exception license before shipping."
        )
    elif license_outcome == "review":
        steps.append(
            f"License {license_id or 'unknown'} needs legal review for this "
            "distribution context."
        )
    if is_stale:
        steps.append(
            f"{library_name} has not been updated in over 2 years — evaluate a "
            "maintained alternative."
        )
    if not steps:
        steps.append("No action required; no risk detected for this dependency.")

    if risk_score >= 75 or (cve_id and internet_facing):
        priority: Priority = "P1"
    elif risk_score >= 50:
        priority = "P2"
    else:
        priority = "P3"
    return RemediationPlaybook(steps=steps, priority=priority)


def build_remediation(
    client: LLMClient,
    *,
    dep: Dependency,
    app: Application,
    risk_score: float,
    severity: str,
    risk_types: list[str],
    cve: Vulnerability | None,
    license_outcome: str,
    is_stale: bool,
    age_years: float,
) -> RemediationPlaybook:
    """Grounded playbook. Fallback = a deterministic one built from the same facts."""
    fallback = _deterministic_playbook(
        library_name=dep.library_name,
        version=dep.version,
        risk_score=risk_score,
        risk_types=risk_types,
        cve_id=cve.cve_id if cve else None,
        fixed_version=cve.fixed_version if cve else None,
        license_id=dep.license,
        license_outcome=license_outcome,
        is_stale=is_stale,
        internet_facing=app.internet_facing,
    )
    if not client.enabled:
        return fallback

    result = client.complete_model(
        prompts.REMEDIATION_SYSTEM,
        prompts.remediation_user(
            library_name=dep.library_name,
            version=dep.version,
            app_name=app.name,
            environment=app.environment.value,
            internet_facing=app.internet_facing,
            risk_score=risk_score,
            severity=severity,
            risk_types=risk_types,
            cve_id=cve.cve_id if cve else None,
            fixed_version=cve.fixed_version if cve else None,
            license_id=dep.license,
            license_outcome=license_outcome,
            is_stale=is_stale,
            age_years=age_years,
        ),
        RemediationPlaybook,
    )
    return result if result and result.steps else fallback
