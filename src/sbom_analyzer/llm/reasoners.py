"""The LLM reasoners, each with a deterministic fallback.

  B. :func:`adjudicate_false_positive` — rules on a POTENTIAL match.
  C. :func:`narrate_attack_path`       — the path is given; nothing is discovered.
  D. :func:`build_remediation`         — grounded in the concrete fix data.

Every reasoner is total: it *always* returns a valid result. If the LLM is off,
errors, times out, returns junk, or violates its schema, the deterministic
fallback is returned instead. Reasoners never raise, so the pipeline cannot be
taken down by the LLM.

Reasoner A (*exploitability adjudication*) was dropped with the dataset change,
and it is worth saying why rather than leaving dead code around: it refined a
per-dependency ``usage_signal`` ("does our code actually call the vulnerable
function?"), and the new SBOM carries no such column. Exploitability is now
published by the advisory itself, so there is nothing left to adjudicate — it is
read, not inferred.

The metric boundary
-------------------
C and D produce prose; they cannot move a number, ever.

**B can.** Dismissing a CVE changes ``risk_score`` and can flip a dependency from
at-risk to clean. CLAUDE.md forbids an LLM producing a number that feeds a metric,
so B's verdict is *always recorded* and only *applied* when
``LLM_AFFECTS_SCORE=true``. With the default (false) the ruling is shown to a
human on the report and every number stays deterministic and reproducible. That
gate is the whole reason the eval means anything.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from ..models.entities import Application, Dependency, Vulnerability
from ..models.findings import RemediationPlaybook
from . import prompts
from .client import LLMClient


class AttackNarrative(BaseModel):
    narrative: str


class FalsePositiveVerdict(BaseModel):
    """Reasoner B's ruling on a `potential` match."""

    is_false_positive: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str


Decision = Literal["vulnerable", "possible", "not_vulnerable"]


class VulnAssessment(BaseModel):
    """Dependency-level verdict from Reasoner B v2."""

    dep_id: str
    decision: Decision
    confidence: float = Field(ge=0.0, le=100.0)
    reason: str = ""
    likely_cves: list[str] = Field(default_factory=list)
    unlikely_cves: list[str] = Field(default_factory=list)


class VulnAssessmentBatch(BaseModel):
    assessments: list[VulnAssessment] = Field(default_factory=list)


Priority = Literal["P1", "P2", "P3"]


# --------------------------------------------------------------------------- #
# B (v2). Dependency-level assessment that ignores `affected_versions`
# --------------------------------------------------------------------------- #
def assess_dependencies(
    client: LLMClient, items: list[dict]
) -> dict[str, VulnAssessment]:
    """Judge a batch of dependencies. Returns {dep_id: assessment}.

    The model is told explicitly NOT to trust `affected_versions`, because in this
    dataset that field is the broken one — no dependency version ever appears in
    its own library's affected list, while the ground truth still calls 176 of them
    vulnerable. Anchoring on it would make the model dismiss everything.

    Batched because it has to be: 301 dependencies against a key that allows a
    couple of dozen requests a day. The per-dependency reasoning contract is
    unchanged; only the envelope is.

    Deterministic fallback: ``possible`` — keep the finding, at reduced weight.
    When nothing can be established, a security tool must not quietly discard a
    candidate vulnerability. Returns an empty dict on failure so the caller can
    tell "the model said nothing" from "the model said no".
    """
    if not client.enabled or not items:
        return {}

    result = client.complete_model(
        prompts.VULN_ASSESSMENT_SYSTEM,
        prompts.vuln_assessment_user(items),
        VulnAssessmentBatch,
        # One reply covers the whole batch, so the budget has to scale with it.
        max_tokens=min(8192, 220 * len(items) + 512),
    )
    if result is None:
        return {}

    wanted = {it["dep_id"] for it in items}
    return {a.dep_id: a for a in result.assessments if a.dep_id in wanted}


# --------------------------------------------------------------------------- #
# B. False-positive adjudication (POTENTIAL matches only)
# --------------------------------------------------------------------------- #
def adjudicate_false_positive(
    client: LLMClient,
    *,
    dep: Dependency,
    cve: Vulnerability,
) -> FalsePositiveVerdict:
    """Rule on whether a `potential` match is a real exposure or noise.

    A *potential* match is one where the library is named in the advisory but the
    dependency's exact version is not in its `affected_versions` list. That is not
    the same as "safe": advisories routinely enumerate only the versions the
    vendor tested, and backports, distro rebuilds and vendor patch levels fall
    outside the list while still carrying the flaw. It is also not "vulnerable".
    It is genuinely undecided, and this is the reasoner that decides it.

    The model is given the advisory description, the affected list and the actual
    version, and asked one bounded question. It cannot invent a CVE, change a
    score, or reach any conclusion other than true/false — the Pydantic schema is
    the guardrail.

    IMPORTANT — the metric boundary. This verdict can *drop a CVE*, which moves
    `risk_score`. CLAUDE.md forbids an LLM producing a number that feeds a metric,
    so the caller only APPLIES this ruling when `LLM_AFFECTS_SCORE=true`.
    Otherwise the verdict is recorded on the report for a human to read, and every
    number stays deterministic. That is not timidity: it is what makes the run
    reproducible and the eval meaningful.

    Deterministic fallback (and the default): **keep the finding**. When nothing
    can be established, a security tool must not quietly discard a possible
    vulnerability — the safe failure direction is to surface it for review, which
    is exactly what `potential` means.
    """
    fallback = FalsePositiveVerdict(
        is_false_positive=False,
        confidence=0.5,
        reasoning=(
            f"Not adjudicated: {dep.library_name} {dep.version} is not in "
            f"{cve.cve_id}'s affected list ({', '.join(cve.affected_versions) or 'none listed'}), "
            f"but an advisory's list is not proof of safety. Kept for review at "
            f"reduced weight."
        ),
    )
    if not client.enabled:
        return fallback

    result = client.complete_model(
        prompts.FALSE_POSITIVE_SYSTEM,
        prompts.false_positive_user(
            library_name=dep.library_name,
            version=dep.version,
            cve_id=cve.cve_id,
            affected_versions=list(cve.affected_versions),
            fixed_version=cve.fixed_version,
            description=cve.description,
            cvss_score=cve.cvss_score,
        ),
        FalsePositiveVerdict,
    )
    return result or fallback


# --------------------------------------------------------------------------- #
# C. Attack-chain narrative
# --------------------------------------------------------------------------- #
def _deterministic_narrative(
    *,
    app_name: str,
    path_labels: list[str],
    library_name: str,
    version: str,
    cve_id: str,
    cvss_severity: str,
    cvss_score: float,
    hop_distance: int,
    confirmed: bool,
) -> str:
    chain = " -> ".join(path_labels)
    claim = (
        f"That version is listed as affected by {cve_id}"
        if confirmed
        else (
            f"{library_name} is affected by {cve_id}, but version {version} is not "
            f"in the advisory's listed affected versions — treat as unconfirmed"
        )
    )
    return (
        f"{app_name} reaches {library_name} {version} through {chain} "
        f"({hop_distance} hop(s)). {claim} ({cvss_severity}, CVSS {cvss_score})."
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
    confirmed: bool = True,
) -> str:
    """Narrate an already-resolved path. Fallback = a deterministic sentence.

    ``path_labels`` is the resolved chain. The LLM is told the exact path — it
    discovers nothing.
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
        confirmed=confirmed,
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
            confirmed=confirmed,
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
    criticality: str,
    confidence: str,
) -> RemediationPlaybook:
    steps: list[str] = []

    if cve_id:
        if confidence == "potential":
            # Do not tell someone to upgrade against an advisory that never named
            # their version. The first step is to establish whether it applies.
            steps.append(
                f"Confirm whether {cve_id} applies: {library_name} {version} is not "
                f"listed in the advisory's affected versions. Check the upstream "
                f"advisory before scheduling any change."
            )
        if fixed_version:
            steps.append(
                f"Upgrade {library_name} {version} -> {fixed_version} to remediate "
                f"{cve_id}."
            )
        else:
            steps.append(
                f"No patch is published for {cve_id}. Pin {library_name} {version}, "
                f"isolate the vulnerable code path, or replace the library."
            )

    if "transitive_vulnerability" in risk_types:
        steps.append(
            "This arrived as a transitive dependency — bump the direct parent that "
            "pulls it in, or override the transitive pin."
        )

    if license_outcome == "conflict":
        steps.append(
            f"Licence {license_id or 'unknown'} is viral and this application ships "
            f"as a proprietary product. Replace the library, or obtain a commercial "
            f"exception before shipping."
        )
    elif license_outcome == "unknown":
        steps.append(
            f"{library_name} declares no licence. Legal cannot sign this off — "
            f"identify the licence or remove the dependency."
        )

    if is_stale:
        steps.append(
            f"{library_name} has not been updated in over 2 years — evaluate a "
            f"maintained alternative."
        )

    if not steps:
        steps.append("No action required; no risk detected for this dependency.")

    # A confirmed CVE on a business-critical app is a drop-everything. An
    # unconfirmed one never is — that is the whole point of the tier.
    confirmed_cve = bool(cve_id) and confidence == "confirmed"
    if risk_score >= 75 or (confirmed_cve and criticality == "critical"):
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
    confidence: str = "confirmed",
) -> RemediationPlaybook:
    """Remediation steps + priority. Fallback = a deterministic playbook."""
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
        criticality=app.business_criticality.value,
        confidence=confidence,
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
            criticality=app.business_criticality.value,
            license_model=app.license_model.value,
            risk_score=risk_score,
            severity=severity,
            risk_types=risk_types,
            cve_id=cve.cve_id if cve else None,
            fixed_version=cve.fixed_version if cve else None,
            license_id=dep.license,
            license_outcome=license_outcome,
            is_stale=is_stale,
            age_years=age_years,
            confidence=confidence,
        ),
        RemediationPlaybook,
    )
    return result if result and result.steps else fallback
