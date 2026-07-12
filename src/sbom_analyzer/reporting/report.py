"""Assemble the final ``AnalysisReport``.

Deterministic composition: wires the detectors and the scorer into per-dependency
findings, per-app reports, and a global summary.

The LLM is layered on *afterwards* and is entirely optional — pass an enabled
:class:`LLMClient` and findings additionally get an attack-chain narrative and a
remediation playbook written by the model. With ``LLM_PROVIDER=none`` every
reasoner returns its deterministic fallback and the report is byte-identical to
the no-LLM run. No model output ever reaches a number.

Determinism: dependencies are processed in dataset (file) order; findings inside
an app are ranked by descending risk score with id as tie-break. The report
carries no wall-clock time — ``generated_at`` comes from the frozen reference
date, never ``datetime.now()``.
"""

from __future__ import annotations

import logging

from datetime import date, datetime
from pathlib import Path

from sbom_analyzer.analysis.classify import primary_of, risk_types_for
from sbom_analyzer.analysis.licenses import LicenseEngine
from sbom_analyzer.analysis.maintenance import TODAY, assess_dependency
from sbom_analyzer.analysis.transitive import classify as classify_exposure
from sbom_analyzer.analysis.vulnerabilities import (
    VulnerabilityMatcher,
    base_vuln_for,
    version_is_affected,
)
from sbom_analyzer.config import Settings, get_settings
from sbom_analyzer.graph.builder import (
    NODE_KIND_EXT,
    build_graph,
    external_node_id,
)
from sbom_analyzer.graph.traversal import paths_to_vulnerable
from sbom_analyzer.ingestion.loaders import Dataset, load_dataset
from sbom_analyzer.llm import reasoners
from sbom_analyzer.llm.cache import VerdictCache
from sbom_analyzer.llm.client import LLMClient
from sbom_analyzer.models.entities import Application, Dependency, Vulnerability
from sbom_analyzer.models.findings import (
    AnalysisReport,
    AppRiskReport,
    AttackPath,
    DependencyFinding,
    GlobalSummary,
    MatchedVulnerability,
    RiskType,
    RiskyDependencyRef,
    Severity,
    TransitiveChild,
    VulnConfidence,
    VulnStatus,
)
from sbom_analyzer.scoring.risk import (
    CveScoreInput,
    score_application,
    score_dependency,
    severity_for_finding,
    severity_from_score,
    vulnerability_component,
)

logger = logging.getLogger(__name__)

TOP_N_RISKIEST = 10

VULN_TYPES = (RiskType.vulnerable_dependency, RiskType.transitive_vulnerability)

# A permanently-disabled client, handed to the reasoners for findings outside the
# LLM budget (and for the whole run when LLM_PROVIDER=none), which sends them down
# their deterministic path. It never makes a call, so its counters never move —
# which is exactly what marks those findings as *not* LLM-enriched.
_NULL_CLIENT = LLMClient(Settings())


def _cve_inputs(matched: list[MatchedVulnerability]) -> list[CveScoreInput]:
    return [
        CveScoreInput(
            cvss_score=m.cvss_score,
            patch_available=m.patch_available,
            exploitability=m.exploitability.value,
            confidence=m.confidence.value,
        )
        for m in matched
    ]


def build_report(
    dataset: Dataset | None = None,
    *,
    data_dir: Path | str | None = None,
    today: date = TODAY,
    run_id: str | None = None,
    client: LLMClient | None = None,
    settings: Settings | None = None,
) -> AnalysisReport:
    """Run the full pipeline and return the assembled report."""
    ds = dataset if dataset is not None else load_dataset(data_dir)
    cfg = settings or get_settings()
    llm_on = client is not None and client.enabled

    matcher = VulnerabilityMatcher(ds.vulnerabilities)
    licenses = LicenseEngine(ds.license_rules, ds.applications)
    graph = build_graph(ds.applications, ds.dependencies)

    app_by_id: dict[str, Application] = {a.app_id: a for a in ds.applications}
    dep_by_id: dict[str, Dependency] = {d.dependency_id: d for d in ds.dependencies}
    cve_by_id: dict[str, Vulnerability] = {v.cve_id: v for v in ds.vulnerabilities}

    # -- pass 1: per-dependency detection facts (deterministic) ---------------- #
    matched_by: dict[str, list[MatchedVulnerability]] = {}
    base_vuln_by_node: dict[str, float] = {}
    for dep in ds.dependencies:
        matched = matcher.match(dep)
        matched_by[dep.dependency_id] = matched
        base_vuln_by_node[dep.dependency_id] = base_vuln_for(matched)

    # Phantom transitive children are not SBOM rows and are never scored — but a
    # vulnerable one is a real exposure for the dependency that pulls it in, and
    # it is what the attack paths are drawn through. Score them as graph nodes
    # only; they never become findings, so they cannot move a metric.
    children_by_dep: dict[str, list[TransitiveChild]] = {}
    for dep in ds.dependencies:
        kids: list[TransitiveChild] = []
        for child in dep.transitive_children:
            advisories = matcher.candidates(child.library_name)
            # Score the phantom through the same scorer as everything else. A
            # child's version is never in an advisory's affected set in this
            # dataset either, so it is a `potential` match by construction — and
            # must be weighted like one rather than scored by a bespoke formula.
            node = external_node_id(dep.app_id, child.library_name, child.version)
            base_vuln_by_node[node] = max(
                (
                    vulnerability_component(
                        [
                            CveScoreInput(
                                cvss_score=c.cvss_score,
                                patch_available=c.patch_available,
                                exploitability=c.exploitability.value,
                                confidence=(
                                    VulnConfidence.confirmed.value
                                    if version_is_affected(
                                        child.version, c.affected_versions
                                    )
                                    else VulnConfidence.potential.value
                                ),
                            )
                        ]
                    )
                    for c in advisories
                ),
                default=0.0,
            )
            kids.append(
                TransitiveChild(
                    library_name=child.library_name,
                    version=child.version,
                    cve_ids=[c.cve_id for c in advisories],
                )
            )
        children_by_dep[dep.dependency_id] = kids

    # -- pass 1b: Reasoner B — adjudicate every POTENTIAL match ---------------- #
    # A `potential` match is a genuine judgement call: the library is named in the
    # advisory, the version is not. Rather than guess, we ask — and we record the
    # answer whether or not we act on it.
    #
    # The ruling only *changes the numbers* when LLM_AFFECTS_SCORE is set. With
    # the default it is advisory: the report shows what the model concluded and
    # every score stays deterministic. Without that gate the eval would be
    # measuring the model's mood, not the analyzer.
    _adjudicate(
        client=client,
        cfg=cfg,
        dep_by_id=dep_by_id,
        cve_by_id=cve_by_id,
        matched_by=matched_by,
    )
    if llm_on and cfg.llm_affects_score:
        # Dismissals removed CVEs, so base_vuln has to be recomputed from what
        # actually survived.
        for dep_id, matched in matched_by.items():
            base_vuln_by_node[dep_id] = base_vuln_for(
                [m for m in matched if not m.dismissed]
            )

    outcomes = {
        d.dependency_id: licenses.outcome_for_dependency(d) for d in ds.dependencies
    }
    maint = {d.dependency_id: assess_dependency(d, today) for d in ds.dependencies}
    exposure = classify_exposure(graph, base_vuln_by_node)

    # -- attack paths, grouped by the node they terminate at ------------------- #
    vulnerable_nodes = {n for n, b in base_vuln_by_node.items() if b > 0.0}
    paths_by_victim: dict[str, list[AttackPath]] = {}
    for app in ds.applications:
        for path in paths_to_vulnerable(graph, app.app_id, vulnerable_nodes):
            victim = path[-1]
            hits = matched_by.get(victim, [])
            paths_by_victim.setdefault(victim, []).append(
                AttackPath(
                    app_id=app.app_id,
                    path=path,
                    vulnerable_dependency_id=victim,
                    cve_id=hits[0].cve_id if hits else None,
                )
            )

    # -- pass 2: score + build findings ---------------------------------------- #
    findings_by_app: dict[str, list[DependencyFinding]] = {
        app.app_id: [] for app in ds.applications
    }
    for dep in ds.dependencies:
        matched = matched_by[dep.dependency_id]
        outcome = outcomes[dep.dependency_id]
        maintenance = maint[dep.dependency_id]
        exp = exposure.get(dep.dependency_id)

        # A CVE Reasoner B ruled out no longer counts — not toward the score, not
        # toward the risk type, not toward severity. It stays ON the report,
        # struck through, so the judgement is auditable rather than invisible.
        live = [m for m in matched if not m.dismissed]

        # Which matches are allowed to make this dependency "vulnerable"?
        # Under strict matching only a CONFIRMED advisory hit counts; by default a
        # POTENTIAL one does too. See Settings.strict_version_matching — that flag
        # is the entire difference between over-flagging and going blind, and the
        # right answer depends on whether the advisory data can be trusted.
        classifying = (
            [m for m in live if m.is_confirmed] if cfg.strict_version_matching else live
        )

        score = score_dependency(
            cves=_cve_inputs(live),
            license_outcome=outcome,
            last_updated=dep.last_updated,
            today=today,
            nearest_descendant_base_vuln=exp.nearest_base_vuln if exp else 0.0,
            transitive_hop_distance=exp.hop_distance if exp else 0,
        )

        types = risk_types_for(
            dependency_type=dep.dependency_type,
            matched_cves=classifying,
            license_outcome=outcome,
            is_stale=maintenance.is_stale,
        )
        primary = primary_of(types)

        # Severity classifies the *kind* of problem; risk_score ranks it. They are
        # different questions, so severity is not a band of the score — see
        # `severity_for_finding`.
        # Worst by CVSS, not by our own weighted cve_score: severity mirrors what
        # the advisory says, and `matched[0]` is ordered by contribution (which
        # folds in patch/exploitability/confidence) — a different CVE entirely.
        worst_cvss = max(live, key=lambda m: m.cvss_score, default=None)
        severity = severity_for_finding(
            primary_risk_type=primary.value,
            worst_cve_severity=worst_cvss.cvss_severity.value if worst_cvss else None,
            license_id=dep.license,
            age_years=maintenance.age_years,
        )

        findings_by_app[dep.app_id].append(
            DependencyFinding(
                dependency_id=dep.dependency_id,
                app_id=dep.app_id,
                library_name=dep.library_name,
                version=dep.version,
                license=dep.license,
                dependency_type=dep.dependency_type,
                risk_score=score.risk_score,
                severity=Severity(severity),
                risk_types=types,
                primary_risk_type=primary,
                matched_cves=matched,
                vuln_status=_status_of(matched),
                license_outcome=outcome,
                maintenance=maintenance,
                transitive_children=children_by_dep[dep.dependency_id],
                attack_paths=paths_by_victim.get(dep.dependency_id, []),
            )
        )

    # -- per-app roll-up -------------------------------------------------------- #
    app_reports: list[AppRiskReport] = []
    for app in ds.applications:
        findings = findings_by_app[app.app_id]
        findings.sort(key=lambda f: (-f.risk_score, f.dependency_id))
        app_score = score_application(
            [f.risk_score for f in findings],
            [f.severity.value for f in findings],
            app.business_criticality,
        )
        app_reports.append(
            AppRiskReport(
                app_id=app.app_id,
                name=app.name,
                business_criticality=app.business_criticality,
                owner=app.owner,
                environment=app.environment.value,
                license_model=app.license_model.value,
                app_score=app_score,
                severity=Severity(severity_from_score(app_score)),
                findings=findings,
            )
        )

    # -- pass 3: narratives + remediation for every at-risk finding ------------- #
    llm_scope: set[str] = set()
    if llm_on:
        ranked = sorted(
            (f for a in app_reports for f in a.findings if f.is_risk),
            key=lambda f: (-f.risk_score, f.dependency_id),
        )
        llm_scope = {
            f.dependency_id for f in ranked[: max(0, cfg.llm_max_findings)]
        }

    _narrate(
        client=client,
        scope=llm_scope,
        app_reports=app_reports,
        deps_by_id=dep_by_id,
        app_by_id=app_by_id,
        cve_by_id=cve_by_id,
        graph_labels=_graph_labels(graph, dep_by_id, app_by_id),
    )

    return AnalysisReport(
        run_id=run_id or f"run-{today.isoformat()}",
        generated_at=datetime(today.year, today.month, today.day),
        llm_provider=cfg.llm_provider.value if llm_on else "none",
        llm_affects_score=bool(llm_on and cfg.llm_affects_score),
        llm_calls=client.calls if llm_on else 0,
        llm_fallbacks=client.failures if llm_on else 0,
        apps=app_reports,
        summary=_build_summary(app_reports),
    )


def _adjudicate(
    *,
    client: LLMClient | None,
    cfg: Settings,
    dep_by_id: dict[str, Dependency],
    cve_by_id: dict[str, Vulnerability],
    matched_by: dict[str, list[MatchedVulnerability]],
) -> None:
    """Reasoner B over the `potential` matches.

    A *confirmed* match needs no ruling — the advisory names the version. Only the
    ambiguous ones are put to the model.

    **Budgeted.** This dataset produces 579 potential matches. Adjudicating all of
    them is 579 API calls, which on a free-tier key is roughly 29x the daily quota
    and on a paid one is a bill nobody agreed to. So the LLM is spent on the
    riskiest ``LLM_MAX_FINDINGS`` dependencies — the ones a human would actually
    open — and everything else takes the deterministic fallback. Every match still
    gets a recorded verdict either way; the budget decides *who wrote it*, not
    whether the report is complete.

    Mutates `matched_by` in place. `dismissed` is only SET when
    ``llm_affects_score`` is on; otherwise the ruling is advisory and every number
    stays deterministic.
    """
    live = client if (client is not None and client.enabled) else None
    apply_it = bool(live and cfg.llm_affects_score)

    # Only the ambiguous ones are put to the model.
    pending = [
        d
        for d, ms in matched_by.items()
        if ms and any(not m.is_confirmed and not m.dismissed for m in ms)
    ]
    pending.sort(
        key=lambda d: (-max((m.cve_score for m in matched_by[d]), default=0.0), d)
    )

    cache = VerdictCache(cfg.reports_dir / "llm_verdicts.json")
    verdicts: dict[str, reasoners.VulnAssessment] = {}

    def payload(dep_id: str) -> dict:
        dep = dep_by_id[dep_id]
        return {
            "dep_id": dep_id,
            "library": dep.library_name,
            "version": dep.version,
            "last_updated": dep.last_updated.isoformat(),
            "cves": [
                {
                    "cve_id": m.cve_id,
                    "cvss_score": m.cvss_score,
                    "severity": m.cvss_severity.value,
                    "exploitability": m.exploitability.value,
                    "published_date": (
                        c.published_date.isoformat()
                        if (c := cve_by_id.get(m.cve_id)) and c.published_date
                        else "unknown"
                    ),
                    "fixed_version": m.fixed_version,
                    "description": m.description,
                }
                for m in matched_by[dep_id]
                if not m.is_confirmed
            ],
        }

    if live:
        # Cache first: a free-tier key allows a couple of dozen calls a day and
        # there are 301 dependencies. Without this, the second run of the day is
        # all 429s and silently degrades to templates while still *looking* like
        # an LLM run.
        todo: list[dict] = []
        for dep_id in pending:
            item = payload(dep_id)
            key = VerdictCache.key(
                item["library"], item["version"], [c["cve_id"] for c in item["cves"]]
            )
            cached = cache.get(key)
            if cached:
                verdicts[dep_id] = reasoners.VulnAssessment.model_validate(
                    {**cached, "dep_id": dep_id}
                )
            else:
                todo.append(item)

        # Batch: one request carries many dependencies. A call per dependency
        # simply cannot run inside the quota.
        for i in range(0, len(todo), cfg.llm_batch_size):
            batch = todo[i : i + cfg.llm_batch_size]
            got = reasoners.assess_dependencies(live, batch)
            for dep_id, a in got.items():
                verdicts[dep_id] = a
                item = next(x for x in batch if x["dep_id"] == dep_id)
                cache.put(
                    VerdictCache.key(
                        item["library"],
                        item["version"],
                        [c["cve_id"] for c in item["cves"]],
                    ),
                    a.model_dump(exclude={"dep_id"}),
                )
            if not got:
                # Quota exhausted or the provider is down. Stop asking; the rest
                # take the deterministic fallback, and the report says so.
                break

        cache.save()

    # Record the verdict on every potential match — LLM-written where we have one,
    # deterministic otherwise. The report must be complete either way.
    for dep_id, matched in matched_by.items():
        dep = dep_by_id[dep_id]
        a = verdicts.get(dep_id)

        for m in matched:
            if m.is_confirmed:
                continue  # the advisory already settled this one

            if a is None:
                m.adjudication = (
                    f"Not adjudicated: {dep.library_name} {dep.version} is not in "
                    f"{m.cve_id}'s affected list, but an advisory's list is not proof "
                    f"of safety. Kept for review at reduced weight."
                )
                m.adjudicated_by_llm = False
                continue

            m.adjudication = f"{a.decision} ({a.confidence:.0f}% confidence) — {a.reason}"
            m.adjudicated_by_llm = True

            # Only an LLM ruling may dismiss, and only when the score gate is open.
            # The fallback never dismisses: it exists to KEEP a finding, not to
            # delete one on the model's behalf.
            ruled_out = (
                a.decision == "not_vulnerable" or m.cve_id in set(a.unlikely_cves)
            ) and m.cve_id not in set(a.likely_cves)

            if apply_it and ruled_out:
                m.dismissed = True
                m.cve_score = 0.0

        if apply_it:
            matched.sort(key=lambda m: (-m.cve_score, m.cve_id))

    if live:
        logger.info(
            "Reasoner B: %d verdicts (%d cached, %d fetched) over %d dependencies",
            len(verdicts),
            cache.hits,
            len(verdicts) - cache.hits,
            len(pending),
        )


def _status_of(matched: list[MatchedVulnerability]) -> VulnStatus:
    """The headline vulnerability verdict for a finding."""
    if not matched:
        return VulnStatus.not_vulnerable
    if any(m.is_confirmed and not m.dismissed for m in matched):
        return VulnStatus.confirmed_vulnerable
    if any(not m.dismissed for m in matched):
        return VulnStatus.potential_vulnerable
    # Every match was ruled out by Reasoner B.
    return VulnStatus.dismissed


def _graph_labels(graph, dep_by_id, app_by_id) -> dict[str, str]:
    """Human labels for every node id, so a path can be read aloud."""
    labels: dict[str, str] = {}
    for node, data in graph.nodes(data=True):
        if data.get("kind") == NODE_KIND_EXT:
            labels[node] = f"{data['library_name']}@{data['version']}"
        elif node in dep_by_id:
            d = dep_by_id[node]
            labels[node] = f"{d.library_name}@{d.version}"
        elif node in app_by_id:
            labels[node] = app_by_id[node].name
    return labels


# --------------------------------------------------------------------------- #
# LLM pass (reasoners fall back deterministically when the client is disabled)
# --------------------------------------------------------------------------- #
def _narrate(
    *,
    client: LLMClient | None,
    scope: set[str],
    app_reports: list[AppRiskReport],
    deps_by_id: dict[str, Dependency],
    app_by_id: dict[str, Application],
    cve_by_id: dict[str, Vulnerability],
    graph_labels: dict[str, str],
) -> None:
    """Narrative + remediation for every at-risk finding.

    This pass always runs. The reasoners have deterministic fallbacks, so with
    LLM_PROVIDER=none every at-risk finding still gets an attack-chain narrative
    and a remediation playbook — built from the same concrete facts, just phrased
    by a template. The LLM upgrades the top-N scope; it never decides whether
    these sections exist.
    """
    for app_report in app_reports:
        app = app_by_id[app_report.app_id]

        for finding in app_report.findings:
            if not finding.is_risk:
                continue

            dep = deps_by_id[finding.dependency_id]
            worst = (
                cve_by_id.get(finding.matched_cves[0].cve_id)
                if finding.matched_cves
                else None
            )

            in_scope = (
                client is not None
                and client.enabled
                and finding.dependency_id in scope
            )
            active = client if in_scope else _NULL_CLIENT

            # Count the calls that *succeed* while enriching this finding. If the
            # provider is down or out of credit, every reasoner below silently
            # returns its fallback — and the finding must not then be labelled
            # LLM-written.
            succeeded_before = active.calls - active.failures

            confirmed = bool(finding.matched_cves) and finding.matched_cves[0].is_confirmed

            if worst is not None:
                for ap in finding.attack_paths:
                    labels = [graph_labels.get(n, n) for n in ap.path]
                    ap.narrative = reasoners.narrate_attack_path(
                        active,
                        app=app,
                        path_labels=labels,
                        library_name=dep.library_name,
                        version=dep.version,
                        cve=worst,
                        hop_distance=max(0, len(ap.path) - 2),
                        confirmed=confirmed,
                    )
                if finding.attack_paths:
                    finding.narrative = finding.attack_paths[0].narrative

            finding.remediation = reasoners.build_remediation(
                active,
                dep=dep,
                app=app,
                risk_score=finding.risk_score,
                severity=finding.severity.value,
                risk_types=[rt.value for rt in finding.risk_types],
                cve=worst,
                license_outcome=finding.license_outcome.value,
                is_stale=bool(finding.maintenance and finding.maintenance.is_stale),
                age_years=finding.maintenance.age_years if finding.maintenance else 0.0,
                confidence=(
                    finding.matched_cves[0].confidence.value
                    if finding.matched_cves
                    else "confirmed"
                ),
            )

            finding.llm_enriched = (active.calls - active.failures) > succeeded_before


# --------------------------------------------------------------------------- #
# Global summary
# --------------------------------------------------------------------------- #
def _build_summary(app_reports: list[AppRiskReport]) -> GlobalSummary:
    """Totals per risk type, global top-N, and a blast-radius dedup note."""
    all_findings = [f for app in app_reports for f in app.findings]

    totals: dict[RiskType, int] = {rt: 0 for rt in RiskType}
    for f in all_findings:
        for rt in f.risk_types:
            totals[rt] += 1

    ranked = sorted(all_findings, key=lambda f: (-f.risk_score, f.dependency_id))
    top = [
        RiskyDependencyRef(
            dependency_id=f.dependency_id,
            app_id=f.app_id,
            library_name=f.library_name,
            version=f.version,
            risk_score=f.risk_score,
            severity=f.severity,
        )
        for f in ranked[:TOP_N_RISKIEST]
    ]

    # Blast radius: vulnerable (library, version) pairs present in more than one app.
    apps_per_lib: dict[tuple[str, str], set[str]] = {}
    for f in all_findings:
        if any(rt in VULN_TYPES for rt in f.risk_types):
            apps_per_lib.setdefault((f.library_name, f.version), set()).add(f.app_id)
    shared = {lib: apps for lib, apps in apps_per_lib.items() if len(apps) > 1}

    if shared:
        worst = max(shared.items(), key=lambda kv: (len(kv[1]), kv[0]))
        dedup_note = (
            f"{len(shared)} vulnerable library/version pair(s) span multiple apps; "
            f"widest blast radius: {worst[0][0]} {worst[0][1]} in {len(worst[1])} apps."
        )
    else:
        dedup_note = "No vulnerable library/version pair is shared across apps."

    return GlobalSummary(
        totals_per_risk_type=totals, top_riskiest=top, dedup_note=dedup_note
    )


def write_report(report: AnalysisReport, path: Path) -> Path:
    """Serialize the report to ``path`` as indented JSON. Returns the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path
