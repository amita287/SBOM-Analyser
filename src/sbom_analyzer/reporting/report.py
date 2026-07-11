"""Assemble the final ``AnalysisReport`` (Phase 7, Section 9.1).

Deterministic composition: wires the Phase 2–4 detectors and the Section-7 scorer
into per-dependency findings, per-app reports, and a global summary.

The LLM (Phase 6) is layered on *afterwards* and is entirely optional — pass an
enabled :class:`LLMClient` and findings additionally get an adjudicated
exploitability, a false-positive verdict, an attack-chain narrative, and a
remediation playbook. With ``LLM_PROVIDER=none`` every reasoner returns its
deterministic fallback and the report is byte-identical to the no-LLM run.

Determinism: dependencies are processed in dataset (file) order; findings inside
an app are ranked by descending risk score with id as tie-break. The report
carries no wall-clock time — ``generated_at`` is derived from the frozen
reference date, never ``datetime.now()``.
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

from sbom_analyzer.analysis.licenses import LicenseEngine, is_conflict
from sbom_analyzer.analysis.maintenance import TODAY, assess_dependency
from sbom_analyzer.analysis.transitive import classify as classify_transitive
from sbom_analyzer.analysis.vulnerabilities import (
    VulnerabilityMatcher,
    base_vuln_score,
    is_vulnerable,
)
from sbom_analyzer.config import Settings, get_settings
from sbom_analyzer.graph.builder import build_graph
from sbom_analyzer.graph.traversal import paths_to_vulnerable
from sbom_analyzer.ingestion.loaders import Dataset, load_dataset
from sbom_analyzer.llm import reasoners
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
)
from sbom_analyzer.scoring.risk import (
    CveScoreInput,
    score_application,
    score_dependency,
    severity_from_score,
    vulnerability_component,
)

TOP_N_RISKIEST = 10

# A permanently-disabled client. Handed to the reasoners for findings outside the
# LLM budget (and for the whole run when LLM_PROVIDER=none), which sends them down
# their deterministic path. It never makes a call, so its counters never move —
# which is exactly what marks those findings as *not* LLM-enriched.
_NULL_CLIENT = LLMClient(Settings())


def _risk_types(
    *, vulnerable: bool, transitive: bool, conflict: bool, unmaintained: bool
) -> list[RiskType]:
    """Assemble a finding's risk-type list in a canonical, stable order."""
    types: list[RiskType] = []
    if vulnerable:
        types.append(RiskType.vulnerable)
    if transitive:
        types.append(RiskType.transitive_vulnerable)
    if conflict:
        types.append(RiskType.license_conflict)
    if unmaintained:
        types.append(RiskType.unmaintained)
    return types or [RiskType.clean]


def build_report(
    dataset: Dataset | None = None,
    *,
    data_dir: Path | str | None = None,
    today: date = TODAY,
    run_id: str | None = None,
    client: LLMClient | None = None,
    settings: Settings | None = None,
) -> AnalysisReport:
    """Run the full pipeline and return the assembled report.

    ``client`` is optional; when it is ``None`` or disabled, the LLM passes are
    skipped entirely and the result is the pure deterministic report.
    """
    ds = dataset if dataset is not None else load_dataset(data_dir)
    cfg = settings or get_settings()
    llm_on = client is not None and client.enabled

    matcher = VulnerabilityMatcher(ds.vulnerabilities)
    licenses = LicenseEngine(ds.license_rules, ds.applications)
    graph = build_graph(ds.applications, ds.dependencies)

    app_by_id: dict[str, Application] = {a.app_id: a for a in ds.applications}
    cve_by_id: dict[str, Vulnerability] = {v.cve_id: v for v in ds.vulnerabilities}

    # -- pass 1: per-dependency detection facts (deterministic) -----------------
    matched_by: dict[str, list[MatchedVulnerability]] = {}
    base_vuln_by_dep: dict[str, float] = {}
    for dep in ds.dependencies:
        matched = matcher.match(dep)
        matched_by[dep.dependency_id] = matched
        base_vuln_by_dep[dep.dependency_id] = base_vuln_score(matched)

    outcomes = {d.dependency_id: licenses.outcome_for_dependency(d) for d in ds.dependencies}
    maint = {d.dependency_id: assess_dependency(d, today) for d in ds.dependencies}
    exposure = classify_transitive(graph, base_vuln_by_dep)

    # -- pass 1b (optional): LLM adjudication (Reasoners A + B) ----------------
    # Scope: the N riskiest findings by a *deterministic provisional score*, so
    # the same findings get adjudicated (A/B) and narrated (C/D) — one coherent
    # "the riskiest findings get the full LLM treatment" story. Adjudication has
    # to run before final scoring, since it may feed into it.
    usage_override: dict[str, object] = {}
    llm_scope: list[str] = []
    if llm_on:
        provisional = {
            d.dependency_id: _score(
                d, matched_by, outcomes, maint, exposure, {}, today
            ).risk_score
            for d in ds.dependencies
        }
        llm_scope = [
            dep_id
            for dep_id, _ in sorted(
                provisional.items(), key=lambda kv: (-kv[1], kv[0])
            )[: max(0, cfg.llm_max_findings)]
        ]
        usage_override = _adjudicate(
            client=client,
            cfg=cfg,
            scope=llm_scope,
            dep_by_id={d.dependency_id: d for d in ds.dependencies},
            app_by_id=app_by_id,
            cve_by_id=cve_by_id,
            matched_by=matched_by,
            base_vuln_by_dep=base_vuln_by_dep,
        )
        if cfg.llm_affects_score:
            # Adjudication moved base_vuln, so inherited exposure must be redone.
            exposure = classify_transitive(graph, base_vuln_by_dep)

    vulnerable_ids = {d for d, b in base_vuln_by_dep.items() if b > 0.0}

    # -- attack paths, grouped by the vulnerable dependency they terminate at ---
    paths_by_victim: dict[str, list[AttackPath]] = {}
    for app in ds.applications:
        for path in paths_to_vulnerable(graph, app.app_id, vulnerable_ids):
            victim = path[-1]
            hits = matched_by[victim]
            paths_by_victim.setdefault(victim, []).append(
                AttackPath(
                    app_id=app.app_id,
                    path=path,
                    vulnerable_dependency_id=victim,
                    cve_id=hits[0].cve_id if hits else None,
                )
            )

    # -- pass 2: score + build findings ----------------------------------------
    findings_by_app: dict[str, list[DependencyFinding]] = {
        app.app_id: [] for app in ds.applications
    }
    for dep in ds.dependencies:
        matched = matched_by[dep.dependency_id]
        outcome = outcomes[dep.dependency_id]
        maintenance = maint[dep.dependency_id]
        exp = exposure.get(dep.dependency_id)

        score = _score(dep, matched_by, outcomes, maint, exposure, usage_override, today)

        findings_by_app[dep.app_id].append(
            DependencyFinding(
                dependency_id=dep.dependency_id,
                app_id=dep.app_id,
                library_name=dep.library_name,
                version=dep.version,
                ecosystem=dep.ecosystem,
                license=dep.license,
                risk_score=score.risk_score,
                severity=Severity(score.severity),
                risk_types=_risk_types(
                    vulnerable=is_vulnerable(matched),
                    transitive=exp is not None,
                    conflict=is_conflict(outcome),
                    unmaintained=maintenance.is_stale,
                ),
                matched_cves=matched,
                license_outcome=outcome,
                maintenance=maintenance,
                attack_paths=paths_by_victim.get(dep.dependency_id, []),
            )
        )

    # -- per-app roll-up --------------------------------------------------------
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
                app_score=app_score,
                severity=Severity(severity_from_score(app_score)),
                findings=findings,
            )
        )

    # -- pass 3: narratives + remediation for every at-risk finding -------------
    # This pass always runs. Reasoners C and D have deterministic fallbacks, so
    # with LLM_PROVIDER=none every at-risk finding still gets an attack-chain
    # narrative and a remediation playbook — built from the same concrete facts,
    # just phrased by a template. The LLM upgrades the top-N scope (pass 1b's
    # scope, so the same findings are adjudicated *and* narrated); it never
    # decides whether these sections exist.
    _narrate(
        client=client,
        scope=set(llm_scope),
        app_reports=app_reports,
        deps_by_id={d.dependency_id: d for d in ds.dependencies},
        app_by_id=app_by_id,
        cve_by_id=cve_by_id,
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


# --------------------------------------------------------------------------- #
# Scoring (shared by the provisional ranking pass and the final pass)
# --------------------------------------------------------------------------- #
def _score(dep, matched_by, outcomes, maint, exposure, usage_override, today):
    """Section-7 score for one dependency from already-detected facts."""
    matched = matched_by[dep.dependency_id]
    exp = exposure.get(dep.dependency_id)
    return score_dependency(
        cves=[
            CveScoreInput(m.cvss_score, m.patch_available)
            for m in matched
            if not m.is_false_positive
        ],
        usage_signal=usage_override.get(dep.dependency_id, dep.usage_signal),
        license_outcome=outcomes[dep.dependency_id],
        last_updated=dep.last_updated,
        today=today,
        nearest_descendant_base_vuln=exp.nearest_base_vuln if exp else 0.0,
        transitive_hop_distance=exp.hop_distance if exp else 0,
    )


# --------------------------------------------------------------------------- #
# LLM passes (never reached when the client is disabled)
# --------------------------------------------------------------------------- #
def _adjudicate(
    *,
    client: LLMClient,
    cfg: Settings,
    scope: list[str],
    dep_by_id: dict[str, Dependency],
    app_by_id: dict[str, Application],
    cve_by_id: dict[str, Vulnerability],
    matched_by: dict[str, list[MatchedVulnerability]],
    base_vuln_by_dep: dict[str, float],
) -> dict[str, object]:
    """Reasoners A + B over ``scope``.

    Mutates ``matched_by`` / ``base_vuln_by_dep`` **only** when
    ``llm_affects_score`` is set. Otherwise the adjudicated bucket is recorded on
    the ``MatchedVulnerability`` for display and every number stays deterministic.

    Returns the per-dependency usage-signal override for scoring — empty unless
    ``llm_affects_score``.
    """
    usage_override: dict[str, object] = {}

    for dep_id in scope:
        dep = dep_by_id[dep_id]
        matched = matched_by[dep_id]
        if not matched:
            continue  # nothing to adjudicate: A and B are both about CVE matches
        app = app_by_id[dep.app_id]

        for m in matched:
            cve = cve_by_id.get(m.cve_id)
            if cve is None:
                continue

            verdict = reasoners.adjudicate_exploitability(
                client, dep=dep, app=app, cve=cve
            )
            fp = reasoners.adjudicate_false_positive(client, dep=dep, cve=cve)

            m.exploitability = verdict.exploitability  # always recorded (advisory)
            if not cfg.llm_affects_score:
                continue

            # Opt-in only: the adjudications now feed the score.
            usage_override[dep_id] = verdict.exploitability
            m.is_false_positive = fp.is_false_positive
            m.cve_score = (
                0.0
                if fp.is_false_positive
                else vulnerability_component(
                    [CveScoreInput(m.cvss_score, m.patch_available)],
                    verdict.exploitability,
                )
            )

        if cfg.llm_affects_score:
            matched.sort(key=lambda m: (-m.cve_score, m.cve_id))
            base_vuln_by_dep[dep_id] = base_vuln_score(matched)

    return usage_override


def _narrate(
    *,
    client: LLMClient | None,
    scope: set[str],
    app_reports: list[AppRiskReport],
    deps_by_id: dict[str, Dependency],
    app_by_id: dict[str, Application],
    cve_by_id: dict[str, Vulnerability],
) -> None:
    """Reasoners C + D over every at-risk finding.

    Findings inside ``scope`` (the same top-N pass 1b adjudicated) get the real
    client; everything else gets a disabled one, which drives the reasoners down
    their deterministic path. So the sections are always populated, and the
    ``llm_max_findings`` budget still caps what the LLM is actually asked to do.
    """
    targets = [f for app in app_reports for f in app.findings if f.is_risk]

    for finding in targets:
        dep = deps_by_id[finding.dependency_id]
        app = app_by_id[finding.app_id]
        real = [m for m in finding.matched_cves if not m.is_false_positive]
        worst = cve_by_id.get(real[0].cve_id) if real else None

        in_scope = (
            client is not None
            and client.enabled
            and finding.dependency_id in scope
        )
        active = client if in_scope else _NULL_CLIENT

        # Count the calls that *succeed* while enriching this finding. If the
        # provider is down or out of credit, every reasoner below silently returns
        # its fallback — and the finding must not then be labelled LLM-written.
        succeeded_before = active.calls - active.failures

        # C — narrate each already-resolved attack path.
        if worst is not None:
            for ap in finding.attack_paths:
                labels = [app.name] + [
                    f"{deps_by_id[n].library_name}@{deps_by_id[n].version}"
                    for n in ap.path[1:]
                    if n in deps_by_id
                ]
                ap.narrative = reasoners.narrate_attack_path(
                    active,
                    app=app,
                    path_labels=labels,
                    library_name=dep.library_name,
                    version=dep.version,
                    cve=worst,
                    hop_distance=max(0, len(ap.path) - 2),
                )
            if finding.attack_paths:
                finding.narrative = finding.attack_paths[0].narrative

        # D — remediation playbook, grounded in the concrete fix data.
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

    # Blast radius: vulnerable (library, version) pairs present in >1 app.
    apps_per_lib: dict[tuple[str, str], set[str]] = {}
    for f in all_findings:
        if RiskType.vulnerable in f.risk_types:
            apps_per_lib.setdefault((f.library_name, f.version), set()).add(f.app_id)
    shared = {lib: apps for lib, apps in apps_per_lib.items() if len(apps) > 1}
    if shared:
        worst = max(shared.items(), key=lambda kv: len(kv[1]))
        dedup_note = (
            f"{len(shared)} vulnerable library/version pair(s) span multiple apps; "
            f"widest blast radius: {worst[0][0]} {worst[0][1]} in {len(worst[1])} apps."
        )
    else:
        dedup_note = "No vulnerable library/version pair is shared across apps."

    return GlobalSummary(
        totals_per_risk_type=totals,
        top_riskiest=top,
        dedup_note=dedup_note,
    )


def write_report(report: AnalysisReport, path: Path) -> Path:
    """Serialize the report to ``path`` as indented JSON. Returns the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return path
