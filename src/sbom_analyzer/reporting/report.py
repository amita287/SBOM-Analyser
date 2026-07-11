"""Assemble the final ``AnalysisReport`` (Phase 7, Section 9.1).

Pure deterministic composition: it wires the Phase 2–4 detectors and the
Section-7 scorer into per-dependency findings, per-app reports, and a global
summary. No LLM — the ``narrative`` / ``remediation`` fields are left ``None``
here and filled later by the Phase 6 reasoners (which always have a deterministic
fallback, so this report is already complete on its own).

Determinism: dependencies are processed in dataset (file) order; findings inside
an app are ranked by descending risk score with id as tie-break. The report
carries no wall-clock time — ``generated_at`` is derived from the frozen
reference date, never ``datetime.now()``.
"""

from __future__ import annotations

from datetime import date, datetime
from pathlib import Path

import networkx as nx

from sbom_analyzer.analysis.licenses import LicenseEngine, is_conflict
from sbom_analyzer.analysis.maintenance import TODAY, assess_dependency
from sbom_analyzer.analysis.transitive import classify as classify_transitive
from sbom_analyzer.analysis.vulnerabilities import (
    VulnerabilityMatcher,
    base_vuln_score,
    is_vulnerable,
)
from sbom_analyzer.graph.builder import build_graph
from sbom_analyzer.graph.traversal import paths_to_vulnerable
from sbom_analyzer.ingestion.loaders import Dataset, load_dataset
from sbom_analyzer.models.findings import (
    AnalysisReport,
    AppRiskReport,
    AttackPath,
    DependencyFinding,
    GlobalSummary,
    RiskType,
    RiskyDependencyRef,
    Severity,
)
from sbom_analyzer.scoring.risk import (
    CveScoreInput,
    score_application,
    score_dependency,
    severity_from_score,
)

TOP_N_RISKIEST = 10


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
) -> AnalysisReport:
    """Run the full deterministic pipeline and return the assembled report."""
    ds = dataset if dataset is not None else load_dataset(data_dir)

    matcher = VulnerabilityMatcher(ds.vulnerabilities)
    licenses = LicenseEngine(ds.license_rules, ds.applications)
    graph = build_graph(ds.applications, ds.dependencies)

    # -- pass 1: per-dependency detection facts --------------------------------
    matched_by: dict[str, list] = {}
    base_vuln_by_dep: dict[str, float] = {}
    for dep in ds.dependencies:
        matched = matcher.match(dep)
        matched_by[dep.dependency_id] = matched
        base_vuln_by_dep[dep.dependency_id] = base_vuln_score(matched)

    exposure = classify_transitive(graph, base_vuln_by_dep)
    vulnerable_ids = {d for d, b in base_vuln_by_dep.items() if b > 0.0}

    # -- attack paths, grouped by the vulnerable dependency they terminate at ---
    paths_by_victim: dict[str, list[AttackPath]] = {}
    for app in ds.applications:
        for path in paths_to_vulnerable(graph, app.app_id, vulnerable_ids):
            victim = path[-1]
            worst = matched_by[victim]
            cve_id = worst[0].cve_id if worst else None
            paths_by_victim.setdefault(victim, []).append(
                AttackPath(
                    app_id=app.app_id,
                    path=path,
                    vulnerable_dependency_id=victim,
                    cve_id=cve_id,
                )
            )

    # -- pass 2: score + build findings ----------------------------------------
    findings_by_app: dict[str, list[DependencyFinding]] = {
        app.app_id: [] for app in ds.applications
    }
    for dep in ds.dependencies:
        matched = matched_by[dep.dependency_id]
        real_cves = [
            CveScoreInput(m.cvss_score, m.patch_available)
            for m in matched
            if not m.is_false_positive
        ]
        outcome = licenses.outcome_for_dependency(dep)
        maintenance = assess_dependency(dep, today)
        exp = exposure.get(dep.dependency_id)

        score = score_dependency(
            cves=real_cves,
            usage_signal=dep.usage_signal,
            license_outcome=outcome,
            last_updated=dep.last_updated,
            today=today,
            nearest_descendant_base_vuln=exp.nearest_base_vuln if exp else 0.0,
            transitive_hop_distance=exp.hop_distance if exp else 0,
        )

        finding = DependencyFinding(
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
        findings_by_app[dep.app_id].append(finding)

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

    summary = _build_summary(app_reports)

    return AnalysisReport(
        run_id=run_id or f"run-{today.isoformat()}",
        generated_at=datetime(today.year, today.month, today.day),
        apps=app_reports,
        summary=summary,
    )


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
