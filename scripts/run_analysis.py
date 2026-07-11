"""CLI entrypoint for a full analysis run (Phases 2-7).

Loads and validates the data, builds the dependency graph, runs every
deterministic analyzer, scores each dependency and app, assembles the
``AnalysisReport``, and writes ``reports/analysis.json``.

Runs entirely without an LLM: the report is complete from deterministic signals
alone (the LLM layer is a later, optional enhancement). Uses the frozen
reference date, never ``datetime.now()``.
"""

from __future__ import annotations

from sbom_analyzer.config import get_settings
from sbom_analyzer.ingestion.loaders import load_dataset
from sbom_analyzer.models.findings import RiskType
from sbom_analyzer.reporting.report import build_report, write_report


def main() -> None:
    settings = get_settings()
    data_dir = settings.data_dir
    out_path = settings.reports_dir / "analysis.json"

    print(f"Loading + validating data from {data_dir} ...")
    dataset = load_dataset(data_dir)
    print(
        f"  apps={len(dataset.applications)}  deps={len(dataset.dependencies)}  "
        f"vulns={len(dataset.vulnerabilities)}"
    )

    print("Building graph, running analysis, scoring ...")
    report = build_report(dataset)

    write_report(report, out_path)

    totals = report.summary.totals_per_risk_type
    n_findings = sum(len(app.findings) for app in report.apps)
    at_risk = sum(
        1
        for app in report.apps
        for f in app.findings
        if f.risk_types != [RiskType.clean]
    )
    print(f"Wrote {out_path}")
    print(f"  findings={n_findings}  at_risk={at_risk}")
    print(
        "  by type: "
        + "  ".join(
            f"{rt.value}={totals.get(rt, 0)}"
            for rt in (
                RiskType.vulnerable,
                RiskType.transitive_vulnerable,
                RiskType.license_conflict,
                RiskType.unmaintained,
                RiskType.clean,
            )
        )
    )
    top = report.summary.top_riskiest
    if top:
        t = top[0]
        print(
            f"  riskiest: {t.library_name} {t.version} "
            f"({t.risk_score:.1f}, {t.severity.value}) in {t.app_id}"
        )


if __name__ == "__main__":
    main()
