"""CLI entrypoint for a full analysis run (Phases 2-7).

Loads and validates the data, builds the dependency graph, runs every
deterministic analyzer, scores each dependency and app, assembles the
``AnalysisReport``, and writes both ``reports/analysis.json`` (canonical,
machine-readable — what the eval harness reads) and ``reports/report.html``
(the human view).

The LLM layer is optional. With ``LLM_PROVIDER=none`` (the default) every
reasoner uses its deterministic fallback and the report is complete on
deterministic signals alone — the LLM is an enhancement, never a dependency.
Uses the frozen reference date, never ``datetime.now()``.
"""

from __future__ import annotations

from sbom_analyzer.config import get_settings
from sbom_analyzer.ingestion.loaders import load_dataset
from sbom_analyzer.llm.client import LLMClient
from sbom_analyzer.models.findings import RiskType
from sbom_analyzer.reporting.html import write_html
from sbom_analyzer.reporting.report import build_report, write_report


def main() -> None:
    settings = get_settings()
    data_dir = settings.data_dir
    out_path = settings.reports_dir / "analysis.json"
    html_path = settings.reports_dir / "report.html"

    print(f"Loading + validating data from {data_dir} ...")
    dataset = load_dataset(data_dir)
    print(
        f"  apps={len(dataset.applications)}  deps={len(dataset.dependencies)}  "
        f"vulns={len(dataset.vulnerabilities)}"
    )

    client = LLMClient(settings)
    if client.enabled:
        scope = "and MAY affect scores" if settings.llm_affects_score else "advisory only"
        print(
            f"LLM enabled: provider={settings.llm_provider.value} "
            f"model={settings.llm_model or '(default)'} "
            f"max_findings={settings.llm_max_findings} ({scope})"
        )
    else:
        print("LLM disabled (LLM_PROVIDER=none) — deterministic fallbacks only.")

    print("Building graph, running analysis, scoring ...")
    report = build_report(dataset, client=client, settings=settings)

    write_report(report, out_path)
    write_html(report, html_path)

    totals = report.summary.totals_per_risk_type
    n_findings = sum(len(app.findings) for app in report.apps)
    at_risk = sum(
        1
        for app in report.apps
        for f in app.findings
        if f.risk_types != [RiskType.clean]
    )
    print(f"Wrote {out_path}")
    print(f"Wrote {html_path}")
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

    # A silent degradation to fallbacks is correct, but must never be invisible:
    # an out-of-credit key or a dead endpoint has to be reported, not papered over.
    if client.enabled:
        ok = client.calls - client.failures
        print(f"  LLM: {client.calls} calls, {ok} succeeded, {client.failures} fell back")
        if client.failures:
            print(f"  WARNING: LLM degraded to deterministic fallbacks.")
            print(f"           last error: {client.last_error}")


if __name__ == "__main__":
    main()
