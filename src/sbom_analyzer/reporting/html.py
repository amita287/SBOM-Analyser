"""Jinja2 HTML rendering of the report (Phase 7, Section 9.2).

Renders a fully self-contained ``reports/report.html`` — no external CSS, JS,
fonts, or images — so it opens offline and survives being mailed around as a
single file.

This module is a *pure view*: it reads an already-assembled
:class:`AnalysisReport` and computes nothing that feeds a metric. Everything it
adds is presentational (sort order, display labels, per-app counts).

Autoescaping is on. Narratives and remediation steps can be LLM-generated, and
model output is untrusted text — it gets escaped like any other input.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..models.findings import AnalysisReport, DependencyFinding, RiskType

TEMPLATE_DIR = Path(__file__).parent / "templates"
TEMPLATE_NAME = "report.html.j2"


def _environment() -> Environment:
    return Environment(
        loader=FileSystemLoader(TEMPLATE_DIR),
        autoescape=True,  # LLM text lands in this page; never trust it raw
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _node_labels(report: AnalysisReport) -> dict[str, str]:
    """dependency_id / app_id -> human label, for rendering attack-path hops.

    ``AttackPath.path`` carries ids (the graph's node keys). A reader needs
    ``jackson-databind 2.14.1``, not ``DEP-00042``.
    """
    labels: dict[str, str] = {app.app_id: app.name for app in report.apps}
    for app in report.apps:
        for f in app.findings:
            labels[f.dependency_id] = f"{f.library_name} {f.version}"
    return labels


def build_context(report: AnalysisReport) -> dict[str, object]:
    """Presentational context for the template."""
    findings: list[DependencyFinding] = [f for app in report.apps for f in app.findings]

    # String-keyed so the template can write `totals.vulnerable`. Every risk type
    # is present, so a zero renders as "0" rather than vanishing.
    totals = {rt.value: 0 for rt in RiskType}
    for rt, count in report.summary.totals_per_risk_type.items():
        totals[rt.value] = count

    return {
        "report": report,
        "apps": sorted(report.apps, key=lambda a: (-a.app_score, a.app_id)),
        "totals": totals,
        "total_deps": len(findings),
        "app_names": {app.app_id: app.name for app in report.apps},
        "node_labels": _node_labels(report),
        "at_risk_counts": {
            app.app_id: sum(1 for f in app.findings if f.is_risk) for app in report.apps
        },
    }


def render_html(report: AnalysisReport) -> str:
    """Render the report to an HTML string."""
    template = _environment().get_template(TEMPLATE_NAME)
    return template.render(**build_context(report))


def write_html(report: AnalysisReport, path: Path) -> Path:
    """Render and write ``reports/report.html``. Returns the path."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(report), encoding="utf-8")
    return path
