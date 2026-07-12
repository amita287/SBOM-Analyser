"""Shared fixtures.

Two flavours of input:

- ``tiny_*`` — hand-built objects, for testing one rule in isolation.
- ``real_report`` — the actual pipeline over the actual ``data/`` directory,
  built once per session. The derived detection rules were reverse-engineered
  from that dataset, so the tests that lock them in have to run against it.
"""

from __future__ import annotations

from datetime import date

import pytest

from sbom_analyzer.ingestion.loaders import load_dataset
from sbom_analyzer.models.entities import (
    Application,
    Dependency,
    LicenseRules,
    Vulnerability,
)
from sbom_analyzer.reporting.report import build_report

TODAY = date(2026, 4, 15)


@pytest.fixture(scope="session")
def dataset():
    return load_dataset()


@pytest.fixture(scope="session")
def real_report(dataset):
    """The full deterministic pipeline over the shipped dataset."""
    return build_report(dataset, today=TODAY)


# --------------------------------------------------------------------------- #
# Hand-built pieces, in the dataset's own on-disk shape (aliases exercised).
# --------------------------------------------------------------------------- #
def make_app(**over) -> Application:
    raw = {
        "app_id": "APP-001",
        "name": "CustomerPortal",
        "language": "Java",
        "criticality": "HIGH",
        "license_model": "proprietary",
        "business_owner": "Sarah Chen",
        "department": "Engineering",
        "deployment": "cloud",
    }
    raw.update(over)
    return Application.model_validate(raw)


def make_dep(**over) -> Dependency:
    raw = {
        "dep_id": "DEP-0001",
        "application_id": "APP-001",
        "application_name": "CustomerPortal",
        "library": "micrometer-core",
        "version": "3.0.10",
        "license": "Apache-2.0",
        "dependency_type": "direct",
        "last_updated": "2025-01-30",
        "transitive_deps": "",
    }
    raw.update(over)
    return Dependency.model_validate(raw)


def make_cve(**over) -> Vulnerability:
    raw = {
        "cve_id": "CVE-2026-1050",
        "library": "micrometer-core",
        "affected_versions": ["4.1.0", "4.4.0"],
        "fixed_version": None,
        "cvss_score": 6.1,
        "severity": "MEDIUM",
        "exploitability": "LOW",
        "description": "Authentication bypass",
        "patch_available": False,
        "published_date": "2026-02-24",
    }
    raw.update(over)
    return Vulnerability.model_validate(raw)


def make_rules() -> LicenseRules:
    return LicenseRules.model_validate(
        {
            "rules": [
                {
                    "license": "Apache-2.0",
                    "spdx": "Apache-2.0",
                    "risk_level": "LOW",
                    "compatible_with_proprietary": True,
                    "viral": False,
                },
                {
                    "license": "GPL-3.0-only",
                    "spdx": "GPL-3.0-only",
                    "risk_level": "CRITICAL",
                    "compatible_with_proprietary": False,
                    "viral": True,
                },
                {
                    "license": "NOASSERTION",
                    "spdx": "NOASSERTION",
                    "risk_level": "HIGH",
                    "compatible_with_proprietary": False,
                    "viral": False,
                },
            ]
        }
    )


@pytest.fixture
def app():
    return make_app()


@pytest.fixture
def rules():
    return make_rules()
