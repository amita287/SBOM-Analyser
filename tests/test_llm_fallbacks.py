"""LLM reasoner + fallback tests (Phase 6, Section 8.6).

The contract under test: **a failed LLM call must never crash the analysis or
corrupt a metric.** Every failure mode — provider off, network error, malformed
JSON, schema violation, invented enum value — must land on the deterministic
fallback.

The provider transport is stubbed at ``LLMClient._raw_complete``, so no network
call is ever made.
"""

from __future__ import annotations

import json
from datetime import date

import pytest

from sbom_analyzer.config import LLMProvider, Settings
from sbom_analyzer.llm import reasoners
from sbom_analyzer.llm.client import LLMClient, strict_json_schema
from sbom_analyzer.llm.reasoners import (
    ExploitabilityVerdict,
    adjudicate_exploitability,
    adjudicate_false_positive,
    build_remediation,
    narrate_attack_path,
)
from sbom_analyzer.models.entities import Application, Dependency, Vulnerability


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
def _app(distributed: bool = True) -> Application:
    return Application(
        app_id="APP-001",
        name="customer-portal",
        business_criticality="critical",
        owner="team-x",
        environment="production",
        internet_facing=True,
        distributed=distributed,
    )


def _dep(version: str = "2.14.1", usage: str = "imports_only") -> Dependency:
    return Dependency(
        dependency_id="DEP-00001",
        app_id="APP-001",
        library_name="log4j-core",
        version=version,
        license="Apache-2.0",
        dependency_type="direct",
        parent_dependency_id="",
        last_updated=date(2025, 1, 1),
        ecosystem="maven",
        usage_signal=usage,
    )


def _cve(
    *, backported: list[str] | None = None, fixed: str | None = "2.15.0"
) -> Vulnerability:
    return Vulnerability(
        cve_id="CVE-2021-44228",
        library_name="log4j-core",
        affected_versions=">=2.0,<2.15.0",
        cvss_score=10.0,
        cvss_severity="critical",
        patch_available=True,
        fixed_version=fixed,
        vulnerable_function="JndiLookup.lookup",
        backported_patch_builds=backported or [],
        description="JNDI lookup allows remote code execution.",
    )


def _client(provider: LLMProvider = LLMProvider.anthropic) -> LLMClient:
    return LLMClient(Settings(llm_provider=provider, llm_model="test-model"))


def _stub(client: LLMClient, monkeypatch: pytest.MonkeyPatch, behaviour) -> list[int]:
    """Replace the transport. `behaviour` is a str to return or an Exception."""
    calls: list[int] = []

    def fake(system, user, schema, max_tokens):  # noqa: ANN001
        calls.append(1)
        if isinstance(behaviour, Exception):
            raise behaviour
        return behaviour

    monkeypatch.setattr(client, "_raw_complete", fake)
    return calls


# --------------------------------------------------------------------------- #
# Client — the disabled path
# --------------------------------------------------------------------------- #
def test_disabled_client_returns_none() -> None:
    client = _client(LLMProvider.none)
    assert client.enabled is False
    assert client.complete_json("sys", "user") is None
    assert client.complete_model("sys", "user", ExploitabilityVerdict) is None


# --------------------------------------------------------------------------- #
# Client — every failure mode collapses to None (never raises)
# --------------------------------------------------------------------------- #
def test_network_error_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    _stub(client, monkeypatch, ConnectionError("connection reset"))
    assert client.complete_json("sys", "user") is None  # no exception escapes


def test_malformed_json_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    _stub(client, monkeypatch, "I'm afraid I can't do that, Dave.")
    assert client.complete_json("sys", "user") is None


def test_schema_violation_returns_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Well-formed JSON, but "banana" is not one of the three buckets.
    client = _client()
    _stub(
        client,
        monkeypatch,
        json.dumps({"exploitability": "banana", "confidence": 0.9, "reasoning": "x"}),
    )
    assert client.complete_model("sys", "user", ExploitabilityVerdict) is None


def test_json_fences_are_tolerated(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    _stub(
        client,
        monkeypatch,
        '```json\n{"exploitability": "not_referenced", "confidence": 0.5, '
        '"reasoning": "ok"}\n```',
    )
    out = client.complete_model("sys", "user", ExploitabilityVerdict)
    assert out is not None and out.exploitability.value == "not_referenced"


def test_strict_schema_is_api_safe() -> None:
    schema = strict_json_schema(ExploitabilityVerdict)
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == {"exploitability", "confidence", "reasoning"}
    # Numeric bounds are stripped from the wire schema (unsupported) but still
    # enforced by Pydantic on the way back in.
    assert "maximum" not in json.dumps(schema)
    with pytest.raises(Exception):
        ExploitabilityVerdict(exploitability="imports_only", confidence=5.0, reasoning="")


# --------------------------------------------------------------------------- #
# Reasoner A — exploitability
# --------------------------------------------------------------------------- #
def test_exploitability_falls_back_to_raw_usage_signal_when_disabled() -> None:
    verdict = adjudicate_exploitability(
        _client(LLMProvider.none), dep=_dep(usage="imports_only"), app=_app(), cve=_cve()
    )
    assert verdict.exploitability.value == "imports_only"  # the raw signal


def test_exploitability_falls_back_on_bad_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    calls = _stub(client, monkeypatch, '{"exploitability": "TOTALLY_MADE_UP"}')
    verdict = adjudicate_exploitability(
        client, dep=_dep(usage="not_referenced"), app=_app(), cve=_cve()
    )
    assert calls  # the LLM *was* consulted
    assert verdict.exploitability.value == "not_referenced"  # ... and rejected


def test_exploitability_uses_valid_llm_verdict(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    _stub(
        client,
        monkeypatch,
        json.dumps(
            {
                "exploitability": "calls_vulnerable_function",
                "confidence": 0.9,
                "reasoning": "JNDI lookup is reached at import time.",
            }
        ),
    )
    verdict = adjudicate_exploitability(
        client, dep=_dep(usage="imports_only"), app=_app(), cve=_cve()
    )
    assert verdict.exploitability.value == "calls_vulnerable_function"
    assert verdict.confidence == 0.9


# --------------------------------------------------------------------------- #
# Reasoner B — false positive (deterministic pre-check FIRST)
# --------------------------------------------------------------------------- #
def test_backported_build_is_decided_without_calling_the_llm(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    calls = _stub(client, monkeypatch, '{"is_false_positive": false}')
    verdict = adjudicate_false_positive(
        client, dep=_dep(version="2.14.1"), cve=_cve(backported=["2.14.1"])
    )
    assert verdict.is_false_positive is True
    assert verdict.confidence == 1.0
    assert not calls  # the deterministic pre-check short-circuited the LLM


def test_unambiguous_hit_never_reaches_the_llm(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    calls = _stub(client, monkeypatch, '{"is_false_positive": true}')
    # In range, no backported builds listed, below the fixed version → not debatable.
    verdict = adjudicate_false_positive(
        client, dep=_dep(version="2.14.1"), cve=_cve(backported=[], fixed="2.15.0")
    )
    assert verdict.is_false_positive is False
    assert not calls


def test_ambiguous_case_consults_llm_and_falls_back_on_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    # Backported builds exist for this CVE but this build is not one of them →
    # ambiguous, so the LLM is asked. It errors; we keep the deterministic verdict.
    calls = _stub(client, monkeypatch, TimeoutError("timed out"))
    verdict = adjudicate_false_positive(
        client, dep=_dep(version="2.14.1"), cve=_cve(backported=["2.14.9"])
    )
    assert calls
    assert verdict.is_false_positive is False  # deterministic fallback: still a hit


# --------------------------------------------------------------------------- #
# Reasoner C — narrative
# --------------------------------------------------------------------------- #
def test_narrative_falls_back_to_deterministic_sentence() -> None:
    text = narrate_attack_path(
        _client(LLMProvider.none),
        app=_app(),
        path_labels=["customer-portal", "a@1.0.0", "log4j-core@2.14.1"],
        library_name="log4j-core",
        version="2.14.1",
        cve=_cve(),
        hop_distance=2,
    )
    assert "customer-portal" in text and "CVE-2021-44228" in text


def test_narrative_uses_llm_when_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client()
    _stub(client, monkeypatch, json.dumps({"narrative": "A crisp explanation."}))
    text = narrate_attack_path(
        client,
        app=_app(),
        path_labels=["customer-portal", "log4j-core@2.14.1"],
        library_name="log4j-core",
        version="2.14.1",
        cve=_cve(),
        hop_distance=1,
    )
    assert text == "A crisp explanation."


# --------------------------------------------------------------------------- #
# Reasoner D — remediation
# --------------------------------------------------------------------------- #
def test_remediation_fallback_is_grounded_in_the_fix_data() -> None:
    playbook = build_remediation(
        _client(LLMProvider.none),
        dep=_dep(),
        app=_app(),
        risk_score=90.0,
        severity="critical",
        risk_types=["vulnerable"],
        cve=_cve(),
        license_outcome="ok",
        is_stale=False,
        age_years=0.5,
    )
    assert playbook.priority == "P1"
    assert any("2.15.0" in step for step in playbook.steps)  # the real fixed version


def test_remediation_fallback_when_no_patch_exists() -> None:
    playbook = build_remediation(
        _client(LLMProvider.none),
        dep=_dep(),
        app=_app(),
        risk_score=40.0,
        severity="medium",
        risk_types=["vulnerable", "unmaintained"],
        cve=_cve(fixed=None),
        license_outcome="ok",
        is_stale=True,
        age_years=3.0,
    )
    assert any("No patch" in step for step in playbook.steps)
    assert any("2 years" in step for step in playbook.steps)


def test_remediation_falls_back_on_malformed_llm_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _client()
    _stub(client, monkeypatch, "not json at all")
    playbook = build_remediation(
        client,
        dep=_dep(),
        app=_app(),
        risk_score=90.0,
        severity="critical",
        risk_types=["vulnerable"],
        cve=_cve(),
        license_outcome="ok",
        is_stale=False,
        age_years=0.5,
    )
    assert playbook.steps and playbook.priority == "P1"  # deterministic playbook


# --------------------------------------------------------------------------- #
# The headline guarantee
# --------------------------------------------------------------------------- #
def test_every_reasoner_is_total_with_llm_disabled() -> None:
    """With LLM_PROVIDER=none all four reasoners return valid results, no raises."""
    off = _client(LLMProvider.none)
    dep, app, cve = _dep(), _app(), _cve()

    assert adjudicate_exploitability(off, dep=dep, app=app, cve=cve) is not None
    assert adjudicate_false_positive(off, dep=dep, cve=cve) is not None
    assert narrate_attack_path(
        off, app=app, path_labels=["a"], library_name="l", version="1",
        cve=cve, hop_distance=1,
    )
    assert build_remediation(
        off, dep=dep, app=app, risk_score=0.0, severity="none", risk_types=["clean"],
        cve=None, license_outcome="ok", is_stale=False, age_years=0.1,
    ).steps
