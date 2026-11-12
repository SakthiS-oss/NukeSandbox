from __future__ import annotations

import json
from pathlib import Path

import pytest

from supply_chain import triage


FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"
SBOM = json.loads((FIXTURES / "sbom.spdx.json").read_text(encoding="utf-8"))
OSV = json.loads((FIXTURES / "osv-response.json").read_text(encoding="utf-8"))
DECISION = json.loads((FIXTURES / "vex-decision.json").read_text(encoding="utf-8"))


def _fake_osv(_purls: list[str]) -> dict:
    return OSV


def _run(tmp_path: Path, decisions: dict, monkeypatch: pytest.MonkeyPatch) -> tuple[int, Path, Path]:
    def fail_open(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("OSV was called")

    monkeypatch.setattr(triage.urllib.request, "urlopen", fail_open)
    monkeypatch.setattr(triage, "_query_osv", _fake_osv)
    sbom_path = tmp_path / "sbom.spdx.json"
    decisions_path = tmp_path / "vex-decisions.json"
    triage_path = tmp_path / "triage.json"
    vex_path = tmp_path / "vex.spdx.json"
    sbom_path.write_text(json.dumps(SBOM), encoding="utf-8")
    decisions_path.write_text(json.dumps(decisions), encoding="utf-8")
    code = triage.main(
        [
            str(sbom_path),
            "--output",
            str(triage_path),
            "--vex-output",
            str(vex_path),
            "--decisions",
            str(decisions_path),
        ]
    )
    return code, triage_path, vex_path


def test_triage_lists_the_purl_package_and_skips_the_package_without_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    code, triage_path, vex_path = _run(tmp_path, {"decisions": []}, monkeypatch)

    assert code == 0
    findings = json.loads(triage_path.read_text(encoding="utf-8"))
    assert findings == [
        {
            "name": "fixture-lib",
            "version": "1.0.0",
            "spdxId": "SPDXRef-Package-fixture-lib",
            "purl": "pkg:pypi/fixture-lib@1.0.0",
            "vulnerabilityId": "GHSA-fixture-0000-0000",
            "severity": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            "fixedVersion": "1.2.0",
        }
    ]
    assert not vex_path.exists()


def test_matching_decision_writes_spdx_vex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    code, _triage_path, vex_path = _run(tmp_path, DECISION, monkeypatch)

    assert code == 0
    document = json.loads(vex_path.read_text(encoding="utf-8"))
    statement = next(item for item in document["@graph"] if item["type"] == "VexNotAffectedVulnAssessmentRelationship")
    decision = DECISION["decisions"][0]
    assert statement["relationshipType"] == "doesNotAffect"
    assert statement["security_justificationType"] == "vulnerableCodeNotInExecutePath"
    assert statement["security_impactStatement"] == decision["security_impactStatement"]
    assert statement["security_assessedElement"] == "SPDXRef-Package-fixture-lib"
    assert statement["creationInfo"]["specVersion"] == "3.0.1"
    assert "fixture-lib" in statement["security_impactStatement"]


def test_live_decisions_file_stays_a_single_optional_statement() -> None:
    decisions = triage.load_decisions(triage.DEFAULT_DECISIONS)
    assert len(decisions) <= 1


def test_checked_in_example_uses_the_not_in_execute_path_justification() -> None:
    decision = DECISION["decisions"][0]
    assert decision["security_justificationType"] == "vulnerableCodeNotInExecutePath"
    assert decision["vulnerabilityId"] == "GHSA-fixture-0000-0000"


def test_missing_vulnerability_does_not_write_vex(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    decisions = {
        "decisions": [
            {
                "vulnerabilityId": "CVE-1999-0001",
                "spdxId": "SPDXRef-Package-fixture-lib",
                "security_justificationType": "componentNotPresent",
                "security_impactStatement": "This id is not in the fixture triage output.",
            }
        ]
    }
    code, triage_path, vex_path = _run(tmp_path, decisions, monkeypatch)

    assert code == 1
    assert triage_path.exists()
    assert not vex_path.exists()
