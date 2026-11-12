"""Triage an SPDX 2.3 SBOM with OSV and emit an SPDX 3.0 VEX statement for one checked-in decision."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
VEX_JUSTIFICATIONS = {
    "componentNotPresent",
    "vulnerableCodeNotPresent",
    "vulnerableCodeNotInExecutePath",
    "vulnerableCodeCannotBeControlledByAdversary",
    "inlineMitigationsAlreadyExist",
}
DEFAULT_DECISIONS = Path(__file__).with_name("vex-decisions.json")


class TriageError(RuntimeError):
    """A decision or SBOM input cannot be turned into a VEX statement."""


def _is_purl_ref(ref: dict) -> bool:
    kind = str(ref.get("referenceType") or "")
    return kind == "purl" or kind.rsplit("/", 1)[-1] == "purl"


def packages_with_purl(sbom: dict) -> list[dict[str, str]]:
    """Return SPDX packages that name a purl. Packages without one are skipped."""
    selected: list[dict[str, str]] = []
    for package in sbom.get("packages") or []:
        if not isinstance(package, dict):
            continue
        purl = ""
        for ref in package.get("externalRefs") or []:
            if isinstance(ref, dict) and _is_purl_ref(ref) and ref.get("referenceLocator"):
                purl = str(ref["referenceLocator"])
                break
        if not purl:
            continue
        selected.append(
            {
                "name": str(package.get("name") or ""),
                "version": str(package.get("versionInfo") or ""),
                "spdxId": str(package.get("SPDXID") or ""),
                "purl": purl,
            }
        )
    return selected


def _query_osv(purls: list[str]) -> dict:
    if not purls:
        return {"results": []}
    body = json.dumps({"queries": [{"package": {"purl": purl}} for purl in purls]}).encode()
    request = urllib.request.Request(
        OSV_BATCH_URL,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode())


def _severity(vuln: dict) -> str | None:
    for item in vuln.get("severity") or []:
        if isinstance(item, dict) and item.get("score"):
            return str(item["score"])
    database_specific = vuln.get("database_specific")
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        return str(database_specific["severity"])
    return None


def _fixed_version(vuln: dict) -> str | None:
    for affected in vuln.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and event.get("fixed"):
                    return str(event["fixed"])
    return None


def _vulnerability_id(vuln: dict) -> str:
    """Prefer a CVE alias when OSV has one. Otherwise keep the OSV id."""
    for alias in vuln.get("aliases") or []:
        if str(alias).startswith("CVE-"):
            return str(alias)
    return str(vuln.get("id") or "")


def triage_findings(sbom: dict, query_osv: Callable[[list[str]], dict] | None = None) -> list[dict[str, str]]:
    """List OSV findings. This does not decide that a finding is harmless."""
    packages = packages_with_purl(sbom)
    payload = (query_osv or _query_osv)([package["purl"] for package in packages])
    results = payload.get("results") or []
    findings: list[dict[str, str]] = []
    for package, result in zip(packages, results):
        if not isinstance(result, dict):
            continue
        for vuln in result.get("vulns") or []:
            if not isinstance(vuln, dict):
                continue
            finding = {
                "name": package["name"],
                "version": package["version"],
                "spdxId": package["spdxId"],
                "purl": package["purl"],
                "vulnerabilityId": _vulnerability_id(vuln),
            }
            severity = _severity(vuln)
            if severity:
                finding["severity"] = severity
            fixed_version = _fixed_version(vuln)
            if fixed_version:
                finding["fixedVersion"] = fixed_version
            findings.append(finding)
    return findings


def load_decisions(path: Path) -> list[dict[str, str]]:
    """Load at most one hand-written VEX decision."""
    data = json.loads(path.read_text(encoding="utf-8"))
    decisions = data.get("decisions") if isinstance(data, dict) else None
    if not isinstance(decisions, list):
        raise TriageError("VEX decisions file must contain a decisions array.")
    if len(decisions) > 1:
        raise TriageError("At most one VEX decision is supported.")
    parsed: list[dict[str, str]] = []
    for decision in decisions:
        if not isinstance(decision, dict):
            raise TriageError("VEX decision must be an object.")
        vulnerability_id = str(decision.get("vulnerabilityId") or "")
        spdx_id = str(decision.get("spdxId") or "")
        justification = str(decision.get("security_justificationType") or "")
        impact = str(decision.get("security_impactStatement") or "")
        if not vulnerability_id or not spdx_id or not impact:
            raise TriageError("VEX decision requires vulnerabilityId, spdxId, and security_impactStatement.")
        if justification not in VEX_JUSTIFICATIONS:
            raise TriageError(f"Unsupported VEX justification: {justification}")
        parsed.append(
            {
                "vulnerabilityId": vulnerability_id,
                "spdxId": spdx_id,
                "security_justificationType": justification,
                "security_impactStatement": impact,
            }
        )
    return parsed


def _slug(value: str) -> str:
    cleaned = "".join(character.lower() if character.isalnum() else "-" for character in value).strip("-")
    return cleaned or "nukesandbox"


def build_vex_document(
    decision: dict[str, str],
    *,
    product_name: str,
    created: str,
) -> dict:
    """SPDX 3.0 not-affected statement. creationInfo is required by the spec."""
    vulnerability_id = decision["vulnerabilityId"]
    vuln_spdx_id = f"urn:spdx.dev:vuln-{_slug(vulnerability_id)}"
    product_id = f"urn:spdx.dev:product-{_slug(product_name)}"
    agent_id = "urn:spdx.dev:agent-nukesandbox"
    creation_info = {
        "type": "CreationInfo",
        "specVersion": "3.0.1",
        "created": created,
        "createdBy": [agent_id],
    }
    return {
        "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "@graph": [
            {
                "type": "Person",
                "spdxId": agent_id,
                "name": "NukeSandbox",
                "creationInfo": creation_info,
            },
            {
                "type": "software_Package",
                "spdxId": product_id,
                "name": product_name,
                "creationInfo": creation_info,
            },
            {
                "type": "Vulnerability",
                "spdxId": vuln_spdx_id,
                "name": vulnerability_id,
                "creationInfo": creation_info,
            },
            {
                "type": "VexNotAffectedVulnAssessmentRelationship",
                "spdxId": "urn:spdx.dev:vex-not-affected-1",
                "relationshipType": "doesNotAffect",
                "from": vuln_spdx_id,
                "to": [product_id],
                "security_assessedElement": decision["spdxId"],
                "security_justificationType": decision["security_justificationType"],
                "security_impactStatement": decision["security_impactStatement"],
                "creationInfo": creation_info,
                "publishedTime": created,
                "suppliedBy": [agent_id],
            },
        ],
    }


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def run(
    sbom_path: Path,
    output_path: Path,
    vex_output_path: Path,
    decisions_path: Path,
    query_osv: Callable[[list[str]], dict] | None = None,
    created: str | None = None,
) -> None:
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    findings = triage_findings(sbom, query_osv=query_osv)
    _write_json(output_path, findings)
    decisions = load_decisions(decisions_path)
    if not decisions:
        return
    decision = decisions[0]
    matched = any(
        finding["vulnerabilityId"] == decision["vulnerabilityId"] and finding["spdxId"] == decision["spdxId"]
        for finding in findings
    )
    if not matched:
        raise TriageError(
            f"{decision['vulnerabilityId']} for {decision['spdxId']} is not in the triage output. VEX was not written."
        )
    document = build_vex_document(
        decision,
        product_name=str(sbom.get("name") or "nukesandbox"),
        created=created or time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )
    _write_json(vex_output_path, document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage an SPDX SBOM and emit SPDX VEX for one checked-in decision.")
    parser.add_argument("sbom", type=Path)
    parser.add_argument("--output", type=Path, default=Path("triage.json"))
    parser.add_argument("--vex-output", type=Path, default=Path("vex.spdx.json"))
    parser.add_argument("--decisions", type=Path, default=DEFAULT_DECISIONS)
    args = parser.parse_args(argv)
    try:
        run(args.sbom, args.output, args.vex_output, args.decisions)
    except (TriageError, OSError, json.JSONDecodeError, urllib.error.URLError) as exc:
        print(f"triage failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
