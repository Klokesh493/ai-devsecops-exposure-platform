"""Convert CycloneDX JSON and Trivy JSON exports into the platform's strict case."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from ops_platform.agent_loop import bounded_json
from ops_platform.domain import Case


def convert(sbom, scan, now, roots):
    if sbom.get("bomFormat") != "CycloneDX":
        raise ValueError("expected a CycloneDX document")
    entries = list(sbom["components"])
    application = sbom.get("metadata", {}).get("component")
    if application and application.get("bom-ref") not in {row["bom-ref"] for row in entries}:
        entries.append(application)
    components = [{"ref": row["bom-ref"], "name": row["name"], "version": row.get("version", "unknown")}
                  for row in entries]
    lookup = {}
    for component in components:
        pair = component["name"], component["version"]
        if pair in lookup:
            raise ValueError("package name and version are ambiguous")
        lookup[pair] = component["ref"]
    results = scan.get("Results")
    if not isinstance(results, list) or not results:
        raise ValueError("Trivy export must contain scanner results")
    if any(not isinstance(result, dict) or not result.get("Target") for result in results):
        raise ValueError("each Trivy result must identify its scanned target")
    findings = {}
    for result in results:
        for item in result.get("Vulnerabilities", []) or []:
            pair = item["PkgName"], item["InstalledVersion"]
            if pair not in lookup:
                raise ValueError("scanner package is missing from the SBOM")
            key = item["VulnerabilityID"], lookup[pair]
            finding = {"id": key[0], "component": key[1], "severity": item["Severity"],
                       "fixed_version": item.get("FixedVersion", "")}
            if key in findings and findings[key] != finding:
                raise ValueError("scanner reports conflicting findings for the same package")
            findings[key] = finding
    case = {"now": now, "sbom": {"roots": roots, "components": components,
            "dependencies": [{"source": row["ref"], "target": target}
                             for row in sbom.get("dependencies", []) for target in row["dependsOn"]]},
            "findings": list(findings.values()), "waivers": []}
    return Case.model_validate(case).model_dump()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sbom", type=Path)
    parser.add_argument("trivy", type=Path)
    parser.add_argument("--now", type=int, required=True)
    parser.add_argument("--root", action="append", required=True)
    args = parser.parse_args()
    case = convert(bounded_json(args.sbom), bounded_json(args.trivy), args.now, args.root)
    print(json.dumps(case, indent=2))


if __name__ == "__main__":
    main()
