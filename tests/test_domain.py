import json
from pathlib import Path

import pytest

from ops_platform.service import evaluate

def fixture(name):
    return json.loads((Path("examples") / (name + ".json")).read_text())


def test_dependency_path_and_waiver_expiry():
    exposed = evaluate(fixture("exposed"))["exposure"][0]
    assert exposed["path"] == ["web", "parser"]
    assert evaluate(fixture("expired-waiver"))["blocking_count"] == 1

def test_dependency_cycles_terminate():
    source = fixture("ready")
    source["sbom"]["dependencies"].append({"source": "parser", "target": "web"})
    assert len(evaluate(source)["exposure"][0]["path"]) == 2

def test_unknown_component_rejected():
    source = fixture("ready")
    source["findings"][0]["component"] = "missing"
    with pytest.raises(ValueError):
        evaluate(source)

def test_cyclonedx_trivy_import():
    from tools.import_scans import convert
    sbom = {"bomFormat": "CycloneDX", "components": [
        {"bom-ref": "web", "name": "web", "version": "1.0.0"},
        {"bom-ref": "parser", "name": "parser", "version": "1.0.0"}],
        "dependencies": [{"ref": "web", "dependsOn": ["parser"]}]}
    scan = {"Results": [{"Target": "requirements", "Vulnerabilities": [
        {"VulnerabilityID": "SYNTHETIC-001", "PkgName": "parser",
         "InstalledVersion": "1.0.0", "FixedVersion": "1.0.1", "Severity": "HIGH"}]}]}
    case = convert(sbom, scan, 100, ["web"])
    assert evaluate(case)["decision"] == "security_hold"

def test_missing_scanner_export_cannot_become_a_clean_report():
    from tools.import_scans import convert
    sbom = {"bomFormat": "CycloneDX", "components": [
        {"bom-ref": "web", "name": "web", "version": "1.0.0"}]}
    with pytest.raises(ValueError, match="scanner results"):
        convert(sbom, {}, 100, ["web"])
