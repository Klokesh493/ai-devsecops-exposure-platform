"""Dependency-graph exposure analysis from normalized CycloneDX and Trivy records."""
from collections import deque
import json
from typing import Annotated, List, Literal

from pydantic import Field, model_validator

from .agent_loop import Probe
from .contracts import Count, Identifier, Record, unique

TITLE = "AI DevSecOps Exposure Platform"
BRIEF = "Inspect SBOM dependency paths, scanner findings and expiring vulnerability waivers."
SOURCES = ["sbom", "findings", "waivers"]
SBOMRef = Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9:/@._+%=-]{0,239}$")]
PackageName = Annotated[str, Field(pattern=r"^[@a-zA-Z0-9][a-zA-Z0-9@/_.-]{0,199}$")]


class Component(Record):
    ref: SBOMRef
    name: PackageName
    version: str = Field(min_length=1, max_length=100, pattern=r"^[ -~]+$")


class Edge(Record):
    source: SBOMRef
    target: SBOMRef


class SBOM(Record):
    roots: List[SBOMRef] = Field(min_length=1, max_length=30)
    components: List[Component] = Field(min_length=1, max_length=200)
    dependencies: List[Edge] = Field(max_length=1000)


class Finding(Record):
    id: Identifier
    component: SBOMRef
    severity: Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    fixed_version: str = Field(default="", max_length=100, pattern=r"^[ -~]*$")


class Waiver(Record):
    finding: Identifier
    component: SBOMRef
    expires_at: Count
    ticket: Identifier


class Case(Record):
    now: Count
    sbom: SBOM
    findings: List[Finding] = Field(max_length=200)
    waivers: List[Waiver] = Field(max_length=200)

    @model_validator(mode="after")
    def references(self):
        known = {component.ref for component in self.sbom.components}
        unique([c.ref for c in self.sbom.components], "component references")
        unique(self.sbom.roots, "root references")
        unique([(f.id, f.component) for f in self.findings], "finding component pairs")
        unique([(w.finding, w.component) for w in self.waivers], "waiver pairs")
        if (not set(self.sbom.roots) <= known or any(
                edge.source not in known or edge.target not in known for edge in self.sbom.dependencies)
                or any(f.component not in known for f in self.findings)):
            raise ValueError("SBOM contains unknown component references")
        pairs = {(f.id, f.component) for f in self.findings}
        if any((w.finding, w.component) not in pairs for w in self.waivers):
            raise ValueError("waiver does not match a finding")
        return self


def prepare(case):
    source = case.model_dump()
    source["waivers"] = {"records": source["waivers"], "now": case.now}
    probes = [Probe(key, "Read " + key + " evidence", lambda key=key: source[key])
              for key in SOURCES]

    def decide(evidence):
        graph = {component.ref: [] for component in case.sbom.components}
        for edge in case.sbom.dependencies:
            graph[edge.source].append(edge.target)
        paths = {root: [root] for root in case.sbom.roots}
        queue = deque(sorted(paths))
        while queue:
            current = queue.popleft()
            for child in sorted(graph[current]):
                if child not in paths:
                    paths[child] = paths[current] + [child]
                    queue.append(child)
        waivers = {(w.finding, w.component): w for w in case.waivers}
        exposure = []
        for finding in case.findings:
            waiver = waivers.get((finding.id, finding.component))
            reachable = finding.component in paths
            waived = bool(waiver and waiver.expires_at > case.now)
            blocking = reachable and not waived and finding.severity in {"HIGH", "CRITICAL"}
            exposure.append({"id": finding.id, "component": finding.component,
                             "severity": finding.severity, "path": paths.get(finding.component, []),
                             "reachable": reachable, "waived": waived, "blocking": blocking,
                             "fixed_version": finding.fixed_version})
        exposure.sort(key=lambda row: (not row["blocking"], row["component"], row["id"]))
        blockers = sum(item["blocking"] for item in exposure)
        return {"decision": "security_hold" if blockers else "security_ready", "ready": blockers == 0,
                "citations": SOURCES, "exposure": exposure, "blocking_count": blockers,
                "reason": "Reachable high or critical findings need remediation or an active waiver."
                          if blockers else "The dependency graph passes the configured exposure policy."}

    return probes, decide


def bundle(report):
    return {"remediation-review.json": json.dumps(report["exposure"], indent=2)}
