# Engineering case study

## Engineering problem

Scanner findings alone do not show which vulnerable packages are reachable from a deployed dependency root, and an expired waiver can silently leave a release exposed.

## Design choices

Breadth-first traversal records a short dependency path and terminates on dependency cycles. Waivers match both a finding and a component. A waiver expires exactly at its deadline. The importer rejects ambiguous package identity and scanner entries absent from the SBOM.

## Implementation

I built a security review platform that imports CycloneDX and Trivy JSON exports, walks declared dependency paths, applies component-specific waiver deadlines, and produces an ordered remediation review.

The API and CLI share ops_platform.service.evaluate. Domain contracts and decisions live in ops_platform/domain.py. SQLite persistence is implemented in ops_platform/storage.py. Prometheus metrics are created per API instance. The deployment directory contains the supplied observability and Kubernetes configuration.

## Technical challenges

A reachable high or critical finding holds the review unless a matching waiver is still active. Unreachable and lower-severity findings remain visible in the report.

Retry handling also matters across all workflows. A duplicate client request reuses its report, while stale approvals fail with HTTP 409. An unavailable model records an incomplete report that cannot be approved. HEC failures leave audit events pending.

## Validation results

5 labeled domain scenarios passed. The actual local Qwen run returned security_ready for ready.json and security_hold for hold.json. Captured reports include the model name, probe trace, content digests, and cited evidence. API and domain tests cover the decision policy and workflow failure cases. [Validation details](VALIDATION.md)

## Lessons learned

A review becomes actionable when a scanner finding has a dependency path, package identity, and a time-bounded exception decision.

## Remaining scope

Fixture vulnerability identifiers are synthetic. Graph reachability describes declared dependencies and does not establish runtime function execution. Live scanner execution and vendor advisory accuracy require their own verification.
