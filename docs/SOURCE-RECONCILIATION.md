# Independent source reconciliation

This branch retains the complete Claude/Astra demo history through `0ba73c7b75e8aa1ae0ae102df9a252bf17cf4a8a` and adds a narrow privacy fix plus current packaging evidence. The source branch is `astra-source-reconciliation-20261013`. Neither `main` nor `claude-and-astra-working-demo` is moved or overwritten by this reconciliation.

The owned main checkout had no unpublished edits or stashes. The earlier diagnostic clone was intentionally made with no checkout; its empty index was not an owned deletion change. Original source folders, immutable archives, local skill guidance and private runtime/mock report directories are not staged as new project source.

## Reviewed changes

The demo's bounded signature-candidate priority heuristic, wider text/dictionary-key redaction, accurate per-tool encoding summary and corrected CI exit wrapper are retained. The heuristic changes review order under the existing 30-item cap and local-file guards; it is not a malware score or expanded cleanup capability.

**Medium privacy defect — Safety.ps1, ConvertTo-SimSafeData:** known sensitive field names were minimized for dictionaries but not PowerShell objects. A reviewed AST-only fixture with `client_secret` and a nested `Password` property preserved both synthetic values before the fix. Expected: the same known-name rules apply across dictionaries, typed objects and nested arrays, while ordinary metadata survives. Fixed by applying the existing field-name pattern in the PowerShell-object branch. One regression covers both types and ordinary metadata. Redaction remains conservative, not a guarantee of secret-free reports.

**Packaging defect — scripts/build_package.py:** the demo provenance recorded newer source/harness hashes but the builder still required the historic `evidence/repository-test-results.json` and exactly 140 passes. That cannot establish acceptance for the changed source. The builder now reads the explicitly declared `ValidationEvidence` file, expected case count and runtime from provenance, and retains the complete source/harness/fixture fingerprint checks. Historical evidence is preserved rather than relabeled as current.

## Executed local validation

The exact revised inert harness passed **143/143**, zero failures, Microsoft PowerShell **7.6.5** on Windows. [windows-reconciliation-tests.json](../evidence/windows-reconciliation-tests.json) records every result and the four runtime-source, harness and historical-fixture hashes. The source-bound result includes the demo's 142 cases and the new structured-redaction case. No source entry point or live Defender action was invoked. Local mock evidence, named-lock exclusion and reviewed output/timeout subprocess fixtures were used.

The structured-redaction probe changed from false to true for known sensitive fields; ordinary metadata remained preserved. Packaging requires the current source-bound result, uses an explicit source-only allowlist, creates an exact SHA-256 manifest and refuses existing output files. The builder is reused rather than replaced by a second packaging implementation. CI infrastructure remains outside the distributed-package allowlist.

## CI and remaining limits

GitHub CI job access previously returned 404 for run `38464446618`; that denied route is not retried here. The source-level stale `$LASTEXITCODE` hazard and the owner's correction at `0ba73c7` were verified separately. Its commit message reports 142 passes, but this review did not retrieve that run's annotations/results or establish the corrected run as green. Local 143/143 evidence is distinct from CI status.

The retained workflow triggers on pushes to the Claude demo branch and on pull requests/manual dispatch. A push of this separate source-reconciliation branch does not match its push filter. This review requests no CI rerun or dispatch. The historical main snapshot at `2d5ade2` has no CI workflow files; the demo/reconciliation snapshots do contain one.

Real elevated scan/remediation lifecycle and efficacy, HP Victus/runtime-minimum compatibility, cross-session OS failure semantics and reboot readiness remain unvalidated. OfflineScan stays blocked. No real scan, quarantine, remediation, signature update, download, EICAR/sample upload, security-setting change or reboot was performed. No clean-system claim is made.
