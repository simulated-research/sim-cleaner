# Validation and acceptance scope

## Current 0.3.2 maintenance validation

[140 regression tests](../evidence/file-scan-regression-results.json) and
[54 file-scan tests](../evidence/file-scan-test-results.json) were rerun against
the [current source fingerprints](../provenance/file-scan.json). They use AST
definitions, mocked Defender dispatch and inert PowerShell child fixtures.
They do not run target scripts or live scans. Run the suites sequentially.

Version 0.3.2 corrects the inspector's encoding summary, the banner and evidence
documentation. The scan implementation's only change from 0.3.1 is its report
version. No new live scan was needed for these maintenance edits.

## Observed 0.3.1 single-file use, 2026-10-15

Two elevated single-ZIP invocations on the Victus returned zero, reported no
threats and preserved the target SHA-256. The fixed arguments requested custom
type 3 with DisableRemediation. Sim Cleaner did not execute archive contents.
The [sanitized record](../evidence/file-scan-live-validation.json) contains the
timestamps, target fingerprint, observed scanner/policy and source fingerprints
from that version. Defender's own MpCmdRun.log independently records the second
invocation's scan start/completion and skipped remediation. A query for events
1000/1001/1002 returned no matching events; no event-correlation proof is claimed.

The first preview had refused Passive Mode. A later preview succeeded in Normal
mode after 0.3.1 accepted the valid Microsoft Windows Publisher signature.
No protection-policy settings were changed by this work. Normal mode was an
observation, not a configuration action. Existing cloud/sample-submission
settings applied; these records do not prove whether uploads occurred.

This verifies that invocation on that host, not detection efficacy, every
archive member, every machine, or application safety. Separately authorized
tests of copied decryptor scripts later used disposable synthetic data; they
were not performed by Sim Cleaner. See [interpretation lessons](SCAN-INTERPRETATION.md).

This remains a local-use prototype, not certified or accepted for unattended
elevated operation. Full/quick scan lifecycle and removal efficacy still require
separately authorized isolated acceptance.

## Historical 0.2.0 evidence

| Evidence | Result and scope |
| --- | --- |
| Authoritative upstream archive | `Sim Cleaner tested prototype.zip`, 118473 bytes; SHA-256 `1D4FC64D4655B7E01DBC132B0B6FA76F91F30F7EFF8659BDE374E11F5E03DC21`; all 29 non-manifest members independently verified against its manifest and copied-source bytes. |
| Upstream exact 140-case harness | 140 passed, 0 failed on PowerShell 7.6.5; [source-bound evidence](../evidence/local-test-results.json). The Fox Hole session also confirms its extracted exact packaged harness passed 140/140. |
| Repository-copy recheck | See [repository-test-results.json](../evidence/repository-test-results.json) for this reviewer's exact execution and fingerprints. Only the reviewed inert harness is run. |
| Independent earlier 118-case acceptance | [118/118 and native read-only inspector exit 0](../evidence/independent-acceptance-118.json), with 8 historical TCP/IP allocation events. The unchanged SimCleaner/Safety/launcher bytes retain the earlier safe guard evidence. |
| Safe entry guards | Earlier [five checks](../evidence/independent-acceptance-112.json): correct target exit 0, wrong target exit 1, partial Status exit 3, actual nonadmin FullScan refusal exit 1, OfflineScan blocked exit 1. No dispatch/pre-dispatch records and no mutation occurred. These guards do not validate an elevated action. |
| Real opted-in advanced inspection, Fox Hole session | [Sanitized integration summary](../evidence/local-live-integration.json): exit 0 reported; 1577 startup metadata rows, 30 completed bounded Sigcheck followups, 52 accessible process-signature records and 8 historical TCP/IP allocation events. Autoruns 14.3 and Sigcheck 2.92 had valid Microsoft signatures and recorded fingerprints. This reviewer inspected the source and sanitized evidence; it did not repeat that live acquisition. |
| Historical quick scan fixture | Preexisting normalized Gigabyte Quick Scan evidence only. Harness replay tests named fields, Scan ID and capitalization; it does not represent a newly invoked scan. |

Original 12-test claims did not validate the delivered original harness: it failed at an invalid `Join-Path` expression. The earlier matching frozen106 candidate was also rejected by independent testing (105/106) for a real Unicode decoding defect. Corrected strict-decoding and installed-event-provider logic subsequently passed the 112/118 stages. Historical dispositions are preserved in [historical-review-118.txt](historical-review-118.txt); pending statements there belong to that snapshot. The current collector follow-up is independently reviewed in [REVIEW-FOLLOWUP.md](REVIEW-FOLLOWUP.md).

At that historical review, the three unchanged runtime files and historical fixture are listed in provenance. Only Inspect-Windows.ps1 and the inert harness had changed from the earlier delivered reviewed snapshot. Those historical fingerprints remain in source.json. Current source fingerprints are in file-scan.json; later changes must not be attributed to the historical runs.

## Remaining acceptance criteria

These require a separately authorized disposable Windows environment. They are not a request to exercise mutations on the live project laptop.

1. Real elevated first full/quick scan lifecycle, delayed completion/recheck, cancellation, partial failure, event/history retention and supported locales; unrelated and scheduled activity must never establish false completion.
2. Separately authorized harmless detection/remediation fixtures, ALL-active scope/new arrivals, exclusion/cloud policy behavior, and complete before/intent/after evidence under interruption. No engine efficacy inference from the mocks.
3. Cross-user/session mutex permissions, disk-full/access-denied/power interruption, Windows reparse/mapped-drive/locked-executable semantics and report persistence under real failure.
4. Broader generic launcher/runtime/script-policy behavior and device compatibility. Historical collector acceptance used the Gigabyte; the later single-file scan used the Victus. Those observations do not establish every action on either device. Runtime minimum declarations are not cross-version test evidence.
5. Broader native/localized output and vendor versions/network/trust behavior. Observed utility contracts are narrow; valid-but-wrong encodings cannot always be recognized from bytes alone. Certificate validity and hashes do not establish complete TLS or revocation assurance.
6. OfflineScan must remain blocked until OS/WinRE/encryption readiness, explicit reboot consent, durable intent and post-boot reconciliation have isolated acceptance evidence.

No quarantine/remediation-efficacy or reboot acceptance is claimed. The actual single-ZIP scans above do not establish clean-system status. Existing cloud/sample policy applied; actual uploads were not measured.
