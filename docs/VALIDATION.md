# Validation and acceptance scope

This is a local-use prototype with reviewed source and inert tests. It is not certified, not accepted for unattended elevated operation and has no malware-detection or removal-efficacy claim. No disposable isolated Windows environment was available for real mutation acceptance.

Current source-reconciliation acceptance is **143/143 local Windows inert cases**, zero failures, PowerShell 7.6.5. Use [windows-reconciliation-tests.json](../evidence/windows-reconciliation-tests.json), the current `ValidationEvidence` declaration in provenance and [SOURCE-RECONCILIATION.md](SOURCE-RECONCILIATION.md) for the source now on this branch. The table below preserves the earlier tested-140/main and integration records; those do not substitute for current source acceptance. CI status remains separately unverified.

## Recorded evidence

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

The three unchanged runtime files and historical fixture are listed in provenance. Only Inspect-Windows.ps1 and the inert harness changed from the earlier delivered reviewed snapshot. Repository preparation preserves their exact bytes and does not broaden cleanup scope. Current portable documentation supersedes stale upstream machine-specific instructions.

## Remaining acceptance criteria

These require a separately authorized disposable Windows environment. They are not a request to exercise mutations on the live project laptop.

1. Real elevated first full/quick scan lifecycle, delayed completion/recheck, cancellation, partial failure, event/history retention and supported locales; unrelated and scheduled activity must never establish false completion.
2. Separately authorized harmless detection/remediation fixtures, ALL-active scope/new arrivals, exclusion/cloud policy behavior, and complete before/intent/after evidence under interruption. No engine efficacy inference from the mocks.
3. Cross-user/session mutex permissions, disk-full/access-denied/power interruption, Windows reparse/mapped-drive/locked-executable semantics and report persistence under real failure.
4. Actual generic launcher/runtime/script-policy behavior and HP Victus compatibility. Only PowerShell 7.6.5 on the Gigabyte has recorded current acceptance. Runtime minimum declarations are not cross-version test evidence.
5. Broader native/localized output and vendor versions/network/trust behavior. Observed utility contracts are narrow; valid-but-wrong encodings cannot always be recognized from bytes alone. Certificate validity and hashes do not establish complete TLS or revocation assurance.
6. OfflineScan must remain blocked until OS/WinRE/encryption readiness, explicit reboot consent, durable intent and post-boot reconciliation have isolated acceptance evidence.

No actual elevated antivirus scan, quarantine/remediation test, reboot, EICAR/sample upload, protection-setting change or removal-efficacy test occurred in this review. Read-only collection and passing mocks do not establish clean-system status.
