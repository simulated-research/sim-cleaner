# Independent collector follow-up review

Historical 0.2.0 review, with the later metadata disposition noted below. The single-file scan
addition has its own [implementation/test scope](FILE-SCAN.md) and
[fingerprints](../provenance/file-scan.json); this old review does not certify
the new module or changed launcher/menu.

Reviewed 2026-10-13 UTC against the independently hashed 140-test upstream archive. At that review, runtime sources and the exact harness were preserved byte for byte. The prior adversarial review is retained as a historical record; [VALIDATION.md](VALIDATION.md) is the current acceptance statement.

| Finding | Severity / location in reviewed 0.2.0 source | Reproduction and expected behavior | Current disposition |
| --- | --- | --- | --- |
| F17: official lowercase ZIP member rejected | Medium compatibility; Inspect-Windows.ps1:85, Get-InspectionArchiveMember | Provide official `autorunsc64.exe`; accept exactly one Windows-equivalent canonical leaf. Case collisions, subdirectories, traversal, empty and over-32-MiB members must fail. | Fixed by explicit approved lowercase names and ordinal case-insensitive uniqueness; eight inert cases. Only the chosen member is extracted to a GUID local stage. |
| F18: inferred executable resource name rejected the vendor console build | Medium compatibility; Inspect-Windows.ps1:92, Test-InspectionCollectorMetadata | Observed signed Autorunsc has OriginalFilename `autoruns.exe`, ProductName `Sysinternals autoruns`; Sigcheck has its corresponding shared product values. Wrong/missing/malformed metadata must fail. | Fixed with controlled vendor-family values and numeric version validation; seven inert cases. The official download/member and exact Microsoft publisher/signature/fingerprint guards remain. Resource fields establish family compatibility, not a cryptographically distinct GUI/console identity. |
| F19: metadata-only Autoruns output required a nonexistent Signer column | Medium compatibility; Inspect-Windows.ps1:106, Convert-InspectionStartupCsv | Provide the real metadata-only CSV schema without Signer. Metadata should be retrieved while signature coverage stays explicitly uncollected; unsupported/empty CSV must not look clean. | Fixed; four inert cases. Profile and Launch String are omitted. Optional supplied signer text is labeled source-reported and not independent safety evidence. |
| F20: actual Sigcheck UTF-16LE output has no BOM | Medium compatibility; Inspect-Windows.ps1:166 and :214, Invoke-InspectionTool | Known verified Sigcheck emits strict UTF-16LE without a BOM; Autorunsc emits UTF-16LE with BOM. Decode only the declared contract, reject odd/malformed bytes and a changed BOM contract, preserve error reason. | Fixed; three added no-BOM subprocess regressions plus inherited strict codec/cap/fault cases. No replacement fallback or automatic encoding switch. Known producer contracts are supported; the decoder cannot detect every valid-but-wrong encoding. |

The 0.2.0 source was reread for selected-member extraction, path/drive/reparse checks, official HTTPS/no redirects, explicit use/download/EULA gates, exact Microsoft certificate identity, recorded hash and held-handle recheck, bounded child arguments/output/time, CSV projection and failure propagation. No new blocking defect was found in the four follow-up changes. No new cleanup capability was added.

The review identified a stale BOM-only/pending-integration summary in
Inspect-Windows.ps1. Version 0.3.2 corrects that metadata: Autorunsc requires a
UTF-16LE BOM; Sigcheck requires UTF-16LE without a BOM. The decoder behavior is
unchanged. Current fingerprints and rerun tests are recorded separately in
file-scan provenance; the old source hashes remain historical evidence.

## Evidence and traceability

- [Historical 0.2.0 source fingerprints and both upstream snapshots](../provenance/source.json).
- [Follow-up source/harness diff](../patches/reviewed-118-to-tested-140.patch).
- [Original-to-reviewed source/launcher diff](../patches/original-to-reviewed-118.patch); historical document changes are omitted from this source patch to avoid obsolete machine instructions.
- [Repository inert execution](../evidence/repository-test-results.json), [upstream inert execution](../evidence/local-test-results.json), and [sanitized peer vendor integration](../evidence/local-live-integration.json).

Independent review means another source/evidence pass, not isolated Windows mutation acceptance. At the 0.2.0 review, real elevated scan/remediation lifecycle, efficacy, Victus runtime compatibility and reboot readiness were unvalidated. Later Victus single-file observations are recorded in VALIDATION.md; full/quick lifecycle, remediation efficacy and reboot readiness remain unvalidated. OfflineScan remains blocked; the appropriate verdict is a transparent prototype for deliberate scoped local use.
