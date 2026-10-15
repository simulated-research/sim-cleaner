# Scan one file or ZIP

`FileScan` is the narrow scan option in Sim Cleaner 0.3.2. It is a Defender
wrapper, not a Python interpreter, sanitizer, decryptor, or independent malware
engine. It never extracts the ZIP itself or invokes any target contents.

## Use

Extract this source package to a new local folder. Use a trusted PowerShell 7
session, select the correct supported device family (`Victus` or `Gigabyte`),
and preview the exact file:

```powershell
.\SimCleaner.ps1 -ExpectedDevice Victus -Action FileScan -ScanPath 'C:\Samples\sample.zip' -PreviewOnly
```

The preview verifies the device, opens the target read-only, fingerprints it,
reads Defender's readiness/cloud policy, and verifies the installed scanner.
It prints the target, policy and fixed argument array and saves a local report.
It does not invoke MpCmdRun. Unknown policy, a passive/disabled engine, or a
missing/untrusted scanner refuses the operation, including preview completion.

After independently reviewing that information, use an already elevated trusted
session for the scan:

```powershell
.\SimCleaner.ps1 -ExpectedDevice Victus -Action FileScan -ScanPath 'C:\Samples\sample.zip' -AcknowledgeImpact
```

Alternatively, start Sim Cleaner and choose **10: Scan one file/ZIP**. Enter a
literal path and confirm `FileScan` after the displayed target/policy. A blank or
different confirmation does not dispatch. The generic `Launch-SimCleaner.ps1`
also forwards `-Action FileScan`, `-ScanPath`, `-PreviewOnly`,
`-AcknowledgeImpact`, and `-ScanTimeoutSeconds` without bypassing script policy
or automatically elevating.

## Scope and preservation

The only scanner arguments are:

```text
-Scan -ScanType 3 -File <validated absolute file path> -DisableRemediation
```

Directories, drive roots, wildcards, relative paths, UNC/device paths, alternate
data streams, nonfixed drives and reparse ancestors are rejected. Spaces and
shell metacharacters remain part of one literal argument; no shell interprets
the command. The target is held against ordinary writes/deletion, and SHA-256
is recorded before and after. Installed MpCmdRun must pass Microsoft signature
and product checks; its checked hash is revalidated under a held handle before
launch. There is no download or PATH-based executable lookup.

Version 0.3.1 accepts the valid Microsoft Windows Publisher signer used by
installed Defender binaries, as well as Microsoft Corporation. Both still
require a valid Authenticode signature and Microsoft Corporation organization;
publisher names alone are not trusted. A live preview now verifies the installed
scanner successfully. The earlier Passive Mode observation is historical.

Microsoft documents that `-DisableRemediation` custom scans inspect archives,
ignore file exclusions, apply no post-detection actions, and report detections
in command output rather than the normal detection UI/event log. This does not
disable independent real-time protection/EDR, change settings, or guarantee
that another component cannot act on the file. Neither held handles nor hashes
defend against a hostile administrator or compromised OS.

Existing cloud protection and sample-submission policy still applies. This is
not an upload-free/offline guarantee. Signature validation may also use Windows
certificate infrastructure. No automatic signature update is requested.
Encrypted or unsupported archive members, resource limits and engine detection
limits prevent any promise of examining every member or finding every threat.

## Results and timeout

Each attempt that reaches report creation gets a unique `SimCleanerReports`
directory with `01-before.json`, optional `02-intent.json` immediately before
dispatch, and `03-final.json`. Required evidence-write failures prevent dispatch
or propagate a failure. An early invalid path can fail before report creation.

The final report retains the scanner's exit code and up to 4 MiB per output
stream. Exact bytes are Base64-encoded; plain text is shown only for the ASCII
subset, avoiding guesses about localized output encoding. Keep these reports
private: raw bytes can contain paths or other sensitive details, even where
the existing display-text redactor hides some fields.

| Result | Meaning |
| --- | --- |
| `PreviewOnly` | No scan dispatched. |
| `CommandReturnedZero` | Scanner exited 0 and produced output. Review that output; this is not proof of safety or complete coverage. |
| `DetectionOrScanError` | Scanner exited 2. Microsoft uses this code for both detections and scanning errors; review output. |
| `Unverified` | Timeout, capture failure, another exit code, missing output, or changed target fingerprint. |
| `RefusedOrUnverified` | A guard, consent, invocation or evidence operation failed. See the error. |

CLI exit 0 covers a completed preview or `CommandReturnedZero`. Exit 3 covers
`DetectionOrScanError`/`Unverified`; thrown guard/report errors exit nonzero.
No exit code proves a file is safe. FileScan does not use the legacy event/history
correlator, because this mode's detection-output contract is different.

The client timeout defaults to 300 seconds (`-ScanTimeoutSeconds`, 1–3600).
Timeout/output failure stops only this invocation's MpCmdRun client. Defender
service work on the file may continue; no global scan cancellation, automatic
retry or whole-machine fallback occurs.

## Validation

54 dedicated inert tests cover scope refusals, arguments, mocks of scanner
dispatch, acknowledgement, policy changes, evidence failures, read locks,
return-code ambiguity, exact byte capture, timeout and output caps. The 140
existing regressions also pass. The process-wrapper tests run only reviewed,
inert PowerShell commands that print bytes, return a code or wait; they never
launch Defender or the supplied archive scripts.

Detection efficacy, localized vendor output and hostile namespace/OS behavior
remain unvalidated. A read-only preview on the development
host initially refused a reported `Passive Mode`; a subsequent 0.3.1 preview
passed with Defender in Normal mode. Two elevated single-ZIP scans subsequently
completed with exit 0 and output reporting no threats, with the target hash
unchanged. This validates that invocation on this host, not detection efficacy
or complete archive-member coverage. No engine or
protection-policy settings were changed.

The live observations are from 0.3.1; 0.3.2 has refreshed inert test evidence
and corrected metadata/documentation. See [validation scope](VALIDATION.md),
[the sanitized live record](../evidence/file-scan-live-validation.json), and
[what a clean scan does not prove](SCAN-INTERPRETATION.md).

## Microsoft reference

[MpCmdRun commands, custom scans, DisableRemediation and return codes](https://learn.microsoft.com/en-us/defender-endpoint/command-line-arguments-microsoft-defender-antivirus)
(checked 2026-10-15).
