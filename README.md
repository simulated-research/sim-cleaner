# Sim Cleaner

## 0.3.2: single-file scanning and evidence update

The new `FileScan` action scans one literal local file through the installed,
Microsoft-signed `MpCmdRun.exe`. It uses custom scan type 3 with
`-DisableRemediation`; it never launches the target, runs its scripts, or falls
back to a whole-computer scan. See [File scan usage and limits](docs/FILE-SCAN.md).

Preview first from a trusted PowerShell 7 session in the extracted package:

```powershell
.\SimCleaner.ps1 -ExpectedDevice Victus -Action FileScan -ScanPath 'C:\Samples\sample.zip' -PreviewOnly
```

For the actual scan, use an already elevated trusted PowerShell 7 session and,
after reviewing the displayed target and cloud/sample policy, replace
`-PreviewOnly` with `-AcknowledgeImpact`. Menu option **10** also offers FileScan.
No automatic elevation or protection-setting change is performed. This version
requires Defender's reported running mode to be `Normal`; passive/unknown modes
refuse the operation. A zero return is not a safe-file certificate.

The addition passed 54 inert file-scan tests and 140 existing regression tests.
These harnesses use mocked dispatch and inert processes. Separately, two actual
0.3.1 single-ZIP scans completed on the Victus with no threats reported and
unchanged target hashes. Defender's own log corroborates the second invocation.
See [validation scope](docs/VALIDATION.md) and the
[sanitized scan record](evidence/file-scan-live-validation.json).
Version 0.3.2 corrects report metadata and documentation; the live observations
belong to 0.3.1, while the rerun inert tests bind to current source.
The earlier evidence below applies to the historical 0.2.0 snapshot; current
fingerprints and test evidence are in [file-scan provenance](provenance/file-scan.json).

Sim Cleaner is a source-reviewed Windows inspection and Microsoft Defender orchestration prototype. It uses the installed Defender engine; it is not a new antivirus engine. Inspection metadata and passing tests do not establish that a computer is clean or that malware can be removed.

The base snapshot was the tested 0.2.0 runtime plus four collector compatibility fixes. Its historical source and harness fingerprints remain in [provenance/source.json](provenance/source.json). Versions 0.3.0–0.3.1 added the file-scan module, menu/CLI and launcher forwarding, signer compatibility fix, tests and packaging. Version 0.3.2 corrects the inspector encoding summary and reconciles documentation and evidence. The existing full/quick/remediation actions retain their prior limits.

## Start with source and inert tests

Read [the review](docs/REVIEW-FOLLOWUP.md), [validation scope](docs/VALIDATION.md), [action semantics](SIM-CLEANER.txt) and [tool/privacy limits](docs/TOOLING.md) before running an entry point.

PowerShell 7.0 or later is required by the runtime source; executed acceptance uses Microsoft-signed PowerShell 7.6.5. Earlier supported-by-declaration versions have not been validated. Use an explicit, independently verified local `pwsh.exe` path. This example assumes the current PowerShell session is already trusted:

```powershell
$trustedPwsh = 'C:\Path\To\Trusted\pwsh.exe'
& $trustedPwsh -NoProfile -NonInteractive -File .\Tests\Test-SimCleaner.ps1 -OutputDirectory C:\Local\NewInertTestResults
```

The result directory must be new. The harness imports source function definitions through the PowerShell AST and mocks Defender, CIM, events, acquisitions and inspection dispatch. It exercises local writes, locking and reviewed console-output/timeout child processes. It never invokes the production entry points or a real Defender scan/removal. See [Tests/README.txt](Tests/README.txt).

## Deliberate local inspection

The device guard supports the reviewed HP Victus and GIGABYTE G6 KF families, not arbitrary Windows computers. Choose the correct family; a mismatch refuses the action. Read-only examples, after source review:

```powershell
& $trustedPwsh -NoProfile -NonInteractive -File .\SimCleaner.ps1 -ExpectedDevice Gigabyte -ValidateOnly
& $trustedPwsh -NoProfile -NonInteractive -File .\SimCleaner.ps1 -ExpectedDevice Gigabyte -Action Status
& $trustedPwsh -NoProfile -NonInteractive -File .\Inspect-Windows.ps1 -ExpectedDevice Gigabyte -SocketSamples 2 -SampleIntervalSeconds 1
```

Read-only inspection writes local reports and can call Windows certificate/network infrastructure. Reports may contain private paths, addresses and identifiers. Keep them local unless independently reviewed for sharing. The package does not include machine reports or downloaded tools.

The portable `.cmd` files bootstrap `Launch-SimCleaner.ps1` with Windows PowerShell 5.1. That bootstrap can be blocked by existing script policy. It selects a Microsoft-signed absolute PowerShell 7 path using `SIMCLEANER_PWSH` or the standard installation location, preserves the child exit code and does not auto-elevate. Where PowerShell 5.1 script policy blocks it, use the explicit trusted PowerShell 7 commands above. No execution-policy bypass, unblocking or security-policy change is prescribed. The generic launcher also supports `-ValidateOnly` and `-Action Status` forwarding when invoked directly in a trusted host.

## Mutation limits

Scan, signature-update and remediation options exist, with actual elevation, policy and explicit impact guards. They are **not accepted for unattended use**. Full/quick scan lifecycle, cancellation and removal efficacy still require a separately authorized disposable Windows environment. OfflineScan is blocked. Do not use the project laptop for those acceptance tests.

Full/quick Defender scans can automatically remediate and can submit samples under existing cloud policy. Exclusions and scope limits apply. `Remove-MpThreat` addresses **ALL active threats at execution**, including arrivals after the last inventory check. A review token detects changes; it cannot make that API atomic or authenticate evidence. Locally saved reports are editable. Full/quick scan completion requires correlated events and history; a command returning successfully is insufficient. A delayed result can be rechecked read-only with `RecheckScan`; see [SIM-CLEANER.txt](SIM-CLEANER.txt).

Exit 0 means the operation-specific result was obtained within its limits; exit 1 means guard/action/storage/unverified lifecycle failure; exit 3 means a partial read-only snapshot or a FileScan detection/error/otherwise unverified child result. None means malware is absent.

## Reproducible source package

Python 3 is used only for packaging, with its standard library:

```powershell
python .\scripts\build_package.py --output .\dist\sim-cleaner-prototype.zip
```

The builder uses an explicit file allowlist, validates reviewed fingerprints, fixes ZIP metadata and generates an exact-content SHA-256 manifest. It refuses an existing output file. Run twice with different filenames to compare byte-identical results. It never executes PowerShell, acquires tools or scans files with Defender. [package-files.json](package-files.json) defines the package contents. `.gitattributes` disables newline conversion so reviewed source fingerprints survive Git checkout.

No additional software license has been selected in this prepared source snapshot. Follow the destination repository's license decision. Microsoft utilities are not redistributed; their own terms apply to separately opted-in acquisition.
