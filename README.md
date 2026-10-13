# Sim Cleaner

Sim Cleaner is a source-reviewed Windows inspection and Microsoft Defender orchestration prototype. It uses the installed Defender engine; it is not a new antivirus engine. Inspection metadata and passing tests do not establish that a computer is clean or that malware can be removed.

This snapshot retains the tested 0.2.0 runtime plus four collector compatibility fixes. The exact source and harness fingerprints are in [provenance/source.json](provenance/source.json). The newer snapshot supersedes the earlier reviewed Library version 4; both archive fingerprints are retained there.

The `astra-source-reconciliation-20261013` branch builds on the Claude/Astra demo through `0ba73c7`, with a structured-object secret-minimization fix and source-bound packaging acceptance. Its exact Windows inert harness passed **143/143** on PowerShell 7.6.5. [Source reconciliation](docs/SOURCE-RECONCILIATION.md) separates these results from the historical main 140-case evidence and unavailable CI results. The existing main and demo branches are preserved.

## Start with source and inert tests

Read [the review](docs/REVIEW-FOLLOWUP.md), [validation scope](docs/VALIDATION.md), [action semantics](SIM-CLEANER.txt) and [tool/privacy limits](docs/TOOLING.md) before running an entry point.

Windows PowerShell 7.0 or later is required by the runtime source; executed acceptance uses Microsoft-signed PowerShell 7.6.5. Earlier supported-by-declaration versions have not been validated. Use an explicit, independently verified local `pwsh.exe` path. This example assumes the current PowerShell session is already trusted:

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

Scan, signature-update and remediation options exist, with actual elevation, policy and explicit impact guards. They are **not accepted for unattended use**. Real elevated lifecycle, cancellation and removal efficacy still require a separately authorized disposable Windows environment. OfflineScan is blocked. Do not use the project laptop for those acceptance tests.

Defender scans can automatically remediate and can submit samples under existing cloud policy. Exclusions and scope limits apply. `Remove-MpThreat` addresses **ALL active threats at execution**, including arrivals after the last inventory check. A review token detects changes; it cannot make that API atomic or authenticate evidence. Locally saved reports are editable. Completion requires correlated events and history; a command returning successfully is insufficient. A delayed result can be rechecked read-only with `RecheckScan`; see [SIM-CLEANER.txt](SIM-CLEANER.txt).

Exit 0 means the operation-specific result was obtained within its limits; exit 1 means guard/action/storage/unverified lifecycle failure; exit 3 means a partial read-only snapshot. None means malware is absent.

## Reproducible source package

Python 3 is used only for packaging, with its standard library:

```powershell
python .\scripts\build_package.py --output .\dist\sim-cleaner-prototype.zip
```

The builder uses an explicit file allowlist, validates reviewed fingerprints, fixes ZIP metadata and generates an exact-content SHA-256 manifest. It refuses an existing output file. Run twice with different filenames to compare byte-identical results. It never executes PowerShell, acquires tools or scans files with Defender. [package-files.json](package-files.json) defines the package contents. `.gitattributes` disables newline conversion so reviewed source fingerprints survive Git checkout.

No additional software license has been selected in this prepared source snapshot. Follow the destination repository's license decision. Microsoft utilities are not redistributed; their own terms apply to separately opted-in acquisition.
