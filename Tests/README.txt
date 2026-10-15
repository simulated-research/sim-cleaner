INERT TEST HARNESSES

The file-scan addition includes Test-FileScan.ps1, requiring a NEW -OutputDirectory. It AST-loads
definitions only, mocks OS/policy/scanner dispatch, writes local evidence and
an inert text fixture, and uses reviewed PowerShell output/timeout fixtures.
It never runs MpCmdRun or any supplied target script. Run it in a separate
trusted PowerShell 7 process. The original 140-case harness remains separate.
Run the suites sequentially: both exercise the application's shared named lock.

From an explicitly trusted PowerShell 7 host:
  pwsh -NoProfile -NonInteractive -File .\Tests\Test-SimCleaner.ps1
Use the absolute reviewed runtime path instead of bare pwsh if origin is uncertain.
Optional: -OutputDirectory C:\absolute\local\new-test-folder
The selected output directory must not already exist.

The harness parses source, imports function definitions through AST extraction,
and intercepts all Defender/CIM/event/tool/inspection-child calls. It never runs
the source scripts' top-level entry code. Local report files and a named mutex
are exercised; an inert second runspace tests lock exclusion. Four reviewed
PowerShell subprocess fixtures print data, exit 7, exceed an output cap, or sleep
until the wrapper's timeout kills only that child. No untrusted executable runs.

historical-scan-fixture.json is a sanitized PREEXISTING quick-scan record from
the Gigabyte. Replaying its normalized fields tests correlation/capitalization,
not a scan invoked or completed by this package. It contains no username or paths.

SourceHashes, HarnessSHA256 and HistoricalFixtureSHA256 in test-results.json
bind reported passes to executed definitions. Static assertions are identified
as such and complement mocked behavior; they do not prove Windows integration.

Full/quick lifecycle, harmful-fixture/remediation and reboot acceptance require
a separately authorized disposable Windows environment. The separately
authorized single-file scans are recorded in docs/VALIDATION.md; neither
inert harness dispatches those scans or tests detection efficacy.
