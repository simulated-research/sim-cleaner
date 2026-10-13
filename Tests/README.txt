RUN ONLY THE INERT HARNESS

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

Additional acceptance tests require a separately authorized disposable Windows
environment. Never introduce EICAR, malware, quarantines, scans or reboot tests
into Rick's project laptop to turn mocks into a release claim.
