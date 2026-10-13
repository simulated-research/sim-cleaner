# Claude and Astra working demo

This file preserves the demo's original record through `0ba73c7`. The independent `astra-source-reconciliation-20261013` branch now has its own **143/143 Windows inert** evidence, with one structured-object privacy fix; see [SOURCE-RECONCILIATION.md](SOURCE-RECONCILIATION.md). The original Linux-only observations below remain historical, and unavailable CI results are not promoted to verified Windows acceptance.

This branch is a working demo built on top of the tested-140 snapshot. It is deliberately kept separate from the main line so it is obvious what it is. It adds three source improvements that came out of the earlier adversarial review, with matching inert tests, and it records a real harness run. It does not add any cleanup or mutation capability, and it does not change the honest scope of the tool: inspection metadata and passing inert tests still do not establish that a machine is clean.

## The take, short version

Sim Cleaner is a Defender-orchestration and Windows-inspection prototype, and it is honestly built. It uses the installed Defender engine, it is not a new antivirus, and the docs say so plainly everywhere it matters: Remove-MpThreat hits all active threats at execution and there is no atomic snapshot API, saved reports are editable and not authenticated, OfflineScan is blocked, and a command returning success is never treated as proof of completion or of a clean system. The collector path (Autoruns, Sigcheck) verifies the official Microsoft signature, pins the hash across a held handle, decodes each tool's exact output contract with no fallback, and bounds child output and time. That is the right shape for this kind of tool. The one thing to never do is sell it as proof a computer is clean. It is a triage and documentation aid, not an EDR or a rootkit finder.

## What this demo changes

1. Sigcheck followups now check the most suspicious files first. Before, the 30-file cap on signature followups took whatever order Autoruns happened to return, so on a machine with more than 30 unverified startup entries the genuinely suspicious ones could fall off the end and only show up as a count. Now the unverified candidates are ranked by a review-priority heuristic before the cap: unsigned or no-publisher entries, files in user-writable or temp locations (AppData, Temp, Downloads, ProgramData, Public), drive-root executables, and anything outside Windows or Program Files score higher. The cap then keeps the highest-ranked, and the report says so (SignatureCandidateCoverage.Ordering). It is a review-priority heuristic only, never a malware verdict. New helper: Get-InspectionSuspicionScore.

2. Wider report redaction. Protect-SimText and the dictionary-key minimizer now cover more of the common secret shapes: more key names (passwd, pwd, secret, client_secret, refresh_token, session_key, private_key, connection_string) and high-confidence shapes regardless of label (Bearer tokens, JWTs, AWS access keys, Slack-style xox tokens, and PEM private-key blocks). This is still conservative minimization, not a guarantee that reports contain no secrets, and reports should still be reviewed before sharing.

3. Stale summary field corrected. The top-level ExternalToolOutputEncoding line still read "UTF-16LE with BOM required; integration acceptance pending", which the last review already flagged as stale. It now states the per-tool contracts (Autorunsc with BOM, Sigcheck without BOM) and points at each tool record's OutputEncodingContract.

## What was looked at and deliberately left alone

The earlier review also flagged the lock. On re-examination the mutex is acquired and released on the same thread in the normal script flow, and a direct acquire/release test raised no cross-thread exception. It is not a live defect here, so it was left unchanged rather than "fixed" for its own sake. The socket-to-process attribution and the Remove-MpThreat all-active scope are inherent to the Windows APIs in use and are already documented as limits, not silently assumed away.

## Verification

Run on PowerShell 7.4.6 on Linux in a cloud container. A live Defender inspection needs Windows and was not run here.

- Real source files on Linux: 91 of 142 inert cases pass. All 51 failures are the Windows-only local-drive path validator (Assert-SimLocalPath) refusing Linux paths, or the same class of "no C: drive on Linux" artifact. None are logic defects.
- With a POSIX path shim applied only to the test environment's path validator (the shipped Safety.ps1 on this branch is unchanged by the shim): 141 of 142 pass. The single remaining failure is a Linux-only "a drive with the name C does not exist" artifact inside a reparse mock.
- The two new cases (wider redaction shapes, suspicion-score ordering) pass, and no previously passing case regressed.

The upstream record already shows 140 of 140 on Windows PowerShell 7.6.5. A native Windows run exercises the path validator properly and is the real acceptance path; it has not been repeated for this branch. See evidence/claude-astra-demo-harness.json.

## Scope that still has not been validated

Everything the main VALIDATION.md lists remains open: no real elevated scan or remediation lifecycle, no removal or detection efficacy, no HP Victus runtime check, OfflineScan stays blocked, and no Windows run of this branch. This demo is a transparent prototype for deliberate scoped local use, not a certified product.
