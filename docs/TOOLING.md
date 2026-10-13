# Optional tools, output contracts and privacy

Default inspection uses existing Windows metadata and bounded native `netsh`/`powercfg` read commands. It does not download tools by default. Optional signing work reuses the process snapshot and startup followups stop at 30 candidates; report caps and omitted coverage remain visible.

Use, acquisition and EULA agreement are separate explicit choices: `-UseMicrosoftTools -DownloadMicrosoftTools -AcceptToolEula`. `-VerifyProcessSignatures` is another optional scope. The Microsoft [Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns), [Sigcheck](https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck) and [license terms](https://learn.microsoft.com/en-us/sysinternals/license-terms) references are preserved from the source review. No vendor executable or cache is distributed here.

Acquisition requires the official HTTPS host, rejects redirects, creates a GUID stage and extracts only one approved canonical member with a 32-MiB member bound. Microsoft Windows signature validity, exact Microsoft publisher identity, observed product family and numeric version are required. Recorded SHA-256 is a fingerprint, not comparison against an independently authenticated vendor expected hash. Held read handles and hash rechecks reduce file replacement races; they do not defend against compromised administrators, trust stores, runtime/dependency resolution or directory namespaces.

Children use argument arrays, four-MiB raw-byte and two-Mi-character caps on each stream, timeouts and disposal. Only a child started by this kit is terminated on wrapper failure. Explicit contracts are:

| Producer | Contract |
| --- | --- |
| Native command default | Strict ASCII; unsupported OEM/localized/high bytes produce unavailable coverage. |
| A specifically declared known UTF-8 producer | Strict UTF-8; malformed bytes are rejected. Used by the inert fixtures. |
| Observed Autorunsc64 14.3 | Strict UTF-16LE with required BOM. |
| Observed Sigcheck64 2.92 | Strict UTF-16LE without BOM; an unexpected BOM is rejected. |

There is no ambient code page or replacement fallback. Stream failures retain their cause. Successful decoding alone cannot identify every wrong-but-valid encoding. New vendor versions and local output environments require focused integration acceptance. The per-tool report contract is authoritative; this branch also retains the Claude demo's correction of the older generic report-summary sentence.

Startup CSV output drops Profile and Launch String; missing Signer is explicitly uncollected. Reports still contain private paths, identifiers and network metadata. Redaction reduces known secret patterns; it is not a guarantee that reports contain no secrets. Keep runtime output outside the repository and review each report before sharing. No raw private inventory is included in this package. Synthetic secret strings in the inert harness are test data.

UNC, device, alternate-stream, mapped/nonfixed drives and reparse ancestors are rejected before local-file signature followups. Opted-in Autoruns can still consult external startup metadata and is not network-free. Windows signature validation can use certificate infrastructure; no certificate-validation bypass, trust root addition or complete TLS/revocation assurance exists. Defender cloud/sample submission follows existing policy and must not be described as upload-free.

Socket ownership is a timed PID snapshot and can become unknown after process exit or reuse. Counts do not establish the cause of port exhaustion, external reachability or remote UDP conversations. Firewall state comes from ActiveStore and maps DomainAuthenticated to Domain; profile enablement does not prove effective rule behavior. Installed-provider discovery records absent versus unknown publishers; TCP allocation events have a separate bounded query, window and cap.
