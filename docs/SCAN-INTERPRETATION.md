# What the decryptor scan established

On 2026-10-15, Sim Cleaner 0.3.1 sent the supplied gentlemen-decryptor-main.zip
to installed Defender twice as a single-file custom scan with remediation
disabled. Both returned zero and reported no threats; the ZIP hash was unchanged.
Defender's own log corroborated the second scan. This was real scanner work,
not merely hashing or a mock. It did not certify the scripts' safety or correctness.

A later, separately authorized investigation ran byte-identical script copies
against disposable generated data. It was not a Sim Cleaner feature. Its 24
checks included 11 independent XChaCha20 comparisons and successful byte-for-byte
recovery of three synthetic files through the extract/key-recovery/decrypt CLI
pipeline. Several passing checks deliberately reproduced hazards:

- Existing output was silently overwritten.
- Wrong keys and damaged ciphertext produced incorrect output reported as OK.
- The default greater-than-1-MiB guard refused output but returned exit zero.
- Key recovery missed a private key at an unaligned dump offset.

These are 24 completed checks, not 24 safety endorsements. Only generated data
was encrypted/decrypted; original ZIP/source hashes were preserved. A Python
audit guard restricted writes/network/process launches during those tests; it
was not an operating-system sandbox. No real victim recovery, every ransomware
variant or output authenticity was established.

Keep the layers distinct: a Defender verdict describes that engine's result;
static review describes observed source behavior; functional tests describe
specific fixtures. A clean scan cannot establish that a program avoids data
loss. Preserve originals, use fresh separate output locations, and verify
recovered bytes independently. Sim Cleaner does not perform these decryption
tests and never runs target scripts as part of FileScan.

The public package contains a sanitized summary only, not private test files,
synthetic keys, target scripts, dependencies or raw machine reports.
