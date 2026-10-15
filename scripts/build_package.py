"""Build a deterministic allowlisted source ZIP; never execute the product.

Python 3 standard library only. Output must be a new file beneath dist/.
The manifest binds bytes but is not a signature or authentication mechanism.
"""
import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
import stat
import zipfile

ROOT = Path(__file__).resolve().parent.parent


def sha(data):
    return hashlib.sha256(data).hexdigest().upper()


def reject_reparse(path):
    relative = path.relative_to(ROOT)
    cursor = ROOT
    for part in ("", *relative.parts):
        if part:
            cursor = cursor / part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Reparse/symlink package paths are unsupported")


def read_inputs():
    reject_reparse(ROOT / "package-files.json")
    names = json.loads((ROOT / "package-files.json").read_text(encoding="utf-8"))
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise ValueError("Package allowlist must be a string array")
    if len(names) != len(set(n.casefold() for n in names)):
        raise ValueError("Duplicate/case-colliding package names")
    payloads = {}
    for name in sorted(names):
        relative = PurePosixPath(name)
        if relative.is_absolute() or any(p in ("..", ".") for p in relative.parts) or "\\" in name or ":" in name or str(relative) != name:
            raise ValueError("Unsafe package name")
        if name == "SHA256SUMS.txt" or relative.parts[0] in (".git", "dist", "Reports", "SimCleanerReports", "Tools"):
            raise ValueError("Forbidden package name")
        path = ROOT / name
        reject_reparse(path)
        if not path.is_file():
            raise ValueError("Package inputs must be regular files")
        payloads[name] = path.read_bytes()
    if "package-files.json" not in payloads or "scripts/build_package.py" not in payloads:
        raise ValueError("Package must contain its reproduction recipe")
    provenance = json.loads(payloads["provenance/source.json"])
    amendment = json.loads(payloads["provenance/file-scan.json"])
    current = amendment["CurrentSourceSHA256"]
    for name, expected in provenance["ReviewedSourceSHA256"].items():
        if name not in payloads or sha(payloads[name]) != current.get(name, expected):
            raise ValueError("Reviewed source/harness bytes changed: " + name)
    for name, expected in current.items():
        if name not in payloads or sha(payloads[name]) != expected:
            raise ValueError("Current file-scan source bytes changed: " + name)
    test = json.loads(payloads["evidence/repository-test-results.json"])
    if test["Failed"] != 0 or test["Passed"] != 140:
        raise ValueError("Missing successful exact reviewed-harness result")
    expected = provenance["ReviewedSourceSHA256"]
    if test["HarnessSHA256"] != expected["Tests/Test-SimCleaner.ps1"] or test["HistoricalFixtureSHA256"] != expected["Tests/historical-scan-fixture.json"]:
        raise ValueError("Test fixture/harness fingerprint mismatch")
    for source in test["SourceHashes"]:
        if source["SHA256"] != expected.get(source["File"]):
            raise ValueError("Executed source fingerprint mismatch")
    if {x["File"] for x in test["SourceHashes"]} != {x for x in expected if x.endswith(".ps1") and "/" not in x}:
        raise ValueError("Test source coverage mismatch")
    # Retain the base evidence above as historical, and require new results bound
    # to every current root runtime source. Neither test suite runs a live scan.
    for report, harness, count in (
        ("evidence/file-scan-regression-results.json", "Tests/Test-SimCleaner.ps1", 140),
        ("evidence/file-scan-test-results.json", "Tests/Test-FileScan.ps1", 54),
    ):
        run = json.loads(payloads[report])
        if run["Failed"] != 0 or run["Passed"] != count or run["HarnessSHA256"] != current[harness]:
            raise ValueError("Current harness evidence missing/mismatched: " + report)
        sources = {x["File"]: x["SHA256"] for x in run["SourceHashes"]}
        runtime = {n: h for n, h in current.items() if n.endswith(".ps1") and "/" not in n}
        if sources != runtime:
            raise ValueError("Current executed source fingerprints mismatch: " + report)
    live = json.loads(payloads["evidence/file-scan-live-validation.json"])
    validation = amendment["Validation"]
    if validation["LiveScanVersion"] != "0.3.1" or validation["LiveScanInvocations"] != len(live["Runs"]):
        raise ValueError("Live observation version/count mismatch")
    if live["Arguments"] != ["-Scan", "-ScanType", "3", "-File", "TARGET_ZIP", "-DisableRemediation"]:
        raise ValueError("Live observation scope mismatch")
    for run in live["Runs"]:
        if (run["Version"] != validation["LiveScanVersion"] or run["PreviewOnly"] is not False
                or run["ExitCode"] != 0 or run["Result"] != "CommandReturnedZero"
                or run["SHA256After"] != live["Target"]["SHA256"]):
            raise ValueError("Live observation contradicts recorded result")
    # This is a targeted privacy check, not a general secret-detection guarantee.
    for name, data in payloads.items():
        text = data.decode("utf-8-sig")
        if "fox-hole\\outputs" in text.lower():
            raise ValueError("Private local path in package input: " + name)
        if re.search(r"(?i)[a-z]:[\\/]+users[\\/]+(?!public\b|default\b)[^\\/\s\"']+", text):
            raise ValueError("User profile path in package input: " + name)
        if re.search(r"(?i)libfile_[0-9a-f]{20,}|github_pat_[a-z0-9_]{20,}|gh[pousr]_[a-z0-9]{20,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", text):
            raise ValueError("Private identifier or credential-shaped content: " + name)
    payloads["SHA256SUMS.txt"] = ("".join(sha(data) + "  " + name + "\n" for name, data in sorted(payloads.items()))).encode("utf-8")
    return payloads


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="dist/sim-cleaner-0.3.2-file-scan.zip")
    args = parser.parse_args()
    payloads = read_inputs()
    requested = Path(args.output)
    requested = requested if requested.is_absolute() else ROOT / requested
    # Validate lexical target before creating directories; never follow an existing junction.
    try:
        relative_output = requested.relative_to(ROOT)
    except ValueError:
        raise ValueError("Output must be beneath this repository's dist directory") from None
    if not relative_output.parts or relative_output.parts[0] != "dist" or ".." in relative_output.parts:
        raise ValueError("Output must be beneath this repository's dist directory")
    cursor = ROOT
    reject_reparse(ROOT)
    for part in relative_output.parts[:-1]:
        cursor = cursor / part
        try:
            cursor.lstat()
        except FileNotFoundError:
            cursor.mkdir()
        reject_reparse(cursor)
    try:
        requested.lstat()
    except FileNotFoundError:
        pass
    else:
        raise FileExistsError("Refusing to overwrite a package")
    with requested.open("xb") as handle:
        with zipfile.ZipFile(handle, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, data in sorted(payloads.items()):
                info = zipfile.ZipInfo("sim-cleaner/" + name, date_time=(1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_STORED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, data)
    # Verify the exact written bytes and membership, not merely the input directory.
    with zipfile.ZipFile(requested) as archive:
        if set(archive.namelist()) != {"sim-cleaner/" + n for n in payloads}:
            raise ValueError("Written ZIP membership mismatch")
        for name, data in payloads.items():
            if archive.read("sim-cleaner/" + name) != data:
                raise ValueError("Written ZIP byte mismatch")
    print(json.dumps({"File": requested.name, "Bytes": requested.stat().st_size, "SHA256": sha(requested.read_bytes()), "Members": len(payloads), "ManifestEntries": len(payloads) - 1}, indent=2))


if __name__ == "__main__":
    main()
