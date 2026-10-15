# Definitions only. Imported by SimCleaner.ps1; never execute the scan target.
function Get-SimSingleFile([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.IndexOfAny([char[]]'*?') -ge 0) {
        throw 'Specify exactly one literal file path; wildcards are not allowed.'
    }
    $full = Assert-SimLocalPath $Path -Leaf
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item -isnot [IO.FileInfo]) { throw 'A regular file is required; directories are not scan targets.' }
    return $full
}

function Get-SimStreamSHA256([IO.Stream]$Stream) {
    $Stream.Position = 0
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($sha.ComputeHash($Stream)).Replace('-', '') }
    finally { $sha.Dispose(); $Stream.Position = 0 }
}

function Get-SimFileScanPolicy {
    $status = @(Get-MpComputerStatus -ErrorAction Stop)
    $policy = @(Get-MpPreference -ErrorAction Stop)
    if ($status.Count -ne 1 -or $policy.Count -ne 1) { throw 'Defender status/policy unavailable or ambiguous.' }
    $s = $status[0]; $p = $policy[0]
    if ($s.AntivirusEnabled -isnot [bool] -or $s.AMServiceEnabled -isnot [bool] -or
        -not $s.AntivirusEnabled -or -not $s.AMServiceEnabled -or $s.AMRunningMode -cne 'Normal') {
        throw 'Defender is disabled, passive or unknown; file scan refused.'
    }
    if ($null -eq $p.SubmitSamplesConsent -or $p.SubmitSamplesConsent -notin @(0,1,2,3) -or
        $null -eq $p.MAPSReporting -or $p.MAPSReporting -notin @(0,1,2) -or
        $p.DisableArchiveScanning -isnot [bool]) { throw 'Defender cloud/archive policy unavailable or unsupported.' }
    [ordered]@{
        SubmitSamplesConsent = [int]$p.SubmitSamplesConsent
        MAPSReporting = [int]$p.MAPSReporting
        DisableArchiveScanning = $p.DisableArchiveScanning
        AntivirusSignatureVersion = [string]$s.AntivirusSignatureVersion
        AntivirusSignatureLastUpdated = $s.AntivirusSignatureLastUpdated
    }
}

function Test-SimScannerSignature($Signature) {
    if ($Signature.Status -ne 'Valid' -or -not $Signature.SignerCertificate) { return $false }
    $certificate = $Signature.SignerCertificate
    $name = $certificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false)
    return ($name -cin @('Microsoft Corporation','Microsoft Windows Publisher') -and
        $certificate.Subject -match '(?:^|,\s*)O=Microsoft Corporation(?:,|$)')
}

function Get-SimMpCmdRun {
    # Known Windows folders, never PATH or a downloaded tool.
    $platform = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'Microsoft\Windows Defender\Platform'
    $candidates = @()
    if (Test-Path -LiteralPath $platform) {
        [void](Assert-SimLocalPath $platform)
        $versions = @(Get-ChildItem -LiteralPath $platform -Directory -ErrorAction Stop |
            Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+(?:-\d+)?$' } |
            Sort-Object { [version]($_.Name.Split('-')[0]) } -Descending)
        foreach ($v in $versions) { $candidates += Join-Path $v.FullName 'MpCmdRun.exe' }
    }
    $candidates += Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Windows Defender\MpCmdRun.exe'
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
        $path = Assert-SimLocalPath $candidate -Leaf
        $held = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $path -ErrorAction Stop
            if (-not (Test-SimScannerSignature $signature)) {
                throw 'Installed MpCmdRun Microsoft signature could not be verified.'
            }
            $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($path)
            if ($version.OriginalFilename -ine 'MpCmdRun.exe' -or $version.FileMajorPart -lt 4) {
                throw 'Unsupported MpCmdRun product metadata.'
            }
            return [ordered]@{Path=$path; SHA256=Get-SimStreamSHA256 $held; Version=$version.FileVersion; Signer=$signature.SignerCertificate.Subject}
        } finally { $held.Dispose() }
    }
    throw 'Installed MpCmdRun.exe not found; no download or fallback scan is performed.'
}

function Get-SimFileScanArguments([string]$Path) {
    # All switches are fixed. The only user-supplied argument is a validated literal leaf.
    return @('-Scan', '-ScanType', '3', '-File', (Get-SimSingleFile $Path), '-DisableRemediation')
}

function Invoke-SimFileScanProcess([string]$Binary, [string[]]$Arguments, [string]$ExpectedHash, [int]$TimeoutSeconds) {
    [void](Assert-SimLocalPath $Binary -Leaf)
    if (-not ('SimFileScanProcess' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Diagnostics;
using System.Threading.Tasks;
using System.Security.Cryptography;
public sealed class SimFileScanProcessResult {
    public int? ExitCode;
    public string Status;
    public byte[] Stdout = Array.Empty<byte>();
    public byte[] Stderr = Array.Empty<byte>();
    public string Error;
}
public static class SimFileScanProcess {
    static async Task<byte[]> Read(Stream source) {
        using (var output = new MemoryStream()) {
            var buffer = new byte[8192]; int n;
            while ((n = await source.ReadAsync(buffer, 0, buffer.Length)) > 0) {
                if (output.Length + n > 4194304) throw new IOException("Output exceeds 4 MiB per stream");
                output.Write(buffer, 0, n);
            }
            return output.ToArray();
        }
    }
    public static SimFileScanProcessResult Run(string file, string[] args, string hash, int seconds) {
        var result = new SimFileScanProcessResult { Status = "Unverified" };
        using (var held = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.Read))
        using (var sha = SHA256.Create())
        using (var p = new Process()) {
            var actual = BitConverter.ToString(sha.ComputeHash(held)).Replace("-", "");
            if (String.IsNullOrEmpty(hash) || !String.Equals(actual, hash, StringComparison.Ordinal))
                throw new IOException("MpCmdRun changed before launch");
            p.StartInfo = new ProcessStartInfo(file) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(file)
            };
            foreach (var arg in args) p.StartInfo.ArgumentList.Add(arg);
            p.Start();
            var stdout = Read(p.StandardOutput.BaseStream);
            var stderr = Read(p.StandardError.BaseStream);
            var clock = Stopwatch.StartNew();
            try {
                while (!p.WaitForExit(50)) {
                    if (stdout.IsFaulted || stderr.IsFaulted) throw new IOException("Output capture failed or exceeded limit");
                    if (clock.Elapsed.TotalSeconds >= seconds) throw new TimeoutException("Scan client timeout; Defender service work may continue for this file");
                }
                if (!Task.WaitAll(new Task[] { stdout, stderr }, 1000)) throw new IOException("Output streams did not close");
                result.Stdout = stdout.GetAwaiter().GetResult();
                result.Stderr = stderr.GetAwaiter().GetResult();
                result.ExitCode = p.ExitCode;
                result.Status = "CommandExited";
            } catch (Exception e) {
                result.Status = "Unverified";
                result.Error = e.GetBaseException().Message;
            } finally {
                // Stop only this client. Never cancel unrelated Defender scans or kill its service.
                if (!p.HasExited) { try { p.Kill(); p.WaitForExit(1000); } catch {} }
                if (stdout.Status == TaskStatus.RanToCompletion) result.Stdout = stdout.Result;
                if (stderr.Status == TaskStatus.RanToCompletion) result.Stderr = stderr.Result;
            }
        }
        return result;
    }
}
'@
    }
    [SimFileScanProcess]::Run($Binary, $Arguments, $ExpectedHash, $TimeoutSeconds)
}

function Convert-SimScanOutput([byte[]]$Bytes) {
    # Preserve exact bounded bytes; never silently guess the vendor's locale/encoding.
    $ascii = $true
    foreach ($b in $Bytes) { if ($b -gt 127 -or ($b -lt 32 -and $b -notin @(9,10,13))) { $ascii=$false; break } }
    [ordered]@{
        Bytes = $Bytes.Length
        Base64 = [Convert]::ToBase64String($Bytes)
        Encoding = if ($ascii) { 'ASCII subset' } else { 'Unknown; exact bytes retained as Base64' }
        Text = if ($ascii) { [Text.Encoding]::ASCII.GetString($Bytes) } else { $null }
    }
}

function Get-SimFileScanOutcome($ProcessResult) {
    if ($ProcessResult.Status -ne 'CommandExited' -or $null -eq $ProcessResult.ExitCode) { return 'Unverified' }
    # Microsoft's code 2 conflates detections and scanning errors. Never label it definitively infected.
    if ($ProcessResult.ExitCode -eq 2) { return 'DetectionOrScanError' }
    if ($ProcessResult.ExitCode -ne 0) { return 'Unverified' }
    if ($ProcessResult.Stdout.Length -eq 0 -and $ProcessResult.Stderr.Length -eq 0) { return 'Unverified' }
    return 'CommandReturnedZero'
}

function Invoke-SimFileScan {
    param([string]$Path, [bool]$Accepted=$false, [bool]$Interactive=$false,
          [bool]$Preview=$false, [ValidateRange(1,3600)][int]$TimeoutSeconds=300)
    $lock=Enter-SimLock; $held=$null; $record=$null; $failure=$null; $runDirectory=$null
    try {
        if ($Interactive) { $Path=Read-Host 'Absolute local FILE path (ZIP is supported; not a folder)' }
        $path=Get-SimSingleFile $Path
        $held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        $fingerprint=Get-SimStreamSHA256 $held
        [void](Assert-SimLocalPath $simReports)
        $runDirectory=Join-Path $simReports ($ExpectedDevice+'-FileScan-'+[guid]::NewGuid().ToString('N'))
        [void](New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop)
        $record=[ordered]@{
            Tool='Sim Cleaner'; Version='0.3.2'; Action='FileScan'; PreviewOnly=$Preview
            StartedAt=(Get-Date).ToString('o'); Target=[ordered]@{Path=$path;Bytes=$held.Length;SHA256=$fingerprint}
            Policy=$null; Binary=$null; Arguments=$null; DispatchAt=$null; Result='Prepared'
            Command=$null; SHA256After=$null; Error=$null
            Limits=@('Single-file custom scan; target contents are never launched or imported by this tool.',
                'DisableRemediation requests no detection actions for this scan; independent real-time/EDR activity is not controlled.',
                'Microsoft documents archive scanning and ignored file exclusions in this mode; encrypted/unsupported archives and engine limits still apply.',
                'Existing Microsoft cloud/sample policy applies; no security settings are changed.',
                'Command return/output are evidence, not proof of safety or complete archive-member coverage.',
                'Timeout stops only the client; Defender service work may continue. No automatic retry or global cancellation.',
                'Reports contain paths and exact raw command output; keep them private. Hashes are fingerprints, not authenticity.')
        }
        Save-SimReport $record (Join-Path $runDirectory '01-before.json')
        $record.Policy=Get-SimFileScanPolicy
        $record.Binary=Get-SimMpCmdRun
        $record.Arguments=@(Get-SimFileScanArguments $path)
        Write-Host ('Single file: '+$path)
        Write-Host ('SHA256: '+$fingerprint)
        Write-Host 'Custom scan; remediation disabled for this invocation. Cloud/sample policy still applies; independent protection remains active.'
        $record.Policy | ConvertTo-Json | Out-Host
        $record.Arguments | ConvertTo-Json | Out-Host
        if ($Preview) { $record.Result='PreviewOnly'; return $record }
        if (-not $simAdmin) { throw 'Administrator rights required; no automatic elevation.' }
        if ($Interactive) { $Accepted=((Read-Host 'Type FileScan to authorize this file scan under the displayed policy, or Enter to cancel') -ceq 'FileScan') }
        if (-not $Accepted) { throw 'File scan not acknowledged. Review -PreviewOnly, then explicitly use -AcknowledgeImpact.' }
        $freshPolicy=Get-SimFileScanPolicy
        if ((Get-SimHash $record.Policy) -cne (Get-SimHash $freshPolicy)) { throw 'Defender policy or signatures changed during review; preview again.' }
        [void](Get-SimSingleFile $path)
        if ((Get-SimStreamSHA256 $held) -cne $fingerprint) { throw 'Target changed before scan.' }
        $record.DispatchAt=(Get-Date).ToString('o')
        Save-SimReport $record (Join-Path $runDirectory '02-intent.json')
        $result=Invoke-SimFileScanProcess $record.Binary.Path $record.Arguments $record.Binary.SHA256 $TimeoutSeconds
        $record.Command=[ordered]@{Status=$result.Status;ExitCode=$result.ExitCode;Error=$result.Error;
            Stdout=Convert-SimScanOutput $result.Stdout;Stderr=Convert-SimScanOutput $result.Stderr}
        $record.Result=Get-SimFileScanOutcome $result
        if ($record.Command.Stdout.Text) { Write-Host $record.Command.Stdout.Text }
        if ($record.Command.Stderr.Text) { Write-Host $record.Command.Stderr.Text }
    } catch { $failure=Protect-SimText $_.Exception.Message; if($record){$record.Error=$failure;$record.Result='RefusedOrUnverified'} }
    finally {
        try {
            if ($record) {
                try {
                    $record.SHA256After=Get-SimStreamSHA256 $held
                    if ($record.SHA256After -cne $record.Target.SHA256) { throw 'Target fingerprint changed; scan result unverified.' }
                } catch { $failure=$_.Exception.Message;$record.Error=$failure;$record.Result='Unverified' }
                $record.FinishedAt=(Get-Date).ToString('o')
                try { Save-SimReport $record (Join-Path $runDirectory '03-final.json') }
                catch { $failure='Final evidence could not be saved: '+$_.Exception.Message }
                Write-Host ('Result: '+$record.Result+'; evidence: '+$runDirectory)
            }
        } finally { if($held){$held.Dispose()}; Exit-SimLock $lock }
        # A return from the preview branch must not hide a final-write failure.
        if ($failure) { throw $failure }
    }
    return $record
}
