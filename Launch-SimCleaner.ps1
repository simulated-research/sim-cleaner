#requires -Version 5.1
[CmdletBinding()]
param([ValidateSet('SimCleaner.ps1','Inspect-Windows.ps1')][string]$Script,[ValidateSet('Victus','Gigabyte')][string]$ExpectedDevice,[switch]$ValidateOnly,[ValidateSet('Menu','Status','CleanupPlan')][string]$Action='Menu')
$ErrorActionPreference='Stop'
try {
    $runtime=$env:SIMCLEANER_PWSH
    if(-not $runtime){$runtime=Join-Path $env:ProgramFiles 'PowerShell\7\pwsh.exe'}
    if($runtime -notmatch '^[A-Za-z]:\\' -or $runtime.Substring(2).Contains(':')){throw 'An absolute local reviewed runtime path is required.'}
    $runtime=[IO.Path]::GetFullPath($runtime)
    $drive=New-Object IO.DriveInfo($runtime.Substring(0,3))
    if($drive.DriveType -ne 'Fixed'){throw 'Runtime must be on a local fixed drive.'}
    $cursor=$runtime.Substring(0,3)
    foreach($part in $runtime.Substring(3).Split('\')) {
        $cursor=Join-Path $cursor $part
        if((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Reparse runtime paths rejected.'}
    }
    if([IO.Path]::GetFileName($runtime) -ine 'pwsh.exe'){throw 'Runtime must be pwsh.exe.'}
    $signature=Get-AuthenticodeSignature -LiteralPath $runtime
    if($signature.Status -ne 'Valid' -or -not $signature.SignerCertificate -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'Microsoft Corporation' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)'){throw 'Microsoft runtime publisher could not be verified.'}
    $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($runtime)
    if($version.FileMajorPart -lt 7 -or $version.OriginalFilename -ine 'pwsh.exe'){throw 'PowerShell 7 or later is required.'}
    # Hold the checked executable against write/delete during launch.
    $held=[IO.File]::Open($runtime,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $childArgs=@('-NoProfile','-File',(Join-Path $PSScriptRoot $Script),'-ExpectedDevice',$ExpectedDevice)
    if($ValidateOnly){$childArgs+='-ValidateOnly'}
    if($Script -eq 'SimCleaner.ps1'){$childArgs+=@('-Action',$Action)}
    try {& $runtime @childArgs;$code=$LASTEXITCODE} finally {$held.Dispose()}
    exit $code
} catch {Write-Error ('Launcher refused: '+$_.Exception.Message) -ErrorAction Continue;exit 1}
