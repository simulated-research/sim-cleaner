#requires -Version 7.0
[CmdletBinding()]
param([Parameter(Mandatory)][string]$OutputDirectory)
$ErrorActionPreference='Stop'
$kitPath=Split-Path $PSScriptRoot -Parent
$definitions=@{}
foreach($file in @('Safety.ps1','SimCleaner.ps1','FileScan.ps1','Launch-SimCleaner.ps1')) {
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $kitPath $file),[ref]$tokens,[ref]$parseErrors)
    if($parseErrors.Count){throw ($parseErrors | Out-String)}
    foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
        . ([scriptblock]::Create($node.Extent.Text));$definitions[$node.Name]=$node.Extent.Text
    }
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if(Test-Path -LiteralPath $OutputDirectory){throw 'Use a new test directory'}
[void](New-Item -ItemType Directory -Path $OutputDirectory)
$target=Join-Path $OutputDirectory 'inert [literal] & file.zip'
[IO.File]::WriteAllText($target,'Harmless text fixture, not a real archive or executable.')
$originalHash=(Get-FileHash -LiteralPath $target).Hash
$simReports=Join-Path $OutputDirectory 'MockReports'
$ExpectedDevice='Victus';$PreviewOnly=$false;$ScanTimeoutSeconds=30;$ScanPath=$target
$script:cases=[Collections.Generic.List[object]]::new()
function Assert($Condition,[string]$Message='Assertion failed'){if(-not $Condition){throw $Message}}
function MustThrow([scriptblock]$Body,[string]$Pattern){$message='';try{& $Body | Out-Null}catch{$message=$_.Exception.Message};Assert ($message -match $Pattern) "Expected '$Pattern', got '$message'"}
function Case([string]$Name,[scriptblock]$Body){try{& $Body;$script:cases.Add(@{Test=$Name;Passed=$true;Error=$null})}catch{$script:cases.Add(@{Test=$Name;Passed=$false;Error=$_.Exception.Message})}}
function Reset {
    $script:simAdmin=$true;$script:dispatches=0;$script:policyReads=0;$script:policyChanges=$false
    $script:failPolicy=$false;$script:failBinary=$false;$script:failWrite='';$script:throwProcess=$false
    $script:resultCode=0;$script:resultStatus='CommandExited';$script:emptyOutput=$false
    $script:finalPath='';$script:heldWasReadOnly=$false
}
function Get-SimFileScanPolicy {
    $script:policyReads++
    if($script:failPolicy){throw 'Synthetic unreadable policy'}
    @{SubmitSamplesConsent=2;MAPSReporting=0;DisableArchiveScanning=$false;AntivirusSignatureVersion=if($script:policyChanges -and $script:policyReads -gt 1){'new'}else{'fixture'}}
}
function Get-SimMpCmdRun {if($script:failBinary){throw 'Synthetic untrusted binary'};@{Path='C:\fixture\MpCmdRun.exe';SHA256=('A'*64);Version='fixture'}}
function Invoke-SimFileScanProcess($Binary,$Arguments,$ExpectedHash,$TimeoutSeconds){
    $script:dispatches++
    Assert ($Binary -ceq 'C:\fixture\MpCmdRun.exe')
    Assert ($Arguments.Count -eq 6 -and $Arguments[0] -ceq '-Scan' -and $Arguments[1] -ceq '-ScanType' -and $Arguments[2] -ceq '3' -and $Arguments[3] -ceq '-File' -and $Arguments[4] -ceq $target -and $Arguments[5] -ceq '-DisableRemediation') 'Scan scope or non-remediation flags changed'
    try {$writer=[IO.File]::Open($target,[IO.FileMode]::Open,[IO.FileAccess]::Write,[IO.FileShare]::ReadWrite);$writer.Dispose()}catch{$script:heldWasReadOnly=$true}
    if($script:throwProcess){throw 'Synthetic child startup failure'}
    [pscustomobject]@{Status=$script:resultStatus;ExitCode=$script:resultCode;Stdout=[Text.Encoding]::ASCII.GetBytes($(if($script:emptyOutput){''}else{'Synthetic scan output'}));Stderr=[byte[]]@();Error=$null}
}
function Save-SimReport($Record,[string]$Path){
    if($script:failWrite -and $Path.EndsWith($script:failWrite)){throw 'Synthetic evidence write failure'}
    & {param($r,$p,$d). ([scriptblock]::Create($d));Save-SimReport $r $p} $Record $Path $definitions['Save-SimReport']
    if($Path.EndsWith('03-final.json')){$script:finalPath=$Path}
}
function Final {Get-Content -LiteralPath $script:finalPath -Raw | ConvertFrom-Json}
# Fail immediately if any accidentally reached legacy/live action is invoked.
function Start-MpScan {throw 'SAFETY: live/global scan forbidden'}
function Remove-MpThreat {throw 'SAFETY: remediation forbidden'}
function Update-MpSignature {throw 'SAFETY: update forbidden'}
function Get-CimInstance {throw 'SAFETY: live CIM forbidden'}
function Get-MpComputerStatus {throw 'SAFETY: live Defender query forbidden'}
function Get-MpPreference {throw 'SAFETY: live policy query forbidden'}

Case 'Literal spaces/brackets/metacharacters stay one file' {Assert ((Get-SimSingleFile $target) -ceq $target);Assert ((Get-SimFileScanArguments $target)[4] -ceq $target)}
$invalidCase=0
foreach($bad in @('', '.', $OutputDirectory, 'C:\', 'relative.zip', '\\server\share\a.zip', '\\?\C:\a.zip', 'C:\sample.zip:stream', 'C:\*.zip', 'C:\?.zip', (Join-Path $OutputDirectory 'missing.zip'))) {
    $invalidCase++
    Case "Invalid file-scope fixture $invalidCase rejected" {MustThrow {Get-SimSingleFile $bad} '.'}
}
Case 'Directory junction is rejected' {
    $junction=Join-Path $OutputDirectory 'junction'
    [void](New-Item -ItemType Junction -Path $junction -Target $OutputDirectory)
    MustThrow {Get-SimSingleFile (Join-Path $junction ([IO.Path]::GetFileName($target)))} 'Reparse'
}
Case 'Preview persists file/hash/policy and never dispatches, even with acknowledgement' {
    Reset;$script:simAdmin=$false
    $r=Invoke-SimFileScan -Path $target -Preview $true -Accepted $true
    Assert ($r.Result -ceq 'PreviewOnly' -and $script:dispatches -eq 0)
    Assert ((Final).SHA256After -ceq $originalHash)
    Assert (-not (Test-Path -LiteralPath (Join-Path (Split-Path $script:finalPath) '02-intent.json')))
}
Case 'File action routes without reading global Defender inventory' {
    Reset;$PreviewOnly=$true
    try {function Get-SimState {throw 'Must not inventory global state'};$r=Invoke-SimAction FileScan $false;Assert ($r.Result -ceq 'PreviewOnly' -and $script:dispatches -eq 0)} finally {$PreviewOnly=$false}
}
Case 'No acknowledgement refuses dispatch' {Reset;MustThrow {Invoke-SimFileScan -Path $target} 'not acknowledged';Assert ($script:dispatches -eq 0)}
Case 'Nonadmin refuses dispatch' {Reset;$script:simAdmin=$false;MustThrow {Invoke-SimFileScan -Path $target -Accepted $true} 'Administrator';Assert ($script:dispatches -eq 0)}
Case 'Unavailable policy refuses dispatch' {Reset;$script:failPolicy=$true;MustThrow {Invoke-SimFileScan -Path $target -Accepted $true} 'unreadable policy';Assert ($script:dispatches -eq 0)}
Case 'Untrusted scanner refuses dispatch' {Reset;$script:failBinary=$true;MustThrow {Invoke-SimFileScan -Path $target -Accepted $true} 'untrusted binary';Assert ($script:dispatches -eq 0)}
Case 'Changed policy/signatures refuse dispatch' {Reset;$script:policyChanges=$true;MustThrow {Invoke-SimFileScan -Path $target -Accepted $true} 'changed during review';Assert ($script:dispatches -eq 0)}
foreach($phase in @('01-before.json','02-intent.json')){
    Case "Evidence failure $phase prevents dispatch" {Reset;$script:failWrite=$phase;MustThrow {Invoke-SimFileScan -Path $target -Accepted $true} 'evidence write failure';Assert ($script:dispatches -eq 0)}
}
Case 'Final write failure cannot turn preview into success' {Reset;$script:failWrite='03-final.json';MustThrow {Invoke-SimFileScan -Path $target -Preview $true} 'Final evidence';Assert ($script:dispatches -eq 0)}
Case 'Final write failure propagates after mocked scan' {Reset;$script:failWrite='03-final.json';MustThrow {Invoke-SimFileScan -Path $target -Accepted $true} 'Final evidence';Assert ($script:dispatches -eq 1)}
Case 'Exactly one narrow dispatch; input held against writes; hashes unchanged' {
    Reset;$r=Invoke-SimFileScan -Path $target -Accepted $true
    Assert ($script:dispatches -eq 1 -and $script:heldWasReadOnly -and $r.Result -ceq 'CommandReturnedZero')
    Assert ((Final).Target.SHA256 -ceq $originalHash -and (Final).SHA256After -ceq $originalHash)
    Assert (Test-Path -LiteralPath (Join-Path (Split-Path $script:finalPath) '02-intent.json'))
}
Case 'Code two remains ambiguous detection OR error and output is retained' {Reset;$script:resultCode=2;$r=Invoke-SimFileScan -Path $target -Accepted $true;Assert ($r.Result -ceq 'DetectionOrScanError' -and (Final).Command.Stdout.Text -ceq 'Synthetic scan output')}
Case 'Unexpected exit is unverified, no retry' {Reset;$script:resultCode=7;$r=Invoke-SimFileScan -Path $target -Accepted $true;Assert ($r.Result -ceq 'Unverified' -and $script:dispatches -eq 1)}
Case 'Missing output with zero exit is unverified' {Reset;$script:emptyOutput=$true;$r=Invoke-SimFileScan -Path $target -Accepted $true;Assert ($r.Result -ceq 'Unverified')}
Case 'Timeout/capture failure is unverified even with zero exit' {Reset;$script:resultStatus='Unverified';$r=Invoke-SimFileScan -Path $target -Accepted $true;Assert ($r.Result -ceq 'Unverified')}
Case 'Child startup failure saves evidence and releases file/lock' {Reset;$script:throwProcess=$true;MustThrow {Invoke-SimFileScan -Path $target -Accepted $true} 'startup failure';Assert ((Final).Result -ceq 'RefusedOrUnverified');$s=[IO.File]::Open($target,'Open','Write','None');$s.Dispose();$m=Enter-SimLock;Exit-SimLock $m}
Case 'Cancelled interactive prompt never dispatches' {
    Reset;$script:prompts=0
    function Read-Host {param($Prompt)$script:prompts++;if($script:prompts -eq 1){$target}else{'FullScan'}}
    try {MustThrow {Invoke-SimFileScan -Interactive $true} 'not acknowledged';Assert ($script:dispatches -eq 0)} finally {Remove-Item Function:\Read-Host}
}
Case 'Interactive exact FileScan prompt dispatches one file' {
    Reset;$script:prompts=0
    function Read-Host {param($Prompt)$script:prompts++;if($script:prompts -eq 1){$target}else{'FileScan'}}
    try {$r=Invoke-SimFileScan -Interactive $true;Assert ($script:dispatches -eq 1 -and $r.Result -ceq 'CommandReturnedZero')} finally {Remove-Item Function:\Read-Host}
}
Case 'Non-ASCII/control bytes retained exactly without invented decoding' {$b=[byte[]]@(255,254,0,27,200);$o=Convert-SimScanOutput $b;Assert ($null -eq $o.Text -and $o.Base64 -ceq [Convert]::ToBase64String($b))}
Case 'ASCII output remains readable' {Assert ((Convert-SimScanOutput ([Text.Encoding]::ASCII.GetBytes('test'))).Text -ceq 'test')}

function SignatureFixture([string]$Name='Microsoft Windows Publisher',[string]$Status='Valid',[string]$Organization='Microsoft Corporation') {
    $certificate=[pscustomobject]@{Subject="CN=$Name, O=$Organization, C=US";Name=$Name}
    $certificate | Add-Member -MemberType ScriptMethod -Name GetNameInfo -Value {param($type,$issuer) $this.Name}
    [pscustomobject]@{Status=$Status;SignerCertificate=$certificate}
}
Case 'Valid Windows Publisher signature accepted' {Assert (Test-SimScannerSignature (SignatureFixture))}
Case 'Valid Microsoft Corporation signature accepted' {Assert (Test-SimScannerSignature (SignatureFixture 'Microsoft Corporation'))}
Case 'Invalid Windows Publisher signature rejected' {Assert (-not (Test-SimScannerSignature (SignatureFixture 'Microsoft Windows Publisher' 'HashMismatch')))}
Case 'Publisher name alone cannot substitute for Microsoft organization' {Assert (-not (Test-SimScannerSignature (SignatureFixture 'Microsoft Windows Publisher' 'Valid' 'Other Corporation')))}
Case 'Unrecognized Microsoft signer rejected' {Assert (-not (Test-SimScannerSignature (SignatureFixture 'Other Publisher')))}
Case 'Missing signer certificate rejected' {Assert (-not (Test-SimScannerSignature ([pscustomobject]@{Status='Valid';SignerCertificate=$null})))}

function PolicyFixture([string]$Fault) {
    & {
        param($definition,$fault)
        . ([scriptblock]::Create($definition))
        $s=[pscustomobject]@{AntivirusEnabled=$true;AMServiceEnabled=$true;AMRunningMode='Normal';AntivirusSignatureVersion='fixture';AntivirusSignatureLastUpdated=$null}
        $p=[pscustomobject]@{SubmitSamplesConsent=2;MAPSReporting=0;DisableArchiveScanning=$false}
        switch($fault){Passive{$s.AMRunningMode='Passive'};Disabled{$s.AntivirusEnabled=$false};Unknown{$s.AMServiceEnabled=$null};MissingConsent{$p.PSObject.Properties.Remove('SubmitSamplesConsent')};BadMaps{$p.MAPSReporting=9};BadArchive{$p.DisableArchiveScanning='false'};Empty{$s=$null}}
        function Get-MpComputerStatus {[CmdletBinding()]param()$s}
        function Get-MpPreference {[CmdletBinding()]param()$p}
        Get-SimFileScanPolicy
    } $definitions['Get-SimFileScanPolicy'] $Fault
}
Case 'Actual policy collector handles known policy' {Assert ((PolicyFixture Normal).SubmitSamplesConsent -eq 2)}
foreach($fault in @('Passive','Disabled','Unknown','MissingConsent','BadMaps','BadArchive','Empty')){Case "Actual policy collector rejects $fault" {MustThrow {PolicyFixture $fault} '.'}}

# Only this reviewed PowerShell host runs here, with literal inert fixture commands.
# No MpCmdRun, target script, Defender scan, download or system policy change runs.
$runtime=(Get-Process -Id $PID).Path
$runtimeHash=(Get-FileHash -LiteralPath $runtime).Hash
function Fixture([string]$Command,[int]$Seconds=10,[string]$Hash=$runtimeHash){
    & {param($d,$binary,$command,$seconds,$hash). ([scriptblock]::Create($d));Invoke-SimFileScanProcess $binary @('-NoProfile','-NonInteractive','-Command',$command) $hash $seconds} $definitions['Invoke-SimFileScanProcess'] $runtime $Command $Seconds $Hash
}
Case 'Real wrapper captures separate stdout/stderr and nonzero exit' {$r=Fixture '[Console]::Write("out");[Console]::Error.Write("err");exit 2';Assert ($r.ExitCode -eq 2 -and [Text.Encoding]::ASCII.GetString($r.Stdout) -ceq 'out' -and [Text.Encoding]::ASCII.GetString($r.Stderr) -ceq 'err')}
Case 'Real wrapper preserves non-ASCII bytes' {$r=Fixture '[Console]::OpenStandardOutput().Write([byte[]]@(255,254,200),0,3)';Assert ([Convert]::ToBase64String($r.Stdout) -ceq '//7I')}
Case 'Real wrapper refuses executable hash change' {MustThrow {Fixture '[Console]::Write("must not run")' 10 ('0'*64)} 'changed before launch'}
Case 'Real wrapper timeout is unverified' {$r=Fixture 'Start-Sleep -Seconds 4' 1;Assert ($r.Status -ceq 'Unverified' -and $r.Error -match 'timeout')}
Case 'Real wrapper bounds output' {$r=Fixture '[Console]::Write(("x"*4500000))';Assert ($r.Status -ceq 'Unverified' -and $r.Error -match 'limit|4 MiB')}
Case 'Original inert fixture unchanged by all tests' {Assert ((Get-FileHash -LiteralPath $target).Hash -ceq $originalHash)}

$failures=@($script:cases | Where-Object {-not $_.Passed})
$evidence=[ordered]@{Scope='AST-only definitions; mocked OS/policy/Defender/scanner dispatch; actual local evidence and file locks; inert PowerShell stdout/stderr/timeout fixtures. No target code execution or live scan.';Runtime=$PSVersionTable.PSVersion.ToString();ExecutedAt=(Get-Date).ToString('o');Passed=$script:cases.Count-$failures.Count;Failed=$failures.Count;HarnessSHA256=(Get-FileHash -LiteralPath $PSCommandPath).Hash;SourceHashes=@(Get-ChildItem -LiteralPath $kitPath -Filter '*.ps1' | ForEach-Object {@{File=$_.Name;SHA256=(Get-FileHash -LiteralPath $_.FullName).Hash}});Results=@($script:cases)}
$evidence | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'test-results.json') -Encoding utf8
$failures | Format-Table Test,Error -Wrap
Write-Host "Passed: $($evidence.Passed); failed: $($evidence.Failed)"
if($failures.Count){exit 1}
