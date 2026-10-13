#requires -Version 7.0
[CmdletBinding()]
param([string]$OutputDirectory=(Join-Path $PSScriptRoot ('Results-'+[guid]::NewGuid().ToString('N'))))
# AST definitions only: never execute SimCleaner/Inspect/launcher top-level code.
# All Defender, CIM, events, optional tools and inspection child dispatch are mocked.
# Two small reviewed subprocess fixtures only print data / exit / wait for timeout.
$ErrorActionPreference='Stop'
$kitPath=Split-Path $PSScriptRoot -Parent
$definitions=@{}
foreach($file in @('Safety.ps1','SimCleaner.ps1','Inspect-Windows.ps1','Launch-SimCleaner.ps1')) {
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $kitPath $file),[ref]$tokens,[ref]$errors)
    if($errors.Count){throw ($errors | Out-String)}
    foreach($node in $ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst]},$true)){
        . ([scriptblock]::Create($node.Extent.Text));$definitions[$node.Name]=$node.Extent.Text
    }
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -ErrorAction Stop | Out-Null
$simReports=Join-Path $OutputDirectory 'MockReports'
$simComputer=[pscustomobject]@{Manufacturer='HP';Model='Victus fixture'};$ExpectedDevice='Victus'
$simSourceRoot=$kitPath
$ScanRunDirectory=''
$script:results=[Collections.Generic.List[object]]::new()
function Assert($Condition,[string]$Message='Assertion failed'){if(-not $Condition){throw $Message}}
function MustThrow([scriptblock]$Body,[string]$Pattern){$errorText=$null;try{& $Body | Out-Null}catch{$errorText=$_.Exception.Message};Assert ($errorText -match $Pattern) "Expected '$Pattern'; got '$errorText'"}
function Case([string]$Name,[scriptblock]$Body){try{& $Body;$script:results.Add([pscustomobject]@{Test=$Name;Passed=$true;Error=$null})}catch{$script:results.Add([pscustomobject]@{Test=$Name;Passed=$false;Error=$_.Exception.Message})}}
function ReadyState {
    [ordered]@{
        Defender=[ordered]@{Status='Retrieved';Data=@([pscustomobject]@{AntivirusEnabled=$true;AMServiceEnabled=$true;AMRunningMode='Normal';RealTimeProtectionEnabled=$true;FullScanStartTime=$null;FullScanEndTime=$null;QuickScanStartTime=$null;QuickScanEndTime=$null})}
        Preferences=[ordered]@{Status='Retrieved';Data=@([pscustomobject]@{ExclusionPath=$null;ExclusionExtension=$null;ExclusionProcess=$null;SubmitSamplesConsent=1;MAPSReporting=2;DisableArchiveScanning=$false;DisableRemovableDriveScanning=$true;DisableScanningMappedNetworkDrivesForFullScan=$true;DisableScanningNetworkFiles=$true})}
        Threats=[ordered]@{Status='Empty';Data=@()};Detections=[ordered]@{Status='Empty';Data=@()};Events=[ordered]@{Status='Empty';Data=@()}
    }
}
function Event($Id,$Record,$At,$ScanId='fixture',$Mode='Full Scan') {[pscustomobject]@{Id=$Id;RecordId=$Record;TimeCreated=$At;ScanId=$ScanId;ScanType='Antimalware';ScanParameters=$Mode}}
function Reset {
    $script:calls=@();$script:states=@((ReadyState),(ReadyState),(ReadyState));$script:reads=0;$script:simAdmin=$true;$script:throwAction=$false;$script:saveFail='';$script:throwAfter=$false
}
# Save adapter still performs actual atomic local writes, with injected failures.
# Invoke the unmodified saved writer in a private scope.
function Save-SimReport($Record,[string]$Path){if($script:saveFail -and $Path.EndsWith($script:saveFail)){throw 'Injected disk write failure'};& {param($r,$p,$definition). ([scriptblock]::Create($definition));Save-SimReport $r $p} $Record $Path $definitions['Save-SimReport']}
function Get-SimState {$i=[math]::Min($script:reads,2);$script:reads++;if($i -eq 2 -and $script:throwAfter){throw 'Injected after query failure'};return $script:states[$i]}
function Show-SimPolicy($State){}
function Start-MpScan {[CmdletBinding()]param($ScanType)$script:calls+='Scan:'+ $ScanType;if($script:throwAction){throw 'Injected scan failure after partial progress'}}
function Update-MpSignature {[CmdletBinding()]param()$script:calls+='Update';if($script:throwAction){throw 'Injected update failure'}}
function Remove-MpThreat {[CmdletBinding()]param()$script:calls+='Remediate';if($script:throwAction){throw 'Injected remediation failure'}}
function Start-MpWDOScan {throw 'SAFETY FAILURE: offline dispatch must never execute'}
function LastReport {$dir=Get-ChildItem -LiteralPath $simReports -Directory | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1; Get-Content -LiteralPath (Join-Path $dir.FullName '03-final.json') -Raw | ConvertFrom-Json}
function ActiveThreat($Resource='C:\fixture\safe.exe'){[pscustomobject]@{ThreatID=1;IsActive=$true;ThreatName='Synthetic';Resources=@($Resource);DidThreatExecute=$false;SeverityID=1}}

foreach($fixture in @(@{M='HP';Model='Victus by HP Laptop';Expected='Victus';Valid=$true},@{M='GIGABYTE';Model='G6 KF';Expected='Gigabyte';Valid=$true},@{M='PHP';Model='Victus';Expected='Victus';Valid=$false},@{M='HP';Model='NotVictus';Expected='Victus';Valid=$false},@{M='GIGABYTE';Model='G6 KFA';Expected='Gigabyte';Valid=$false},@{M='HP';Model='Victus';Expected='Gigabyte';Valid=$false})) {
    Case "Target $($fixture.M)/$($fixture.Model)/$($fixture.Expected)" {Assert ((Test-SimTarget ([pscustomobject]@{Manufacturer=$fixture.M;Model=$fixture.Model}) $fixture.Expected) -eq $fixture.Valid)}
}
Case 'Null target refused' {Assert (-not (Test-SimTarget $null 'Victus'))}
Case 'Multiple targets refused' {Assert (-not (Test-SimTarget @($simComputer,$simComputer) 'Victus'))}
Case 'Empty singleton unavailable' {Assert ((Read-SimSection -Singleton {}).Status -eq 'Unavailable')}
Case 'Explicit null query unavailable' {Assert ((Read-SimSection {$null}).Status -eq 'Unavailable')}
Case 'Empty list distinguished' {Assert ((Read-SimSection {}).Status -eq 'Empty')}
Case 'Thrown query unavailable, defined empty Data' {$s=Read-SimSection {throw 'synthetic'};Assert ($s.Status -eq 'Unavailable' -and $s.Data.Count -eq 0)}
Case 'Nonterminating query error unavailable' {Assert ((Read-SimSection {Write-Error 'synthetic'}).Status -eq 'Unavailable')}
Case 'Hidden exclusions placeholder refused' {Assert ((Read-SimSection -Required ExclusionPath {[pscustomobject]@{ExclusionPath='N/A: Must be an administrator to view exclusions'}}).Status -eq 'Unavailable')}
Case 'Unknown state read-only partial' {Reset;$script:states[0].Defender.Status='Unavailable';$r=Invoke-SimAction Status $false;Assert ($r.Result -eq 'PartialReadOnlySnapshot' -and $script:calls.Count -eq 0)}
foreach($mode in @('Passive','EDR Block Mode','')){Case "Defender mode '$mode' refused" {Reset;$script:states[0].Defender.Data[0].AMRunningMode=$mode;MustThrow {Invoke-SimAction FullScan $true} 'disabled, passive, or unknown';Assert ($script:calls.Count -eq 0)}}
Case 'String false is not a boolean state' {Reset;$script:states[0].Defender.Data[0].AntivirusEnabled='false';MustThrow {Invoke-SimAction FullScan $true} 'disabled, passive, or unknown';Assert ($script:calls.Count -eq 0)}
Case 'Nonadmin refuses action' {Reset;$script:simAdmin=$false;MustThrow {Invoke-SimAction FullScan $true} 'Administrator';Assert ($script:calls.Count -eq 0)}
Case 'No consent refuses action' {Reset;MustThrow {Invoke-SimAction FullScan $false} 'not acknowledged';Assert ($script:calls.Count -eq 0)}
Case 'Unknown policy refuses action' {Reset;$script:states[0].Preferences.Status='Unavailable';MustThrow {Invoke-SimAction FullScan $true} 'policy unavailable';Assert ($script:calls.Count -eq 0)}
Case 'Policy changed since review refuses action' {Reset;$script:states[1].Preferences.Data[0].SubmitSamplesConsent=2;MustThrow {Invoke-SimAction FullScan $true} 'policy changed';Assert ($script:calls.Count -eq 0)}
Case 'Signature updates require consent' {Reset;MustThrow {Invoke-SimAction UpdateSignatures $false} 'not acknowledged';Assert ($script:calls.Count -eq 0)}
Case 'Signature update uses mock and three phase files' {Reset;$r=Invoke-SimAction UpdateSignatures $true;Assert (($script:calls -join ',') -eq 'Update');$files=Get-ChildItem (Join-Path $simReports $r.RunId);Assert ($files.Count -eq 3)}
Case 'Offline always blocked even acknowledged' {Reset;MustThrow {Invoke-SimAction OfflineScan $true} 'OfflineScan blocked';Assert ($script:calls.Count -eq 0)}
Case 'Initial evidence failure prevents dispatch' {Reset;$script:saveFail='01-before.json';MustThrow {Invoke-SimAction FullScan $true} 'disk write';Assert ($script:calls.Count -eq 0)}
Case 'Intent evidence failure prevents dispatch' {Reset;$script:saveFail='02-intent.json';MustThrow {Invoke-SimAction FullScan $true} 'disk write';Assert ($script:calls.Count -eq 0)}
Case 'Action failure captures after state' {Reset;$script:throwAction=$true;MustThrow {Invoke-SimAction FullScan $true} 'Injected scan failure';$r=LastReport;Assert ($null -ne $r.After -and $r.Error -match 'Injected scan failure')}
Case 'Final evidence failure preserves primary error and before/intent' {Reset;$script:throwAction=$true;$script:saveFail='03-final.json';MustThrow {Invoke-SimAction FullScan $true} 'Injected scan failure.*Final evidence';$dir=Get-ChildItem $simReports -Directory|Sort-Object LastWriteTimeUtc -Descending|Select-Object -First 1;Assert ((Test-Path (Join-Path $dir.FullName '01-before.json')) -and (Test-Path (Join-Path $dir.FullName '02-intent.json')))}
Case 'Completed first FullScan exact correlated event/history' {Reset;$at=Get-Date;$script:states[2].Events=[ordered]@{Status='Retrieved';Data=@((Event 1000 1 $at),(Event 1001 2 $at.AddSeconds(1)))};$script:states[2].Defender.Data[0].FullScanStartTime=$at;$script:states[2].Defender.Data[0].FullScanEndTime=$at.AddSeconds(1);$r=Invoke-SimAction FullScan $true;Assert ($r.Result -eq 'CompletedWithCorrelatedEvidence' -and ($script:calls -join ',') -eq 'Scan:FullScan')}
Case 'Command return without lifecycle is nonzero/unknown' {Reset;MustThrow {Invoke-SimAction FullScan $true} 'Unverified';Assert ((LastReport).Result -eq 'Unverified')}
Case 'Cancelled scan has explicit outcome' {Reset;$at=Get-Date;$script:states[2].Events=[ordered]@{Status='Retrieved';Data=@((Event 1000 1 $at),(Event 1002 2 $at.AddSeconds(1)))};MustThrow {Invoke-SimAction FullScan $true} 'Cancelled';Assert ((LastReport).Result -eq 'Cancelled')}
Case 'Cleanup missing token refused' {Reset;$script:states[0].Threats=[ordered]@{Status='Retrieved';Data=@((ActiveThreat))};$script:states[1].Threats=$script:states[0].Threats;MustThrow {Invoke-SimAction Remediate $true} 'token missing/stale';Assert ($script:calls.Count -eq 0)}
Case 'Cleanup fresh reviewed token dispatches ALL mock once' {Reset;foreach($s in $script:states[0..1]){$s.Threats=[ordered]@{Status='Retrieved';Data=@((ActiveThreat))}};$token=Get-SimPlanToken $script:states[0];$r=Invoke-SimAction Remediate $true $token;Assert (($script:calls -join ',') -eq 'Remediate' -and $r.Result -match 'efficacy unverified')}
Case 'Cleanup new resource invalidates token' {Reset;$script:states[0].Threats=[ordered]@{Status='Retrieved';Data=@((ActiveThreat))};$script:states[1].Threats=[ordered]@{Status='Retrieved';Data=@((ActiveThreat 'C:\fixture\new.exe'))};$token=Get-SimPlanToken $script:states[0];MustThrow {Invoke-SimAction Remediate $true $token} 'token missing/stale';Assert ($script:calls.Count -eq 0)}
Case 'Cleanup no threats invokes no removal' {Reset;$token=Get-SimPlanToken $script:states[0];Invoke-SimAction Remediate $true $token | Out-Null;Assert ($script:calls.Count -eq 0)}
Case 'Malformed threat boolean refused' {Reset;$script:states[0].Threats=[ordered]@{Status='Retrieved';Data=@([pscustomobject]@{ThreatID=1;IsActive='false'})};MustThrow {Get-SimPlanToken $script:states[0]} 'Malformed'}
Case 'Unavailable threat plan refused' {Reset;$script:states[0].Threats.Status='Unavailable';MustThrow {Invoke-SimAction CleanupPlan $false} 'Readable threat';Assert ($script:calls.Count -eq 0)}
Case 'Remaining active threats propagate incomplete outcome' {Reset;foreach($s in $script:states){$s.Threats=[ordered]@{Status='Retrieved';Data=@((ActiveThreat))}};$token=Get-SimPlanToken $script:states[0];MustThrow {Invoke-SimAction Remediate $true $token} 'Active threats remain'}
Case 'Action primary error survives after collection failure' {Reset;$script:throwAction=$true;$script:throwAfter=$true;MustThrow {Invoke-SimAction FullScan $true} 'Injected scan failure.*After evidence failed';Assert ((LastReport).After.Status -eq 'Unavailable')}
Case 'Unreadable events cause partial status' {Reset;$script:states[0].Events.Status='Unavailable';Assert ((Invoke-SimAction Status $false).Result -eq 'PartialReadOnlySnapshot')}
Case 'Known preexisting active scan blocks new dispatch' {Reset;$script:states[1].Events=[ordered]@{Status='Retrieved';Data=@((Event 1000 1 (Get-Date).AddMinutes(-1)))};MustThrow {Invoke-SimAction FullScan $true} 'unresolved scan';Assert ($script:calls.Count -eq 0)}
Case 'Unreadable pre-dispatch events block scan' {Reset;$script:states[1].Events.Status='Unavailable';MustThrow {Invoke-SimAction FullScan $true} 'evidence unavailable';Assert ($script:calls.Count -eq 0)}
Case 'Wrong interactive acknowledgment cancels mutation' {Reset;function Read-Host {param($Prompt)'QuickScan'};try{MustThrow {Invoke-SimAction FullScan $false '' $true} 'not acknowledged';Assert ($script:calls.Count -eq 0)}finally{Remove-Item Function:\Read-Host}}

# Exercise unmodified collection function with every OS/API dependency intercepted.
function QueryFixture([string]$Kind) {
    & {
        param($kind,$definition)
        . ([scriptblock]::Create($definition))
        $state=ReadyState
        $defender=$state.Defender.Data[0];$preferences=$state.Preferences.Data[0]
        switch($kind){EmptyDefender{$defender=$null};MissingHistory{$defender.PSObject.Properties.Remove('FullScanEndTime')};HiddenExclusions{$preferences.ExclusionPath=@('N/A: Must be an administrator to view exclusions')};MissingExclusionField{$preferences.PSObject.Properties.Remove('ExclusionPath')};NullPreferences{$preferences=$null};StringCoverage{$preferences.DisableArchiveScanning='false'}}
        function Get-MpComputerStatus {[CmdletBinding()]param()$defender}
        function Get-MpPreference {[CmdletBinding()]param()$preferences}
        function Get-MpThreat {[CmdletBinding()]param()}
        function Get-MpThreatDetection {[CmdletBinding()]param()}
        function Get-WinEvent {[CmdletBinding()]param($FilterHashtable,$MaxEvents)}
        Get-SimState
    } $Kind $definitions['Get-SimState']
}
Case 'Actual collector accepts genuine nullable empty exclusions' {$s=QueryFixture EmptyExclusions;Assert ($s.Preferences.Status -eq 'Retrieved');Assert-SimReady $s}
Case 'Actual collector hidden admin sentinel fails closed' {Assert ((QueryFixture HiddenExclusions).Preferences.Status -eq 'Unavailable')}
Case 'Actual collector missing exclusion property fails closed' {Assert ((QueryFixture MissingExclusionField).Preferences.Status -eq 'Unavailable')}
Case 'Actual collector empty Defender singleton unavailable' {Assert ((QueryFixture EmptyDefender).Defender.Status -eq 'Unavailable')}
Case 'Actual collector missing history is not first-scan null' {Assert ((QueryFixture MissingHistory).Defender.Status -eq 'Unavailable')}
Case 'Actual collector null preferences unavailable' {Assert ((QueryFixture NullPreferences).Preferences.Status -eq 'Unavailable')}
Case 'Actual collector string coverage refused' {$s=QueryFixture StringCoverage;MustThrow {Assert-SimReady $s} 'malformed'}
Case 'Preflight omits redundant detection history' {
 & {param($definition). ([scriptblock]::Create($definition));function Get-MpComputerStatus {[CmdletBinding()]param()(ReadyState).Defender.Data[0]};function Get-MpPreference {[CmdletBinding()]param()(ReadyState).Preferences.Data[0]};function Get-MpThreat {[CmdletBinding()]param()};function Get-MpThreatDetection {throw 'Redundant query must not run'};function Get-WinEvent {[CmdletBinding()]param($FilterHashtable,$MaxEvents)};$s=Get-SimState -PreflightOnly;Assert ($s.Detections.Status -eq 'NotCollected')} $definitions['Get-SimState']
}
Case 'Confirmed no matching events is known Empty history' {
 function Get-WinEvent {[CmdletBinding()]param($FilterHashtable,$MaxEvents,$ListLog)if($ListLog){[pscustomobject]@{IsEnabled=$true}}else{Write-Error 'No matching fixtures' -ErrorId 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'}}
 try{Assert ((Get-SimEvents).Status -eq 'Empty')}finally{Remove-Item Function:\Get-WinEvent}
}
Case 'Disabled log is Unavailable despite no-matches signal' {
 function Get-WinEvent {[CmdletBinding()]param($FilterHashtable,$MaxEvents,$ListLog)if($ListLog){[pscustomobject]@{IsEnabled=$false}}else{Write-Error 'No matching fixtures' -ErrorId 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'}}
 try{Assert ((Get-SimEvents).Status -eq 'Unavailable')}finally{Remove-Item Function:\Get-WinEvent}
}
Case 'Event permission failure is Unavailable not Empty' {
 function Get-WinEvent {[CmdletBinding()]param($FilterHashtable,$MaxEvents,$ListLog)throw 'Synthetic access denied'}
 try{Assert ((Get-SimEvents).Status -eq 'Unavailable')}finally{Remove-Item Function:\Get-WinEvent}
}

# Direct lifecycle matrix: no command dispatch, synthetic data only.
$at=[datetime]'2026-10-13T01:00:00Z'
function Lifecycle {
    $before=ReadyState;$after=ReadyState
    $after.Events=[ordered]@{Status='Retrieved';Data=@((Event 1000 1 $at),(Event 1001 2 $at.AddSeconds(30)))}
    $after.Defender.Data[0].FullScanStartTime=$at;$after.Defender.Data[0].FullScanEndTime=$at.AddSeconds(30)
    return @($before,$after)
}
foreach($kind in @('WrongId','WrongType','OtherStart','StaleHistory','MissingHistory','UnavailableLog','Truncated','Localized','Preexisting','ClearedLog')) {
 Case "Lifecycle $kind cannot claim completion" {
    $pair=Lifecycle;$b=$pair[0];$a=$pair[1]
    switch($kind){
      WrongId {$a.Events.Data[1].ScanId='other'}
      WrongType {$a.Events.Data[0].ScanParameters='Quick Scan'}
      OtherStart {$a.Events.Data+=Event 1000 3 $at.AddSeconds(2) 'other'}
      StaleHistory {$b.Defender.Data[0].FullScanEndTime=$a.Defender.Data[0].FullScanEndTime}
      MissingHistory {$a.Defender.Data[0].FullScanEndTime=$null}
      UnavailableLog {$b.Events.Status='Unavailable'}
      Truncated {$a.Events.Data=@($a.Events.Data[0])*4096}
      Localized {$a.Events.Data[0].ScanParameters='Analyse complete'}
      Preexisting {$a.Events.Data[0].TimeCreated=$at.AddHours(-1)}
      ClearedLog {$b.Events=[ordered]@{Status='Retrieved';Data=@((Event 1117 200 $at.AddMinutes(-1)))}}
    }
    Assert ((Get-SimScanOutcome $b $a FullScan $at).Status -eq 'Unverified')
 }
}
Case 'Historical real Quick Scan fixture (not invoked)' {
 $fixture=Get-Content (Join-Path $PSScriptRoot 'historical-scan-fixture.json') -Raw|ConvertFrom-Json
 $b=ReadyState;$a=ReadyState;$start=$fixture.Start;$start.TimeCreated=[datetime]$start.TimeCreated
 foreach($e in $fixture.EndEvents){$e.TimeCreated=[datetime]$e.TimeCreated}
 $a.Events=[ordered]@{Status='Retrieved';Data=@($start)+@($fixture.EndEvents)}
 $a.Defender.Data[0].QuickScanStartTime=[datetime]$fixture.CurrentHistory.QuickScanStartTime;$a.Defender.Data[0].QuickScanEndTime=[datetime]$fixture.CurrentHistory.QuickScanEndTime
 Assert ((Get-SimScanOutcome $b $a QuickScan $start.TimeCreated).Status -eq 'CompletedWithCorrelatedEvidence')
}
Case 'Named XML parsed; no localized message use' {
 $event=[pscustomobject]@{Id=1000;RecordId=1;TimeCreated=$at};$event|Add-Member ScriptMethod ToXml {'<Event><EventData><Data Name="Scan ID">fixture</Data><Data Name="Scan Type">Antimalware</Data><Data Name="Scan Parameters">Quick Scan</Data></EventData></Event>'}
 $r=Convert-SimEvent $event;Assert ($r.ScanId -eq 'fixture' -and $r.ScanParameters -eq 'Quick Scan')
}
function IntentFixture {
 Reset;$pair=Lifecycle;$folder=Join-Path $OutputDirectory ('intent-'+[guid]::NewGuid().ToString('N'));New-Item -ItemType Directory -Path $folder|Out-Null
 $intent=[ordered]@{Tool='Sim Cleaner';Version='0.2.0';Device='Victus';RunId='original-synthetic';Action='FullScan';DispatchAt=$at.ToString('o');PreDispatch=$pair[0]}
 Save-SimReport $intent (Join-Path $folder '02-intent.json');return @($folder,$pair[1])
}
Case 'Read-only recheck verifies delayed same-ID completion' {$fixture=IntentFixture;$script:states[0]=$fixture[1];$r=Invoke-SimAction RecheckScan $false '' $false $fixture[0];Assert ($r.Result -eq 'CompletedWithCorrelatedEvidence' -and $script:calls.Count -eq 0 -and $r.SourceIntent.SHA256.Length -eq 64)}
Case 'Read-only recheck running/start-only remains Unverified' {$fixture=IntentFixture;$fixture[1].Events.Data=@($fixture[1].Events.Data[0]);$script:states[0]=$fixture[1];MustThrow {Invoke-SimAction RecheckScan $false '' $false $fixture[0]} 'Unverified';Assert ($script:calls.Count -eq 0)}
Case 'Read-only recheck cancellation does not dispatch' {$fixture=IntentFixture;$fixture[1].Events.Data[1].Id=1002;$script:states[0]=$fixture[1];MustThrow {Invoke-SimAction RecheckScan $false '' $false $fixture[0]} 'Cancelled';Assert ($script:calls.Count -eq 0)}
Case 'Read-only recheck rejects wrong-device intent' {Reset;$folder=Join-Path $OutputDirectory 'wrong-device';New-Item -ItemType Directory $folder|Out-Null;Save-SimReport @{Tool='Sim Cleaner';Version='0.2.0';Device='Gigabyte';Action='FullScan';PreDispatch=@{};DispatchAt=$at.ToString('o')} (Join-Path $folder '02-intent.json');MustThrow {Invoke-SimAction RecheckScan $false '' $false $folder} 'different-device';Assert ($script:calls.Count -eq 0)}
Case 'Read-only recheck rejects remote input before access' {Reset;MustThrow {Invoke-SimAction RecheckScan $false '' $false '\\fixture.invalid\share'} 'absolute local';Assert ($script:calls.Count -eq 0)}
foreach($path in @('\\fixture.invalid\share\a.exe','\\?\UNC\fixture.invalid\share\a.exe','\\.\C:\a.exe','relative.exe','C:\safe.exe:stream')){Case "Reject remote/device/ADS path $path" {MustThrow {Assert-SimLocalPath $path -Leaf} 'absolute local'}}
Case 'Reparse ancestor rejected before descendant probe (inert mocks)' {
 $script:probes=@()
 function Test-Path {param($LiteralPath,$PathType)$script:probes+=$LiteralPath;return $true}
 function Get-Item {[CmdletBinding()]param($LiteralPath,[switch]$Force)$script:probes+=$LiteralPath;[pscustomobject]@{Attributes=if($LiteralPath -eq 'C:\fixture\junction'){[IO.FileAttributes]::ReparsePoint}else{[IO.FileAttributes]::Directory}}}
 try {MustThrow {Assert-SimLocalPath 'C:\fixture\junction\remote.exe' -Leaf} 'Reparse';Assert ($script:probes -notcontains 'C:\fixture\junction\remote.exe')}finally{Remove-Item Function:\Test-Path;Remove-Item Function:\Get-Item}
}
Case 'Bearer, quoted password, URL credentials minimized' {
 $safe=Protect-SimText "authorization: Bearer SYNTHETIC_BEARER`npassword='SYNTHETIC MULTI WORD'`nhttps://syntheticuser:syntheticpass@example.invalid/p?q=SYNTHETIC_QUERY#secret"
 Assert ($safe -notmatch 'SYNTHETIC|syntheticuser|syntheticpass|secret')
}
Case 'Wider redaction covers common token and key shapes' {
 $pem="-----BEGIN RSA PRIVATE KEY-----`nSYNTHKEYLINE`n-----END RSA PRIVATE KEY-----"
 $safe=Protect-SimText ("token1 eyJabcdef.ghijkl.mnopqr`ntoken2 AKIAABCDEFGHIJKLMNOP`ntoken3 xoxb-1234567890-ZZZZ`nclient_secret=SYNTHSECRET`npwd=SYNTHPWD`n"+$pem)
 Assert ($safe -notmatch 'SYNTH|eyJabcdef|AKIAABCDEFGHIJKLMNOP|xoxb-1234567890')
}
Case 'Known sensitive fields minimized across structured objects and dictionaries' {
 $safe=ConvertTo-SimSafeData ([pscustomobject]@{client_secret='SYNTHETIC_SECRET';Nested=@([pscustomobject]@{Password='SYNTHETIC_PASSWORD'},[ordered]@{RefreshToken='SYNTHETIC_REFRESH'});Description='fixture metadata'})
 Assert ($safe.client_secret -ceq '[redacted]' -and $safe.Nested[0].Password -ceq '[redacted]' -and $safe.Nested[1].RefreshToken -ceq '[redacted]')
 Assert ($safe.Description -ceq 'fixture metadata' -and ($safe|ConvertTo-Json -Depth 8) -notmatch 'SYNTHETIC')
}
Case 'Suspicion score ranks unsigned temp file above signed program file' {
 $hot=Get-InspectionSuspicionScore ([pscustomobject]@{'Image Path'='C:\Users\u\AppData\Local\Temp\x.exe';Signer='Not collected';Company='';Enabled='enabled'})
 $cold=Get-InspectionSuspicionScore ([pscustomobject]@{'Image Path'='C:\Program Files\Vendor\app.exe';Signer='Vendor Inc';Company='Vendor Inc';Enabled='enabled'})
 Assert ($hot -gt $cold)
}
Case 'Safe report recursively minimizes synthetic secrets' {Reset;$path=Join-Path $OutputDirectory 'privacy.json';Save-SimReport ([ordered]@{Authorization='SYNTHETIC';Nested=@('authorization: Bearer SYNTHETIC')}) $path;Assert ((Get-Content $path -Raw) -notmatch 'SYNTHETIC')}
Case 'Atomic report refuses overwrite and preserves bytes' {Reset;$path=Join-Path $OutputDirectory 'durable.json';Save-SimReport @{Value=1} $path;$old=(Get-FileHash $path).Hash;MustThrow {Save-SimReport @{Value=2} $path} 'refusing overwrite';Assert ((Get-FileHash $path).Hash -eq $old)}
Case 'Unique run directories even close invocation times' {Reset;$a=Invoke-SimAction Status $false;Reset;$b=Invoke-SimAction Status $false;Assert ($a.RunId -ne $b.RunId)}
Case 'Lock refuses another thread/runspace, releases afterwards' {
 $lock=Enter-SimLock
 $ps=[powershell]::Create()
 try {$ps.AddScript('$m=[Threading.Mutex]::new($false,"Global\SimCleaner.LocalReview.v02");try{$got=$m.WaitOne(0);if($got){$m.ReleaseMutex()};$got}finally{$m.Dispose()}')|Out-Null;$r=$ps.Invoke();Assert ($r.Count -eq 1 -and $r[0] -eq $false)}finally{$ps.Dispose();Exit-SimLock $lock}
 $again=Enter-SimLock;Exit-SimLock $again
}
Case 'Unavailable count is Unknown, not null row 1' {Assert ((Get-InspectionCount @{Status='Unavailable';Data=@()}) -eq 'Unknown')}
Case 'Empty count is known zero' {Assert ((Get-InspectionCount @{Status='Empty';Data=@()}) -eq 0)}
Case 'Nested socket failures included' {$problems=@(Get-InspectionProblems @{SocketSamples=@(@{Status='Unavailable';Error='fixture';Data=@()})});Assert ($problems.Count -eq 1 -and $problems[0] -match 'SocketSamples/0')}
Case 'DomainAuthenticated maps to effective Domain firewall' {$summary=Get-InspectionFirewallSummary ([pscustomobject]@{NetworkCategory='DomainAuthenticated';InterfaceAlias='fixture'}) @{Status='Retrieved';Data=@([pscustomobject]@{Name='Domain';Enabled=$true})};Assert ($summary -match 'Domain; firewall enabled: True.*ActiveStore')}
Case 'Missing firewall profile is Unknown' {Assert ((Get-InspectionFirewallSummary ([pscustomobject]@{NetworkCategory='DomainAuthenticated'}) @{Status='Unavailable';Data=@()}) -match 'Unknown')}
Case 'Inspector child nonzero propagated using inert function adapter' {
 function Get-Process {param($Id)[pscustomobject]@{Path='Invoke-InertInspectionChild'}}
 function Invoke-InertInspectionChild {param([switch]$NoProfile,$File,$ExpectedDevice)$global:LASTEXITCODE=7}
 try {MustThrow {Invoke-SimInspection} 'exit 7'}finally{Remove-Item Function:\Get-Process;Remove-Item Function:\Invoke-InertInspectionChild}
}
# Static boundary assertions complement mocks; they are not Windows integration tests.
$inspector=Get-Content (Join-Path $kitPath 'Inspect-Windows.ps1') -Raw;$source=Get-Content (Join-Path $kitPath 'SimCleaner.ps1') -Raw
Case 'No offline API call in production source' {Assert ($source -notmatch 'Start-MpWDOScan')}
Case 'Effective firewall store explicit in exact package' {Assert ($inspector -match 'Get-NetFirewallProfile -PolicyStore ActiveStore')}
Case 'Installed provider subset used for bounded event query' {Assert ($inspector -match 'Filter.ProviderName=@\(\$ProviderCoverage.InstalledProviders\)' -and $inspector -match 'TcpAllocationEvents=Get-InspectionEventSection')}
Case 'Missing optional driver provider does not break installed event query' {
 $script:queriedProviders=@()
 function Get-WinEvent {[CmdletBinding()]param($ListProvider,$FilterHashtable,$MaxEvents,$ListLog)
  if($ListProvider){throw 'Full provider metadata must not be queried'}
  elseif($ListLog){[pscustomobject]@{IsEnabled=$true}}
  else{$script:queriedProviders=@($FilterHashtable.ProviderName);[pscustomobject]@{Id=4231;ProviderName='Tcpip';TimeCreated=Get-Date;LevelDisplayName='Warning'}}
 }
 try{$coverage=Get-InspectionProviderCoverage @('Tcpip','Netwtw10','Netwtw14') @{Status='Retrieved';Data=@('Tcpip','Netwtw14')};$section=Get-InspectionEventSection System @{LogName='System';StartTime=(Get-Date).AddDays(-7)} 500 $coverage;Assert ($coverage.Status -eq 'Retrieved' -and $coverage.AbsentProviders -contains 'Netwtw10' -and $section.Status -eq 'Retrieved' -and $script:queriedProviders -notcontains 'Netwtw10' -and $script:queriedProviders -contains 'Netwtw14')}
 finally{Remove-Item Function:\Get-WinEvent}
}
Case 'Provider access denied remains unknown and blocks empty-success query' {
 $script:eventQueryCalled=$false
 function Get-WinEvent {[CmdletBinding()]param($ListProvider,$FilterHashtable,$MaxEvents,$ListLog)if($ListProvider){throw 'Synthetic metadata access denied'}else{$script:eventQueryCalled=$true}}
 try{$coverage=Get-InspectionProviderCoverage @('Tcpip') @{Status='Unavailable';Data=@();Error='Synthetic access denied'};$section=Get-InspectionEventSection System @{LogName='System';StartTime=Get-Date} 500 $coverage;Assert ($coverage.Status -eq 'Unavailable' -and $section.Status -eq 'Unavailable' -and -not $script:eventQueryCalled)}finally{Remove-Item Function:\Get-WinEvent}
}
Case 'No installed TCP providers is unknown, not zero failures' {
 function Get-WinEvent {[CmdletBinding()]param($ListProvider,$FilterHashtable,$MaxEvents,$ListLog)Write-Error 'Missing fixture provider' -ErrorId 'NoMatchingProvidersFound,Microsoft.PowerShell.Commands.GetWinEventCommand'}
 try{$coverage=Get-InspectionProviderCoverage @('Tcpip') @{Status='Retrieved';Data=@('OtherPublisher')};$section=Get-InspectionEventSection System @{LogName='System'} 500 $coverage;Assert ($section.Status -eq 'Unavailable')}
 finally{Remove-Item Function:\Get-WinEvent}
}
Case 'Known no event matches requires readable enabled log' {
 function Get-WinEvent {[CmdletBinding()]param($ListProvider,$FilterHashtable,$MaxEvents,$ListLog)if($ListLog){[pscustomobject]@{IsEnabled=$true}}else{Write-Error 'No matching synthetic events' -ErrorId 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'}}
 try{$section=Get-InspectionEventSection System @{LogName='System'} 500;Assert ($section.Status -eq 'Empty' -and -not $section.CapReached)}finally{Remove-Item Function:\Get-WinEvent}
}
Case 'No matching events with unreadable log remains unavailable' {
 function Get-WinEvent {[CmdletBinding()]param($ListProvider,$FilterHashtable,$MaxEvents,$ListLog)if($ListLog){throw 'Synthetic log access denied'}else{Write-Error 'No matches' -ErrorId 'NoMatchingEventsFound,Microsoft.PowerShell.Commands.GetWinEventCommand'}}
 try{Assert ((Get-InspectionEventSection System @{LogName='System'} 500).Status -eq 'Unavailable')}finally{Remove-Item Function:\Get-WinEvent}
}
Case 'Dedicated TCP query cannot be crowded out by general provider cap' {
 $script:filterSeen=$null
 function Get-WinEvent {[CmdletBinding()]param($ListProvider,$FilterHashtable,$MaxEvents,$ListLog)$script:filterSeen=$FilterHashtable;[pscustomobject]@{Id=4231;ProviderName='Tcpip';TimeCreated=Get-Date;LevelDisplayName='Warning'}}
 try{$coverage=@{Status='Retrieved';InstalledProviders=@('Tcpip')};$s=Get-InspectionEventSection System @{LogName='System';Id=@(4231,4266,4227);StartTime=(Get-Date).AddDays(-7)} 500 $coverage;Assert ($s.Status -eq 'Retrieved' -and ($script:filterSeen.Id -join ',') -eq '4231,4266,4227' -and $s.Data.Count -eq 1)}finally{Remove-Item Function:\Get-WinEvent}
}
Case 'No untrusted CSV written' {Assert ($inspector -notmatch 'Export-Csv')}
Case 'Downloads do not follow redirects' {Assert ($inspector -match '-MaximumRedirection 0')}
Case 'External tools and EULA require explicit options' {Assert ($inspector -match 'UseMicrosoftTools -and -not \$AcceptToolEula' -and $inspector -match 'if\(-not \$DownloadMicrosoftTools\)')}
Case 'No VirusTotal flags added' {Assert ($inspector -notmatch "'-(v|vs|vt)'" )}
Case 'Launchers preserve exit and avoid PATH search' {foreach($file in Get-ChildItem $kitPath -Filter '*.cmd'){$text=Get-Content $file.FullName -Raw;Assert ($text -match 'setlocal' -and $text -match 'exit /b %inspection_exit%' -and $text -notmatch 'where pwsh|set .*pwsh.exe')}}

Case 'Official lowercase Autoruns member accepted' {$m=Get-InspectionArchiveMember @([pscustomobject]@{FullName='autorunsc64.exe';Length=1460024}) 'autorunsc64.exe';Assert ($m.FullName -ceq 'autorunsc64.exe')}
Case 'Windows-equivalent case variant accepted uniquely' {$m=Get-InspectionArchiveMember @([pscustomobject]@{FullName='Autorunsc64.exe';Length=1460024}) 'autorunsc64.exe';Assert ($m.FullName -ceq 'Autorunsc64.exe')}
Case 'Case-colliding collector members rejected' {MustThrow {Get-InspectionArchiveMember @([pscustomobject]@{FullName='autorunsc64.exe';Length=1},[pscustomobject]@{FullName='Autorunsc64.exe';Length=1}) 'autorunsc64.exe'} 'ambiguous'}
Case 'Subdirectory collector member rejected' {MustThrow {Get-InspectionArchiveMember @([pscustomobject]@{FullName='folder/autorunsc64.exe';Length=1}) 'autorunsc64.exe'} 'invalid'}
Case 'Traversal collector member rejected' {MustThrow {Get-InspectionArchiveMember @([pscustomobject]@{FullName='../autorunsc64.exe';Length=1}) 'autorunsc64.exe'} 'invalid'}
Case 'Oversize collector member rejected' {MustThrow {Get-InspectionArchiveMember @([pscustomobject]@{FullName='autorunsc64.exe';Length=33554433}) 'autorunsc64.exe'} 'too large'}
Case 'Empty collector member rejected' {MustThrow {Get-InspectionArchiveMember @([pscustomobject]@{FullName='autorunsc64.exe';Length=0}) 'autorunsc64.exe'} 'invalid'}
Case 'Unapproved canonical collector name rejected' {MustThrow {Get-InspectionArchiveMember @([pscustomobject]@{FullName='other.exe';Length=1}) 'other.exe'} 'Unexpected'}

Case 'Observed Autorunsc shared GUI original filename accepted' {Assert (Test-InspectionCollectorMetadata Autoruns ([pscustomobject]@{OriginalFilename='autoruns.exe';ProductName='Sysinternals autoruns';FileVersion='14.3'}))}
Case 'Observed signed Sigcheck family accepted' {Assert (Test-InspectionCollectorMetadata Sigcheck ([pscustomobject]@{OriginalFilename='sigcheck.exe';ProductName='Sysinternals Sigcheck';FileVersion='2.92'}))}
Case 'Collector wrong original filename rejected' {Assert (-not (Test-InspectionCollectorMetadata Autoruns ([pscustomobject]@{OriginalFilename='cmd.exe';ProductName='Sysinternals autoruns';FileVersion='14.3'})))}
Case 'Collector wrong product rejected' {Assert (-not (Test-InspectionCollectorMetadata Autoruns ([pscustomobject]@{OriginalFilename='autoruns.exe';ProductName='Other';FileVersion='14.3'})))}
Case 'Collector missing version rejected' {Assert (-not (Test-InspectionCollectorMetadata Autoruns ([pscustomobject]@{OriginalFilename='autoruns.exe';ProductName='Sysinternals autoruns';FileVersion=''})))}
Case 'Collector invalid version rejected' {Assert (-not (Test-InspectionCollectorMetadata Autoruns ([pscustomobject]@{OriginalFilename='autoruns.exe';ProductName='Sysinternals autoruns';FileVersion='garbage'})))}
Case 'Collector null metadata rejected' {Assert (-not (Test-InspectionCollectorMetadata Autoruns $null))}

Case 'Actual metadata-only Autoruns schema accepted without signer' {
 $csv="Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String`n0,local,Synthetic,true,Logon,local,description,company,C:\fixture\safe.exe,1.0,SYNTHETIC_SECRET"
 $rows=@(Convert-InspectionStartupCsv $csv);Assert ($rows.Count -eq 1 -and $rows[0].Signer -ceq 'Not collected' -and $rows[0].SignatureCoverage -match 'Not requested');Assert (($rows|ConvertTo-Json) -notmatch 'SYNTHETIC_SECRET|Launch String|Profile')
}
Case 'Autoruns optional reported signer preserved without safety inference' {
 $csv="Time,Entry Location,Entry,Enabled,Category,Profile,Description,Company,Image Path,Version,Launch String,Signer`n0,local,Synthetic,true,Logon,local,description,company,C:\fixture\safe.exe,1.0,SYNTHETIC_SECRET,(Verified) Synthetic"
 $r=@(Convert-InspectionStartupCsv $csv)[0];Assert ($r.Signer -ceq '(Verified) Synthetic' -and $r.SignatureCoverage -match 'not independently')
}
Case 'Autoruns missing required columns rejected' {MustThrow {Convert-InspectionStartupCsv "Entry,Signer`nSynthetic,unknown"} 'schema unsupported'}
Case 'Autoruns empty output rejected without clean inference' {MustThrow {Convert-InspectionStartupCsv ''} 'empty or unsupported'}

# Exercise bounded process wrapper only against a reviewed inert PowerShell fixture.
# Current host executable is used explicitly; no collector/scan entry point runs.
$runtime=(Get-Process -Id $PID).Path
Case 'Bounded runner handles declared strict UTF8 fixture' {$r=Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','[Console]::OutputEncoding=[Text.Encoding]::UTF8;[Console]::Write("fixture café")') 10 -OutputEncoding Utf8;Assert ($r -eq 'fixture café')}
Case 'Unsupported high byte rejected by default ASCII contract' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$s.Write([byte[]]@(255),0,1)') 10} 'decoding failed under Ascii';}
Case 'Malformed UTF8 rejected without replacement character or cap misclassification' {
 $message=$null;try{Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$s.Write([byte[]]@(255),0,1);Start-Sleep -Milliseconds 300') 10 -OutputEncoding Utf8|Out-Null}catch{$message=$_.Exception.Message}
 Assert ($message -match 'decoding failed under Utf8' -and $message -notmatch 'cap exceeded|�')
}
Case 'Strict UTF16LE accepts BOM and Unicode fixture' {$r=Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$b=[byte[]]@(255,254)+[Text.Encoding]::Unicode.GetBytes("fixture café");$s.Write($b,0,$b.Length)') 10 -OutputEncoding Utf16LE;Assert ($r -eq 'fixture café')}
Case 'Verified Sigcheck no-BOM contract accepts strict UTF16LE Unicode' {$r=Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$b=[Text.Encoding]::Unicode.GetBytes("fixture café");$s.Write($b,0,$b.Length)') 10 -OutputEncoding Utf16LENoBom;Assert ($r -eq 'fixture café')}
Case 'No-BOM UTF16LE rejects odd malformed byte sequence' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$s.Write([byte[]]@(65),0,1)') 10 -OutputEncoding Utf16LENoBom} 'decoding failed under Utf16LENoBom'}
Case 'No-BOM UTF16LE does not silently accept a changed BOM contract' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$s.Write([byte[]]@(255,254,65,0),0,4)') 10 -OutputEncoding Utf16LENoBom} 'unexpected UTF-16LE BOM'}
Case 'Unknown UTF16 without BOM unavailable' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','[Console]::OutputEncoding=[Text.Encoding]::UTF8;[Console]::Write("fixture")') 10 -OutputEncoding Utf16LE} 'missing UTF-16LE BOM'}
Case 'Malformed UTF16 rejected without silent replacement' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$s.Write([byte[]]@(255,254,65),0,3)') 10 -OutputEncoding Utf16LE} 'decoding failed under Utf16LE'}
Case 'Early decoding stream fault keeps decoding classification while child lives' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','$s=[Console]::OpenStandardOutput();$s.Write([byte[]]@(255),0,1);$s.Close();Start-Sleep -Seconds 2') 10 -OutputEncoding Utf8} 'decoding failed under Utf8'}
Case 'Bounded runner rejects inert child nonzero' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','exit 7') 10} 'exit code 7'}
Case 'Bounded runner output cap kills only its fixture child' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','[Console]::Write(("x"*2200000))') 10} 'cap exceeded|aggregate'}
Case 'Bounded runner timeout kills only its fixture child' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 5') 1} 'timeout'}
Case 'Changed collector fingerprint rejected under held handle' {MustThrow {Invoke-InspectionTool $runtime @('-NoProfile','-NonInteractive','-Command','[Console]::Write("must not start")') 10 -ExpectedHash ('0'*64)} 'changed before launch'}
Case 'Unexpected tool download host rejected before transfer' {MustThrow {Get-VerifiedMicrosoftTool Autoruns 'https://fixture.invalid/a.zip' 'Autorunsc64.exe'} 'official Sysinternals'}
Case 'Tool download requires explicit opt-in' {$DownloadMicrosoftTools=$false;MustThrow {Get-VerifiedMicrosoftTool Autoruns 'https://download.sysinternals.com/files/Autoruns.zip' 'Autorunsc64.exe'} 'explicit -Download'}
Case 'Unexpected tool binary name rejected' {MustThrow {Get-VerifiedMicrosoftTool Autoruns 'https://download.sysinternals.com/files/Autoruns.zip' 'other.exe'} 'Unexpected collector'}

$failures=@($script:results|Where-Object {-not $_.Passed})
$evidence=[ordered]@{Scope='AST-loaded reviewed definitions; mocked Defender/CIM/events/tools; local atomic writes; inert output-only/process-timeout fixtures. No live scans, remediation, updates, downloads, reboot, EICAR, settings changes or sample uploads.';Runtime=$PSVersionTable.PSVersion.ToString();ExecutedAt=(Get-Date).ToString('o');Passed=$script:results.Count-$failures.Count;Failed=$failures.Count;HarnessSHA256=(Get-FileHash $PSCommandPath).Hash;HistoricalFixtureSHA256=(Get-FileHash (Join-Path $PSScriptRoot 'historical-scan-fixture.json')).Hash;SourceHashes=@(Get-ChildItem $kitPath -Filter '*.ps1' | ForEach-Object {@{File=$_.Name;SHA256=(Get-FileHash $_.FullName).Hash}});Results=@($script:results)}
$evidence|ConvertTo-Json -Depth 12|Set-Content -LiteralPath (Join-Path $OutputDirectory 'test-results.json') -Encoding utf8
$script:results|Format-Table Test,Passed,Error -Wrap
Write-Host "Passed: $($evidence.Passed); failed: $($evidence.Failed); evidence: $OutputDirectory"
if($failures.Count){exit 1}
