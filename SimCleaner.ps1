#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Victus','Gigabyte')][string]$ExpectedDevice='Victus',
    [ValidateSet('Menu','Inspect','Status','FullScan','QuickScan','UpdateSignatures','CleanupPlan','Remediate','OfflineScan','RecheckScan')][string]$Action='Menu',
    [switch]$AcknowledgeImpact,
    [string]$ReviewedPlanToken='',
    [switch]$ValidateOnly,
    [string]$ScanRunDirectory=''
)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'Safety.ps1')
$simSourceRoot=$PSScriptRoot
$simComputer=Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
if (-not (Test-SimTarget $simComputer $ExpectedDevice)) { throw 'TARGET MISMATCH or unknown hardware; no action performed.' }
if ($ValidateOnly) { Write-Host "Sim Cleaner target verified: $ExpectedDevice"; return }
$simPrincipal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
$simAdmin=$simPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$simReports=Join-Path $PSScriptRoot 'SimCleanerReports'

function Convert-SimEvent($Event) {
    [xml]$xml=$Event.ToXml();$fields=@{}
    foreach($data in $xml.Event.EventData.Data) { $fields[[string]$data.Name]=[string]$data.'#text' }
    [pscustomobject]@{Id=[int]$Event.Id;RecordId=[long]$Event.RecordId;TimeCreated=$Event.TimeCreated;ScanId=$fields['Scan ID'];ScanParameters=$fields['Scan Parameters'];ScanType=$fields['Scan Type']}
}
function Get-SimEvents {
    Read-SimSection {
        try {
            Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Windows Defender/Operational';Id=1000,1001,1002,1006,1007,1008,1116,1117,1118,1119,2030,2031,2050;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 4096 -ErrorAction Stop | ForEach-Object { Convert-SimEvent $_ }
        } catch {
            if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}
            $log=@(Get-WinEvent -ListLog 'Microsoft-Windows-Windows Defender/Operational' -ErrorAction Stop)
            if($log.Count -ne 1 -or $log[0].IsEnabled -ne $true){throw 'Empty Defender history could not be confirmed in a readable enabled log.'}
            # Known no matches differs from unreadable/disabled logs; emit no records.
        }
    }
}
function Get-SimState([switch]$PreflightOnly) {
    [ordered]@{
        CapturedAt=(Get-Date).ToString('o')
        Defender=Read-SimSection -Singleton -Required AMServiceEnabled,AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled {
            $status=Get-MpComputerStatus -ErrorAction Stop
            foreach($field in @('FullScanStartTime','FullScanEndTime','QuickScanStartTime','QuickScanEndTime')){if($status.PSObject.Properties.Name -notcontains $field){throw "Scan history field unavailable: $field"}}
            $status | Select-Object AMServiceEnabled,AMRunningMode,AntivirusEnabled,RealTimeProtectionEnabled,IsTamperProtected,AntivirusSignatureVersion,AntivirusSignatureLastUpdated,FullScanStartTime,FullScanEndTime,FullScanAge,QuickScanStartTime,QuickScanEndTime,RebootRequired
        }
        Preferences=Read-SimSection -Singleton -Required SubmitSamplesConsent,MAPSReporting,DisableArchiveScanning,DisableRemovableDriveScanning,DisableScanningMappedNetworkDrivesForFullScan,DisableScanningNetworkFiles {
            $p=Get-MpPreference -ErrorAction Stop
            foreach($field in @('ExclusionPath','ExclusionExtension','ExclusionProcess')) {
                if($p.PSObject.Properties.Name -notcontains $field -or [string]$p.$field -match 'N/A:|Must be an administrator'){throw "Visible exclusions unavailable: $field"}
            }
            $p | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess,DisableArchiveScanning,DisableRemovableDriveScanning,DisableScanningMappedNetworkDrivesForFullScan,DisableScanningNetworkFiles,SubmitSamplesConsent,MAPSReporting,ThreatIDDefaultAction_Ids,ThreatIDDefaultAction_Actions,LowThreatDefaultAction,ModerateThreatDefaultAction,HighThreatDefaultAction,SevereThreatDefaultAction,DisableAutoExclusions
        }
        Threats=Read-SimSection -Required ThreatID,IsActive { Get-MpThreat -ErrorAction Stop | Select-Object ThreatID,ThreatName,SeverityID,IsActive,DidThreatExecute,Resources }
        Detections=if($PreflightOnly){[ordered]@{Status='NotCollected';Data=@();Reason='Pre-dispatch snapshot skips redundant detection-history enumeration'}}else{Read-SimSection { Get-MpThreatDetection -ErrorAction Stop | Select-Object ThreatID,DetectionID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,ThreatStatusID,Resources }}
        Events=Get-SimEvents
    }
}
function Assert-SimReady($State) {
    if ($State.Defender.Status -ne 'Retrieved') { throw 'Defender state is unavailable or malformed.' }
    $d=$State.Defender.Data[0]
    if ($d.AntivirusEnabled -isnot [bool] -or $d.AMServiceEnabled -isnot [bool] -or -not $d.AntivirusEnabled -or -not $d.AMServiceEnabled -or $d.AMRunningMode -ne 'Normal') { throw 'Defender is disabled, passive, or unknown; no mutation allowed.' }
    if ($State.Preferences.Status -ne 'Retrieved') { throw 'Coverage/cloud/remediation policy unavailable; visible preferences required.' }
    $p=$State.Preferences.Data[0]
    foreach($field in @('DisableArchiveScanning','DisableRemovableDriveScanning','DisableScanningMappedNetworkDrivesForFullScan','DisableScanningNetworkFiles')){if($p.$field -isnot [bool]){throw 'Coverage policy fields are malformed.'}}
    if($p.SubmitSamplesConsent -notin @(0,1,2,3) -or $p.MAPSReporting -notin @(0,1,2)){throw 'Cloud policy values unsupported.'}
}
function Get-SimPlanToken($State) {
    Assert-SimReady $State
    if ($State.Threats.Status -notin @('Retrieved','Empty')) { throw 'Readable threat inventory is required.' }
    foreach($t in $State.Threats.Data) { if ($t.IsActive -isnot [bool] -or $null -eq $t.ThreatID) { throw 'Malformed threat inventory.' } }
    $active=@($State.Threats.Data | Where-Object {$_.IsActive -eq $true} | Sort-Object ThreatID | ForEach-Object {
        [ordered]@{ThreatID=$_.ThreatID;ThreatName=$_.ThreatName;Resources=@($_.Resources | Sort-Object);DidThreatExecute=$_.DidThreatExecute;SeverityID=$_.SeverityID}
    })
    Get-SimHash ([ordered]@{Device=$ExpectedDevice;Manufacturer=$simComputer.Manufacturer;Model=$simComputer.Model;Threats=$active;Policy=$State.Preferences.Data[0]})
}
function Show-SimPolicy($State) {
    Write-Host 'Existing Defender policy can quarantine/delete and send samples/data to Microsoft. No policies are changed.'
    Write-Host 'FullScan honors exclusions; removable/network drives, archives, encrypted content and automatic exclusions can limit coverage.'
    Write-Host 'Visible exclusions can omit managed/automatic exclusions; this is not proof of effective scope.'
    ConvertTo-SimSafeData $State.Preferences | ConvertTo-Json -Depth 8 | Out-Host
}
function Assert-SimScanIdle($State) {
    if($State.Events.Status -notin @('Retrieved','Empty') -or @($State.Events.Data).Count -ge 4096){throw 'Scan lifecycle evidence unavailable/truncated; scan dispatch blocked.'}
    foreach($start in @($State.Events.Data | Where-Object {$_.Id -eq 1000})){
        if(-not $start.ScanId -or -not @($State.Events.Data | Where-Object {$_.ScanId -ceq $start.ScanId -and $_.RecordId -gt $start.RecordId -and $_.Id -in @(1001,1002)}).Count){throw 'Existing/unresolved scan start observed; cannot establish idle state.'}
    }
}
function Get-SimScanOutcome($Before,$After,[string]$Selected,[datetime]$RequestedAt) {
    $unknown=[ordered]@{Status='Unverified';Reason='Complete matching scan evidence unavailable';ScanId=$null}
    if ($Before.Events.Status -notin @('Retrieved','Empty') -or $After.Events.Status -ne 'Retrieved' -or @($Before.Events.Data).Count -ge 4096 -or @($After.Events.Data).Count -ge 4096 -or $After.Defender.Status -ne 'Retrieved') { return $unknown }
    $watermark=($Before.Events.Data | Measure-Object RecordId -Maximum).Maximum
    if ($null -eq $watermark) { if($Before.Events.Status -eq 'Empty'){$watermark=0}else{return $unknown} }
    $new=@($After.Events.Data | Where-Object {$_.RecordId -gt $watermark -and $_.TimeCreated -ge $RequestedAt.AddSeconds(-2)})
    $starts=@($new | Where-Object {$_.Id -eq 1000})
    if ($starts.Count -ne 1 -or -not $starts[0].ScanId) { $unknown.Reason='No unique new scan start; unrelated/concurrent scans cannot be attributed'; return $unknown }
    $start=$starts[0];$expected=if($Selected -eq 'FullScan'){'Full scan'}else{'Quick scan'}
    if ($start.ScanParameters -ine $expected -or $start.ScanType -ine 'Antimalware') { $unknown.Reason='Unsupported/different scan type or localized parameters; isolated validation required'; return $unknown }
    $matched=@($new | Where-Object {$_.ScanId -ceq $start.ScanId -and $_.RecordId -gt $start.RecordId -and $_.TimeCreated -ge $start.TimeCreated})
    $unknown.ScanId=$start.ScanId
    if (@($matched | Where-Object {$_.Id -eq 1002}).Count) { return [ordered]@{Status='Cancelled';Reason='Matching cancellation event';ScanId=$start.ScanId} }
    $ends=@($matched | Where-Object {$_.Id -eq 1001 -and $_.ScanParameters -ieq $expected -and $_.ScanType -ieq $start.ScanType})
    if ($ends.Count -ne 1) { $unknown.Reason='Matching start observed; no unique matching terminal completion. Scan may still run or evidence may be missing'; return $unknown }
    $prefix=if($Selected -eq 'FullScan'){'FullScan'}else{'QuickScan'}
    $a=$After.Defender.Data[0];$b=$Before.Defender.Data[0]
    $hs=$a.($prefix+'StartTime');$he=$a.($prefix+'EndTime');$old=$b.($prefix+'EndTime')
    if ($Before.Defender.Status -ne 'Retrieved' -or ($null -ne $old -and ($old -isnot [datetime] -or $he -le $old)) -or $hs -isnot [datetime] -or $he -isnot [datetime] -or $hs -lt $RequestedAt.AddSeconds(-2) -or $he -lt $hs -or [math]::Abs(($hs-$start.TimeCreated).TotalSeconds) -gt 5 -or [math]::Abs(($he-$ends[0].TimeCreated).TotalSeconds) -gt 5) { $unknown.Reason='History does not match the same scan window'; return $unknown }
    return [ordered]@{Status='CompletedWithCorrelatedEvidence';Reason='Unique new start/completion ID, type and matching advanced history; coverage/detection efficacy not established';ScanId=$start.ScanId;RequestOwnership='Inferred from request window; API supplies no request-bound scan ID and independent Windows activity cannot be fully excluded'}
}
function Read-SimScanIntent([string]$Directory) {
    $directory=Assert-SimLocalPath $Directory
    $path=Assert-SimLocalPath (Join-Path $directory '02-intent.json') -Leaf
    $held=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
        if($held.Length -gt 16MB){throw 'Scan intent exceeds input size limit.'}
        $intent=Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        $fingerprint=(Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    } finally {$held.Dispose()}
    if($intent.Tool -cne 'Sim Cleaner' -or $intent.Version -cne '0.2.0' -or $intent.Device -cne $ExpectedDevice -or $intent.Action -notin @('FullScan','QuickScan') -or -not $intent.PreDispatch -or -not $intent.DispatchAt){throw 'Invalid/different-device scan intent; no correlation possible.'}
    $request=[datetime]::Parse($intent.DispatchAt,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)
    foreach($e in $intent.PreDispatch.Events.Data){$e.TimeCreated=[datetime]::Parse([string]$e.TimeCreated,[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)}
    foreach($d in $intent.PreDispatch.Defender.Data){foreach($field in @('FullScanStartTime','FullScanEndTime','QuickScanStartTime','QuickScanEndTime')){if(-not $d.Contains($field)){throw 'Scan intent has incomplete history schema.'};if($null -ne $d[$field]){$d[$field]=[datetime]::Parse([string]$d[$field],[Globalization.CultureInfo]::InvariantCulture,[Globalization.DateTimeStyles]::RoundtripKind)}}}
    [ordered]@{Path=$path;Fingerprint=$fingerprint;Intent=$intent;RequestedAt=$request;Trust='Locally mutable evidence; fingerprint is not authenticity'}
}
function Invoke-SimInspection {
    $runtime=(Get-Process -Id $PID).Path
    & $runtime -NoProfile -File (Join-Path $simSourceRoot 'Inspect-Windows.ps1') -ExpectedDevice $ExpectedDevice
    if ($LASTEXITCODE -ne 0) { throw "Inspection child failed or partial (exit $LASTEXITCODE)." }
}
function Invoke-SimAction([string]$Selected,[bool]$Accepted,[string]$PlanToken='', [bool]$Interactive=$false,[string]$RecheckDirectory=$ScanRunDirectory) {
    if ($Selected -eq 'Inspect') { Invoke-SimInspection; return }
    if ($Selected -eq 'OfflineScan') { throw 'OfflineScan blocked in this prototype: isolated WinRE/BitLocker/reboot readiness and durable post-boot evidence unvalidated.' }
    $lock=Enter-SimLock;$record=$null;$failure=$null;$runDirectory=$null
    try {
        [void](Assert-SimLocalPath $simReports)
        $runDirectory=Join-Path $simReports ($ExpectedDevice+'-'+[guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $runDirectory -ErrorAction Stop | Out-Null
        $record=[ordered]@{Tool='Sim Cleaner';Version='0.2.0';RunId=Split-Path $runDirectory -Leaf;Device=$ExpectedDevice;Manufacturer=$simComputer.Manufacturer;Model=$simComputer.Model;Elevated=$simAdmin;Action=$Selected;StartedAt=(Get-Date).ToString('o');DispatchAt=$null;Result='Prepared';Before=Get-SimState;PreDispatch=$null;After=$null;ScanEvidence=$null;Error=$null;EvidenceError=$null;Limits=@('Microsoft Defender orchestration; no separate antivirus engine.','Existing exclusions/remediation/cloud/sample policy apply.','No negative result proves malware absent. Reports contain paths/detection details.','Atomic unique local phase files are not signed/tamper-proof evidence.','Lock coordinates this tool only; Windows/scheduled scans/other clients remain independent.')}
        Save-SimReport $record (Join-Path $runDirectory '01-before.json')
        if($Selected -eq 'RecheckScan') {
            if($Interactive){$RecheckDirectory=Read-Host 'Absolute local original scan run directory'}
            $source=Read-SimScanIntent $RecheckDirectory
            $record.SourceIntent=[ordered]@{Path=$source.Path;SHA256=$source.Fingerprint;OriginalRunId=$source.Intent.RunId;Trust=$source.Trust}
            $record.ScanEvidence=Get-SimScanOutcome $source.Intent.PreDispatch $record.Before $source.Intent.Action $source.RequestedAt
            $record.Result=$record.ScanEvidence.Status
            if($record.Result -ne 'CompletedWithCorrelatedEvidence'){throw ('Scan recheck: '+$record.Result+'; '+$record.ScanEvidence.Reason)}
        } elseif ($Selected -in @('Status','CleanupPlan')) {
            ConvertTo-SimSafeData $record.Before | ConvertTo-Json -Depth 12 | Out-Host
            if ($Selected -eq 'CleanupPlan') {
                $record.PlanToken=Get-SimPlanToken $record.Before
                Write-Host ('Review token: '+$record.PlanToken)
                Write-Host 'Remove-MpThreat acts on ALL active threats at execution time, including newly arriving threats. No per-file cleanup scope.'
            }
            $record.Result=if($record.Before.Defender.Status -eq 'Retrieved' -and $record.Before.Preferences.Status -eq 'Retrieved' -and $record.Before.Threats.Status -in @('Retrieved','Empty') -and $record.Before.Events.Status -in @('Retrieved','Empty') -and $record.Before.Detections.Status -in @('Retrieved','Empty')){'ReadOnlySnapshot'}else{'PartialReadOnlySnapshot'}
        } else {
            if (-not $simAdmin) { throw 'Administrator rights required; no automatic elevation.' }
            Assert-SimReady $record.Before;Show-SimPolicy $record.Before
            if ($Interactive) {
                $phrase=$Selected
                if ($Selected -eq 'Remediate') {
                    $PlanToken=Get-SimPlanToken $record.Before;$record.Before.Threats.Data | Format-List | Out-Host
                    Write-Host 'ALL active threats at execution, including new threats, may be quarantined/deleted. No atomic snapshot-scoped Remove-MpThreat API.'
                    $phrase='Remediate ALL '+$PlanToken
                }
                $Accepted=((Read-Host "Type $phrase to authorize, or Enter to cancel") -ceq $phrase)
            }
            if (-not $Accepted) { throw 'Action not acknowledged or cancelled; no mutation invoked.' }
            $record.PreDispatch=Get-SimState -PreflightOnly;Assert-SimReady $record.PreDispatch
            if($Selected -in @('FullScan','QuickScan')){Assert-SimScanIdle $record.PreDispatch}
            if ((Get-SimHash $record.Before.Preferences.Data) -cne (Get-SimHash $record.PreDispatch.Preferences.Data)) { throw 'Defender policy changed during review; review a fresh snapshot.' }
            if ($Selected -eq 'Remediate') {
                $fresh=Get-SimPlanToken $record.PreDispatch
                if (-not $PlanToken -or $PlanToken -cne (Get-SimPlanToken $record.Before) -or $PlanToken -cne $fresh) { throw 'Cleanup token missing/stale; active threats or policy changed. Review a new CleanupPlan.' }
                $record.PlanToken=$fresh
            }
            $record.DispatchAt=(Get-Date).ToString('o');$record.Result='DispatchIntentPersisted'
            Save-SimReport $record (Join-Path $runDirectory '02-intent.json')
            $commandError=$null;$afterError=$null
            try {
                switch($Selected) {
                    'FullScan' { Start-MpScan -ScanType FullScan -ErrorAction Stop }
                    'QuickScan' { Start-MpScan -ScanType QuickScan -ErrorAction Stop }
                    'UpdateSignatures' { Update-MpSignature -ErrorAction Stop }
                    'Remediate' { if(@($record.PreDispatch.Threats.Data | Where-Object {$_.IsActive -eq $true}).Count) { Remove-MpThreat -ErrorAction Stop } }
                    default { throw 'Unsupported action.' }
                }
                $record.Result='CommandReturnedOutcomeUnverified'
            } catch {$commandError=Protect-SimText $_.Exception.Message}
            finally {try{$record.After=Get-SimState}catch{$afterError=Protect-SimText $_.Exception.Message;$record.After=[ordered]@{Status='Unavailable';Error=$afterError}}}
            if($commandError){throw ($commandError+$(if($afterError){'; After evidence failed: '+$afterError}))}
            if($afterError){throw ('After evidence failed: '+$afterError)}
            if ($Selected -in @('FullScan','QuickScan')) {
                $record.ScanEvidence=Get-SimScanOutcome $record.PreDispatch $record.After $Selected ([datetime]$record.DispatchAt);$record.Result=$record.ScanEvidence.Status
                if ($record.ScanEvidence.Status -ne 'CompletedWithCorrelatedEvidence') { throw ('Scan outcome: '+$record.ScanEvidence.Status+'; '+$record.ScanEvidence.Reason) }
            } elseif ($Selected -eq 'Remediate') {
                if($record.After.Threats.Status -notin @('Retrieved','Empty')){throw 'After threat inventory unavailable; remediation outcome unverified.'}
                foreach($t in $record.After.Threats.Data){if($t.IsActive -isnot [bool] -or $null -eq $t.ThreatID){throw 'After threat inventory malformed.'}}
                if(@($record.After.Threats.Data | Where-Object {$_.IsActive -eq $true}).Count){throw 'Active threats remain; remediation outcome incomplete.'}
                $record.Result='RemediationCommandReturned; remaining active threats: '+@($record.After.Threats.Data | Where-Object {$_.IsActive -eq $true}).Count+'; removal efficacy unverified'
            }
        }
    } catch {$failure=Protect-SimText $_.Exception.Message;if($record){$record.Error=$failure;if($record.Result -notin @('Cancelled','Unverified')){$record.Result='FailedOrIncomplete'}}}
    finally {
        try {
            if($record){$record.FinishedAt=(Get-Date).ToString('o');try {Save-SimReport $record (Join-Path $runDirectory '03-final.json')}catch{$record.EvidenceError=$_.Exception.Message;$failure=($failure+' Final evidence persistence failed: '+$record.EvidenceError).Trim()};Write-Host "Evidence: $runDirectory";Write-Host $record.Result}
        } finally {Exit-SimLock $lock}
    }
    if($failure){throw $failure};return $record
}
if ($Action -ne 'Menu') { $result=Invoke-SimAction $Action $AcknowledgeImpact.IsPresent $ReviewedPlanToken $false $ScanRunDirectory; if($result -and $result.Result -eq 'PartialReadOnlySnapshot'){exit 3}; return }
Write-Host "SIM CLEANER 0.2.0 - $ExpectedDevice - administrator: $simAdmin"
Write-Host 'Local prototype; lifecycle and detection efficacy require isolated acceptance.'
$sessionFailed=$false
do {
    Write-Host "`n1 Inspect Windows/network (no optional tools by default)`n2 Defender status`n3 Update signatures`n4 Full scan`n5 Quick scan`n6 Cleanup plan`n7 Remediate ALL active threats`n8 OfflineScan (blocked prototype feature)`n9 Recheck original scan evidence (read-only)`n0 Exit"
    $choice=Read-Host 'Choose'
    $selected=switch($choice){'1'{'Inspect'}'2'{'Status'}'3'{'UpdateSignatures'}'4'{'FullScan'}'5'{'QuickScan'}'6'{'CleanupPlan'}'7'{'Remediate'}'8'{'OfflineScan'}'9'{'RecheckScan'}default{$null}}
    if($selected){try {$result=Invoke-SimAction $selected $false '' $true;if($result -and $result.Result -eq 'PartialReadOnlySnapshot'){$sessionFailed=$true}}catch{$sessionFailed=$true;Write-Warning $_.Exception.Message}}
}while($choice -ne '0')
if($sessionFailed){exit 3}
