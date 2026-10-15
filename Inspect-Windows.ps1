#requires -Version 7.0
[CmdletBinding()]
param(
    [ValidateSet('Gigabyte','Victus')][string]$ExpectedDevice = 'Victus',
    [string]$OutputDirectory = '',
    [string]$ToolDirectory = '',
    [ValidateRange(1,60)][int]$SocketSamples = 6,
    [ValidateRange(1,30)][int]$SampleIntervalSeconds = 10,
    [switch]$ValidateOnly,
    [switch]$UseMicrosoftTools,
    [switch]$DownloadMicrosoftTools,
    [switch]$AcceptToolEula,
    [switch]$VerifyProcessSignatures
)

# Inspection only: no firewall changes, service changes, repairs, quarantine,
# password queries, browser-history reads, or VirusTotal submissions.
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Safety.ps1')
$inspectionComputer = Get-CimInstance Win32_ComputerSystem
$inspectionMatches = Test-SimTarget $inspectionComputer $ExpectedDevice
if (-not $inspectionMatches) {
    Write-Host ('TARGET MISMATCH: Expected {0}; this device reports {1} / {2}. No inspection performed.' -f $ExpectedDevice,$inspectionComputer.Manufacturer,$inspectionComputer.Model)
    throw 'Target mismatch; inspection blocked.'
}
if ($ValidateOnly) {
    Write-Host ('Target verified: {0} / {1}' -f $inspectionComputer.Manufacturer,$inspectionComputer.Model)
    return
}
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $PSScriptRoot 'Reports' }
if (-not $ToolDirectory) { $ToolDirectory = Join-Path $PSScriptRoot 'Tools' }
$inspectionLock=Enter-SimLock
try {
$inspectionRunDirectory = Join-Path (Assert-SimLocalPath ([IO.Path]::GetFullPath($OutputDirectory))) ($ExpectedDevice + '-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $inspectionRunDirectory -ErrorAction Stop | Out-Null
if($UseMicrosoftTools -and -not $AcceptToolEula){throw 'Optional Sysinternals use requires explicit -AcceptToolEula after reviewing Microsoft agreements.'}
if($UseMicrosoftTools){[void](Assert-SimLocalPath ([IO.Path]::GetFullPath($ToolDirectory)))}
$inspectionIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
$inspectionPrincipal = New-Object Security.Principal.WindowsPrincipal($inspectionIdentity)
$inspectionElevated = $inspectionPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
$inspectionReport = [ordered]@{
    StartedAt = (Get-Date).ToString('o')
    Device = [ordered]@{Manufacturer=$inspectionComputer.Manufacturer;Model=$inspectionComputer.Model;Expected=$ExpectedDevice;Elevated=$inspectionElevated}
    Scope = 'Local metadata, security state, startup signatures, socket samples, driver and error-log evidence. No remediation.'
    ConfigurationChangesApplied = $false
    OptionalToolsRequested = $UseMicrosoftTools.IsPresent
    ToolEulaAcceptanceRequested = $AcceptToolEula.IsPresent
    FirewallPolicyStore = 'ActiveStore'
    NativeOutputEncoding = 'Strict ASCII; localized/non-ASCII native output is unavailable rather than guessed'
    ExternalToolOutputEncoding = 'Strict UTF-16LE: Autorunsc requires BOM; Sigcheck requires no BOM; see per-tool OutputEncodingContract'
    Limitations = @()
}

function Get-InspectionSection {
    param([string]$SectionName,[scriptblock]$Read,[switch]$Singleton,[string[]]$Required=@())
    Write-Host ('Collecting: ' + $SectionName)
    if(($SectionName -match '^Microsoft tool|^Autoruns startup|^Sigcheck review' -and -not $UseMicrosoftTools) -or ($SectionName -eq 'Accessible running-executable signatures' -and -not $VerifyProcessSignatures)) { return [ordered]@{Status='Skipped';Data=@();Error='Optional scope not requested'} }
    $section=Read-SimSection -Query $Read -Singleton:$Singleton -Required $Required
    if($section.Status -eq 'Unavailable'){$section.Error=Protect-SimText $section.Error}
    return $section
}

function Get-InspectionProcessMap {
    $processMap = @{}
    foreach ($inspectionProcess in @(Get-Process -ErrorAction Stop)) {
        $processMap[[int]$inspectionProcess.Id] = [ordered]@{Name=$inspectionProcess.ProcessName;Path=$inspectionProcess.Path;Handles=$inspectionProcess.HandleCount;WorkingSetMB=[math]::Round($inspectionProcess.WorkingSet64/1MB,1)}
    }
    return $processMap
}

function Get-SocketInspection {
    $processMap = Get-InspectionProcessMap
    $tcpSockets = @(Get-NetTCPConnection)
    $udpSockets = @(Get-NetUDPEndpoint)
    $tcpStates = @($tcpSockets | Group-Object State | ForEach-Object {[ordered]@{State=$_.Name;Count=$_.Count}})
    $topTcp = @($tcpSockets | Where-Object {$_.OwningProcess -ne 0} | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        $ownerId = [int]$_.Name
        [ordered]@{ProcessId=$ownerId;Process=$processMap[$ownerId].Name;EndpointCount=$_.Count;Handles=$processMap[$ownerId].Handles}
    })
    $topUdp = @($udpSockets | Group-Object OwningProcess | Sort-Object Count -Descending | Select-Object -First 15 | ForEach-Object {
        $ownerId = [int]$_.Name
        [ordered]@{ProcessId=$ownerId;Process=$processMap[$ownerId].Name;EndpointCount=$_.Count;Handles=$processMap[$ownerId].Handles}
    })
    [ordered]@{At=(Get-Date).ToString('o');TcpEndpointCount=$tcpSockets.Count;UdpEndpointCount=$udpSockets.Count;TcpStates=$tcpStates;TopTcpProcesses=$topTcp;TopUdpProcesses=$topUdp}
}

function Get-InspectionArchiveMember($Entries,[string]$CanonicalName) {
    if($CanonicalName -cnotin @('autorunsc64.exe','sigcheck64.exe')){throw 'Unexpected collector filename.'}
    # Windows-equivalent names must be unique. Never extract an archive path.
    $matches=@($Entries | Where-Object {[string]::Equals($_.FullName,$CanonicalName,[StringComparison]::OrdinalIgnoreCase)})
    if($matches.Count -ne 1 -or $matches[0].Length -le 0 -or $matches[0].Length -gt 32MB){throw 'Collector archive member invalid, ambiguous, or too large.'}
    return $matches[0]
}
function Test-InspectionCollectorMetadata([string]$Name,$Version) {
    # Product resources can be shared by GUI/console builds. These are observed
    # signed vendor family values, not an inference from the external filename.
    $family=switch($Name){
        'Autoruns' { @{OriginalFilename='autoruns.exe';ProductName='Sysinternals autoruns'} }
        'Sigcheck' { @{OriginalFilename='sigcheck.exe';ProductName='Sysinternals Sigcheck'} }
        default {return $false}
    }
    $parsedVersion=$null
    return ($null -ne $Version -and [string]::Equals($Version.OriginalFilename,$family.OriginalFilename,[StringComparison]::OrdinalIgnoreCase) -and [string]::Equals($Version.ProductName,$family.ProductName,[StringComparison]::OrdinalIgnoreCase) -and [Version]::TryParse([string]$Version.FileVersion,[ref]$parsedVersion) -and $parsedVersion.Major -gt 0)
}
function Convert-InspectionStartupCsv([string]$Csv) {
    $rows=@($Csv | ConvertFrom-Csv -ErrorAction Stop)
    if($rows.Count -eq 0){throw 'Autoruns output empty or unsupported; no clean result inferred.'}
    $required=@('Time','Entry Location','Entry','Enabled','Category','Profile','Description','Company','Image Path','Version','Launch String')
    foreach($column in $required){if($rows[0].PSObject.Properties.Name -cnotcontains $column){throw 'Autoruns output schema unsupported; no clean result inferred.'}}
    foreach($row in $rows){
        [pscustomobject]@{Entry=$row.Entry;'Entry Location'=$row.'Entry Location';Enabled=$row.Enabled;Category=$row.Category;Description=$row.Description;Signer=if($row.PSObject.Properties.Name -ccontains 'Signer'){$row.Signer}else{'Not collected'};Company=$row.Company;'Image Path'=$row.'Image Path';Version=$row.Version;SignatureCoverage=if($row.PSObject.Properties.Name -ccontains 'Signer'){'Reported by source, not independently established'}else{'Not requested in metadata-only mode'}}
    }
}
function Get-VerifiedMicrosoftTool {
    param([string]$Name,[string]$ArchiveUrl,[string]$BinaryName)
    $expected= switch($Name){'Autoruns'{'autorunsc64.exe'}'Sigcheck'{'sigcheck64.exe'}default{throw 'Unsupported collector.'}}
    if(-not [string]::Equals($BinaryName,$expected,[StringComparison]::OrdinalIgnoreCase)){throw 'Unexpected collector filename.'}
    $BinaryName=$expected
    $uri = [uri]$ArchiveUrl
    if ($uri.Scheme -ne 'https' -or $uri.Host -ne 'download.sysinternals.com' -or $uri.UserInfo) { throw 'Only official Sysinternals HTTPS acquisition is allowed.' }
    if(-not $DownloadMicrosoftTools){throw 'Tool acquisition requires explicit -DownloadMicrosoftTools; no automatic download/cache execution.'}
    $toolFolder = Join-Path ([IO.Path]::GetFullPath($ToolDirectory)) ($Name+'-'+[guid]::NewGuid().ToString('N'))
    [void](Assert-SimLocalPath $toolFolder)
    $toolBinary = Join-Path $toolFolder $BinaryName
    New-Item -ItemType Directory -Path $toolFolder -ErrorAction Stop | Out-Null
    $toolArchive = Join-Path $toolFolder 'download.zip'
    Invoke-WebRequest -Uri $ArchiveUrl -OutFile $toolArchive -TimeoutSec 40 -MaximumRedirection 0 -UseBasicParsing -ErrorAction Stop
    $zip=[IO.Compression.ZipFile]::OpenRead($toolArchive)
    try {
        $member=Get-InspectionArchiveMember $zip.Entries $BinaryName
        [IO.Compression.ZipFileExtensions]::ExtractToFile($member,$toolBinary,$false)
    } finally {$zip.Dispose()}
    [void](Assert-SimLocalPath $toolBinary -Leaf)
    $verificationHandle=[IO.File]::Open($toolBinary,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    try {
    $signature = Get-AuthenticodeSignature -LiteralPath $toolBinary
    if ($signature.Status -ne 'Valid' -or $null -eq $signature.SignerCertificate -or $signature.SignerCertificate.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName,$false) -cne 'Microsoft Corporation' -or $signature.SignerCertificate.Subject -notmatch '(?:^|,\s*)O=Microsoft Corporation(?:,|$)') { throw ('Microsoft publisher validation failed for ' + $Name) }
    $version=[Diagnostics.FileVersionInfo]::GetVersionInfo($toolBinary)
    if(-not (Test-InspectionCollectorMetadata $Name $version)){throw 'Collector product/version metadata unsupported.'}
    [ordered]@{Name=$Name;Path=$toolBinary;SourceURL=$ArchiveUrl;RedirectsAllowed=$false;AcquiredAt=(Get-Date).ToString('o');VerifiedAt=(Get-Date).ToString('o');FileVersion=$version.FileVersion;OriginalFilename=$version.OriginalFilename;OutputEncodingContract=if($Name -eq 'Sigcheck'){'Strict UTF-16LE without BOM, observed verified Sigcheck contract'}else{'Strict UTF-16LE with BOM required'};SignatureStatus=[string]$signature.Status;Signer=$signature.SignerCertificate.Subject;SHA256=(Get-FileHash -LiteralPath $toolBinary -Algorithm SHA256).Hash;HashMeaning='Recorded fingerprint; no trusted vendor expected hash available'}
    } finally {$verificationHandle.Dispose()}
}

function Invoke-InspectionTool {
    param([string]$Binary,[string[]]$Arguments,[int]$TimeoutSeconds=180,[string]$ExpectedHash='', [ValidateSet('','Ascii','Utf8','Utf16LE','Utf16LENoBom')][string]$OutputEncoding='')
    [void](Assert-SimLocalPath $Binary -Leaf)
    if(-not ('SimBoundedProcess' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading.Tasks;
public static class SimBoundedProcess {
    static async Task<string> Read(Stream stream,string contract,string channel) {
        using(var bytes=new MemoryStream()) {
            var buffer=new byte[4096]; int n;
            while((n=await stream.ReadAsync(buffer,0,buffer.Length))>0) {
                if(bytes.Length+n>4194304) throw new InvalidOperationException(channel+" output cap exceeded");
                bytes.Write(buffer,0,n);
            }
            var raw=bytes.ToArray(); Encoding encoding; int offset=0;
            if(contract=="Utf16LE") {
                if(raw.Length>0 && (raw.Length<2||raw[0]!=255||raw[1]!=254)) throw new InvalidDataException(channel+" missing UTF-16LE BOM; output unavailable");
                encoding=new UnicodeEncoding(false,false,true); if(raw.Length>0) offset=2;
            } else if(contract=="Utf16LENoBom") {
                if(raw.Length>=2&&raw[0]==255&&raw[1]==254) throw new InvalidDataException(channel+" unexpected UTF-16LE BOM under no-BOM contract; output unavailable");
                encoding=new UnicodeEncoding(false,false,true);
            } else if(contract=="Utf8") {
                encoding=new UTF8Encoding(false,true);
                if(raw.Length>=3&&raw[0]==239&&raw[1]==187&&raw[2]==191) offset=3;
            } else {
                encoding=Encoding.GetEncoding(20127,EncoderFallback.ExceptionFallback,DecoderFallback.ExceptionFallback);
            }
            string text;
            try {text=encoding.GetString(raw,offset,raw.Length-offset);}
            catch(DecoderFallbackException e) {throw new InvalidDataException(channel+" decoding failed under "+contract+" contract; output unavailable",e);}
            if(text.Length>2097152) throw new InvalidOperationException(channel+" output cap exceeded");
            return text;
        }
    }
    public static string Run(string file,string[] args,int seconds,string contract,string expectedHash) {
        using(var held=new FileStream(file,FileMode.Open,FileAccess.Read,FileShare.Read))
        using(var p=new Process()) {
            if(!String.IsNullOrEmpty(expectedHash)) {
                using(var sha=System.Security.Cryptography.SHA256.Create()) {
                    var hash=BitConverter.ToString(sha.ComputeHash(held)).Replace("-","");
                    if(!String.Equals(hash,expectedHash,StringComparison.Ordinal)) throw new InvalidOperationException("Collector changed before launch");
                }
            }
            p.StartInfo=new ProcessStartInfo(file) {UseShellExecute=false,CreateNoWindow=true,RedirectStandardOutput=true,RedirectStandardError=true,WorkingDirectory=Path.GetDirectoryName(file)};
            foreach(var arg in args) p.StartInfo.ArgumentList.Add(arg);
            p.Start();
            // Decode raw streams ourselves: no ambient code page, BOM auto-switch,
            // or StreamReader replacement fallback is accepted.
            var stdout=Read(p.StandardOutput.BaseStream,contract,"stdout"); var stderr=Read(p.StandardError.BaseStream,contract,"stderr");
            var deadline=DateTime.UtcNow.AddSeconds(seconds);
            try {
                while(!p.WaitForExit(50)) {
                    if(stdout.IsFaulted) throw stdout.Exception.Flatten().InnerExceptions[0];
                    if(stderr.IsFaulted) throw stderr.Exception.Flatten().InnerExceptions[0];
                    if(DateTime.UtcNow>deadline) throw new TimeoutException("Collector timeout");
                }
                try {if(!Task.WaitAll(new Task[]{stdout,stderr},1000)) throw new TimeoutException("Collector streams did not close");}
                catch(AggregateException e) {throw e.Flatten().InnerExceptions[0];}
                if(p.ExitCode!=0) throw new InvalidOperationException("Collector exit code "+p.ExitCode+"; raw diagnostics omitted");
                return stdout.GetAwaiter().GetResult().TrimStart('\uFEFF');
            } finally {if(!p.HasExited) {try{p.Kill();p.WaitForExit(1000);}catch{}}}
        }
    }
}
'@
    }
    if(-not $OutputEncoding){$OutputEncoding=switch -Regex ([IO.Path]::GetFileName($Binary)){'^autorunsc64\.exe$'{'Utf16LE';break}'^sigcheck64\.exe$'{'Utf16LENoBom';break}default{'Ascii'}}}
    [SimBoundedProcess]::Run($Binary,$Arguments,$TimeoutSeconds,$OutputEncoding,$ExpectedHash)
}
function Invoke-InspectionNative([string]$Name,[string[]]$Arguments) {
    $binary=Join-Path ([Environment]::GetFolderPath('System')) ($Name+'.exe')
    [void](Assert-SimLocalPath $binary -Leaf)
    Invoke-InspectionTool $binary $Arguments 30
}
function Get-InspectionCount($Section) {
    if($Section.Status -notin @('Retrieved','Empty')){return 'Unknown'}
    @($Section.Data | Where-Object {$null -ne $_}).Count
}
function Get-InspectionProblems($Value,[string]$Prefix='') {
    if($Value -is [Collections.IDictionary]) {
        if($Value.Status -in @('Unavailable','Skipped')){ "$Prefix : $($Value.Status) $($Value.Error)";return }
        foreach($key in $Value.Keys){Get-InspectionProblems $Value[$key] ($Prefix+'/'+$key)}
    } elseif($Value -is [array]){for($i=0;$i -lt $Value.Count;$i++){Get-InspectionProblems $Value[$i] ($Prefix+'/'+$i)}}
}
function Get-InspectionFirewallSummary($Network,$Profiles) {
    $name=if($Network.NetworkCategory -eq 'DomainAuthenticated'){'Domain'}else{[string]$Network.NetworkCategory}
    $profile=@($Profiles.Data | Where-Object {$_.Name -eq $name})
    $enabled=if($Profiles.Status -eq 'Retrieved' -and $profile.Count -eq 1){$profile[0].Enabled}else{'Unknown'}
    "Active network $($Network.InterfaceAlias): profile $name; firewall enabled: $enabled (ActiveStore; reachability/rule coverage unproven)"
}
function Get-InspectionInstalledProviders {
    Read-SimSection {
        $names=@([Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetProviderNames())
        if($names.Count -eq 0){throw 'Installed publisher-name discovery returned no metadata; availability unknown.'}
        $names
    }
}
function Get-InspectionProviderCoverage([string[]]$ExpectedProviders,$AvailableProviders=$null) {
    $installed=@();$absent=@();$unavailable=@();$details=@()
    if($null -eq $AvailableProviders){$AvailableProviders=Get-InspectionInstalledProviders}
    if($AvailableProviders.Status -ne 'Retrieved' -or @($AvailableProviders.Data).Count -eq 0) {
        $unavailable=@($ExpectedProviders);$details=@($ExpectedProviders|ForEach-Object {[ordered]@{Name=$_;Status='Unavailable';Error=$AvailableProviders.Error}})
    } else {
        $lookup=@{};foreach($provider in $AvailableProviders.Data){$lookup[[string]$provider]=[string]$provider}
        foreach($name in $ExpectedProviders) {
            if($lookup.ContainsKey($name)){$installed+=$lookup[$name];$details+=[ordered]@{Name=$name;Status='Installed'}}
            else{$absent+=$name;$details+=[ordered]@{Name=$name;Status='Absent'}}
        }
    }
    [ordered]@{Status=if($unavailable.Count){'Unavailable'}else{'Retrieved'};Data=@();ExpectedProviders=$ExpectedProviders;InstalledProviders=$installed;AbsentProviders=$absent;UnavailableProviders=$unavailable;Details=$details;Error=if($unavailable.Count){'Provider availability unknown; query coverage incomplete'}else{$null}}
}
function Get-InspectionEventSection([string]$LogName,[hashtable]$Filter,[int]$Limit,$ProviderCoverage=$null) {
    $section=Read-SimSection {
        if($ProviderCoverage) {
            if($ProviderCoverage.Status -ne 'Retrieved'){throw 'Provider availability incomplete; permission/metadata failure is not empty history.'}
            if($ProviderCoverage.InstalledProviders.Count -eq 0){throw 'No supported providers installed; event coverage unavailable.'}
            $Filter.ProviderName=@($ProviderCoverage.InstalledProviders)
        }
        try {Get-WinEvent -FilterHashtable $Filter -MaxEvents $Limit -ErrorAction Stop | Select-Object TimeCreated,ProviderName,Id,LevelDisplayName}
        catch {
            if($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*'){throw}
            $log=@(Get-WinEvent -ListLog $LogName -ErrorAction Stop)
            if($log.Count -ne 1 -or $log[0].IsEnabled -ne $true){throw 'No matches cannot establish readable enabled event coverage.'}
        }
    }
    $section.Log=$LogName;$section.Limit=$Limit;$section.WindowStart=$Filter.StartTime;$section.CapturedAt=(Get-Date).ToString('o');$section.CapReached=if($section.Status -in @('Retrieved','Empty')){($section.Data.Count -ge $Limit)}else{$null}
    if($ProviderCoverage){$section.ProviderCoverage=$ProviderCoverage}
    return $section
}

$inspectionReport.OperatingSystem = Get-InspectionSection 'Windows and firmware metadata' {
    $os = Get-CimInstance Win32_OperatingSystem
    $bios = Get-CimInstance Win32_BIOS
    [ordered]@{Windows=$os.Caption;Version=$os.Version;Build=$os.BuildNumber;Architecture=$os.OSArchitecture;BootTime=$os.LastBootUpTime.ToString('o');TotalMemoryMB=[math]::Round($inspectionComputer.TotalPhysicalMemory/1MB);BiosManufacturer=$bios.Manufacturer;BiosVersion=$bios.SMBIOSBIOSVersion;BiosReleaseDate=$bios.ReleaseDate}
}
$inspectionReport.Defender = Get-InspectionSection -Singleton -Required AMServiceEnabled,AntivirusEnabled,AMRunningMode 'Defender protection and detection history' {
    Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,IsTamperProtected,AntivirusSignatureLastUpdated,AntivirusSignatureVersion,QuickScanStartTime,QuickScanEndTime,FullScanStartTime,FullScanEndTime,AMRunningMode
}
$inspectionReport.DefenderDetections = Get-InspectionSection 'Defender recorded detections' {
    Get-MpThreatDetection | Select-Object ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,ActionSuccess,ThreatStatusID
}
$inspectionReport.SecurityProducts = Get-InspectionSection 'Registered antivirus products' { Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName,productState }
$inspectionReport.Firewall = Get-InspectionSection 'Effective firewall profiles' { Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction }
$inspectionReport.ActiveNetworks = Get-InspectionSection 'Active network categories' { Get-NetConnectionProfile | Select-Object InterfaceAlias,NetworkCategory,IPv4Connectivity,IPv6Connectivity }
$inspectionReport.Adapters = Get-InspectionSection 'Network adapters and drivers' { Get-NetAdapter | Select-Object Name,InterfaceDescription,Status,LinkSpeed,DriverInformation }
$inspectionReport.AdapterCounters = Get-InspectionSection 'Network error and discard counters' { Get-NetAdapterStatistics | Select-Object Name,ReceivedPacketErrors,OutboundPacketErrors,ReceivedDiscardedPackets,OutboundDiscardedPackets }
$inspectionReport.NetworkBindings = Get-InspectionSection 'Enabled network filter components' { Get-NetAdapterBinding -AllBindings | Where-Object {$_.Enabled} | Select-Object Name,DisplayName,ComponentID }
$inspectionReport.IpConfiguration = Get-InspectionSection 'IP and DNS configuration' { Get-NetIPConfiguration | Select-Object InterfaceAlias,@{Name='IPv4';Expression={$_.IPv4Address.IPAddress}},@{Name='Gateway';Expression={$_.IPv4DefaultGateway.NextHop}},@{Name='DNS';Expression={$_.DNSServer.ServerAddresses}} }
$inspectionReport.Proxy = Get-InspectionSection 'Proxy configuration' {
    $internet = Get-ItemProperty -LiteralPath 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    [ordered]@{Enabled=$internet.ProxyEnable;ProxyServerConfigured=[bool]$internet.ProxyServer;AutoConfigURLConfigured=[bool]$internet.AutoConfigURL;SensitiveEndpointsOmitted=$true}
}
$inspectionReport.DynamicPorts = Get-InspectionSection 'Dynamic and excluded port ranges' {
    foreach ($family in @('ipv4','ipv6')) { foreach ($protocol in @('tcp','udp')) { [ordered]@{Family=$family;Protocol=$protocol;Range=Invoke-InspectionNative 'netsh' @('int',$family,'show','dynamicport',$protocol);Exclusions=Invoke-InspectionNative 'netsh' @('int',$family,'show','excludedportrange',('protocol='+$protocol))} } }
}
$inspectionReport.Disk = Get-InspectionSection 'Storage capacity and health status' { Get-Volume | Where-Object {$_.DriveLetter -eq 'C'} | Select-Object DriveLetter,HealthStatus,SizeRemaining,Size }
$inspectionReport.SecureBootState = Get-InspectionSection 'Reported Secure Boot state (no setting changes)' { Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State' | Select-Object UEFISecureBootEnabled }
$inspectionReport.PowerPlan = Get-InspectionSection 'Active Windows power plan' { [ordered]@{Plan=Invoke-InspectionNative 'powercfg' @('/getactivescheme')} }
$inspectionReport.Memory = Get-InspectionSection 'Memory and paging snapshot' { Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory | Select-Object AvailableMBytes,PercentCommittedBytesInUse,PagesPersec }
$inspectionReport.Processes = Get-InspectionSection 'Process executable metadata (no arguments)' {
    $script:inspectionProcessSnapshot=@(Get-Process -ErrorAction Stop)
    $script:inspectionProcessSnapshot | Select-Object ProcessName,Id,Path,HandleCount,@{Name='WorkingSetMB';Expression={[math]::Round($_.WorkingSet64/1MB,1)}},CPU
}
$inspectionReport.ProcessSignatures = Get-InspectionSection 'Accessible running-executable signatures' {
    if(-not $VerifyProcessSignatures){throw 'Optional signature inspection skipped; use -VerifyProcessSignatures with network/certificate-service disclosure.'}
    $executables = @($script:inspectionProcessSnapshot | Where-Object {$_.Path} | Select-Object -ExpandProperty Path -Unique)
    foreach ($executable in $executables) {
        try { [void](Assert-SimLocalPath $executable -Leaf); $signature = Get-AuthenticodeSignature -LiteralPath $executable; [ordered]@{Path=$executable;Status=[string]$signature.Status;Signer=$signature.SignerCertificate.Subject} }
        catch { [ordered]@{Path=$executable;Status='Unavailable';Signer=$null} }
    }
}
$inspectionReport.Listeners = Get-InspectionSection 'TCP listening services' {
    $processMap = Get-InspectionProcessMap
    Get-NetTCPConnection -State Listen | ForEach-Object { [ordered]@{Address=$_.LocalAddress;Port=$_.LocalPort;ProcessId=$_.OwningProcess;Process=$processMap[[int]$_.OwningProcess].Name;LoopbackOnly=[Net.IPAddress]::IsLoopback([Net.IPAddress]::Parse($_.LocalAddress))} }
}
$inspectionReport.ActiveConnections = Get-InspectionSection 'Established and closing TCP connections' {
    $processMap = Get-InspectionProcessMap
    Get-NetTCPConnection | Where-Object {$_.State -in @('Established','CloseWait','Bound')} | ForEach-Object { [ordered]@{State=[string]$_.State;LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;RemoteAddress=$_.RemoteAddress;RemotePort=$_.RemotePort;ProcessId=$_.OwningProcess;Process=$processMap[[int]$_.OwningProcess].Name} }
}
$inspectionInstalledProviders=Get-InspectionInstalledProviders
$inspectionProviderCoverage=Get-InspectionProviderCoverage @('Tcpip','Microsoft-Windows-TCPIP','Microsoft-Windows-WLAN-AutoConfig','Microsoft-Windows-NDIS','Microsoft-Windows-WHEA-Logger','WHEA-Logger','Disk','Ntfs','stornvme','storahci','Microsoft-Windows-Kernel-Processor-Power','Microsoft-Windows-Kernel-Power','Service Control Manager','Netwtw10','Netwtw12','Netwtw14') $inspectionInstalledProviders
$inspectionReport.SystemEvents=Get-InspectionEventSection 'System' @{LogName='System';StartTime=(Get-Date).AddDays(-7);Level=@(1,2,3)} 500 $inspectionProviderCoverage
$tcpProviders=Get-InspectionProviderCoverage @('Tcpip','Microsoft-Windows-TCPIP') $inspectionInstalledProviders
$inspectionReport.TcpAllocationEvents=Get-InspectionEventSection 'System' @{LogName='System';StartTime=(Get-Date).AddDays(-7);Id=@(4231,4266,4227)} 500 $tcpProviders
$inspectionReport.ApplicationCrashes=Get-InspectionEventSection 'Application' @{LogName='Application';StartTime=(Get-Date).AddDays(-7);Id=@(1000,1001,1026)} 150
$inspectionReport.WiFiEvents=Get-InspectionEventSection 'Microsoft-Windows-WLAN-AutoConfig/Operational' @{LogName='Microsoft-Windows-WLAN-AutoConfig/Operational';StartTime=(Get-Date).AddDays(-7);Id=@(8001,8002,8003,11004,11005,11006)} 100

$inspectionReport.MicrosoftTools = Get-InspectionSection 'Microsoft tool signature verification' {
    if(-not $UseMicrosoftTools){throw 'Optional Microsoft tools skipped by default.'}
    Write-Host 'External collectors may inspect startup references, contact network paths/certificate services and accept Microsoft EULAs. No VirusTotal flags are used.'
    Get-VerifiedMicrosoftTool 'Autoruns' 'https://download.sysinternals.com/files/Autoruns.zip' 'Autorunsc64.exe'
    Get-VerifiedMicrosoftTool 'Sigcheck' 'https://download.sysinternals.com/files/Sigcheck.zip' 'sigcheck64.exe'
}
$inspectionToolRecords = @($inspectionReport.MicrosoftTools.Data)
$autorunsTool = $inspectionToolRecords | Where-Object {$_.Name -eq 'Autoruns'} | Select-Object -First 1
$sigcheckTool = $inspectionToolRecords | Where-Object {$_.Name -eq 'Sigcheck'} | Select-Object -First 1
$inspectionReport.StartupEntries = Get-InspectionSection 'Autoruns startup audit and signature checks' {
    if (-not $autorunsTool) { throw 'Verified Autorunsc was unavailable.' }
    [void](Assert-SimLocalPath $autorunsTool.Path -Leaf)
    if((Get-FileHash -LiteralPath $autorunsTool.Path).Hash -cne $autorunsTool.SHA256){throw 'Collector changed since verification.'}
    # Omit -s/-h: collect startup metadata first; only guarded local files get followups.
    $csv = Invoke-InspectionTool $autorunsTool.Path @('-accepteula','-nobanner','-a','*','-c') -ExpectedHash $autorunsTool.SHA256
    Convert-InspectionStartupCsv $csv
}
$inspectionReport.SignatureFollowups = Get-InspectionSection 'Sigcheck review of accessible unverified startup files' {
    if (-not $sigcheckTool) { throw 'Verified Sigcheck was unavailable.' }
    $candidates = @($inspectionReport.StartupEntries.Data | Where-Object {$_.Signer -notmatch '^\(Verified\)' -and $_.'Image Path' -and $_.'Image Path' -notmatch '^File not found:'} | Select-Object -ExpandProperty 'Image Path' -Unique)
    $inspectionReport.SignatureCandidateCoverage=[ordered]@{Total=$candidates.Count;Limit=30;OmittedByCap=[math]::Max(0,$candidates.Count-30)}
    foreach ($candidate in ($candidates | Select-Object -First 30)) {
        try {
            [void](Assert-SimLocalPath $candidate -Leaf)
            [void](Assert-SimLocalPath $sigcheckTool.Path -Leaf)
            if((Get-FileHash -LiteralPath $sigcheckTool.Path).Hash -cne $sigcheckTool.SHA256){throw 'Collector changed since verification.'}
            $checked = Invoke-InspectionTool $sigcheckTool.Path @('-accepteula','-nobanner','-a','-h',$candidate) 30 -ExpectedHash $sigcheckTool.SHA256
            [ordered]@{Path=$candidate;Result=Protect-SimText $checked}
        } catch { [ordered]@{Path=Protect-SimText $candidate;Status='Skipped';Reason=Protect-SimText $_.Exception.Message} }
    }
}

$inspectionReport.SocketSamples = @()
for ($sampleIndex=0; $sampleIndex -lt $SocketSamples; $sampleIndex++) {
    $inspectionReport.SocketSamples += Get-InspectionSection ('Socket sample {0}/{1}' -f ($sampleIndex+1),$SocketSamples) { Get-SocketInspection }
    if ($sampleIndex+1 -lt $SocketSamples) { Start-Sleep -Seconds $SampleIntervalSeconds }
}
$inspectionReport.CompletedAt = (Get-Date).ToString('o')
$inspectionReport.EventCoverage=[ordered]@{WindowDays=7;SystemProviderFilter='Installed subset of explicit provider allowlist; absent/unknown providers recorded; other providers not covered';SystemLimit=500;SystemCapReached=$inspectionReport.SystemEvents.CapReached;TcpAllocationLimit=500;TcpAllocationCapReached=$inspectionReport.TcpAllocationEvents.CapReached;ApplicationLimit=150;ApplicationCapReached=$inspectionReport.ApplicationCrashes.CapReached;WifiLimit=100;WifiCapReached=$inspectionReport.WiFiEvents.CapReached;Meaning='Bounded snapshots; missing/truncated logs are not evidence of no faults'}
if (-not $inspectionElevated) { $inspectionReport.Limitations += 'Not elevated. Protected processes and some system/security metadata may be unavailable. No administrator prompt was automated.' }
$inspectionReport.Limitations += 'No antivirus scan with automatic remediation was started. No clean bill of health or absence of malware is established by this metadata inspection.'
$inspectionReport.Limitations += 'No raw packet capture, browser sessions, saved credentials or VirusTotal queries requested. Certificate/signature operations and opted-in tools can use network infrastructure. Defender can submit under existing policy.'
$inspectionReport.Limitations += 'No TLS handshake, root-store integrity, revocation success or complete certificate-chain audit is established. Optional tools accept EULAs and create local cache/report files.'
$inspectionReport.Limitations += 'Router parental profiles still require authenticated router access. Laptop diagnostics do not establish their state.'

$jsonPath = Join-Path $inspectionRunDirectory 'inspection.json'
Save-SimReport $inspectionReport $jsonPath
$startupEntries = @($inspectionReport.StartupEntries.Data | Where-Object {$null -ne $_})
# Startup metadata remains in JSON; avoid formula interpretation of untrusted CSV cells.
$summary = New-Object Collections.Generic.List[string]
$summary.Add('WINDOWS INSPECTION - ' + $ExpectedDevice)
$summary.Add('Device: ' + $inspectionComputer.Manufacturer + ' / ' + $inspectionComputer.Model)
$summary.Add('Window: ' + $inspectionReport.StartedAt + ' through ' + $inspectionReport.CompletedAt)
$summary.Add('No remediation or security configuration changes applied.')
$summary.Add('')
$portFailures = @($inspectionReport.TcpAllocationEvents.Data | Where-Object {$_.Id -in @(4231,4266,4227)})
$summary.Add('Port-allocation failure events in dedicated bounded TCP/IP history: ' + $(if($inspectionReport.TcpAllocationEvents.Status -in @('Retrieved','Empty')){$portFailures.Count}else{'Unknown'}))
foreach ($event in ($portFailures | Select-Object -First 8)) { $summary.Add(('  {0} | {1} | event {2}' -f $event.TimeCreated,$event.ProviderName,$event.Id)) }
foreach ($network in @($inspectionReport.ActiveNetworks.Data)) {
    $summary.Add((Get-InspectionFirewallSummary $network $inspectionReport.Firewall))
}
$summary.Add('Startup entries retrieved: ' + (Get-InspectionCount $inspectionReport.StartupEntries))
$summary.Add('Startup entries are metadata only; unverified/unchecked references do not establish malware or signature validity.')
$summary.Add('Unsigned, missing, or directory entries are review items; none alone proves malware.')
$summary.Add('Application crash records retrieved: ' + (Get-InspectionCount $inspectionReport.ApplicationCrashes))
$summary.Add('')
$summary.Add('Unavailable sections:')
foreach($problem in @(Get-InspectionProblems $inspectionReport)){$summary.Add('  '+$problem)}
$summary.Add('')
$summary.Add('Limitations:')
foreach ($limitation in $inspectionReport.Limitations) { $summary.Add('  ' + $limitation) }
$summary.Add('')
$summary.Add('Details: inspection.json; no untrusted startup CSV generated.')
$summary.Add('References: https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns')
$summary.Add('https://learn.microsoft.com/en-us/sysinternals/downloads/sigcheck')
$summary.Add('https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/tcp-ip-port-exhaustion-troubleshooting')
Save-SimReport ([ordered]@{Lines=@($summary | ForEach-Object {Protect-SimText $_})}) (Join-Path $inspectionRunDirectory 'summary.json')
Write-Host ('Inspection evidence saved: ' + $inspectionRunDirectory)
$inspectionPartial=@(Get-InspectionProblems $inspectionReport | Where-Object {$_ -match ': Unavailable'}).Count -gt 0
} finally {Exit-SimLock $inspectionLock}
if($inspectionPartial){exit 3}
