# Definitions only: inert on import.
function Test-SimTarget($Computer,[string]$Expected) {
    if (@($Computer).Count -ne 1 -or -not $Computer.Manufacturer -or -not $Computer.Model) { return $false }
    if ($Expected -eq 'Gigabyte') { return ($Computer.Manufacturer -match '^GIGABYTE(?:\s|$)' -and $Computer.Model -match '^G6\s+KF(?:\s|$)') }
    return ($Expected -eq 'Victus' -and $Computer.Manufacturer -match '^(HP|Hewlett-Packard|Hewlett Packard)(?:\s|$)' -and $Computer.Model -match '^(HP\s+)?Victus(?:\s|$)')
}
function Assert-SimLocalPath([string]$Path,[switch]$Leaf) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path.Substring(2).Contains(':')) { throw 'Only an absolute local drive path is allowed.' }
    $full=[IO.Path]::GetFullPath($Path)
    $drive=[IO.DriveInfo]::new($full.Substring(0,3))
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) { throw 'Only a fixed local drive is allowed.' }
    $cursor=$full.Substring(0,3)
    $parts=$full.Substring(3).Split([char[]]'\/',[StringSplitOptions]::RemoveEmptyEntries)
    $paths=@($cursor)
    foreach($part in $parts){$cursor=Join-Path $cursor $part;$paths+= $cursor}
    foreach($cursor in $paths) {
        if (Test-Path -LiteralPath $cursor) {
            $item=Get-Item -LiteralPath $cursor -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse paths are not allowed.' }
        }
    }
    if ($Leaf -and -not (Test-Path -LiteralPath $full -PathType Leaf)) { throw 'A readable local regular file is required.' }
    return $full
}
function Enter-SimLock {
    $mutex=[Threading.Mutex]::new($false,'Global\SimCleaner.LocalReview.v02')
    try {
        try { $owned=$mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $owned=$true }
        if (-not $owned) { throw 'Another Sim Cleaner/inspection action is running. No action performed.' }
        return $mutex
    } catch { $mutex.Dispose(); throw }
}
function Exit-SimLock($Mutex) { if ($Mutex) { try { $Mutex.ReleaseMutex() } finally { $Mutex.Dispose() } } }
function Save-SimReport($Record,[string]$Path) {
    $safe=Assert-SimLocalPath $Path
    if (Test-Path -LiteralPath $safe) { throw 'Evidence file already exists; refusing overwrite.' }
    $temp=$safe+'.'+[guid]::NewGuid().ToString('N')+'.tmp'
    try {
        $bytes=[Text.UTF8Encoding]::new($false).GetBytes(((ConvertTo-SimSafeData $Record) | ConvertTo-Json -Depth 20))
        $stream=[IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try { $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
        [IO.File]::Move($temp,$safe,$false)
    } finally { if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Force } }
}
function Read-SimSection([scriptblock]$Query,[switch]$Singleton,[string[]]$Required=@()) {
    try {
        $rows=@(& $Query)
        if ($Singleton -and $rows.Count -ne 1) { throw 'Expected exactly one record; query empty or ambiguous.' }
        foreach($row in $rows) {
            if ($null -eq $row) { throw 'Query returned a null record.' }
            foreach($field in $Required) { if ($null -eq $row.$field -or [string]$row.$field -match 'N/A:|Must be an administrator') { throw "Required field unavailable: $field" } }
        }
        return [ordered]@{Status=if($rows.Count){'Retrieved'}else{'Empty'};Data=$rows}
    } catch { return [ordered]@{Status='Unavailable';Data=@();Error=Protect-SimText $_.Exception.Message} }
}
function Get-SimHash($Value) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes(($Value | ConvertTo-Json -Depth 16 -Compress)))).Replace('-','') } finally { $sha.Dispose() }
}
function Protect-SimText([string]$Text) {
    # Conservative minimization, not a guarantee of secret-free diagnostics.
    # Labelled key=value / key: value secrets, widened to the common key names.
    $safe=$Text -replace '(?im)\b(password|passwd|pwd|api[_-]?key|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|authorization|session[_-]?key|private[_-]?key|connection[_-]?string)\s*[:=][^\r\n]*','$1=[redacted]'
    # High-confidence secret shapes, redacted regardless of the surrounding label.
    $safe=$safe -replace '(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{10,}','Bearer [redacted]'
    $safe=$safe -replace '\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b','[redacted JWT]'
    $safe=$safe -replace '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b','[redacted AWS key]'
    $safe=$safe -replace '\bxox[baprs]-[A-Za-z0-9-]{10,}\b','[redacted token]'
    $safe=$safe -replace '(?s)-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----.*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----','[redacted private key]'
    [regex]::Replace($safe,'(?i)\b(?:https?|ftp)://[^\s"<>]+',{
        param($match)
        try {$u=[UriBuilder]::new($match.Value);$u.UserName='';$u.Password='';$u.Query='';$u.Fragment='';$u.Uri.AbsoluteUri}catch{'[redacted URL]'}
    })
}
function ConvertTo-SimSafeData($Value) {
    if($null -eq $Value){return $null}
    if($Value -is [string]){return (Protect-SimText $Value)}
    if($Value -is [Collections.IDictionary]){$copy=[ordered]@{};foreach($key in $Value.Keys){$copy[$key]=if($key -match '^(password|passwd|pwd|api[_-]?key|secret|client[_-]?secret|access[_-]?token|refresh[_-]?token|authorization|session[_-]?key|private[_-]?key|connection[_-]?string)$'){'[redacted]'}else{ConvertTo-SimSafeData $Value[$key]}};return $copy}
    if($Value -is [array]){$copy=@(foreach($v in $Value){ConvertTo-SimSafeData $v});return ,$copy}
    if($Value -is [pscustomobject]){$copy=[ordered]@{};foreach($prop in $Value.PSObject.Properties){$copy[$prop.Name]=ConvertTo-SimSafeData $prop.Value};return $copy}
    return $Value
}
