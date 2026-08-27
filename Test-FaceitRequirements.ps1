[CmdletBinding()]param([switch]$Json, [switch]$NoPause, [switch]$Ascii)
$ErrorActionPreference = 'Stop'; $ProgressPreference = 'SilentlyContinue'
try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { $Ascii = $true }

$Gly = if ($Ascii) {
    @{ Full='#'; Dim='-'; LCap='['; RCap=']'; Ok='+'; No='x'; Wrn='!'; Skp='-'; Ell='..'
       TL='+'; TR='+'; BL='+'; BR='+'; Hz='-'; Vt='|'; Half='='; Arw='>'
       K7='\'; KL='\'; KR='/'; KJ='/'; KE='='; KV='|' }
} else {
    $ch = { param($hex) [char][Convert]::ToInt32($hex, 16) }
    @{ Full=&$ch '2588'; Dim=&$ch '2591'; LCap=&$ch '2590'; RCap=&$ch '258C'
       Ok=&$ch '2714'; No=&$ch '2716'; Wrn=&$ch '25B2'; Skp=&$ch '00B7'; Ell=[string](&$ch '2026')
       TL=&$ch '250C'; TR=&$ch '2510'; BL=&$ch '2514'; BR=&$ch '2518'
       Hz=&$ch '2500'; Vt=&$ch '2502'; Half=&$ch '2584'; Arw=&$ch '203A'
       K7=&$ch '2557'; KL=&$ch '255A'; KR=&$ch '2554'; KJ=&$ch '255D'; KE=&$ch '2550'; KV=&$ch '2551' }
}

$Stencil = @(
    '##7  ##7######7 ######7 ######7 ######7  ######7 ######7 '
    'L##7##rJ##r==##7##r==##7##r==##7##r==##7##r===##7##r==##7'
    ' L###rJ ##|  ##|######rJ##|  ##|######rJ##|   ##|######rJ'
    ' ##r##7 ##|  ##|##r===J ##|  ##|##r==##7##|   ##|##r===J '
    '##rJ ##7######rJ##|     ######rJ##|  ##|L######rJ##|     '
    'L=J  L=JL=====J L=J     L=====J L=J  L=J L=====J L=J     ')
$Swap = @{ '#'=$Gly.Full; '7'=$Gly.K7; 'L'=$Gly.KL; 'r'=$Gly.KR; 'J'=$Gly.KJ; '='=$Gly.KE; '|'=$Gly.KV }

$LogoW = 57; $CardW = 62; $BarW = 46
try { $Win = $Host.UI.RawUI.WindowSize.Width } catch { $Win = 100 }
if (!$Win -or $Win -lt 64) { $Win = 100 }
$Pad = ' ' * [Math]::Max(0, [int](($Win - $CardW) / 2))
try { $null = [Console]::CursorTop; [Console]::CursorVisible = $false; $CanPos = $true } catch { $CanPos = $false }
$Elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

function Mid($text, $color = 'Gray', $width = 0) {
    if (!$width) { $width = $text.Length }
    Write-Host ((' ' * [Math]::Max(0, [int](($Win - $width) / 2))) + $text) -Fore $color
}
function Logo {
    Write-Host ''
    foreach ($row in $Stencil) {
        foreach ($k in $Swap.Keys) { $row = $row.Replace($k, [string]$Swap[$k]) }
        Mid $row 'Red' $LogoW
    }
    Write-Host ''; Mid 'FACEIT Anti-Cheat readiness' 'DarkRed'; Write-Host ''
}
function Bar($pct, $task) {
    if ($CanPos) { try { [Console]::SetCursorPosition(0, $script:BarY) } catch {} }
    $fill = [int][Math]::Round($pct / 100 * $BarW); $rest = $BarW - $fill
    Write-Host "$Pad  " -N; Write-Host $Gly.LCap -Fore DarkRed -N
    if ($fill) { Write-Host ([string]$Gly.Full * $fill) -Fore Red -N }
    if ($rest) { Write-Host ([string]$Gly.Dim * $rest) -Fore DarkGray -N }
    Write-Host $Gly.RCap -Fore DarkRed -N; Write-Host ('  {0,3}%' -f $pct) -Fore White
    if ($task.Length -gt $CardW - 6) { $task = $task.Substring(0, $CardW - 9) + '...' }
    Write-Host ($Pad + "   $task".PadRight($CardW)) -Fore DarkGray
}
function Sweep($from, $to, $task) {
    if ($to -le $from) { Bar $to $task; return }
    $from..$to | ForEach-Object { Bar $_ $task; Start-Sleep -M 9 }
}

function Res($state, $note, $fix = '') { @{ S = $state; D = $note; F = $fix } }
function Tpm {
    if (-not $script:TpmCache) {
        $c = @{ Obj = $null; Wmi = $null; Tool = ''; Pnp = @() }
        try { $c.Obj = Get-Tpm } catch {}
        try { $c.Wmi = Get-CimInstance -Namespace root\cimv2\security\microsofttpm -ClassName Win32_Tpm -EA Stop } catch {}
        try { $c.Tool = (& tpmtool getdeviceinformation 2>&1 | Out-String) } catch {}
        try { $c.Pnp = @(Get-PnpDevice -Class SecurityDevices -PresentOnly -EA SilentlyContinue |
                         Where-Object FriendlyName -match 'Trusted Platform') } catch {}
        $script:TpmCache = $c
    }
    $script:TpmCache
}
function Field($name) { if ((Tpm).Tool -match ('(?im)^[\s-]*' + $name + '\s*:\s*(.+)$')) { $Matches[1].Trim() } }
function Guard {
    if ($null -eq $script:GuardOnce) {
        $script:GuardOnce = 1
        try { $script:GuardData = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -EA Stop } catch { $script:GuardData = $null }
    }
    $script:GuardData
}

$Checks = @(
    @{ N = 'UEFI Firmware Mode'; R = {
        $mode = if ($env:firmware_type) { $env:firmware_type } else { (Get-ComputerInfo -Property BiosFirmwareType).BiosFirmwareType }
        if ($mode -match 'UEFI') { Res OK 'UEFI' } else { Res FAIL "$mode / CSM" 'Convert with mbr2gpt, then switch firmware to UEFI' } }}

    @{ N = 'GPT System Disk'; R = {
        $disk = Get-Partition -DriveLetter ($env:SystemDrive.TrimEnd(':')) | Get-Disk
        if ($disk.PartitionStyle -eq 'GPT') { Res OK 'GPT' } else { Res FAIL $disk.PartitionStyle 'mbr2gpt /convert /disk:0 /allowFullOS' } }}

    @{ N = 'Secure Boot'; R = {
        try { if (Confirm-SecureBootUEFI) { Res OK 'Enabled' } else { Res FAIL 'Disabled' 'Enable Secure Boot in BIOS, disable CSM' } }
        catch { Res FAIL 'Unsupported' 'Machine is not UEFI booted' } }}

    @{ N = 'TPM Present'; R = {
        $t = Tpm
        if ($t.Obj -and $t.Obj.TpmPresent) { Res OK $(if ($t.Wmi) { "$($t.Wmi.ManufacturerIdTxt)".Trim() } else { 'Detected' }) }
        elseif ($t.Wmi) { Res OK "$($t.Wmi.ManufacturerIdTxt)".Trim() }
        elseif ($t.Pnp) { Res OK 'Detected (PnP)' }
        elseif (!$Elevated) { Res SKIP 'Needs admin' 'Re-run PowerShell as Administrator' }
        else { Res FAIL 'Not detected' 'Enable Intel PTT or AMD fTPM in BIOS' } }}

    @{ N = 'TPM Version 2.0'; R = {
        $v = if ((Tpm).Wmi) { (((Tpm).Wmi.SpecVersion) -split ',')[0].Trim() } else { Field 'TPM Version' }
        if (!$v) { Res SKIP $(if ($Elevated) { 'Unknown' } else { 'Needs admin' }) }
        elseif ($v -like '2.*') { Res OK $v }
        else { Res FAIL $v 'TPM 1.2 will not pass, check for a BIOS update' } }}

    @{ N = 'TPM Ready State'; R = {
        $t = (Tpm).Obj
        if (!$t) { return Res SKIP $(if ($Elevated) { 'Unavailable' } else { 'Needs admin' }) }
        if (!$t.TpmPresent) { return Res SKIP 'No TPM' }
        $bad = @(); if (!$t.TpmEnabled) { $bad += 'disabled' }; if (!$t.TpmActivated) { $bad += 'inactive' }; if (!$t.TpmReady) { $bad += 'not ready' }
        if (!$bad) { Res OK 'Ready' } else { Res FAIL ($bad -join ', ') 'Run tpm.msc, then Prepare the TPM' } }}

    @{ N = 'IOMMU / DMA Protection'; R = {
        $g = Guard; if (!$g) { return Res SKIP 'Unavailable' }
        if ($g.AvailableSecurityProperties -contains 3) { return Res OK 'Kernel DMA active' }
        if (Get-PnpDevice -PresentOnly -EA SilentlyContinue | Where-Object FriendlyName -match 'IOMMU|DMA Remapping') {
            Res WARN 'IOMMU on, DMA off' 'No Kernel DMA Protection on this platform, verify with the AC client' }
        else { Res FAIL 'Unavailable' 'Enable VT-d (Intel) or IOMMU (AMD) in BIOS' } }}

    @{ N = 'CPU Virtualization'; R = {
        if ((Get-CimInstance Win32_ComputerSystem).HypervisorPresent) { return Res OK 'Hypervisor running' }
        if ((Get-CimInstance Win32_Processor | Select-Object -First 1).VirtualizationFirmwareEnabled) { Res OK 'Enabled in firmware' }
        else { Res FAIL 'Disabled' 'Enable Intel VT-x or AMD SVM in BIOS' } }}

    @{ N = 'Virtualization Based Security'; R = {
        $g = Guard; if (!$g) { return Res SKIP 'Unavailable' }
        switch ($g.VirtualizationBasedSecurityStatus) {
            2 { Res OK 'Running' }
            1 { Res WARN 'Not running' 'Check virtualization in BIOS and hypervisorlaunchtype' }
            default { Res FAIL 'Off' 'Enable Core Isolation in Windows Security' } } }}

    @{ N = 'Memory Integrity (HVCI)'; R = {
        $g = Guard; if (!$g) { return Res SKIP 'Unavailable' }
        if ($g.SecurityServicesRunning -contains 2) { Res OK 'Running' }
        elseif ($g.SecurityServicesConfigured -contains 2) { Res WARN 'Blocked by driver' 'Windows Security lists the incompatible driver' }
        else { Res WARN 'Off' 'Core isolation, Memory integrity. Enforced per account' } }}

    @{ N = 'Windows Build'; R = {
        $b = [int](Get-CimInstance Win32_OperatingSystem).BuildNumber
        $u = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').UBR
        if ($b -ge 22631) { Res OK "$b.$u" }
        elseif ($b -ge 22000) { Res WARN "$b.$u below 23H2" 'Update to Windows 11 23H2 or newer' }
        else { Res FAIL "Windows 10 ($b)" 'Blocked from 14 Oct 2026, upgrade to Windows 11' } }}

    @{ N = 'Boot Integrity Flags'; R = {
        $bcd = & bcdedit /enum '{current}' 2>&1 | Out-String; $on = @()
        if ($bcd -match '(?im)^\s*testsigning\s+Yes') { $on += 'testsigning' }
        if ($bcd -match '(?im)^\s*debug\s+Yes') { $on += 'debug' }
        if ($bcd -match '(?im)^\s*nointegritychecks\s+Yes') { $on += 'nointegritychecks' }
        if (!$on) { Res OK 'Clean' } else { Res FAIL ($on -join ', ') 'bcdedit /set testsigning off, then reboot' } }}

    @{ N = 'Attestation Capable'; R = {
        $v = Field 'Is Capable For Attestation'
        if (!$v) { return Res SKIP $(if ($Elevated) { 'Not reported' } else { 'Needs admin' }) }
        if ($v -eq 'True') { Res OK 'Yes' } else { Res FAIL 'No' 'Virtual TPM or blocklisted firmware, not fixable in software' } }}

    @{ N = 'Attestation Ready'; R = {
        $v = Field 'Ready For Attestation'
        if (!$v) { return Res SKIP $(if ($Elevated) { 'Not reported' } else { 'Needs admin' }) }
        if ($v -eq 'True') { Res OK 'Yes' } else { Res FAIL 'No' 'Prepare the TPM and confirm the EK certificate is present' } }}

    @{ N = 'Endorsement Key Certificate'; R = {
        try { $ek = Get-TpmEndorsementKeyInfo -Hash Sha256 } catch { return Res SKIP 'Needs admin' 'Re-run PowerShell as Administrator' }
        if (!$ek.IsPresent) { return Res FAIL 'No EK' }
        $n = @($ek.ManufacturerCertificates).Count
        if ($n) { Res OK "$n manufacturer cert(s)" } else { Res WARN 'EK present, no cert' 'Common on AMD fTPM. Update BIOS, then clear the TPM' } }}

    @{ N = 'TPM Firmware Health'; R = {
        $v = Field 'TPM Has Vulnerable Firmware'
        if (!$v) { return Res SKIP 'Not reported' }
        if ($v -eq 'True') { Res FAIL 'Vulnerable' 'Update motherboard BIOS' } else { Res OK 'Healthy' } }}
)

function RunAll {
    $out = @(); $total = $Checks.Count; $idx = 0; $prev = 0
    foreach ($chk in $Checks) {
        $idx++; $goal = [int](($idx / $total) * 100); $mid = [Math]::Max($prev, $goal - 4)
        Sweep $prev $mid $chk.N
        try { $r = & $chk.R } catch { $r = Res SKIP ('Error: ' + $_.Exception.Message) }
        if (!$r) { $r = Res SKIP 'No result' }
        $out += [pscustomobject]@{ Check = $chk.N; Status = $r.S; Detail = $r.D; Fix = $r.F }
        Sweep $mid $goal $chk.N; $prev = $goal
    }
    Sweep $prev 100 'Finalising'; Start-Sleep -M 250; $out
}

function Report($rows) {
    Clear-Host; Logo
    if (!$Elevated) { Mid 'NOT ELEVATED - TPM RESULTS INCOMPLETE' 'Yellow'; Write-Host '' }
    $bad = @($rows | Where-Object Status -eq 'FAIL').Count
    $wrn = @($rows | Where-Object Status -eq 'WARN').Count
    Write-Host ($Pad + $Gly.TL + ([string]$Gly.Hz * ($CardW - 2)) + $Gly.TR) -Fore DarkRed
    foreach ($row in $rows) {
        switch ($row.Status) {
            'OK'    { $sym = $Gly.Ok;  $col = 'Green' }
            'FAIL'  { $sym = $Gly.No;  $col = 'Red' }
            'WARN'  { $sym = $Gly.Wrn; $col = 'Yellow' }
            default { $sym = $Gly.Skp; $col = 'DarkGray' }
        }
        $name = $row.Check; if ($name.Length -gt 30) { $name = $name.Substring(0, 28) + $Gly.Ell }
        $det = "$($row.Detail)"; if ($det.Length -gt 22) { $det = $det.Substring(0, 20) + $Gly.Ell }
        Write-Host ($Pad + $Gly.Vt + ' ') -Fore DarkRed -N; Write-Host "$sym " -Fore $col -N
        Write-Host $name.PadRight(31) -Fore Gray -N; Write-Host $det.PadRight(23) -Fore $col -N
        Write-Host $Gly.Vt -Fore DarkRed
    }
    Write-Host ($Pad + $Gly.BL + ([string]$Gly.Hz * ($CardW - 2)) + $Gly.BR) -Fore DarkRed; Write-Host ''
    $edge = [string]$Gly.Half * 3
    if (!$bad -and !$wrn) { Mid "$edge  SYSTEM READY FOR FACEIT  $edge" 'Green' }
    elseif (!$bad) { Mid "PASSED WITH $wrn WARNING(S)" 'Yellow' }
    else { Mid "$bad BLOCKING ISSUE(S), $wrn WARNING(S)" 'Red' }
    $todo = @($rows | Where-Object { $_.Fix -and $_.Status -in 'FAIL', 'WARN' })
    if ($todo) {
        Write-Host ''; Mid 'ACTION REQUIRED' 'DarkRed'; Write-Host ''
        foreach ($t in $todo) {
            Write-Host ($Pad + '  ' + $Gly.Arw + ' ') -Fore Red -N; Write-Host $t.Check -Fore Gray
            Write-Host ($Pad + '    ' + $t.Fix) -Fore DarkGray
        }
    }
    Write-Host ''; Mid ("XDPDROP   $env:COMPUTERNAME   " + (Get-Date -f 'yyyy-MM-dd HH:mm')) 'DarkGray'; Write-Host ''
}

if ($Json) { RunAll | ConvertTo-Json -Depth 3; if ($CanPos) { try { [Console]::CursorVisible = $true } catch {} }; return }

Clear-Host; Logo
$script:BarY = if ($CanPos) { [Console]::CursorTop } else { 0 }
Write-Host ''; Write-Host ''
$rows = RunAll; Report $rows
if ($CanPos) { try { [Console]::CursorVisible = $true } catch {} }
if (!$NoPause -and $Host.Name -eq 'ConsoleHost') {
    Mid 'Press any key to exit' 'DarkGray'; $null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
}
exit $(if (@($rows | Where-Object Status -eq 'FAIL').Count) { 1 } else { 0 })