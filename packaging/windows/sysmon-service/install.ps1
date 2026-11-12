# derm-sysmon: installs the Windows service that reads Sysmon's channel for
# each user's derm daemon (wave 5b lane 5bE; contracts/sysmon-service.md).
#
# Run from an elevated PowerShell. It prints every step first and asks,
# unless -Yes is given (rules section 5, item 2). Its undo is uninstall.ps1.
#
#   .\install.ps1 -From <folder holding derm-sysmon.exe and derm-daemon.exe>
#
# What it does, in order:
#   1. copies derm-sysmon.exe and derm-daemon.exe into
#      "$env:ProgramFiles\derm" (a folder only administrators write; the
#      service serves only a daemon started from there);
#   2. creates the service "derm-sysmon" (New-Service), run as the virtual account
#      "NT SERVICE\derm-sysmon", started at boot;
#   3. lets signed-in users ask whether it runs (the daemon checks that the
#      pipe's server is the service's process), nothing more;
#   4. adds that account to Event Log Readers (S-1-5-32-573), the group the
#      Sysmon channel grants read (Windows test w5 5.1);
#   5. makes "$env:ProgramData\derm-sysmon" writable by SYSTEM,
#      administrators and the service only, readable by signed-in users,
#      and writes its config.json;
#   6. starts the service.
# It never installs or configures Sysmon itself.

param(
    [Parameter(Mandatory = $true)][string]$From,
    [switch]$Yes
)

$ErrorActionPreference = 'Stop'
$Name = 'derm-sysmon'
$Account = "NT SERVICE\$Name"
$Bin = Join-Path $env:ProgramFiles 'derm'
$Data = Join-Path $env:ProgramData $Name

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this from an elevated PowerShell (as administrator).' }

foreach ($exe in 'derm-sysmon.exe', 'derm-daemon.exe') {
    if (-not (Test-Path -LiteralPath (Join-Path $From $exe) -PathType Leaf)) { throw "$exe is not in $From" }
}

# The group's name is localized; its SID is not.
$Readers = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-573')).Translate(
    [Security.Principal.NTAccount]).Value.Split('\')[-1]

$daemon = Join-Path $Bin 'derm-daemon.exe'
$config = @{ daemon = $daemon; sandboxAccounts = @('srt-sandbox') } | ConvertTo-Json -Compress

Write-Host "derm-sysmon will:"
Write-Host "  copy derm-sysmon.exe and derm-daemon.exe from $From to $Bin"
Write-Host "  New-Service $Name for `"$Bin\derm-sysmon.exe`" service (automatic), then sc.exe config $Name obj= `"$Account`""
Write-Host "  sc.exe sdset $Name (signed-in users may query its status)"
Write-Host "  net localgroup `"$Readers`" `"$Account`" /add"
Write-Host "  make $Data (SYSTEM, Administrators, $Account write; signed-in users read) with config.json: $config"
Write-Host "  sc.exe start $Name"
Write-Host "Undo: .\uninstall.ps1"
if (-not $Yes) {
    $answer = Read-Host 'Go ahead? (y/N)'
    if ($answer -ne 'y') { Write-Host 'Nothing changed.'; exit 1 }
}

# 1. The programs, in an administrators-only folder.
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
Copy-Item -LiteralPath (Join-Path $From 'derm-sysmon.exe') -Destination $Bin -Force
Copy-Item -LiteralPath (Join-Path $From 'derm-daemon.exe') -Destination $Bin -Force

# 2. The service, as its virtual account.
# New-Service takes the quoted program path as one value; Windows
# PowerShell 5.1 passes an argument with inner quotes to a native program
# wrongly, so sc.exe gets only plain words here.
New-Service -Name $Name -BinaryPathName "`"$Bin\derm-sysmon.exe`" service" -StartupType Automatic -DisplayName 'derm Sysmon reader' | Out-Null
& sc.exe config $Name obj= $Account
if ($LASTEXITCODE -ne 0) { throw "sc.exe config obj= failed ($LASTEXITCODE)" }
& sc.exe description $Name 'Reads the Sysmon channel and hands each user''s events to that user''s derm daemon.' | Out-Null

# 3. Signed-in users (AU) may query its status (LC) and read it, as
#    interactive users may by default; SYSTEM and administrators as before.
& sc.exe sdset $Name 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;AU)'
if ($LASTEXITCODE -ne 0) { throw "sc.exe sdset failed ($LASTEXITCODE)" }

# 4. Event Log Readers.
& net.exe localgroup $Readers $Account /add
if ($LASTEXITCODE -ne 0) { throw "net localgroup failed ($LASTEXITCODE)" }

# 5. The service's folder. A folder already there that an administrator does
#    not own may have been made by someone else first: refused.
if (Test-Path -LiteralPath $Data) {
    $owner = (Get-Acl -LiteralPath $Data).Owner
    if ($owner -notin @('BUILTIN\Administrators', 'NT AUTHORITY\SYSTEM')) {
        throw "$Data exists and is owned by $owner; remove it first"
    }
} else {
    New-Item -ItemType Directory -Path $Data | Out-Null
}
& icacls.exe $Data /setowner '*S-1-5-32-544' | Out-Null
& icacls.exe $Data /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' "${Account}:(OI)(CI)M" '*S-1-5-11:(OI)(CI)RX' | Out-Null
if ($LASTEXITCODE -ne 0) { throw "icacls failed ($LASTEXITCODE)" }
# UTF-8 with no byte order mark (Windows PowerShell 5.1 has no utf8NoBOM).
[IO.File]::WriteAllText((Join-Path $Data 'config.json'), $config)

# 6. Start.
& sc.exe start $Name
if ($LASTEXITCODE -ne 0) {
    $why = Join-Path $Data 'last-error.txt'
    if (Test-Path -LiteralPath $why) { Get-Content -LiteralPath $why }
    throw "sc.exe start failed ($LASTEXITCODE)"
}
Write-Host "derm-sysmon is installed. Start the daemon from $daemon so the service serves it."
