# derm-sysmon: the undo of install.ps1 (wave 5b lane 5bE). Elevated
# PowerShell. Prints each step and asks, unless -Yes. Leaves Sysmon alone.

param([switch]$Yes, [switch]$KeepPrograms)

$ErrorActionPreference = 'Continue'
$Name = 'derm-sysmon'
$Account = "NT SERVICE\$Name"
$Bin = Join-Path $env:ProgramFiles 'derm'
$Data = Join-Path $env:ProgramData $Name

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { throw 'Run this from an elevated PowerShell (as administrator).' }
$Readers = (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-573')).Translate(
    [Security.Principal.NTAccount]).Value.Split('\')[-1]

Write-Host 'This will:'
Write-Host "  sc.exe stop $Name; sc.exe delete $Name"
Write-Host "  net localgroup `"$Readers`" `"$Account`" /delete"
Write-Host "  remove $Data"
if (-not $KeepPrograms) { Write-Host "  remove derm-sysmon.exe and derm-daemon.exe from $Bin" }
if (-not $Yes) {
    $answer = Read-Host 'Go ahead? (y/N)'
    if ($answer -ne 'y') { Write-Host 'Nothing changed.'; exit 1 }
}

& sc.exe stop $Name | Out-Null
Start-Sleep -Seconds 2
& net.exe localgroup $Readers $Account /delete
& sc.exe delete $Name
if (Test-Path -LiteralPath $Data) { Remove-Item -LiteralPath $Data -Recurse -Force }
if (-not $KeepPrograms) {
    foreach ($exe in 'derm-sysmon.exe', 'derm-daemon.exe') {
        $p = Join-Path $Bin $exe
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force }
    }
}
Write-Host 'derm-sysmon is removed.'
