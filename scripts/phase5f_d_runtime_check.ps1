<#
phase5f_d_runtime_check.ps1

Read-only preflight for the dedicated LumiRuntime Python runtime.
Does not modify accounts, ACLs, the existing .venv, or project files.

Required production runtime:
  C:\Program Files\Python312\python.exe

The runtime must live outside D:\Lumi so LumiRuntime cannot modify the
interpreter through the project's inherited write permissions.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'
$RuntimeRoot = 'C:\Program Files\LumiRuntime'
$RuntimePython = Join-Path $RuntimeRoot 'Python312\python.exe'

Write-Output "=== LumiRuntime production-runtime preflight ==="

$user = Get-LocalUser -Name $RuntimeName -ErrorAction SilentlyContinue
if (-not $user) {
    Write-Output "FAIL: LumiRuntime does not exist."
    exit 1
}

$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction Stop
$isAdmin = $admins | Where-Object {
    $_.Name -ieq "$env:COMPUTERNAME\$RuntimeName" -or
    $_.SID.Value -eq $user.SID.Value
}
if ($isAdmin) {
    Write-Output "FAIL: LumiRuntime is in Administrators."
    exit 1
}
Write-Output "PASS: LumiRuntime exists and is not an Administrator."

if (-not (Test-Path -LiteralPath $RuntimePython -PathType Leaf)) {
    Write-Output "FAIL: dedicated Python runtime is missing:"
    Write-Output "  $RuntimePython"
    Write-Output ""
    Write-Output "Use the existing machine-wide Python 3.12 installation at this exact path before continuing."
    exit 1
}
Write-Output "PASS: dedicated Python runtime exists."

$acl = (& icacls.exe $RuntimePython 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0) {
    Write-Output "FAIL: could not inspect runtime ACL."
    exit 1
}

$identity = "$env:COMPUTERNAME\$RuntimeName"
if ($acl -match [regex]::Escape($identity) -and
    $acl -match '\(R,\s*X\)|\(RX\)|\(GR,GE\)') {
    Write-Output "PASS: LumiRuntime has read/execute access on the interpreter."
} else {
    Write-Output "WARN: no explicit LumiRuntime RX ACE found."
    Write-Output "      This is acceptable only if inherited policy grants RX and denies write."
}

if ($acl -match [regex]::Escape($identity) -and
    $acl -match '\(M\)|\(F\)|\(W,') {
    Write-Output "FAIL: LumiRuntime appears to have write/full access to the interpreter."
    exit 1
}

Write-Output ""
Write-Output "=== preflight complete: PASS ==="
exit 0
