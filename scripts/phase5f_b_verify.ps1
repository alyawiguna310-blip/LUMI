<#
phase5f_b_verify.ps1

Verifies the state of LumiRuntime after setup. Read-only.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'

Write-Output "=== LumiRuntime verification ==="

$u = Get-LocalUser -Name $RuntimeName -ErrorAction SilentlyContinue
if (-not $u) {
    Write-Output "FAIL: LumiRuntime does not exist."
    exit 1
}

Write-Output "PASS: exists"
Write-Output "  SID:     $($u.SID.Value)"
Write-Output "  Enabled: $($u.Enabled)"

$admins = Get-LocalGroupMember -Group 'Administrators'
$isAdmin = $admins | Where-Object {
    $_.Name -ieq "$env:COMPUTERNAME\$RuntimeName" -or
    $_.SID.Value -eq $u.SID.Value
}
if ($isAdmin) {
    Write-Output "FAIL: LumiRuntime IS in Administrators."
    exit 1
}
Write-Output "PASS: not in Administrators"

# Confirm the credential is retrievable under the human's vault.
$cmdkeyOut = & cmdkey.exe /list 2>&1 | Out-String
if ($cmdkeyOut -match "LumiRuntime") {
    Write-Output "PASS: credential 'LumiRuntime' present in Credential Manager"
} else {
    Write-Output "WARN: credential 'LumiRuntime' not found via cmdkey /list"
}

Write-Output "=== verification complete ==="