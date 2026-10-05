<#
phase5f_b_inspect.ps1

READ-ONLY inspection of the intended LumiRuntime account and the
filesystem compatibility of D:\Lumi for a future runtime identity.

This script makes no changes. It only queries local account state and
filesystem access using read-only APIs.

Run from an elevated PowerShell session (to read local account state
comprehensively). Running non-elevated is fine; some queries may return
less detail.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'

Write-Output "=== LumiRuntime inspection (read-only) ==="
Write-Output "Machine: $env:COMPUTERNAME"
Write-Output "Current user: $(whoami)"
Write-Output "Current user SID: $((whoami /user /fo csv /nh) -split ',' | Select-Object -Last 1)"
Write-Output ""

# --- 1. Account existence, SID, enabled state -------------------------------

Write-Output "--- Account state ---"
$acct = $null
try {
    $acct = Get-LocalUser -Name $RuntimeName -ErrorAction SilentlyContinue
} catch {
    Write-Output "Get-LocalUser failed: $_"
}

if (-not $acct) {
    Write-Output "LumiRuntime: DOES NOT EXIST"
} else {
    Write-Output "LumiRuntime: EXISTS"
    Write-Output "  SID:        $($acct.SID.Value)"
    Write-Output "  Enabled:    $($acct.Enabled)"
    Write-Output "  Description:$($acct.Description)"
    Write-Output "  LastLogon:  $($acct.LastLogon)"
    Write-Output "  PasswordLastSet: $($acct.PasswordLastSet)"
}

Write-Output ""

# --- 2. Administrator group membership --------------------------------------

Write-Output "--- Administrator group membership ---"
$admins = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
if ($admins) {
    $admins | ForEach-Object {
        Write-Output "  $($_.Name) [$($_.ObjectClass)]"
    }
    $match = $admins | Where-Object {
        $_.Name -ieq "$env:COMPUTERNAME\$RuntimeName" -or
        ($acct -and $_.SID -and $_.SID.Value -eq $acct.SID.Value)
    }
    if ($match) {
        Write-Output "  >>> WARNING: LumiRuntime is a member of Administrators"
    } else {
        Write-Output "  LumiRuntime is NOT a member of Administrators"
    }
} else {
    Write-Output "  (could not enumerate Administrators group)"
}
Write-Output ""

# --- 3. Groups LumiRuntime belongs to ---------------------------------------

if ($acct) {
    Write-Output "--- LumiRuntime group memberships ---"
    try {
        $groups = Get-LocalGroup | Where-Object {
            $m = Get-LocalGroupMember -Group $_.Name -ErrorAction SilentlyContinue
            $m -and ($m | Where-Object { $_.SID.Value -eq $acct.SID.Value })
        }
        $groups | ForEach-Object { Write-Output "  $($_.Name)" }
    } catch {
        Write-Output "  (could not enumerate groups: $_)"
    }
    Write-Output ""
}

# --- 4. Filesystem paths of interest ----------------------------------------
# NOTE: The actual venv path is D:\Lumi\.venv (with a leading dot).

Write-Output "--- Filesystem paths of interest ---"
$paths = @(
    'D:\Lumi',
    'D:\Lumi\workspace',
    'D:\Lumi\.venv',
    'D:\Lumi\security',
    'D:\Lumi\tools',
    'D:\Lumi\storage',
    'D:\Lumi\core',
    'D:\Lumi\models',
    'D:\Lumi\config.py',
    'D:\Lumi\.env',
    'D:\Lumi\main.py'
)
foreach ($p in $paths) {
    if (Test-Path -LiteralPath $p) {
        $item = Get-Item -LiteralPath $p -Force
        Write-Output "  EXISTS  $p  ($(if ($item.PSIsContainer) {'dir'} else {'file'}))"
    } else {
        Write-Output "  MISSING $p"
    }
}
Write-Output ""

# --- 5. Python interpreter for the venv -------------------------------------

Write-Output "--- venv interpreter ---"
$venvPython = 'D:\Lumi\.venv\Scripts\python.exe'
if (Test-Path -LiteralPath $venvPython) {
    Write-Output "  venv python: EXISTS at $venvPython"
    try {
        $ver = & $venvPython --version 2>&1
        Write-Output "  reports:     $ver"
    } catch {
        Write-Output "  reports:     (failed to run: $_)"
    }
} else {
    Write-Output "  venv python: MISSING at $venvPython"
}
Write-Output ""

# --- 6. ADB presence ---------------------------------------------------------

Write-Output "--- ADB ---"
$adb = Get-Command adb -ErrorAction SilentlyContinue
if ($adb) {
    Write-Output "  adb path: $($adb.Source)"
} else {
    Write-Output "  adb: not on PATH"
}
if (Test-Path -LiteralPath 'D:\Lumi\platform-tools\adb.exe') {
    Write-Output "  adb bundled: D:\Lumi\platform-tools\adb.exe"
}
Write-Output ""

# --- 7. Profile presence -----------------------------------------------------

Write-Output "--- Runtime profile ---"
if ($acct) {
    $profilePath = "C:\Users\$RuntimeName"
    if (Test-Path -LiteralPath $profilePath) {
        Write-Output "  profile EXISTS at $profilePath"
    } else {
        Write-Output "  profile NOT YET CREATED (created on first logon / CreateProcessWithLogonW with LOGON_WITH_PROFILE)"
    }
}
Write-Output ""

# --- 8. ACL state of protected paths (read-only) ----------------------------

Write-Output "--- ACL of D:\Lumi\security (read-only) ---"
if (Test-Path -LiteralPath 'D:\Lumi\security') {
    $acl = Get-Acl -LiteralPath 'D:\Lumi\security'
    Write-Output "  Owner: $($acl.Owner)"
    $acl.Access | ForEach-Object {
        Write-Output "  $($_.AccessControlType) $($_.IdentityReference) : $($_.FileSystemRights) (inherited=$($_.IsInherited))"
    }
}
Write-Output ""

Write-Output "=== Inspection complete. No changes made. ==="