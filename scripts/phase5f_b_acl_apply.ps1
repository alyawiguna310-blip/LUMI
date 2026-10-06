<#
phase5f_b_acl_apply.ps1

Explicit Windows-side enforcement for the LumiRuntime control-plane ACL.

Requires -Confirm. Requires an existing non-administrator LumiRuntime account.
Changes only the discovered control-plane paths. The deny ACE blocks
write/delete/ACL-owner changes while preserving read access.

Rollback removes only the explicit deny ACE for the LumiRuntime SID; it does
not reset or replace unrelated ACL entries.
#>

[CmdletBinding()]
param(
    [switch]$Confirm,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'
$ProjectRoot = 'D:\Lumi'

if (-not $Confirm) {
    Write-Output "Refusing without -Confirm."
    Write-Output "No ACL changes were made."
    exit 2
}

$icacls = Get-Command icacls.exe -ErrorAction SilentlyContinue
if (-not $icacls) {
    Write-Output "FAIL: icacls.exe was not found."
    exit 1
}

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
    Write-Output "FAIL: LumiRuntime is a member of Administrators."
    exit 1
}

$sid = $user.SID.Value
$protectedDirs = @(
    (Join-Path $ProjectRoot 'security')
)
$protectedFiles = @(
    (Join-Path $ProjectRoot 'main.py'),
    (Join-Path $ProjectRoot 'config.py'),
    (Join-Path $ProjectRoot '.env'),
    (Join-Path $ProjectRoot 'core\tool_router.py'),
    (Join-Path $ProjectRoot 'tools\admin_tasks.py'),
    (Join-Path $ProjectRoot 'tools\terminal_guard.py'),
    (Join-Path $ProjectRoot 'storage\audit.py')
)

function Invoke-Icacls {
    param([string[]]$Arguments)
    & $icacls.Source @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "icacls failed with exit code $LASTEXITCODE"
    }
}

function Verify-Path {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "protected path does not exist: $Path"
    }
}

try {
    # .env is a control-plane path even though it is intentionally untracked.
    # Create an empty placeholder as Administrator so LumiRuntime cannot later
    # create or replace the security configuration itself.
    $envPath = Join-Path $ProjectRoot '.env'
    if (-not (Test-Path -LiteralPath $envPath)) {
        New-Item -ItemType File -Path $envPath -Force | Out-Null
    }

    foreach ($p in $protectedDirs + $protectedFiles) {
        Verify-Path $p
    }

    if ($Rollback) {
        Write-Output "Removing only the LumiRuntime deny ACEs..."
        foreach ($p in $protectedDirs + $protectedFiles) {
            Invoke-Icacls -Arguments @($p, '/remove:d', ("*" + $sid))
        }
        Write-Output "Rollback complete."
        exit 0
    }

    Write-Output "Applying LumiRuntime control-plane deny ACEs..."
    Write-Output "SID: $sid"

    foreach ($p in $protectedDirs) {
        Invoke-Icacls -Arguments @(
            $p, '/deny', ("*" + $sid + ":(OI)(CI)(W,D,WDAC,WO)")
        )
    }

    foreach ($p in $protectedFiles) {
        if (Test-Path -LiteralPath $p) {
            Invoke-Icacls -Arguments @(
                $p, '/deny', ("*" + $sid + ":(W,D,WDAC,WO)")
            )
        }
    }

    Write-Output ""
    Write-Output "ACL enforcement commands completed."
    Write-Output "Run the read-only verifier next:"
    Write-Output "  .\phase5f_b_inspect.ps1"
    Write-Output "Rollback command (explicit):"
    Write-Output "  .\phase5f_b_acl_apply.ps1 -Confirm -Rollback"
    exit 0
}
catch {
    Write-Output "FAIL: $($_.Exception.Message)"
    Write-Output "Attempting best-effort rollback of LumiRuntime deny ACEs..."
    foreach ($p in $protectedDirs + $protectedFiles) {
        try {
            if (Test-Path -LiteralPath $p) {
                Invoke-Icacls -Arguments @($p, '/remove:d', ("*" + $sid)) | Out-Null
            }
        } catch {
            Write-Output "ROLLBACK WARNING: could not clean deny ACE from $p"
        }
    }
    exit 1
}
