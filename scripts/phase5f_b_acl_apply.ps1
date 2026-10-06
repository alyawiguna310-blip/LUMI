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
$ProjectRoot = 'D:Lumi'

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
    $_.Name -ieq "$env:COMPUTERNAME$RuntimeName" -or
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
    (Join-Path $ProjectRoot 'core	ool_router.py'),
    (Join-Path $ProjectRoot 'toolsadmin_tasks.py'),
    (Join-Path $ProjectRoot 'tools	erminal_guard.py'),
    (Join-Path $ProjectRoot 'storageaudit.py')
)

# Do not use the generic "W" right here. FILE_GENERIC_WRITE contains
# READ_CONTROL and SYNCHRONIZE, which would unintentionally prevent the
# runtime from opening protected files for read access. Deny only the
# mutation rights required by the control-plane policy.
$denyFileRights = 'WD,AD,WEA,WA,D,WDAC,WO'
$denyDirectoryRights = 'WD,AD,WEA,WA,DC,DD,D,WDAC,WO'

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

    Write-Output "Checking for pre-existing LumiRuntime deny ACEs..."

    foreach ($p in $protectedDirs + $protectedFiles) {
        $aclText = (& $icacls.Source $p 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) {
            throw "could not inspect ACL before applying: $p"
        }
        if ($aclText -match [regex]::Escape($sid) -and $aclText -match 'DENY') {
            throw "pre-existing LumiRuntime deny ACE found on $p; refusing to modify existing deny state"
        }
    }

    Write-Output "Applying LumiRuntime control-plane deny ACEs..."
    Write-Output "SID: $sid"
    Write-Output "File deny rights: $denyFileRights"
    Write-Output "Directory deny rights: $denyDirectoryRights"

    foreach ($p in $protectedDirs) {
        Invoke-Icacls -Arguments @(
            $p, '/deny', ("*" + $sid + ":(" + $denyDirectoryRights + ")")
        )
    }

    foreach ($p in $protectedFiles) {
        if (Test-Path -LiteralPath $p) {
            Invoke-Icacls -Arguments @(
                $p, '/deny', ("*" + $sid + ":(" + $denyFileRights + ")")
            )
        }
    }

    Write-Output ""
    Write-Output "ACL enforcement commands completed."
    Write-Output "Run the read-only verifier next:"
    Write-Output "  .phase5f_b_verify.ps1"
    Write-Output "Rollback command (explicit):"
    Write-Output "  .phase5f_b_acl_apply.ps1 -Confirm -Rollback"
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
