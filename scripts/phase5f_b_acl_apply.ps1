<#
phase5f_b_acl_apply.ps1

Explicit Windows-side enforcement for the LumiRuntime control-plane ACL.

Requires -Confirm. Requires an existing non-administrator LumiRuntime account.
Changes only the discovered control-plane paths. The deny ACE blocks
write/delete/ACL-owner changes while preserving read access.

The ACL is applied with .NET FileSystemAccessRule instead of icacls symbolic
rights because icacls can canonicalize a broad write mask in a way that
causes AccessCheck/normal read opens to fail. The exact rights below contain
only mutation/security-control rights and intentionally exclude
ReadControl/Synchronize.
#>

[CmdletBinding()]
param(
    [switch]$Confirm,
    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'
$ProjectRoot = 'D:/Lumi'

if (-not $Confirm) {
    Write-Output "Refusing without -Confirm."
    Write-Output "No ACL changes were made."
    exit 2
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
$identity = New-Object System.Security.Principal.SecurityIdentifier($sid)

$protectedDirs = @(
    (Join-Path $ProjectRoot 'security')
)
$protectedFiles = @(
    (Join-Path $ProjectRoot 'main.py'),
    (Join-Path $ProjectRoot 'config.py'),
    (Join-Path $ProjectRoot '.env'),
    (Join-Path $ProjectRoot 'core/tool_router.py'),
    (Join-Path $ProjectRoot 'tools/admin_tasks.py'),
    (Join-Path $ProjectRoot 'tools/terminal_guard.py'),
    (Join-Path $ProjectRoot 'storage/audit.py')
)

# Exact mutation/security rights. Do not use GenericWrite or other broad
# masks: they can include standard rights such as ReadControl/Synchronize.
$denyFileRights =
    [System.Security.AccessControl.FileSystemRights]::WriteData -bor
    [System.Security.AccessControl.FileSystemRights]::AppendData -bor
    [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
    [System.Security.AccessControl.FileSystemRights]::Delete -bor
    [System.Security.AccessControl.FileSystemRights]::WritePermissions -bor
    [System.Security.AccessControl.FileSystemRights]::TakeOwnership

$denyDirectoryRights =
    $denyFileRights -bor
    [System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles

function Verify-Path {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        throw "protected path does not exist: $Path"
    }
}

function Get-LumiRuntimeDenyRules {
    param([System.Security.AccessControl.FileSystemSecurity]$Acl)

    @($Acl.Access | Where-Object {
        $_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny -and
        $_.IdentityReference.Value -ieq "$env:COMPUTERNAME\$RuntimeName"
    })
}

function Remove-LumiRuntimeDeny {
    param([string]$Path)

    $acl = Get-Acl -LiteralPath $Path
    $rules = @(Get-LumiRuntimeDenyRules $acl)

    foreach ($rule in $rules) {
        [void]$acl.RemoveAccessRuleSpecific($rule)
    }

    if ($rules.Count -gt 0) {
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
}

function Add-LumiRuntimeDeny {
    param(
        [string]$Path,
        [bool]$IsDirectory
    )

    $acl = Get-Acl -LiteralPath $Path

    if (@(Get-LumiRuntimeDenyRules $acl).Count -gt 0) {
        throw "pre-existing LumiRuntime deny ACE found on $Path; refusing to modify existing deny state"
    }

    if ($IsDirectory) {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            $denyDirectoryRights,
            ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
    }
    else {
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $identity,
            $denyFileRights,
            [System.Security.AccessControl.AccessControlType]::Deny
        )
    }

    [void]$acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}

try {
    foreach ($p in $protectedDirs + $protectedFiles) {
        Verify-Path $p
    }

    if ($Rollback) {
        Write-Output "Removing LumiRuntime deny ACEs..."
        foreach ($p in $protectedDirs + $protectedFiles) {
            Remove-LumiRuntimeDeny $p
        }
        Write-Output "Rollback complete."
        exit 0
    }

    Write-Output "Checking for pre-existing LumiRuntime deny ACEs..."
    foreach ($p in $protectedDirs + $protectedFiles) {
        $acl = Get-Acl -LiteralPath $p
        if (@(Get-LumiRuntimeDenyRules $acl).Count -gt 0) {
            throw "pre-existing LumiRuntime deny ACE found on $p; refusing to modify existing deny state"
        }
    }

    Write-Output "Applying LumiRuntime control-plane deny ACEs..."
    Write-Output "SID: $sid"
    Write-Output "Exact file deny rights: $denyFileRights"
    Write-Output "Exact directory deny rights: $denyDirectoryRights"

    foreach ($p in $protectedDirs) {
        Add-LumiRuntimeDeny -Path $p -IsDirectory $true
    }

    foreach ($p in $protectedFiles) {
        Add-LumiRuntimeDeny -Path $p -IsDirectory $false
    }

    Write-Output ""
    Write-Output "ACL enforcement commands completed."
    Write-Output "Run the read-only verifier next:"
    Write-Output "  ./phase5f_b_verify.ps1"
    exit 0
}
catch {
    Write-Output "FAIL: $($_.Exception.Message)"
    Write-Output "Attempting best-effort rollback of LumiRuntime deny ACEs..."
    foreach ($p in $protectedDirs + $protectedFiles) {
        try {
            if (Test-Path -LiteralPath $p) {
                Remove-LumiRuntimeDeny $p
            }
        } catch {
            Write-Output "ROLLBACK WARNING: could not clean deny ACE from $p"
        }
    }
    exit 1
}
