<#
phase5f_b_verify.ps1

Verifies the LumiRuntime account and the actual Windows ACL boundary.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'
$ProjectRoot = 'D:\Lumi'
$icacls = Get-Command icacls.exe -ErrorAction SilentlyContinue

Write-Output "=== LumiRuntime + control-plane ACL verification ==="

$u = Get-LocalUser -Name $RuntimeName -ErrorAction SilentlyContinue
if (-not $u) { Write-Output "FAIL: LumiRuntime does not exist."; exit 1 }

$sid = $u.SID.Value
Write-Output "PASS: exists"
Write-Output "  SID:     $sid"
Write-Output "  Enabled: $($u.Enabled)"

$admins = Get-LocalGroupMember -Group 'Administrators'
$isAdmin = $admins | Where-Object {
    $_.Name -ieq "$env:COMPUTERNAME\\$RuntimeName" -or $_.SID.Value -eq $sid
}
if ($isAdmin) { Write-Output "FAIL: LumiRuntime IS in Administrators."; exit 1 }
Write-Output "PASS: not in Administrators"

if (-not $icacls) { Write-Output "FAIL: icacls.exe was not found."; exit 1 }

$protectedDirs = @(Join-Path $ProjectRoot 'security')
$protectedFiles = @(
    (Join-Path $ProjectRoot 'main.py'),
    (Join-Path $ProjectRoot 'config.py'),
    (Join-Path $ProjectRoot '.env'),
    (Join-Path $ProjectRoot 'core\\tool_router.py'),
    (Join-Path $ProjectRoot 'tools\\admin_tasks.py'),
    (Join-Path $ProjectRoot 'tools\\terminal_guard.py'),
    (Join-Path $ProjectRoot 'storage\\audit.py')
)

Write-Output ""
Write-Output "Checking expected deny ACEs..."

# The ACL apply step creates explicit .NET FileSystemAccessRule entries with
# specific mutation/security rights only. icacls displays those rights using
# the following abbreviations and may reorder them during canonicalization:
#   files:      (DENY)(DE,WO,WD,AD,WEA,WA)
#   directories:(OI)(CI)(DENY)(DE,WO,WD,AD,WEA,DC,WA)
# The semantic protection is verified by the runtime probe below.
function Test-DenyAce {
    param([string]$AclText, [bool]$Directory)

    $identity = [regex]::Escape("$env:COMPUTERNAME\$RuntimeName")
    if ($AclText -notmatch 'DENY' -or $AclText -notmatch $identity) { return $false }

    if ($Directory) {
        return $AclText -match '\(OI\)\(CI\)\(DENY\)\(DE,WO,WD,AD,WEA,DC,WA\)'
    }

    return $AclText -match '\(DENY\)\(DE,WO,WD,AD,WEA,WA\)'
}

foreach ($p in $protectedDirs + $protectedFiles) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Output "FAIL: protected path missing: $p"; exit 1
    }

    $aclText = (& $icacls.Source $p 2>&1 | Out-String)
    if ($LASTEXITCODE -ne 0) {
        Write-Output "FAIL: could not inspect ACL: $p"; exit 1
    }

    if (-not (Test-DenyAce -AclText $aclText -Directory ($p -eq $protectedDirs[0]))) {
        Write-Output "FAIL: expected LumiRuntime deny ACE not found on: $p"
        exit 1
    }
    Write-Output "PASS: deny ACE present: $p"
}

$repoRoot = $ProjectRoot
$runtimePython = 'C:\\Program Files\\Python312\\python.exe'
$launcher = Join-Path $repoRoot 'scripts\\launch_lumi_as_runtime.py'
$probeResult = Join-Path $repoRoot 'workspace\\phase5fb_acl_result.json'

if (-not (Test-Path -LiteralPath $runtimePython)) {
    Write-Output "FAIL: dedicated LumiRuntime Python missing: $runtimePython"; exit 1
}
if (-not (Test-Path -LiteralPath $launcher)) {
    Write-Output "FAIL: runtime launcher missing: $launcher"; exit 1
}

Remove-Item -LiteralPath $probeResult -Force -ErrorAction SilentlyContinue

Write-Output ""
Write-Output "Running fixed LumiRuntime ACL probe..."
& $runtimePython -c "import sys; sys.path.insert(0, r'$repoRoot\\scripts'); import launch_lumi_as_runtime as launcher; result = launcher.launch_acl_probe(); raise SystemExit(1 if (not result.create_ok or result.timed_out or result.exit_code != 0) else 0)"
if ($LASTEXITCODE -ne 0) {
    Write-Output "FAIL: LumiRuntime ACL probe failed."; exit 1
}

if (-not (Test-Path -LiteralPath $probeResult)) {
    Write-Output "FAIL: ACL probe did not produce a result file."; exit 1
}

try { $probe = Get-Content -LiteralPath $probeResult -Raw | ConvertFrom-Json }
catch { Write-Output "FAIL: ACL probe result is not valid JSON."; exit 1 }

if (-not $probe.passed) {
    Write-Output "FAIL: effective LumiRuntime ACL checks did not pass."
    $probe.checks | ConvertTo-Json -Depth 4 | Write-Output
    exit 1
}

$expectedChecks = @(
    'security_directory_create',
    'main_py_write_open','config_py_write_open','env_write_open',
    'tool_router_write_open','admin_tasks_write_open','terminal_guard_write_open',
    'audit_write_open','main_py_read','env_read',
    'security_directory_read','workspace_write'
)

foreach ($name in $expectedChecks) {
    if (-not $probe.checks.$name.passed) {
        Write-Output "FAIL: expected ACL probe check did not pass: $name"; exit 1
    }
    Write-Output "PASS: effective check: $name"
}

if ($probe.username -ne $RuntimeName) {
    Write-Output "FAIL: ACL probe ran as unexpected user: $($probe.username)"; exit 1
}

Remove-Item -LiteralPath $probeResult -Force -ErrorAction SilentlyContinue

Write-Output ""
Write-Output "=== verification complete: PASS ==="
