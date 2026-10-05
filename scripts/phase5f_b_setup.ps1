<#
phase5f_b_setup.ps1

Creates the dedicated LumiRuntime local standard user, if it does not
already exist, and provisions its password into Windows Credential
Manager.

REQUIRES EXPLICIT HUMAN APPROVAL.

Lifecycle (fail-closed):

  1. Refuse to proceed without -Confirm.
  2. Refuse to proceed if LumiRuntime already exists.
  3. Generate a random password in memory.
  4. Create LumiRuntime as a standard local user.
  5. Verify that LumiRuntime is NOT a member of Administrators.
  6. Store the password in Credential Manager via native CredWriteW
     (P/Invoke, in-memory). No command-line argument carries the
     password.
  7. If credential storage fails: remove the LumiRuntime account that
     THIS invocation created, report the rollback, and exit non-zero.
     No fallback storage is attempted.

"Setup complete" is printed ONLY after account creation, standard-user
verification, and credential storage all succeed.

It does NOT modify any ACL, does NOT change any existing user other
than LumiRuntime, does NOT create a service, does NOT create a
scheduled task, does NOT modify UAC.

PowerShell compatibility: this script must run under Windows PowerShell
5.1. It uses only 5.1-compatible syntax (no ternary, no null-coalescing,
no pipeline chain operators). If you port this script to PowerShell 7+,
the same syntax remains valid.

NetUser description limit: New-LocalUser -Description is capped at 48
characters by the underlying NetUserAdd API. The description used below
is 39 characters and fits.
#>

[CmdletBinding()]
param(
    [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'

# ------------------------------------------------------------------ preflight

if (-not $Confirm) {
    Write-Output "Refusing to run without -Confirm."
    Write-Output "This operation creates a Windows local user account."
    Write-Output "Re-run with:  .\phase5f_b_setup.ps1 -Confirm"
    exit 2
}

$existing = Get-LocalUser -Name $RuntimeName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Output "LumiRuntime already exists. No changes made."
    Write-Output "  SID:     $($existing.SID.Value)"
    Write-Output "  Enabled: $($existing.Enabled)"
    exit 0
}

# ------------------------------------------------------------------ helpers

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class LumiCredMan
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredWriteW(ref CREDENTIAL cred, uint flags);

    public static void Write(string target, string username, string password)
    {
        byte[] bytes = System.Text.Encoding.Unicode.GetBytes(password);
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        try
        {
            Marshal.Copy(bytes, 0, ptr, bytes.Length);

            CREDENTIAL c = new CREDENTIAL();
            c.Type = 1;
            c.TargetName = target;
            c.UserName = username;
            c.Comment = "";
            c.CredentialBlob = ptr;
            c.CredentialBlobSize = (uint)bytes.Length;
            c.Persist = 2;

            bool ok = CredWriteW(ref c, 0);
            if (!ok)
            {
                int err = Marshal.GetLastWin32Error();
                throw new System.ComponentModel.Win32Exception(err);
            }
        }
        finally
        {
            byte[] zeros = new byte[bytes.Length];
            Marshal.Copy(zeros, 0, ptr, zeros.Length);
            Marshal.FreeHGlobal(ptr);
            Array.Clear(bytes, 0, bytes.Length);
        }
    }
}
"@

function Remove-LumiRuntimeAccount {
    param([string]$Reason)
    Write-Output ""
    Write-Output "ROLLBACK: $Reason"
    Write-Output "Removing local user '$RuntimeName' (created by this invocation)..."
    try {
        Remove-LocalUser -Name $RuntimeName -ErrorAction Stop
        Write-Output "  Account removed."
    } catch {
        Write-Output "  FAILED to remove account: $_"
        Write-Output "  Manual cleanup required:"
        Write-Output "    Remove-LocalUser -Name $RuntimeName"
        return $false
    }
    return $true
}

# ------------------------------------------------------------------ 1. password

Add-Type -AssemblyName System.Web
$pwPlain = [System.Web.Security.Membership]::GeneratePassword(32, 12)
$secure  = ConvertTo-SecureString $pwPlain -AsPlainText -Force

# ------------------------------------------------------------------ 2. create

Write-Output "Creating standard local user '$RuntimeName'..."
try {
    $user = New-LocalUser -Name $RuntimeName `
        -Password $secure `
        -Description 'Low-privilege runtime identity for Lumi' `
        -PasswordNeverExpires `
        -AccountNeverExpires
} catch {
    Write-Output "FATAL: New-LocalUser failed: $_"
    $pwPlain = $null
    $secure = $null
    exit 1
}

Write-Output "  Created. SID: $($user.SID.Value)"
$sid = $user.SID.Value

# ------------------------------------------------------------------ 3. verify standard user

Write-Output "Verifying standard-user state..."
$adminCheckOk = $true
try {
    $admins = Get-LocalGroupMember -Group 'Administrators'
    $match = $admins | Where-Object {
        $_.Name -ieq "$env:COMPUTERNAME\$RuntimeName" -or
        $_.SID.Value -eq $sid
    }
    if ($match) {
        Write-Output "  LumiRuntime appeared in Administrators. Removing."
        Remove-LocalGroupMember -Group 'Administrators' -Member $RuntimeName
        Write-Output "  Removed from Administrators."
    }
    $admins2 = Get-LocalGroupMember -Group 'Administrators'
    $match2 = $admins2 | Where-Object {
        $_.Name -ieq "$env:COMPUTERNAME\$RuntimeName" -or
        $_.SID.Value -eq $sid
    }
    if ($match2) {
        Write-Output "  FAIL: still a member after removal attempt."
        $adminCheckOk = $false
    } else {
        Write-Output "  Verified: NOT in Administrators."
    }
} catch {
    Write-Output "  FAIL: admin verification raised: $_"
    $adminCheckOk = $false
}

if (-not $adminCheckOk) {
    $null = Remove-LumiRuntimeAccount -Reason "administrator-membership verification failed"
    $pwPlain = $null
    $secure = $null
    exit 1
}

# ------------------------------------------------------------------ 4. store credential

Write-Output "Storing password in Credential Manager (native CredWriteW)..."
$target = 'LumiRuntime'
$userForCred = "$env:COMPUTERNAME\$RuntimeName"
$credentialStored = $false

try {
    [LumiCredMan]::Write($target, $userForCred, $pwPlain) | Out-Null
    $credentialStored = $true
    Write-Output "  Stored under target '$target'."
} catch {
    Write-Output "  FAIL: CredWriteW raised: $_"
}

$pwPlain = $null
$secure  = $null

# ------------------------------------------------------------------ 5. fail-closed rollback

if (-not $credentialStored) {
    $removed = Remove-LumiRuntimeAccount -Reason "credential provisioning failed; no fallback attempted"
    Write-Output ""
    Write-Output "PROVISIONING ROLLED BACK"
    if ($removed) {
        Write-Output "  Account created by this invocation: removed"
    } else {
        Write-Output "  Account created by this invocation: NOT removed (manual cleanup required)"
    }
    Write-Output "  Credential stored:                  NO"
    Write-Output "  Provisioning complete:              NO"
    Write-Output ""
    Write-Output "No fallback storage was attempted. Fix the CredWriteW failure and re-run."
    exit 1
}

# ------------------------------------------------------------------ 6. success

Write-Output ""
Write-Output "Setup complete."
Write-Output "  Account created:                    YES"
Write-Output "  SID:                                $sid"
Write-Output "  Enabled:                            $($user.Enabled)"
Write-Output "  Administrator membership verified:  YES (not a member)"
Write-Output "  Credential stored (target '$target'): YES"
Write-Output "  Provisioning complete:              YES"
Write-Output ""
Write-Output "Next: run scripts/phase5f_b_verify.ps1 to confirm."
exit 0