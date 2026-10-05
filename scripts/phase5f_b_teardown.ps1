<#
phase5f_b_teardown.ps1

Removes the LumiRuntime local user and its stored credential. Does not
touch any ACL, does not remove any file in D:\Lumi, does not affect the
human user's account.

Refuses to run without -Confirm.

The credential deletion uses the native CredDeleteW API for symmetry
with the setup script. No secret is involved in deletion.
#>

[CmdletBinding()]
param(
    [switch]$Confirm
)

$ErrorActionPreference = 'Stop'
$RuntimeName = 'LumiRuntime'

if (-not $Confirm) {
    Write-Output "Refusing without -Confirm."
    exit 2
}

# Same in-memory helper used by setup, for CredDeleteW.
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public static class LumiCredManDelete
{
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CredDeleteW(string target, uint type, uint flags);
}
"@

$u = Get-LocalUser -Name $RuntimeName -ErrorAction SilentlyContinue
if (-not $u) {
    Write-Output "LumiRuntime does not exist."
} else {
    Write-Output "Removing credential 'LumiRuntime' from Credential Manager..."
    try {
        $ok = [LumiCredManDelete]::CredDeleteW('LumiRuntime', 1, 0)
        if ($ok) {
            Write-Output "  Removed."
        } else {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Output "  WARN: CredDeleteW returned False (WinError $err)."
            Write-Output "  The credential may not have existed, or may belong to another user's vault."
        }
    } catch {
        Write-Output "  WARN: CredDeleteW threw: $_"
    }

    Write-Output "Removing local user '$RuntimeName'..."
    Remove-LocalUser -Name $RuntimeName
    Write-Output "  Removed."
}

$profile = "C:\Users\$RuntimeName"
if (Test-Path -LiteralPath $profile) {
    Write-Output "NOTE: profile directory still exists at $profile"
    Write-Output "      It can be removed manually by an Administrator if desired."
}

Write-Output "Teardown complete. No ACLs were changed; no files in D:\Lumi were affected."