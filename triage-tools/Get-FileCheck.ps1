<#
.SYNOPSIS
    Quick triage of a single file: returns its path, SHA256 hash and digital signature status.

.DESCRIPTION
    Get-FileCheck takes a file path and runs two read-only checks:
      1. Get-FileHash              - SHA256 fingerprint, ready to look up in threat intel (e.g. VirusTotal)
      2. Get-AuthenticodeSignature - is the file signed, and is the signature valid?
    The results are returned as one object, so they can be piped to Where-Object,
    Sort-Object or Export-Csv.

    Read-only: the script does not change, move or run the file.

.PARAMETER Path
    Full path to the file to check.

.EXAMPLE
    Get-FileCheck -Path 'C:\Windows\System32\notepad.exe'

.EXAMPLE
    Get-ChildItem "$env:LOCALAPPDATA\Temp" -Recurse -Filter *.exe -ErrorAction SilentlyContinue |
        ForEach-Object { Get-FileCheck -Path $_.FullName } |
        Where-Object Signature -ne 'Valid'

    Checks every .exe under the user's Temp folder and shows only files without a valid signature.

.NOTES
    Author : Sandra
    Tested on Windows PowerShell 5.1 (Windows 11).
#>
function Get-FileCheck {
    param($Path)

    # Step 1: SHA256 fingerprint of the file
    $hash = Get-FileHash $Path

    # Step 2: digital signature check (Valid, NotSigned, HashMismatch, ...)
    $sig  = Get-AuthenticodeSignature $Path

    # Step 3: return one row with the results
    [PSCustomObject]@{
        File      = $Path
        Hash      = $hash.Hash
        Signature = $sig.Status
    }
}
