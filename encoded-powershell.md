# Suspicious Encoded PowerShell Execution

**ATT&CK:** T1059.001, Command and Scripting Interpreter: PowerShell; T1027, Obfuscated Files or Information

## Why it matters
PowerShell is built into Windows, so attackers use it to run payloads, download tools and move around without dropping obvious files. Encoding or hiding the command is a common way to avoid simple string-based detections. But admins also use PowerShell heavily, so the behavior has to be separated from normal use.

## Logs needed
- Process creation events (Security Event ID 4688 with command-line auditing enabled, Sysmon Event ID 1, or EDR telemetry)
- PowerShell Script Block Logging, Event ID 4104 (shows the decoded script)
- PowerShell Module Logging, Event ID 4103 (optional, adds detail)
- Parent process information for every `powershell.exe` launch

## What to look for
- `-EncodedCommand`, `-enc` or `-e` followed by a long Base64 string
- Flags that hide or relax the session: `-WindowStyle Hidden`, `-NoProfile`, `-ExecutionPolicy Bypass`
- Download-and-run patterns: `Invoke-Expression` or `IEX` with `DownloadString`, `Invoke-WebRequest`, or `Net.WebClient`
- `FromBase64String` or compression used inside a script block
- Unusual parent processes: Office apps, browsers, `wscript`, `mshta`, or a service that doesn't normally launch PowerShell
- PowerShell started by a user or on a host that doesn't normally use it

## Detection logic (pseudo-query)
```
event = process_creation
  where image ends with "powershell.exe"
  and (
    command_line contains any ["-enc", "-encodedcommand"]
    or command_line contains "-windowstyle hidden"
    or command_line contains any ["downloadstring", "invoke-expression", "iex ", "frombase64string"]
  )
  and not parent_process in (approved_management_tools)
```
Then decode the Base64 string and review the Script Block Log (4104) to see what actually ran.

## False positives and tuning
- Software deployment and endpoint management tools, installers and admin scripts often use encoded commands or `-ExecutionPolicy Bypass`.
- Tune by allow-listing the specific parent process and script, not by ignoring all encoded PowerShell.
- Combine signals for priority: encoded command plus a download string plus an unusual parent is much higher risk than one alone.
- Make sure Script Block Logging is on, because it shows the decoded content even when the command line is obfuscated.

## Triage steps
1. Decode the command and read what it does.
2. Identify the parent process, user and host.
3. Check for network connections, files written, or child processes started by the command.
4. Search for the same command or Base64 string on other hosts.
5. If malicious, isolate the host and review the user's recent logins and activity.

## Coverage gaps
- PowerShell can run without `powershell.exe` (for example through other hosts or .NET), which may not match this query.
- Without command-line auditing or Script Block Logging, this detection has little to see.
