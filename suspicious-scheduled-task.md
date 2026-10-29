# Suspicious Scheduled Task Creation

**ATT&CK:** T1053.005, Scheduled Task/Job: Scheduled Task (Execution, Persistence, Privilege Escalation)

## Why it matters
Attackers use scheduled tasks to keep access after a reboot, to run malware on a timer, or to run code as a higher-privileged account. Because admins and software updaters create tasks all the time, the goal is to spot the unusual ones, not every one.

## Logs needed
- Windows Security log, Event ID 4698 (task created) and 4702 (task updated). Requires the "Other Object Access Events" audit policy.
- Windows Task Scheduler Operational log, Event ID 106 (task registered).
- Process creation events (Sysmon Event ID 1 or EDR telemetry) for `schtasks.exe` and its command line.

## What to look for
A task is more suspicious when it has one or more of these:
- Created with `schtasks.exe /create` or PowerShell from an unusual parent process (Office app, browser, script host)
- The action runs from a user-writable path: `AppData`, `Temp`, `Public`, `ProgramData`
- The action launches `powershell.exe` with encoded or hidden arguments, `wscript`, `mshta`, `rundll32`, or `cmd /c`
- Runs as SYSTEM or with highest privileges
- Created on a remote host (`/s` flag) or by a non-admin account
- Task name that imitates a legitimate one, or a random-looking name

## Detection logic (pseudo-query)
```
event = process_creation
  where image ends with "schtasks.exe"
  and command_line contains "/create"
  and (
    command_line contains any ["appdata", "\\temp\\", "\\public\\", "programdata"]
    or command_line contains any ["powershell", "wscript", "mshta", "rundll32", "-enc"]
    or command_line contains "/ru system"
  )
  and not task_name in (approved_task_list)
```

## False positives and tuning
- Software updaters (browsers, Adobe, collaboration apps) and IT management tools create tasks routinely.
- Tune by allow-listing known task names and signed publishers, not whole folders.
- Baseline which hosts normally create tasks, then raise severity for rare combinations, for example a first-seen task name on a workstation plus a script interpreter.
- Lower the priority of tasks created by known IT admin accounts during change windows.

## Triage steps
1. Identify the host, user and parent process that created the task.
2. Read the task's action, trigger and run-as account.
3. Check whether the file or script it runs exists, and review its reputation and contents.
4. Look for other activity from the same host and user around the same time.
5. If malicious, isolate the host, remove the task, and scope for similar tasks across other hosts.

## Coverage gaps
- Tasks created through COM or direct registry changes may not appear as `schtasks.exe` activity.
- Requires audit policy and process command-line logging to be enabled.
