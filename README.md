# detection_engineering
Practice notes and examples for building, mapping and tuning detections, alongside my day-to-day security engineering work.

## What's here
- Detection ideas written up per behavior: what to look for, required log sources, logic, and likely false positives
- MITRE ATT&CK mapping for each detection
- PowerShell and Python tools for endpoint triage and investigation

## Contents

### Detections
- [Encoded PowerShell](detections/encoded-powershell.md)
- [Suspicious scheduled task](detections/suspicious-scheduled-task.md)
- [Suspicious sign-in (Entra ID)](detections/suspicious-signin-entra.md)

### PowerShell tools
- [Get-FileCheck](powershell/Get-FileCheck.ps1): returns a file's SHA256 hash and signature status for quick triage

## Approach
1. Start from an attacker behavior or technique
2. Identify the logs that would show it
3. Write the detection logic
4. Think through false positives and tuning
5. Map to ATT&CK and note coverage gaps

More examples will be added over time.
