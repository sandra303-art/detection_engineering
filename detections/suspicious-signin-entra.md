# Suspicious Sign-In and Possible Account Takeover (Entra ID)

**ATT&CK:** T1078.004, Valid Accounts: Cloud Accounts; T1110.003, Brute Force: Password Spraying; T1098.005, Account Manipulation: Device Registration (MFA method changes)

## Why it matters
Attackers often log in with stolen or guessed credentials instead of using malware. A successful login from an attacker looks like a normal login unless you check the context around it: where it came from, what happened before, and what the account did next.

## Logs needed
- Entra ID sign-in logs (interactive and non-interactive), including IP, location, app, device, client app (legacy or modern) and Conditional Access result
- Entra ID risk detections (risky sign-ins and risky users)
- Entra ID audit logs (MFA method changes, password resets, app consent)
- Mailbox audit or email logs for new inbox rules and forwarding

## What to look for
- Many failed sign-ins across many accounts from one IP or small set of IPs, followed by a success (password spray)
- A successful sign-in from a new country or an anonymizer, VPN or hosting provider IP
- Two sign-ins for the same user from distant locations in a short time (impossible travel)
- Sign-ins using legacy authentication, which bypasses MFA
- Repeated MFA prompts denied or ignored, then a success (MFA fatigue)
- A new MFA method or device registered soon after a risky sign-in
- New inbox rules, mail forwarding or OAuth app consents after the sign-in

## Detection logic (pseudo-query)
```
signins = sign_in_logs
  where result == "success"
  and (
    country not in user_usual_countries
    or ip_type in ["anonymizer", "hosting"]
    or client_app == "legacy"
  )

join on same user within 1 hour:
  failed_signins >= 10 from same ip
  or mfa_denied >= 3
  or new_mfa_method_registered
  or new_inbox_rule_created
```

## False positives and tuning
- Employees travelling, using a personal VPN, or on mobile carrier IPs often trigger location rules.
- Tune by building a per-user baseline of usual countries and devices, and by allow-listing known corporate VPN and office IPs.
- Raise priority when signals stack up, for example new country plus MFA change plus inbox rule, rather than alerting on location alone.
- Use named locations and Conditional Access results to cut noise: a login that passed all policies from a compliant device is lower risk.

## Triage steps
1. Confirm with the user (through a trusted channel) whether the sign-in was them.
2. Review the full sign-in timeline: IPs, apps, devices and Conditional Access results.
3. If suspicious: revoke sessions and refresh tokens, reset the password, and require MFA re-registration.
4. Check for new MFA methods, inbox rules, forwarding and app consents; remove anything unauthorized.
5. Search for the same IP or pattern across other accounts to scope the impact.

## Coverage gaps
- Stolen session tokens can bypass MFA and may not look like a new login.
- Detection quality depends on having sign-in logs retained and ingested, including non-interactive sign-ins.
