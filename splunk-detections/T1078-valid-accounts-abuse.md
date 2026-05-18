# T1078 — Valid Accounts

**MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/)  
**Tactic:** Initial Access, Persistence, Privilege Escalation, Defence Evasion  
**Platform:** Windows, Linux, Cloud  
**Detection Platform:** Splunk (SPL)  
**Severity:** High  
**Data Sources Required:** Windows Security Event Log (4624, 4625, 4648, 4768), VPN/IdP logs, O365/Entra audit logs

---

## Why This Technique Is Dangerous

Valid account abuse is one of the most difficult techniques to detect because the attacker is using real credentials — there is no malware, no exploit, no signature to match. The logon looks identical to a legitimate user. Attackers obtain credentials via:

- Phishing
- Credential stuffing (reusing leaked passwords from other breaches)
- Purchasing credentials from dark web markets
- Brute force
- Pass-the-Hash / Pass-the-Ticket (using credential hashes without knowing the plaintext)

This technique appears across **every** major threat actor group. Scattered Spider built their entire operational model on it. The MGM Resorts breach (2023, ~$100m impact) began with a phone call to a help desk and a social engineering request to reset MFA — pure valid account abuse.

Detecting it requires behavioural analytics rather than signature matching.

---

## Detection Rule 1: Impossible Travel Login

A user cannot physically be in Dublin at 09:00 and in Singapore at 09:15. If we see successful logins from geographically distant locations within a timeframe that no human could travel, that is strong evidence of credential compromise.

```spl
index=authentication sourcetype=vpn_logs action=success
| eval login_epoch=strptime(_time, "%Y-%m-%dT%H:%M:%S")
| sort 0 user, login_epoch
| streamstats window=2 current=t list(src_country) as countries list(login_epoch) as times by user
| eval country_1=mvindex(countries,0), country_2=mvindex(countries,1)
| eval time_1=mvindex(times,0), time_2=mvindex(times,1)
| eval time_diff_minutes=round((time_2-time_1)/60,2)
| where country_1!=country_2 AND time_diff_minutes < 120
| table _time, user, country_1, country_2, time_diff_minutes, src_ip
| sort -_time
```

**What this detects:** Successful logins from two different countries within a 2-hour window — physically impossible travel, indicating account takeover.

---

## Detection Rule 2: Brute Force Followed by Success

Failed logins are noise. Failed logins followed by a success are signal.

```spl
index=wineventlog source="WinEventLog:Security"
    (EventCode=4625 OR EventCode=4624)
| eval event_type=if(EventCode=4624,"success","failure")
| bucket _time span=10m
| stats count(eval(event_type="failure")) as failures,
        count(eval(event_type="success")) as successes
        by _time, user, src_ip
| where failures >= 5 AND successes >= 1
| eval alert="Brute force followed by successful login"
| table _time, user, src_ip, failures, successes, alert
| sort -_time
```

**What this detects:** An account that fails authentication 5 or more times in a 10-minute window and then succeeds — consistent with a brute force or credential stuffing attack that eventually found the correct password.

---

## Detection Rule 3: Login Outside Business Hours for Privileged Accounts

Privileged accounts (domain admins, service accounts) should rarely be interactive outside working hours. When they are, it warrants investigation.

```spl
index=wineventlog source="WinEventLog:Security"
    EventCode=4624
    Logon_Type=2
| eval hour=strftime(_time,"%H")
| eval day_of_week=strftime(_time,"%A")
| where (hour < "07" OR hour > "19") OR day_of_week IN ("Saturday","Sunday")
| lookup privileged_accounts.csv Account_Name AS user OUTPUT is_privileged
| where is_privileged="true"
| table _time, user, src_ip, Logon_Type, day_of_week, hour
| sort -_time
```

**What this detects:** Interactive logons by privileged accounts outside business hours — a pattern consistent with an attacker using stolen admin credentials to avoid detection during quiet periods.

*Note: Requires a `privileged_accounts.csv` lookup table maintained by the analyst team listing all admin and service accounts.*

---

## Detection Rule 4: New Admin Account Created

A classic attacker persistence technique is creating a new administrator account. Unless your organisation has a formal IAM provisioning workflow, this should be rare.

```spl
index=wineventlog source="WinEventLog:Security"
    EventCode=4720
| eval new_account=Target_Account_Name
| join type=left new_account
    [search index=wineventlog source="WinEventLog:Security" EventCode=4732
     | eval new_account=Member_Account_Name
     | table new_account, Group_Name]
| where Group_Name="Administrators" OR Group_Name="Domain Admins"
| table _time, new_account, Group_Name, user, src_ip
| sort -_time
```

**What this detects:** A new user account being created AND added to an administrator group in the same session — textbook attacker persistence.

---

## True Positive Example

```
Time: 2024-03-15 03:12:00 UTC
User: m.sullivan
Login 1: Dublin, IE (company VPN) — 2024-03-15 01:58:00 UTC
Login 2: Kuala Lumpur, MY — 2024-03-15 03:12:00 UTC
Time delta: 74 minutes
```

Interpretation: 74-minute travel from Ireland to Malaysia is impossible. Account is compromised. Analyst should immediately reset credentials, revoke active sessions, and review all actions taken by this account in the past 30 days.

---

## False Positive Examples

| Scenario | Why It Fires | How to Distinguish |
|---|---|---|
| Employee using a VPN that exits in a different country | VPN exit node shows wrong country | Correlate with HR-confirmed travel records; suppress known corporate VPN exit IPs |
| Shared service account used by automated processes globally | Logins from multiple countries simultaneously | Service accounts should not have interactive logins — remediate rather than suppress |
| Admin account used for after-hours patching | Logon outside hours | Should come from a known jump server IP — add jump server to allowlist |

---

## Tuning Recommendations

1. **Maintain an HR travel lookup table** — if an employee is confirmed travelling, suppress impossible-travel alerts for them during that period.
2. **Suppress known corporate VPN exit nodes** from the impossible-travel rule — the source IP will be the VPN exit, not the employee's actual location.
3. **Increase threshold for brute force/success rule** for accounts used by automated scripts — these may have multiple legitimate "failures" from misconfigured scripts.
4. **Define "business hours" per timezone** for geographically distributed teams.

---

## References

- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [Okta: Identity Attack Trends](https://www.okta.com/resources/whitepaper/identity-attack-trends/)
- [MGM Breach Analysis — CISA](https://www.cisa.gov/)
- [Microsoft: Detecting Credential Attacks](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app)
