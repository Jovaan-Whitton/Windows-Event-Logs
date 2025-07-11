# Windows Event Logging Basics

## Overview
This document summarizes the key learnings and practical experience gained from the **Windows Event Logging Basics** section of the *Windows Event Logs & Finding Evil* module on Hack The Box. The focus was on understanding the structure of Windows Event Logs, using Event Viewer effectively, correlating event IDs, and crafting custom XML queries for threat detection.

---

## Key Concepts & Why They Matter

### Event Log Categories
Understanding different log types like **Application**, **System**, and **Security** is critical because each category reveals different types of system and user activity. For defenders, recognizing what belongs where helps quickly zero in on anomalies.

- **Forwarded Events** enable centralized log collection—essential for enterprise-scale monitoring.
- Event logs are accessible via Event Viewer or Windows APIs for automation and analysis.

### Anatomy of an Event Log Entry
Knowing the structure of each event allows analysts to correlate related events and pinpoint malicious behavior. Fields like **Logon ID** or **Event ID** are crucial for building attack timelines.

- Log Name: Category (e.g., Security, Application)
- Event ID: Unique identifier for log type (e.g., 4624 for successful logon)
- Source: Component generating the log (e.g., SideBySide)
- Level: Info, Warning, Error, Critical
- Keywords: Audit Success/Failure, others
- Logged Time, User, Computer, XML View, etc.

### Investigating Event ID 4624
Event ID 4624 reveals successful logons. This information is foundational for detecting unauthorized access or brute-force attacks—especially when tied to service accounts like `SYSTEM`.

#### Logon Type Analysis
Identifying **Logon Type 5** (Service logon) helps differentiate between normal user logins and automated/system-driven access, a key factor in detecting lateral movement and privilege abuse.

### Using XML Queries
Custom XML queries allow you to filter large log files and focus on events of interest. This skill is vital in SOC roles, where analysts must triage hundreds of events in real time.

```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">*[System[(EventID=4624)] and EventData[Data[@Name='SubjectLogonId'] = '0x3E7']]</Select>
  </Query>
</QueryList>
```

### XML Query Use Case
Tracked Event ID **4907** (audit policy change) and identified `SetupHost.exe` as the responsible process. This practical use of XML filtering shows how logs can be used to trace privilege escalation or audit tampering in real-world investigations.

---

## Important Windows Event IDs for Security Monitoring

Monitoring the following event IDs helps detect signs of attacks like persistence, lateral movement, or exfiltration:

##System Events

- **1074**: Unexpected shutdowns
- **6005 / 6006**: Event Log start/stop (can indicate restarts)
- **7040**: Service start type changed

## Security Events

- **4624 / 4625** – Logon success/failure
- **4672** – Special privileges assigned (SeDebugPrivilege, etc.)
- **4698–4702** – Scheduled task activity (used for persistence)
- **4719** – Audit policy changes (often altered by attackers)
- **7045** – New service installation (malware tactic)
- **5140 / 5145** – Access to network shares
- **1102 / 1116 / 1120** – Audit log clearing and malware detection by Defender

These logs form the core dataset for threat detection platforms like SIEMs and EDR tools.

---

## Practical Investigation Summary

- Investigated Event ID **4624** at `10:23:25` on `08/03/2022`
- Identified **SetupHost.exe** as the executable responsible for modifying auditing settings (via Event ID **4907**)
- Constructed XML queries to filter events tied to:
  - `SubjectLogonId` = `0x3E7`
  - File: `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\WPF\wpfgfx_v0400.dll`

Identified Event Time: **10:23:30**

---

## Skills Demonstrated

- Interpreting complex log structures and event correlations
- Building XML queries to streamline investigations
- Detecting audit tampering and privilege escalation
- Creating filtered views for high-value log events
- Mapping event flows in forensic investigations

---

## Summary

This section enhanced my understanding of:

- Windows event log structure and investigation methodology
- Using Event Viewer for in-depth incident analysis
- Correlating security-related events via Logon ID
- Building XML queries to streamline threat detection
- These skills are critical for entry-level SOC analysts, threat hunters, or anyone working in Windows-based environments.

---

## Additional References

- [Microsoft Docs – Event ID 4624](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624)
- [Access Control Lists (SACLs)](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-control-lists)
- [SDDL and ACE Strings](https://docs.microsoft.com/en-us/windows/win32/secauthz/ace-strings)

---

*[Back to Main Project](../README.md)*
