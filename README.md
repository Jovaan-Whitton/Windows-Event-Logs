# Windows Event Logs & Finding Evil

## Project Overview
This project documents my completion of the **Windows Event Logs & Finding Evil** module on Hack The Box Academy. The module explored how defenders can leverage Windows Event Logs, Sysmon, and Event Tracing for Windows (ETW) to detect and investigate malicious behavior on Windows systems. Through real-world examples and hands-on labs, I developed skills in filtering logs, correlating suspicious activities, and using PowerShell for event log analysis.

---

## Module Scope 
This HTB module provides insight into how security analysts and defenders can detect "evil" on Windows endpoints by analyzing event logs. Topics included:

- Anatomy of Windows Event Logs
- Installing and configuring Sysmon
- Detecting credential dumping, PowerShell injection, DLL hijacking
- Understanding Event Tracing for Windows (ETW) architecture
- Using the Get-WinEvent cmdlet for filtering and extracting log data
- Real-world detection techniques (e.g., malicious parent-child relationships)

---

## Objectives
- Identify the most critical Windows Event Logs for security monitoring
- Detect abnormal behavior using Sysmon event IDs
- Investigate process creation, registry changes, and PowerShell abuse
- Explore ETW architecture and utilize key ETW providers
- Perform advanced filtering with PowerShell’s Get-WinEvent

---

## Tools & Technologies
- **Platform**: Hack The Box Academy
- **Log Sources**: Windows Security Logs, Sysmon, ETW
- **Tools Used**: Event Viewer, Sysmon, PowerShell (Get-WinEvent), Log Parser
- **Techniques Practiced**:
  - Event ID correlation
  - Parent-child process tracing
  - .NET assembly detection
  - Credential dump & DLL hijack recognition

---

## Key Concepts Covered

### Windows Event Log Essentials
- Learned how to navigate Security, Application, and System logs
- Focused on common IDs such as 4624 (login), 4688 (process creation), 4720 (user creation)

### Sysmon Integration
- Installed Sysmon and tested its event ID coverage
- Detected:
  - PowerShell/C# injection (Sysmon Event ID 1 & 7)
  - Unusual image loads (DLL hijack)
  - Registry tampering

### ETW Architecture
- Studied ETW architecture and provider types
- Used examples of:
  - Malicious .NET assemblies
  - Suspicious process spawning chains

### Get-WinEvent Filtering
- Used `Get-WinEvent` to:
  - Query specific logs by name
  - Filter for timestamps, Event IDs, or log level
  - Export findings for reporting or SIEM ingestion

---

## Skills Gained
- Interpreting Windows Event Logs for threat detection
- Investigating post-exploitation techniques via logs
- Using PowerShell to extract and filter key events
- Recognizing red team activity through behavioral patterns

---

## Sample Visuals
<details>
<summary><strong>Screenshots (click to expand)</strong></summary>

*Coming soon: Event Viewer breakdowns, Sysmon output, Get-WinEvent queries.*

</details>

---

## Files Included

- [Windows Event Logging Basics](/docs/Windows-Event-Logging-Basics.md)
- [Analyzing Evil Sysmon](/docs/Analyzing-Evil-Sysmon.md)
- [ETW Threat Detection](/docs/ETW-Threat-Detection.md)
- [Get WinEvent](/docs/Get-WinEvent.md)


---

## Result
Completed the module with a strong grasp of Windows logging mechanisms and practical detection use cases. I’m now confident in my ability to use logs and PowerShell to detect, investigate, and report suspicious activity across Windows environments.

---

## Let’s Connect
I’m pursuing entry-level opportunities in **SOC Analysis**, **Threat Detection**, or **Windows Security** where I can apply event log monitoring and detection engineering skills.

**Email**: jovaan.jwhitton@gmail.com  
**LinkedIn**: [linkedin.com/in/jovaan-whitton-profile](https://linkedin.com/in/jovaan-whitton-profile)

