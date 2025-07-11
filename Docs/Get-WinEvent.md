# Get-WinEvent - Mass Log Analysis & Threat Detection

## Project Overview
This project focuses on using the PowerShell `Get-WinEvent` cmdlet to perform mass analysis of Windows Event Logs, as covered in Hack The Box’s **Windows Event Logs & Finding Evil** module. These techniques are crucial for SOC analysts, threat hunters, and incident responders working in environments where visibility into system activity is critical for detection and response.

---

## Key Concepts & Why They Matter

### What is Get-WinEvent?
`Get-WinEvent` is a PowerShell cmdlet designed for efficient querying and filtering of logs from the Windows Event Log and ETW (Event Tracing for Windows) system. It helps identify:
- **Suspicious Activities**: Such as unusual logins, network connections, or process creation.
- **Historical Forensics**: Including log file review, remote system auditing, and correlation with IOCs.
- **Efficient Filtering**: Through hashtables, XPath queries, and event IDs to locate malicious behaviors quickly.

### Importance
- **Scale**: Many organizations generate millions of logs daily. Parsing them efficiently is key to detection.
- **Precision**: Tailored filtering allows investigation of event types like Sysmon IDs, encoded PowerShell, suspicious IPs, and more.
- **Flexibility**: Supports `.evtx` offline analysis, remote log access, and real-time querying.

---

## What Was Learned
- Navigating the Windows logging ecosystem using PowerShell
- Filtering logs by date, event ID, provider, and content
- Using XPath and XML parsing to extract fields like source IP, process GUIDs, or loaded DLLs
- Detecting encoded PowerShell usage and suspicious command line arguments
- Understanding the context of network connections, image loads, and parent-child process relationships

---

## Practical Exercises

| Exercise | Objective | Outcome |
|---------|-----------|---------|
| Query Logs by LogName | View logs like `System`, `Security`, and `Sysmon` | Identified counts, enabled status, and log modes |
| Filter with Hashtable | Pull Sysmon IDs 1 & 3 | Observed process creation and network connections |
| Use XPath Queries | Target encoded PowerShell (`-enc`) or C2 IP addresses | Found suspicious command lines and connections |
| Analyze .evtx Files | Open offline logs (e.g., LOLBins, C2 payloads) | Confirmed behaviors using Sysmon and WinRM logs |
| XML Field Extraction | Parse IPs and Process IDs from EventData | Mapped activity back to original threat actor process |

---

## Practical Investigation Summary

### Detection 1: Suspicious Network Connections
- **Technique**: Used XPath and XML parsing on Event ID 3
- **Why it matters**: Captures lateral movement or beaconing behavior
- **Command Used**: `Get-WinEvent -FilterHashtable {ID=3} | ForEach { parse XML for DestinationIP }`

### Detection 2: Encoded PowerShell
- **Technique**: XPath + Hashtable filter for `-enc` in ParentCommandLine
- **Why it matters**: Indicates obfuscated execution or bypass attempts
- **Result**: Identified suspicious PowerShell spawning CSC.exe in memory

### Detection 3: .EVTX Forensics
- **Technique**: Parsed attack samples using `-Path` to load `.evtx`
- **Why it matters**: Enables remote triage or backup log review
- **Example**: Identified use of `pcalua.exe` for LOLBin execution

---

## Tools Used
- `PowerShell` – Primary tool to invoke `Get-WinEvent`
- `Event Viewer` – Cross-verification of event ID fields and structure
- `Chainsaw` – For enrichment and log analysis
- `.evtx` Samples – Used for threat emulation and offline parsing

---

## Skills Demonstrated
- Proficient use of `Get-WinEvent` with advanced filters
- XML parsing and XPath query design for forensic triage
- Detection of C2 traffic, encoded PowerShell, and LOLBin usage
- Analyzing parent-child command lines and Sysmon trace behaviors
- Use of event timelines for attack correlation and investigation

---

## Summary
This section of the Windows Event Logs & Finding Evil module focused on using `Get-WinEvent` for large-scale log analysis. I practiced retrieving, filtering, and correlating logs across operational, security, and Sysmon providers.

Completed the lab with successful detection and analysis of:
- Suspicious process creation from `.evtx` threat samples
- Obfuscated PowerShell behavior using `-enc` command line arguments
- Stealthy command and control communications using Sysmon network logs

These exercises developed my skills in scripting and data triage—key for incident response and threat hunting in enterprise environments.

---

## References
- [Get-WinEvent Documentation](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- [Understanding Windows Event Logs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-security-audit-events)
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

---

*[Back to Main Project](../README.md)*
