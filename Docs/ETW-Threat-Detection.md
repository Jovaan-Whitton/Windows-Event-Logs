# Event Tracing for Windows (ETW) - Threat Detection & Analysis

## Project Overview
This project captures the advanced capabilities of Event Tracing for Windows (ETW) as explored in Hack The Box’s **Windows Event Logs & Finding Evil** module. The section highlights how ETW enriches threat detection and forensic analysis through deep system telemetry, surpassing traditional event log limitations.

---

## Key Concepts & Why They Matter

### What is ETW?
ETW is a kernel-level tracing facility that collects and logs events from Windows components, third-party applications, and custom providers. It plays a vital role in:
- **Advanced Threat Detection**: Capturing low-level events like DLL loading, process creation, and .NET runtime activity.
- **Forensics & Incident Response**: Logging subtle behaviors that are missed by high-level monitoring tools.
- **Performance & Stability**: ETW’s design ensures minimal performance overhead, making it suitable for real-time use.

### Architecture Overview
- **Providers**: Generate event data (e.g., Kernel-Network, PowerShell).
- **Controllers**: Start/stop sessions (e.g., logman).
- **Consumers**: Tools like `SilkETW`, `Get-WinEvent`, and ETW Explorer that collect and analyze data.
- **Channels/ETL files**: Organize events and provide persistent storage for investigation.

### Importance
- **Gaps in traditional logs**: ETW captures telemetry that Sysmon or native event logs may miss.
- **Advanced malware detection**: Useful for detecting stealthy attacks like process injection, credential dumping, and unmanaged PowerShell use.
- **Customizable depth**: Event providers and keyword filters allow tailored visibility.

---

## What Was Learned
- How ETW expands detection beyond Sysmon by capturing kernel/user-mode telemetry
- How to use logman and SilkETW to monitor real-time system activity
- How to detect unusual .NET assembly loads and parent process spoofing
- Why monitoring DLL loads alone may not reveal full attacker activity
- The importance of using multiple sources (Sysmon, ETW, JSON logs) for forensic-level threat detection
ETW offers a comprehensive, low-overhead event tracing framework that collects real-time telemetry from both user-mode and kernel-mode processes. With hundreds of providers capturing granular data on process behavior, network activity, file system interaction, and code execution, ETW enables cybersecurity professionals to uncover stealthy and advanced threats.

---

## Practical Exercises

| Exercise | Objective | Outcome |
|---------|-----------|---------|
| Replicate Seatbelt Execution | Simulate malicious .NET loading | Used `SilkETW` + `Sysmon` to capture and identify `clr.dll` & `ManagedInteropMethodName` |
| Detect Parent PID Spoofing | Uncover false parent-child relationships | Compared `Sysmon` with ETW logs to discover real creator |
| Log ETW Session Info | Understand active trace sessions | Queried providers and extracted GUIDs, channels, levels |

---

## Practical Investigation Summary

### Detection 1: Strange Parent-Child Relationships
- **Technique**: Parent PID Spoofing (e.g., `cmd.exe` spoofed under `spoolsv.exe`)
- **Why it matters**: Identifies process manipulation techniques used by attackers.
- **ETW Advantage**: `Microsoft-Windows-Kernel-Process` revealed the *true* parent process despite spoofing.

### Detection 2: Malicious .NET Assembly Loading
- **Technique**: Execution of Seatbelt.exe in memory using `.NET` runtime
- **Why it matters**: Bypasses on-disk detection by loading directly into memory.
- **ETW Advantage**: `Microsoft-Windows-DotNETRuntime` provider revealed runtime method names and behavior.

---

## Tools Used
- `logman` – Manage and inspect active ETW trace sessions
- `SilkETW` – Lightweight tool to collect ETW events and export to JSON
- `Event Viewer` – GUI-based review of ETW data
- `Process Hacker` – Analyze running processes and parent-child relationships

---

## Skills Demonstrated
- Understanding of ETW architecture and telemetry ecosystem
- Identifying stealth techniques like parent PID spoofing and in-memory .NET execution
- Analyzing and parsing ETW JSON logs with command-line tools
- Mapping event logs to MITRE ATT&CK techniques (e.g., T1055 – Process Injection)


---

## Summary
This section of the Windows Event Logs & Finding Evil module focused on using ETW (Event Tracing for Windows) to detect advanced adversarial behavior. By leveraging ETW providers beyond Sysmon, I extended visibility into the .NET runtime, process creation, and suspicious telemetry that would otherwise go unnoticed.
Event Tracing for Windows (ETW) is a powerful telemetry layer every blue teamer should leverage. When properly configured and analyzed, it reveals subtle attack behaviors that evade traditional logging. Mastering ETW is essential for elite threat detection, digital forensics, and continuous monitoring.

Completed the lab with successful detection and analysis of:
- Abnormal parent-child process relationships (e.g., Parent PID Spoofing)
- Malicious .NET assembly loads (e.g., in-memory execution of Seatbelt)
- Process creation visibility beyond Sysmon limits using ETW providers

These exercises strengthened my ability to detect stealthy post-exploitation tactics by combining event-based and behavior-based detection techniques.

---

## References
- [Microsoft ETW Docs](https://learn.microsoft.com/en-us/windows/win32/etw/about-event-tracing)
- [A Primer on ETW](https://nasbench.medium.com/a-primer-on-event-tracing-for-windows-etw-997725c082bf)
- [ETW Analysis Guide](https://bmcder.com/blog/a-begginers-all-inclusive-guide-to-etw)

---

*[_Back to Main Project](../README.md)*

