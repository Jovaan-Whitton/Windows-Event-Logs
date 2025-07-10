# Analyzing Evil with Sysmon & Event Logs

## Overview

This lab from the **Windows Event Logs & Finding Evil** module on Hack The Box focuses on advanced detection techniques using **Sysmon** and **Windows Event Logs**. It covers how to identify and investigate suspicious behaviors such as DLL hijacking, unmanaged PowerShell/C# injection, and credential dumping. These hands-on exercises reinforce detection strategies using real-world indicators of compromise (IOCs).

---

## Key Concepts & Why They Matter

- **Sysmon** extends native Windows logging by capturing low-level system activity like process creation, network connections, and module loads.
- **Event IDs** act as key markers of specific behaviors. Understanding which IDs map to suspicious actions is vital for threat hunting.
- **IOCs** (Indicators of Compromise) such as unsigned DLLs, unexpected file locations, and privilege requests are used to build detection rules.
- **Attack Techniques Covered**:
  - DLL Hijacking
  - PowerShell Injection
  - Credential Dumping (via LSASS)
- These techniques are **real-world tactics** used by attackers. Learning to detect them enhances readiness for **SOC** or **IR** roles.

---

## What Was Learned

### 1. Sysmon Installation and Configuration
- Installed Sysmon with extended hash logging (`-h md5,sha256,imphash`)
- Used SwiftOnSecurity's XML config for high-quality logging
- Modified rules to include image load events (Event ID 7)

### 2. DLL Hijacking Detection
- Performed hijack using `calc.exe` and `WININET.dll`
- Captured Event ID 7 logs showing unsigned DLL loaded by calc.exe
- Compared normal vs. hijacked behavior using signature and path analysis

### 3. Unmanaged PowerShell Injection
- Injected C# payload into `spoolsv.exe`
- Verified that managed CLR DLLs (clr.dll, clrjit.dll) were loaded
- Used Process Hacker and Event Viewer to validate execution flow

### 4. Credential Dumping with Mimikatz
- Ran `sekurlsa::logonpasswords` to dump credentials from LSASS
- Used Sysmon Event ID 10 (ProcessAccess) to detect suspicious access to `lsass.exe`
- Detected SeDebugPrivilege escalation and privilege misuse

---

## Practical Exercises

| Attack Technique         | Evidence Required                             | Example Event ID |
|--------------------------|-----------------------------------------------|------------------|
| DLL Hijacking            | SHA256 hash of malicious `WININET.dll`       | Sysmon ID 7      |
| PowerShell Injection     | SHA256 hash of `clrjit.dll` from `spoolsv.exe`| Sysmon ID 7      |
| Credential Dumping       | NTLM hash of Administrator (from Mimikatz)    | Sysmon ID 10     |

## Practical Investigation Summary
In this lab, I replicated and investigated three types of malicious activities:

- **DLL Hijacking** – Using `calc.exe` and a malicious `WININET.dll`, I observed unsigned DLL loading from an unusual location and analyzed Sysmon Event ID 7 for image load details.
- **Unmanaged PowerShell Injection** – Leveraged `PSInject` to load CLR components into a process (`spoolsv.exe`) not normally associated with .NET. Used Process Hacker and Sysmon to validate the abnormal state.
- **Credential Dumping** – Executed `mimikatz` and correlated Event ID 10 to detect unauthorized process access to LSASS, revealing credential theft behavior.

---

## Tools & Commands Used

- **Sysmon** (Microsoft Sysinternals)
- **SwiftOnSecurity Sysmon Config**: [GitHub](https://github.com/SwiftOnSecurity/sysmon-config)
- `sysmon.exe -i -accepteula -h md5,sha256,imphash -l -n`
- `sysmon.exe -c sysmonconfig-export.xml`
- **Process Hacker** (for observing runtime behavior)
- **PowerShell** + PSInject
- **Mimikatz**: `sekurlsa::logonpasswords`

---

## Skills Demonstrated
- Sysmon configuration and live telemetry analysis
- Identification and correlation of malicious behavior using Event Viewer
- Detection of unauthorized DLL loads and memory injections
- Behavioral threat hunting using process access, DLL signatures, and logon correlations
- Practical use of Microsoft Sysinternals, PowerShell, and Process Hacker

---

## Summary
This section of the Windows Event Logs & Finding Evil module focused on using Sysmon to detect advanced adversarial behavior. By extending native event logging with Sysmon and analyzing real-world attack techniques like DLL hijacking, unmanaged PowerShell injection, and credential dumping, I developed the ability to identify Indicators of Compromise (IOCs) using both static rules and behavioral patterns.

Completed the lab with successful detection and analysis of:
- DLL Hijacking with unsigned, misplaced DLLs
- Unmanaged PowerShell injection through .NET runtime observation
- Credential dumping through LSASS process access

These exercises provided deep exposure to real attacker tactics and how to detect them using Windows Event Logs and Sysmon telemetry.

---

*[_Back to Main Project](../README.md)*

