# Windows Event Logs & Finding Evil – SOC Investigation Lab

## 📝 Overview
This lab represents the culmination of lessons from the **Windows Event Logs & Finding Evil** module on Hack The Box. Acting as a SOC analyst, the objective is to review event logs captured during simulated attacks and answer key questions to identify attacker behavior, IOCs, and suspicious system activity.

---

## 🔍 Objective
Analyze pre-captured event logs from various directories using Windows Event Viewer and Sysmon telemetry. Your goal is to trace signs of:
- DLL Hijacking
- Unmanaged PowerShell Execution
- Process Injection
- Credential Dumping (LSASS)
- Suspicious Logins
- Abnormal Parent-Child Execution

---

## 🛠️ Environment Setup
- **Access** via RDP  
  - **Username**: `Administrator`  
  - **Password**: `HTB_@cad3my_lab_W1n10_r00t!@0`

- **Log Directories**:  
  - `C:\Logs\DLLHijack`  
  - `C:\Logs\PowershellExec`  
  - `C:\Logs\Dump`  
  - `C:\Logs\StrangePPID`

Use **Event Viewer** and **Sysmon logs** to complete the tasks.

---

## 📂 Walkthrough

### 🔸 1. DLL Hijacking Detection
**Question:** What process was responsible for executing the DLL hijack?  
- **Path**: `C:\Logs\DLLHijack`
- **Hint**: Look for **Sysmon Event ID 7** (ImageLoad)
- **Approach**:
  - Filter logs by Event ID 7.
  - Search for unsigned DLLs loaded by unexpected executables.
  - Identify the parent process.

✅ **Submit the executable name (e.g., `explorer.exe`)**

---

### 🔸 2. Unmanaged PowerShell Execution
**Question 1:** Which process executed unmanaged PowerShell code?  
**Question 2:** Which process injected into it?  
- **Path**: `C:\Logs\PowershellExec`
- **Hint**:
  - Use **Sysmon Event ID 7** (DLL Load) for `clr.dll` or `clrjit.dll`
  - Use **Event ID 10** for `ProcessAccess` (injection)
- **Approach**:
  - Filter Event ID 7 to detect .NET runtime loaded in suspicious processes.
  - Correlate with Event ID 10 to see which process accessed it.

✅ Submit answers in the format: `processname.exe`

---

### 🔸 3. LSASS Dump & Post-Login Analysis
**Question 1:** Which process dumped LSASS?  
**Question 2:** Was there a suspicious login attempt after the dump?  
- **Path**: `C:\Logs\Dump`
- **Hint**:
  - Event ID 10 (process accessing `lsass.exe`)
  - Event ID 4624 (new logon)
- **Approach**:
  - Identify non-security software accessing LSASS.
  - Review logon events immediately after the dump.

✅ Submit: `processname.exe` and `Yes` or `No`

---

### 🔸 4. Suspicious Parent-Child Process Behavior
**Question:** Which process was used to temporarily execute code via an unusual parent-child pairing?  
- **Path**: `C:\Logs\StrangePPID`
- **Hint**:
  - Look for **Sysmon Event ID 1** (Process Creation)
  - Compare parent-child names and GUIDs

✅ Submit the child process executable name (e.g., `cmd.exe`)

---

## ✅ Skills Demonstrated
- Detection of advanced attacker behavior using Sysmon and event logs
- IOC identification from DLL injection and unmanaged code execution
- Analysis of credential dumping via LSASS access
- Identification of logon anomalies and parent process spoofing
- Use of Event Viewer filtering and Sysmon Event ID correlation

---

## 🧠 What Was Learned
This exercise reinforced how attacker techniques surface in event logs—often subtly. Knowing what to filter for (e.g., Event IDs 1, 3, 7, 10, 4624) allows analysts to:
- Detect post-exploitation activity
- Reconstruct attacks from log artifacts
- Improve real-world threat hunting workflows

---

## 🔗 References
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Windows Security Event IDs](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/basic-audit-events)
