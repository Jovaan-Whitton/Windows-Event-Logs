# Windows Event Logs & Finding Evil – Hack The Box

## Project Overview
This lab from **Hack The Box Academy** focused on analyzing **Windows Event Logs** to detect suspicious activity, privilege escalation, and attacker lateral movement. I investigated a simulated compromise by parsing logs, tracing attacker behavior, and identifying indicators of malicious activity.

---

## Objectives
- Analyze Windows Security, System, and Application logs for malicious behavior
- Identify common attack techniques such as logon abuse, privilege escalation, and remote access
- Correlate Event IDs and timestamps to reconstruct the attacker’s path
- Improve detection and documentation skills in a Windows environment

---

## Tools & Technologies
- **Platform**: Hack The Box Academy  
- **Tools Used**: Event Viewer, PowerShell, Windows CLI, Online Resources (MITRE ATT&CK, EventID.net)  
- **Environment**: Windows 10 (Simulated Lab)  
- **Log Types**: Security.evtx, System.evtx, Application.evtx

---

## Steps Taken

1. **Log Gathering & Filtering**
   - Accessed Event Viewer and applied filters for Event IDs (e.g., 4624, 4672, 4688, 7045)
   - Exported relevant logs for deeper analysis

2. **Suspicious Activity Detection**
   - Identified abnormal logon patterns and privilege escalation attempts
   - Tracked the creation of new services and scheduled tasks (Event ID 7045)

3. **Behavior Reconstruction**
   - Correlated timestamps and actions to build a timeline of the attack
   - Verified evidence of lateral movement and user impersonation

4. **IOC Extraction**
   - Noted suspicious process names, user accounts, command-line parameters, and IP addresses

---

## Key Skills & Learnings
- Mastered reading and interpreting key Windows Event IDs for threat detection
- Improved analytical thinking by tracing attacker actions across log files
- Strengthened use of Event Viewer and PowerShell to triage incidents
- Applied MITRE ATT&CK mapping to real log artifacts

---

## Screenshots
> (Place all screenshots in a `screenshots/` folder)

- ![Event ID 4624 Logon](screenshots/logon-event-4624.png)
- ![Privilege Escalation](screenshots/privilege-event-4672.png)
- ![Service Creation](screenshots/service-creation-7045.png)

---

## Files Included
- `event-analysis-notes.md` – Summary of suspicious Event IDs and investigation process  
- `ioc_list.txt` – Extracted indicators of compromise (usernames, processes, IPs)  
- `screenshots/` – Visual examples of log analysis

---

## Result
This lab reinforced my ability to investigate complex Windows security events and detect signs of attacker behavior. These skills directly apply to SOC environments where log monitoring and incident documentation are critical.

---

## Let’s Connect
I’m currently seeking opportunities as a **SOC Analyst Tier 1**, **Cybersecurity Technician**, or **Security Support Specialist** in **New York City** or remote-friendly roles.

**Email**: jovaan.jwhitton@gmail.com  
**LinkedIn**: [linkedin.com/in/jovaan-whitton-profile](https://linkedin.com/in/jovaan-whitton-profile)

