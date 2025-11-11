# SOC Investigation Report: PowerShell Suspicious Web Request

## Incident Description

A suspicious series of PowerShell executions using `Invoke-WebRequest` were detected across multiple endpoints in the environment. These executions originated from the `SYSTEM` account via `cmd.exe`, targeted `powershell.exe`, and downloaded scripts from a known GitHub URL using the `-ExecutionPolicy Bypass` parameter. The behavior was found on several hosts with repeated activity, suggesting either automation misuse or potential malicious compromise.

---

## Tools & Technologies

- Microsoft Sentinel (Log Analytics / Advanced Hunting)
- DeviceProcessEvents (Endpoint Telemetry)
- Microsoft Sentinel Analytics Rule
- Kusto Query Language (KQL)

---

## Tables Queried

- `DeviceProcessEvents`

---

## Investigation Steps

1. **Alert Detection and Analytics Rule Creation**
    - **What Was Done:** Created a Sentinel Analytics Rule to detect PowerShell processes (powershell.exe, powershell_ise.exe) using `Invoke-WebRequest` in their command line arguments.
    - **Why:** `Invoke-WebRequest` is frequently used to download remote content—a common step in malware delivery or exploitation.
      
     <img width="1321" height="762" alt="Screenshot 2025-11-11 101847" src="https://github.com/user-attachments/assets/b73c2448-72c7-4d30-991d-9e852f0d19d7" />
     <img width="1759" height="770" alt="Screenshot 2025-11-11 104115" src="https://github.com/user-attachments/assets/e5ca5068-3705-40b7-862e-860e78dc8a5c" />
     <img width="741" height="777" alt="Screenshot 2025-11-11 104234" src="https://github.com/user-attachments/assets/2681cefa-f58e-4042-ab28-a0338cea958a" />
     <img width="1526" height="781" alt="Screenshot 2025-11-11 104526" src="https://github.com/user-attachments/assets/91bbb744-92f7-4c76-adf8-d5a7f75383b9" />





2. **Initial Query and Aggregation**
    - **What Was Done:** Queried the `DeviceProcessEvents` table and aggregated results by DeviceName, InitiatingProcessAccountName, and FolderPath, summarizing event counts and extracting command-line samples.
    - **Why:** Identifying which endpoints and accounts showed repeated suspicious behavior helps focus the scope of the investigation for efficiency and effectiveness.
      
      
    <img width="1088" height="747" alt="Screenshot 2025-11-11 110015" src="https://github.com/user-attachments/assets/2407bcd0-2301-48bd-ac04-c7f214a6704b" />



3. **Drilldown on High-Activity Entities**
    - **What Was Done:** Focused queries on top Device/Account/Folder combinations to isolate where most suspicious activity occurred.
    - **Why:** High activity may indicate compromised automation or widespread misuse.
      
      
    <img width="1109" height="791" alt="Screenshot 2025-11-11 123133" src="https://github.com/user-attachments/assets/3b841888-786c-4683-bd34-f483fbd99f45" />




4. **Parent Process Analysis**
    - **What Was Done:** Extracted InitiatingProcessFileName and InitiatingProcessCommandLine to find and analyze the parent process launching PowerShell.
    - **Why:** Determining the origin (often cmd.exe or a scheduled script) can reveal root cause—whether it’s a scheduled task, startup script, or attacker persistence tactic.
      
      
    <img width="1103" height="796" alt="Screenshot 2025-11-11 111216" src="https://github.com/user-attachments/assets/d1fa301f-5bec-4864-ba1c-98a3077bdb5a" />


5. **Validation of ProcessCommandLine and URLs**
    - **What Was Done:** Grouped and reviewed unique ProcessCommandLine entries and parsed out referenced URLs.
    - **Why:** This clarifies whether files/scripts being downloaded are legitimate, malicious, or anomalous, and supports further investigation or takedown of harmful resources.
      
      
    <img width="1109" height="577" alt="Screenshot 2025-11-11 111257" src="https://github.com/user-attachments/assets/c2a6dd1a-ce20-4734-af42-570513a81701" />


6. **Hash Collection for Reputation Checks**
    - **What Was Done:** Pulled SHA256, SHA1, and MD5 hashes for both PowerShell and parent processes.
    - **Why:** Hashes allow cross-reference with threat intelligence feeds to identify known malware or suspicious binaries.
      
      
    <img width="1106" height="802" alt="Screenshot 2025-11-11 110846" src="https://github.com/user-attachments/assets/334ce762-2080-44ec-9fde-6b989f67d693" />


7. **Timeline Correlation**
    - **What Was Done:** Ordered and visualized events by timestamp to establish incident duration and event clusters.
    - **Why:** Confirming persistence, lateral movement, or campaign coordination is critical for understanding scope and impact.
      
      
    <img width="1104" height="798" alt="Screenshot 2025-11-11 122724" src="https://github.com/user-attachments/assets/e3500bd4-c456-474e-99af-6b82b3f12f2a" />


---

## Key Findings

- Multiple hosts (including `windows-target-1`, `masif`, `threat-hunt-lab`, `remi-windows`) ran PowerShell web requests using SYSTEM account via `cmd.exe`.
- The executed command lines used `-ExecutionPolicy Bypass`, and repeatedly downloaded from:
  - `https://raw.githubusercontent.com/joshmadakor1/lognpacific-public/refs/main/cyber-range/entropy-go`
- Automation or scheduled scripts may be responsible, but activity is inconsistent with change management or user-driven events.
- Collected IoCs include specific command lines, URLs, file hashes, parent process command lines, and affected systems.

---

## Containment, Eradication & Remediation Recommendations

**Why:**  
To prevent further downloads or potential code execution, halt lateral movement, and ensure that any backdoor or persistence mechanism is removed.

## Escalated to L2 Analyst for:

### Containment
- Isolate affected endpoints from the network.
- Block access to identified URLs at firewalls, proxies, and web filters.
- Suspend/disable scheduled tasks or automation accounts executing these commands.

### Eradication
- Remove any unauthorized or suspicious scripts, scheduled tasks, or startup items on affected endpoints.
- Revoke or rotate SYSTEM/admin credentials if compromise is suspected.
- Scan affected hosts for malware, persistence, and further compromise.
- Delete any files downloaded from the suspicious URLs.

### Recovery
- Patch and harden any vulnerable systems implicated by the campaign.
- Restore pristine copies of critical system executables if tampering is found.
- Monitor for residual activity using enhanced detection rules for the revealed IoCs.
- Update staff and playbooks with new detection and response learning.

---

## Incident Summary

A security incident was detected involving automated PowerShell scripts downloading potentially unapproved content from the internet. The activity was discovered on several computers and was executed by accounts with high-level (SYSTEM) access using command-line automation. While the scripts downloaded files from GitHub, further investigation is required to ensure that these activities do not represent a security threat and that no malicious payloads were delivered or executed. The incident response team has taken steps to isolate and investigate affected machines, gathered essential forensic evidence, and provided recommendations to block similar events in the future. No direct evidence of data exfiltration or ransomware was identified, but ongoing monitoring and improvements to automation controls are recommended.

