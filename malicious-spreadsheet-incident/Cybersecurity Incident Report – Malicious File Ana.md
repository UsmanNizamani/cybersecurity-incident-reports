## Analyst:
**Muhammad Usman**


##  Date of Report:

31/07/2025


---

## Scenario

You are a level one security operations center (SOC) analyst at a financial services company. You have received an alert about a suspicious file being downloaded on an employee's computer. 

You investigate this alert and discover that the employee received an email containing an attachment. The attachment was a password-protected spreadsheet file. The spreadsheet's password was provided in the email. The employee downloaded the file, then entered the password to open the file. When the employee opened the file, a malicious payload was then executed on their computer. 

You retrieve the malicious file and create a SHA256 hash of the file. You might recall from a previous course that a hash function is an algorithm that produces a code that can't be decrypted. Hashing is a cryptographic method used to uniquely identify malware, acting as the file's unique fingerprint. 

* * *

##  Incident Overview

A suspicious file was reported on an employee’s workstation. Investigation revealed the employee received a **password-protected spreadsheet via email**, opened it, and a **malicious payload** was executed. This report documents the incident analysis using **VirusTotal** and categorizes indicators of compromise (IoCs) using the **Pyramid of Pain** framework.

---

##  Evidence Collected

- **File Type:** Password-protected spreadsheet  
- **Trigger:** File opened after entering password provided in the email  
- **Payload Behavior:** Malicious payload executed and created multiple unauthorized executable files  
- **Hash Type:** SHA-256  
- **SHA-256 Hash Value:**  
  `54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b`  
- **Initial Alert Source:** Intrusion Detection System (IDS)

---

##  Timeline of Events

| Time       | Event Description                                                                 |
|------------|------------------------------------------------------------------------------------|
| 1:11 p.m.  | Employee receives an email containing a file attachment.                           |
| 1:13 p.m.  | Employee downloads and opens the password-protected spreadsheet.                  |
| 1:15 p.m.  | Unauthorized executable files are created on the employee’s computer.             |
| 1:20 p.m.  | Intrusion Detection System detects malicious files and sends an alert to the SOC. |

---

##  VirusTotal Report Analysis

The file with SHA-256 hash `54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b` was analyzed using VirusTotal. Below is a summary of key findings from the report across the Detection, Details, Relations, and Behavior tabs.

---

###  Detection Tab

- **Total Vendors Analyzed:** 70+
- **Vendors Flagged as Malicious:** 50+  
- **Common Detection Labels:**
  - `Trojan.Flagpro`
  - `Trojan.Win32.Agent`
  - `HEUR.Backdoor`
  - `GenericRXRH-KX`
  - `Trojan.Win32.Fragtor`
  - `Backdoor.Win32.Flagpr`
  - `Malware.AI.41615`
  - `Gen:Variant.Fragtor`

These labels indicate a **backdoor/trojan threat**, likely related to targeted or advanced persistent threat (APT) malware.

---

###  Details Tab

- **MD5 Hash:** `287d612e29b71c90aa54947313810a25`
- **SHA-1 Hash:** `8f35a9e70dbec8f1904991773f394cd4f9a07f5e`
- **SHA-256 Hash:** `54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b`
- **VHash:** `045056655d15551023z12z577z305bz2fz`
- **Authentihash:** `019439328ea87e4559b653ad7df933d20623bdd00d3793abc7ff35e57db24853`
- **Imphash:** `a59ed1599cc2f8311b215c83c51a2cc4`
- **SSDEEP:**  
  `6144:CdaRD0n4URr6zIKgDCVh84DLn5X3lWiDSVS1dGSLaYWis:XRonpRroIKgDCY4DLVlW3UiSL4R`
- **TLSH:**  
  `T13594AD933541C371CA177D7695789AAD4B3F8D3816BAB987B3B83B8F5C303918636902`
- **File Type:** PE32 Win32 EXE (Windows GUI executable)
- **Compiler:** Microsoft Visual C/C++ (2008-2010), Linker 9.00.21022
- **Magic:** `PE32 executable (GUI) Intel 80386, for MS Windows`
- **Product Name:** Microsoft® Windows® Operating System
- **Internal Name:** `bfsvc.exe`
- **Description:** Boot File Servicing Utility
- **File Size:** 430 KB (440320 bytes)
- **File Creation Time:** 2020-09-14 01:13:36 UTC
- **First Seen in Wild:** 2020-02-15
- **First Submission to VirusTotal:** 2020-10-01
- **Last Submission:** 2024-09-21
- **Last Analysis:** 2025-07-30

---
###  Relations Tab (Network Connections)

| Type   | Value                         | Detections |
|--------|-------------------------------|------------|
| Domain | flagpro[.]com                 | 8/90       |
| Domain | cdn-0[.]flagpro[.]com         | 6/92       |
| Domain | cdn-1[.]flagpro[.]com         | 7/91       |
| Domain | avtech[.]jp                   | 4/87       |
| IP     | 103.139.1.234                 | 7/93       |
| IP     | 103.139.1.235                 | 6/91       |

> The malware attempts to contact multiple subdomains under `flagpro[.]com`, which is a known C2 (Command and Control) domain for malware. IPs `103.139.1.234` and `103.139.1.235` are also associated with malicious activity.


## Maliciousness Assessment

###  Vendors' Ratio

- **Flagged by:** Over 50 security vendors  
- **Total vendors analyzed:** ~70  
- **Conclusion:** High detection ratio strongly indicates the file is **malicious**

###  Community Score

- **Score:** Negative (Red X shown in VirusTotal report)
- **Community Tags:** Likely includes terms like *trojan*, *backdoor*, *Flagpro*, etc.
- **Conclusion:** Community sentiment agrees this file is **malicious**

###  Security Vendors' Analysis

- Majority of security vendors flagged the file with:
  - `Trojan.Win32.Agent`
  - `Backdoor.Flagpro`
  - `GenericRXRH-KX`
  - `HEUR.Backdoor`, etc.
- Only a small number of vendors marked it as clean
- File impersonates a legitimate Windows file (`bfsvc.exe`) to avoid detection

---

###  Final Determination

**This file is confirmed as malicious.**

#### Reasoning:
- Detected by a **significant majority of security vendors**
- Associated with known malware families like **Flagpro** and **Backdoor.Agent**
- Community score is **negative**, indicating consensus from experienced analysts
- Exhibits behavior consistent with malware, including **network communication**, **process spawning**, and **possible persistence techniques**

> These indicators confirm that the file is **not safe** and must be treated as a threat in the environment.


