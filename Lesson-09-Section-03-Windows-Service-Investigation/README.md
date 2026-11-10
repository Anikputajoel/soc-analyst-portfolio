Lesson 9 — Section 3: Windows Service Investigation

1. Investigation Overview

Lab: SOC Analyst Home Lab
Operating System: Windows 11
Tool: Windows PowerShell
Service Investigated: Application Information (Appinfo)
Investigation Type: Windows Service Configuration and Integrity Verification

Objective

To investigate a Windows service by examining its configuration, running state, startup mode, service account, executable location, and digital signature.

The objective was to identify potentially suspicious service configurations and determine whether the observed service appeared consistent with legitimate Windows activity.

---

2. Service Enumeration

The investigation began by enumerating running Windows services.

PowerShell command:

Get-Service | Where-Object {$_.Status -eq "Running"} | Select-Object -First 15 Name,DisplayName,Status

The output displayed 15 running services.

Two recognized services included:

- Appinfo — Application Information
- Audio Endpoint Builder — Windows Audio Endpoint Builder

The Appinfo service was selected for further investigation.

---

3. Service Configuration Investigation

The following command was used to retrieve the Appinfo service configuration:

Get-CimInstance Win32_Service -Filter "Name='Appinfo'" | Select-Object Name,DisplayName,State,StartMode,StartName,PathName

Evidence collected

Field| Observed value
Service Name| Appinfo
Display Name| Application Information
State| Running
Start Mode| Manual
Service Account| Local System
Executable Path| C:\Windows\System32\svchost.exe
Arguments| -k netsvcs -p

Initial analysis

The service was running under the Local System account with a manual startup configuration.

The use of Local System requires attention because it is a highly privileged Windows account. However, its use by itself does not indicate malicious activity.

The executable path pointed to the Windows System32 directory, which is consistent with the expected location of the Windows Service Host executable.

---

4. Executable Location Verification

The following command was used to verify whether the executable existed at the reported location:

Test-Path "C:\Windows\System32\svchost.exe"

Observed result: True

Analysis

The executable existed at the expected Windows System32 location.

This confirmed file presence but did not independently establish file authenticity or integrity.

---

5. Digital Signature Verification

PowerShell Authenticode verification was performed using:

Get-AuthenticodeSignature "C:\Windows\System32\svchost.exe"

Observed result

- Signature Status: Valid
- Signer Certificate: Microsoft Windows
- Certificate Organization: Microsoft Corporation
- Certificate Locality: Redmond
- Certificate State: Washington
- Certificate Country: US

The certificate subject was retrieved using:

(Get-AuthenticodeSignature "C:\Windows\System32\svchost.exe").SignerCertificate.Subject

Analysis

The digital signature status was reported as valid, and the certificate subject identified Microsoft Windows.

The organization field identified Microsoft Corporation.

This supports the authenticity of the executable as a Microsoft-signed Windows component.

A valid digital signature is an important verification indicator, although it does not independently prove that every activity associated with a service is harmless.

---

6. Findings and Risk Assessment

Investigation area| Finding| Assessment
Service identity| Appinfo| Expected Windows service
Running state| Running| Not suspicious by itself
Startup mode| Manual| Consistent with on-demand operation
Service account| Local System| Privileged; usage requires context
Executable location| System32| Expected location
File existence| True| File exists
Digital signature| Valid| Supports authenticity
Certificate publisher| Microsoft Windows| Consistent with Windows component

Overall assessment

Classification: Likely legitimate Windows activity

No immediately suspicious configuration was identified from the evidence collected.

No confirmed malicious activity was established during this investigation.

---

7. Conclusion

The investigation examined the Windows Application Information service (Appinfo), including its configuration, execution state, service account, executable location, and digital signature.

The service was found running under the Local System account with a manual startup configuration.

The executable existed in the expected Windows System32 directory, and its digital signature was reported as valid, identifying Microsoft Windows as the certificate subject and Microsoft Corporation as the organization.

Based on the available evidence, the service configuration appeared consistent with legitimate Windows activity.

The investigation did not establish malicious activity.

---

8. Recommendations

1. Preserve the collected service configuration and signature verification results.
2. Monitor unexpected modifications to Windows service configurations.
3. Investigate unusual changes to service executable paths or startup modes.
4. Correlate suspicious service activity with relevant Windows event logs and endpoint security telemetry.
5. Escalate findings if additional evidence indicates unauthorized service modification or suspicious execution.

---

9. Skills Demonstrated

- Windows service enumeration
- PowerShell service investigation
- Windows service configuration analysis
- Service account privilege awareness
- Executable path verification
- Authenticode digital signature verification
- Windows persistence investigation
- Evidence collection and interpretation
- SOC risk assessment and reporting

---

10. Investigation Status

Lesson: 9
Section: 3 — Investigating Windows Services
Practical Investigation: Completed
Assessment: Passed
Final Classification: Likely legitimate Windows activity

Analyst Note: This report documents observations from a controlled Windows 11 SOC home lab. Findings are limited to the evidence collected during the investigation.
