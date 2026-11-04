Lesson 9 — Section 2: Windows Scheduled Task Investigation

Objective

Investigate Windows scheduled tasks to understand their names, paths, states, triggers, execution actions, executable locations, and digital signatures.

Skills Demonstrated

- Scheduled task enumeration
- Task properties investigation
- Trigger and execution-action analysis
- Executable path verification
- PowerShell file-existence checks
- Authenticode digital signature verification
- Evidence-based SOC assessment

1. Scheduled Task Enumeration

Command used:

Get-ScheduledTask

Approximately 50 scheduled tasks were displayed.

The first 10 tasks were examined using:

Get-ScheduledTask | Select-Object -First 10 TaskName, TaskPath, State

No unfamiliar task names were identified during the initial review.

2. Scheduled Task Investigation

The OneDrive Startup Task was selected for further examination.

Observed properties:

Property| Evidence
Task name| OneDrive Startup Task followed by a user SID
Task path| "\"
State| Ready
Trigger| Logon trigger
Principal| "MSFT_TaskPrincipal2"

3. Execution Action Analysis

The task's action was inspected.

Observed information:

- Executable: "OneDriveLauncher.exe"
- Arguments: "/start instance"
- Working directory: Not specified

4. Executable Path Verification

The initially supplied path did not resolve.

Further investigation identified the executable at:

"C:\Users\anayl\AppData\Local\Microsoft\OneDrive\26.195.1006.0007\OneDriveLauncher.exe"

PowerShell's "Test-Path" command returned:

"True"

This confirmed that the executable existed at the corrected path.

5. Digital Signature Verification

The executable was examined using PowerShell's "Get-AuthenticodeSignature" command.

The lab observation was that the signature was verified and the publisher was Microsoft Corporation. Certificate details, including a serial number, were displayed.

This supported the assessment that the executable was signed by Microsoft.

6. Investigation Analysis

The scheduled task was configured to run at user logon and launched OneDriveLauncher.exe from a Microsoft OneDrive application directory.

The executable existed at the corrected path and was reported to have a verified Microsoft digital signature.

These findings were consistent with legitimate OneDrive startup activity.

A valid digital signature does not independently prove that a file is harmless. Additional validation and correlation may be necessary in a real SOC investigation.

7. Analyst Conclusion

Assessment: Likely legitimate OneDrive startup activity.

No evidence collected during this exercise confirmed malicious persistence or system compromise.

The investigation demonstrated how to examine scheduled task properties, identify an executable, verify its location, and inspect its digital signature.

8. Recommendations

1. Preserve task details and screenshots as investigation evidence.
2. Verify executable paths and digital signatures.
3. Correlate scheduled task activity with process-creation and Windows Security events.
4. Investigate suspicious tasks further before reaching a final determination.
5. Do not delete or disable tasks without authorization and supporting evidence.

Assessment Result

Section 2: Passed.

The user correctly identified the task as likely legitimate OneDrive startup activity and selected the appropriate evidence-preservation and escalation response for a suspicious task scenario.
