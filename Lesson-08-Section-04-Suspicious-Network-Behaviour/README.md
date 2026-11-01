Lesson 8 — Section 4: Detecting Suspicious Network Behaviour

Objective

Investigate established outbound TCP connections on a Windows system, identify the processes responsible, examine associated Windows services, and apply evidence-based SOC investigation techniques.

Skills Demonstrated

- Windows network connection investigation
- PowerShell network analysis
- TCP connection inspection
- Process ID (PID) identification
- Windows service investigation
- Executable path verification
- Process-to-network correlation
- Evidence-based security assessment
- SOC investigation documentation

Lab Environment

- Operating System: Windows 11 virtual machine
- Local IP Address: "10.0.2.15"
- Investigation Tools: PowerShell, Windows CIM, Windows process and service information
- Network State Investigated: Established TCP connections

Evidence Collected

A PowerShell network inspection identified four established outbound TCP connections.

Network Connection Evidence

Local Port| Destination IP| Destination Port| PID| Process
59004| 52.110.20.1| 443| 6120| Start Menu Experience Host
59002| 52.110.20.7| 443| 6120| Start Menu Experience Host
52728| 74.151.238.140| 443| 3140| MpDefenderCoreService
49688| 98.66.133.185| 443| 3108| svchost.exe

All four connections were observed using TCP remote port 443.

Process Investigation

1. Start Menu Experience Host

Observed information:

- Process ID: "6120"
- Process Name: "StartMenuExperienceHost.exe"
- Executable path began with: "C:\Windows\SystemApps\Microsoft.Windows..."
- Associated network destinations:
  - "52.110.20.1:443"
  - "52.110.20.7:443"

The executable path was truncated in the collected output. The full path, digital signature, and parent process were not verified.

2. Microsoft Defender Core Service

Observed information:

- Process ID: "3140"
- Process name: "MpDefenderCoreService"
- Service name: "mdcoresvc"
- Executable path began with:

"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\..."

- Associated destination: "74.151.238.140:443"

The service name and reported path are consistent with a Microsoft Defender platform component. The complete executable path and digital signature were not independently verified.

3. Windows Push Notifications System Service

Observed information:

- Process ID: "3108"
- Process: "svchost.exe"
- Service name: "WpnService"
- Display name: Windows Push Notifications System Service
- State: Running
- Start mode: Automatic
- Executable path:

"C:\Windows\System32\svchost.exe -k netsvcs -p"

- Associated destination: "98.66.133.185:443"

The service identity and executable path are consistent with expected Windows service activity.

Investigation and Correlation

The investigation followed this process:

1. Identified established TCP connections.
2. Collected local and remote IP addresses and ports.
3. Identified the owning process IDs.
4. Resolved the process names.
5. Investigated the associated Windows services.
6. Examined executable path information.
7. Reviewed the available evidence before reaching a conclusion.

An initial inconsistency in process ownership information was resolved by repeating the collection and verifying the process IDs.

The investigation also demonstrated the importance of distinguishing a process ID from a service name and validating that the collected information refers to the same process instance.

Security Assessment

The observed connections were associated with identifiable Windows components:

- Start Menu Experience Host
- Microsoft Defender Core Service
- Windows Push Notifications System Service

The service identities and reported executable path information were generally consistent with expected Windows components.

However, the investigation did not independently establish:

- The reputation or ownership of all destination IP addresses.
- The complete executable paths for every process.
- Digital signature validity or file integrity.
- Whether the connections were expected under the organisation's security policy.
- Whether the observed connections were associated with any malicious activity.

Final assessment: No malicious activity was confirmed from the available evidence. The connections were not classified as malicious, but further validation would be required before declaring them definitively benign.

Recommendations

1. Verify complete executable paths and digital signatures.
2. Investigate the destination IP addresses using trusted threat intelligence sources.
3. Correlate network connections with Sysmon Event IDs 1, 3 and 22.
4. Review additional endpoint telemetry where available.
5. Compare observed connections with normal system and organisational behaviour.
6. Document any unusual findings and escalate only when supported by sufficient evidence.

Analyst Conclusion

This investigation demonstrated how a SOC analyst can inspect outbound network connections, identify their owning processes, investigate Windows services, and assess network activity using an evidence-first approach.

The presence of multiple established connections on TCP port 443 does not automatically indicate malicious activity.

A reliable security assessment requires process identification, service validation, destination investigation, supporting telemetry, and organisational context.

Skills Demonstrated

- PowerShell network investigation
- Windows process analysis
- Windows service identification
- TCP connection investigation
- Security event correlation concepts
- Evidence validation
- SOC reporting and documentation
