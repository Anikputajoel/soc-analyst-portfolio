1. Observation:
Source: Windows security
Timestamp: 16:20:01
Event: 4624 ( successful logon)
Account: administrator
Logon type 10
Source IP: 10.20.30.45

Timestamp: 16:20:05
Source: Windows security
Event: 4688 (process creation)
Process: cmd.exe
Process id: 5100
Account: administrator

Timestamp: 16:20:07
Source : Windows security
Event: 4688 ( process creation)
ProcessId: 6200
Creator PID: 5100

Timestamp: 16:20:08
Source: sysmon
Event: 3 (network connection)
PID: 6200
External IP address: 203.0.113.50
Port : 443

Timestamp: 16: 20:09
Source: sysmon
Event: 22 (DnsQuery)
PID: 6200
Domain: example.com
Querystatue: 0

Timestamp: 16:20:12
Source: Windows security
Event: 4688 ( process creation)
Process: powershell.exe
PID: 7300
Account: administrator

Timestamp: 16:20:13
Source: sysmon
Event: 3 ( network connection)
PID: 7300
External IP address: 198.51.100.25
Port: 443

2. Evidence:
Evidence 1: Windows security
Event 4624 : successful logon type 10 was recorded.
Account: administrator
Timestamp: 16:20:01
Source IP address: 10.20.30.45



Evidence 2: Windows security
Event 4688 (process creation)
Process: cmd.exe was created under
Account: administrator
PID: 5100

Evidence 3: Windows security
Event 4688 ( process creation)
Process: powershell.exe was created
PID: 6200
Creator PID: 5100

Evidence 4: sysmon operational log
Event 3: network connection
PID: 6200
Port 443
External IP address: 203.0.113.50

Evidence 5: sysmon operational log
Event 22 ( DnsQuery)
PID 6200
Domain: example.com
Query status 0

Evidence 6: Windows security
Event 4688. ( Process creation)
Process: powershell.exe
PID 7300
Account: administrator

Evidence 7: sysmon operational log
Event 3
PID 7300
External IP address: 198.51.100.25
Port: 443

Additional evidence to obtain
Firewall logs
Authentication logs
IAM logs
EDR telemetry logs
Network/ proxy logs
Threat intelligence lookup

Analysis:
The available evidence indicates suspicious activities. powershell process with two different PID 6200 and 7300 was observed. The event is unusual but warrants further investigation, a successful logon type 10 under administrator, within a short time interval a cmd.exe process was created under the same account with PID 5100, cmd.exe created a powershell process with PID 6200 and creator PID 5100,  An outbound connection to destination IP address: 203.0.113.50 on port 443 was observed with PID 6200, subsequently the same process PID 6200 queried example.com with query status 0. A successful DnsQuery was recorded. Within the same time fragment another powershell process was created under administrator with PID 7300,  an outbound connection to a destination IP address 198.51.100.25 on port 433 associated with PID 7300.

With the available evidence isn't enough to validate malicious which warrants further investigation to ascertain the risk. The use of Outbound connection and the DnsQuery warrant further investigation however these  observations do not alone by themselves establish malicious activity, escalate to the assest owners or IT team for confirmation and review other endpoints telemetry.

4. Conclusion:
   Based on the available evidence, the activity represents a suspicious process and network activity sequence that warrants further investigation. The sequence includes a successful Type 10 logon for the administrator account, creation of "cmd.exe", creation of two separate PowerShell processes, and network activity associated with each PowerShell process. The first PowerShell process also generated a DNS query with QueryStatus 0.

The available evidence does not establish that the activity was malicious. The two PowerShell processes should be treated as separate process executions, and additional authentication, endpoint, network, and DNS telemetry is required to determine the significance and risk of the activity. Authorization should also be validated with the asset owner or IT team.

5. Recommendations:

1. Review the authentication logs and the Event ID 4624 Logon ID, where available, to determine the associated Windows logon session.

2. Correlate Event ID 4688 with Sysmon Events 3 and 22 using PID, timestamp, process name, and ProcessGuid where available.

3. Investigate PowerShell PID 6200 and PID 7300 separately to avoid incorrect attribution of activity between the two processes.

4. Review the available PowerShell command-line information, parent process, and process chain for both PowerShell processes.

5. Review available endpoint telemetry, network telemetry, and firewall logs for the outbound connections to "203.0.113.50:443" and "198.51.100.25:443".

6. Review DNS logs and related endpoint telemetry for the "example.com" query.

7. Perform threat-intelligence checks on the destination IP addresses in accordance with organizational procedures.

8. Validate the administrator activity with the asset owner or IT team and review relevant change-management or maintenance records.

9. Escalate to a Tier 2 SOC analyst if the activity cannot be validated as authorized or if additional suspicious indicators are identified.

10. Document the investigation findings, correlation results, validation outcomes, and actions taken.

Hands-On Lab: Windows Process and Network Correlation

Objective

Investigate Windows process creation, establish parent-child relationships using Sysmon Process GUIDs, and examine associated network activity.

1. Evidence Collected

Source: Microsoft Sysmon Operational Log

Parent process

- Image: "C:\Windows\System32\svchost.exe"
- Process ID: "1300"
- Parent image: "C:\Windows\System32\services.exe"
- Command line: "C:\Windows\System32\svchost.exe -k netsvcs -p -s schedule"
- UTC timestamp: "2026-10-12 20:39:16"
- ProcessGuid: "{890b2ad7-4572-6acd-1b00-000000002600}"

Child process

- Image: "C:\Windows\System32\taskhostw.exe"
- Process ID: "4788"
- Parent image: "C:\Windows\System32\svchost.exe"
- Parent Process ID: "1300"
- UTC timestamp: "2026-10-12 21:21:47"
- ProcessGuid: "{890b2ad7-5579-6acd-0902-000000002600}"

Network activity

- Sysmon Event ID: "3"
- Process: "taskhostw.exe"
- Process ID: "4788"
- Source IP: "10.0.2.15"
- Destination IP: "20.42.179.192"
- Destination port: "443"
- Protocol: TCP
- UTC timestamp: "2026-10-12 21:47:40"
- ProcessGuid: "{890b2ad7-5579-6acd-0902-000000002600}"

Executable validation

- Image path: "C:\Windows\System32\taskhostw.exe"
- Authenticode signature status: "Valid"
- Certificate subject identifies Microsoft Windows and Microsoft Corporation.

Destination context

- An IP ownership lookup associated "20.42.179.192" with Microsoft Corporation.
- This is contextual information, not proof that the connection was authorized or benign.

2. Analysis

The Sysmon Event ID 1 records support a parent-child relationship between "svchost.exe" (PID 1300) and "taskhostw.exe" (PID 4788). The child's ParentProcessGuid matched the recorded ProcessGuid of the parent.

The Sysmon Event ID 3 record has the same ProcessGuid as the "taskhostw.exe" creation event, supporting correlation of the network connection with that process instance.

The connection was made over TCP to destination port 443. Port 443 alone does not establish the application-layer protocol or the legitimacy of the connection.

The executable's location and valid Microsoft-associated signature support its authenticity, but do not independently establish that its observed behavior was authorized. Likewise, the destination's reported ownership does not prove the connection was safe.

3. Conclusion

The collected evidence supports a process-creation and network-activity relationship involving "taskhostw.exe". The available records do not establish malicious activity or conclusively verify the purpose of the outbound connection.

Assessment: Further validation required.

4. Recommendations

1. Validate the executable's signature and file integrity using trusted Windows tools.
2. Review the destination IP's ownership and reputation using reliable sources.
3. Examine related Sysmon and Windows events around the recorded timestamps.
4. Determine whether the connection is consistent with expected system behavior.
5. Correlate with other available telemetry before assigning a final disposition.

5. Skills Demonstrated

- Sysmon Event ID 1 process-creation analysis.
- Sysmon Event ID 3 network-connection analysis.
- Parent-child process correlation using ProcessGuid and ParentProcessGuid.
- Executable path and digital signature validation.
- IP ownership investigation.
- Evidence-based analysis and cautious SOC reporting.
