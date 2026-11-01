Lesson 8 — Section 3: Investigating Suspicious Network Connections

1. Objective

Investigate a PowerShell network connection using Windows Sysmon events. Correlate process creation, network connection, and DNS-query activity to understand the observed behavior and assess whether the available evidence supports a security concern.

2. Lab Environment

- Operating system: Windows 11 virtual machine
- Monitoring tool: Sysmon
- Log source: Microsoft-Windows-Sysmon/Operational
- Process investigated: Windows PowerShell

3. Evidence Collected

Event ID 1 — Process Creation

Field| Observed value
Event ID| 1
UTC timestamp| 2026-10-28 00:03:49
Process image| "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
Process ID| 9616
ProcessGuid| "{890b2ad7-3be5-6ae1-7601-000000002c00}"
Parent image| "C:\Windows\explorer.exe"
Command line| ""C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe""

Event ID 3 — Network Connection

Field| Observed value
Event ID| 3
UTC timestamp| 2026-10-28 00:11:44
Process image| "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
Process ID| 9616
ProcessGuid| "{890b2ad7-3be5-6ae1-7601-000000002c00}"
Source IP| "10.0.2.15"
Destination IP| "1.1.1.1"
Destination port| "443"
Protocol| TCP

Event ID 22 — DNS Query

Field| Observed value
Event ID| 22
UTC timestamp| 2026-10-28 00:11:45
Process image| "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
ProcessGuid| "{890b2ad7-3be5-6ae1-7601-000000002c00}"
Query name| "1.1.1.1.in-addr.arpa"

4. Timeline Analysis

UTC timestamp| Event| Observation
00:03:49| Event ID 1| PowerShell process creation recorded
00:11:44| Event ID 3| TCP connection to "1.1.1.1:443" recorded
00:11:45| Event ID 22| Reverse-DNS query recorded

The network connection was recorded 7 minutes and 55 seconds after process creation. The DNS query was recorded one second after the network connection.

These timestamps establish the recorded event sequence. They do not prove continuous process activity between events or establish that one event caused another.

5. Correlation Analysis

The three events contain the same ProcessGuid:

"{890b2ad7-3be5-6ae1-7601-000000002c00}"

This strongly supports correlating the process-creation, network-connection, and DNS-query events to the same process instance.

The destination IP address "1.1.1.1" is associated with Cloudflare's public DNS resolver. Port 443 is commonly used for HTTPS traffic, but the port number alone does not establish the application protocol or prove that the traffic was encrypted.

The query "1.1.1.1.in-addr.arpa" is consistent with a reverse-DNS lookup for the IP address "1.1.1.1". The available evidence does not establish why the query occurred or whether it was directly related to the network connection.

6. Security Assessment

Confirmed observations

- Sysmon recorded PowerShell process creation.
- Sysmon recorded a TCP connection from "10.0.2.15" to "1.1.1.1" on port "443".
- Sysmon recorded a DNS query for "1.1.1.1.in-addr.arpa".
- The three events contain the same ProcessGuid.

Unconfirmed findings

- Whether the connection was malicious.
- Whether the DNS query directly caused or resulted from the connection.
- Whether PowerShell performed additional activity between the recorded events.
- Whether any data was transferred beyond what the available logs establish.
- Whether the activity represented a security incident.

7. Recommendations

1. Review the PowerShell command line and surrounding process activity.
2. Examine relevant DNS, firewall, and network telemetry.
3. Review available EDR alerts and process activity for additional context.
4. Compare the observed connection with expected system and administrative behavior.
5. Preserve the original event records and timestamps for further investigation.
6. Avoid classifying the activity as malicious unless additional evidence supports that determination.

8. Conclusion

The investigation correlated Sysmon Event IDs 1, 3, and 22 using a matching ProcessGuid. The records show PowerShell process creation followed by a TCP connection and a reverse-DNS query.

The available evidence establishes the observed process and network activity but does not independently confirm malicious behavior or system compromise. Further validation would be required before making a final security determination..

9. Skills Demonstrated

- Sysmon event analysis
- Windows process investigation
- Network connection analysis
- DNS-query investigation
- ProcessGuid correlation
- Timeline reconstruction
- Evidence-based security assessment
- SOC report writing 
