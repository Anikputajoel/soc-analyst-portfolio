# Lesson 05 — Detecting Suspicious PowerShell Activity

## Objective

Investigate potentially suspicious PowerShell activity using Windows Event Logs and Sysmon telemetry.

## Skills Demonstrated

- PowerShell process analysis
- Sysmon Event ID 1 analysis
- Sysmon Event ID 3 analysis
- Process ID correlation
- Base64 encoded PowerShell analysis
- Network connection analysis
- Evidence-based SOC investigation
- Avoiding premature conclusions

## Investigation Summary

A controlled PowerShell process was created using the `-EncodedCommand` parameter.

The encoded command was safely decoded and produced:

`Write-Output 'SOC-LAB-TEST'`

The decoded command was a controlled test command and did not demonstrate malicious behavior.

A separate Sysmon Event ID 3 recorded an outbound connection:

- Process: `taskhostw.exe`
- Process ID: `7184`
- Source IP: `10.0.2.15`
- Destination IP: `40.84.97.4`
- Destination Port: `443`
- Initiated: `true`

The PowerShell process had Process ID `6360`.

Because the Process IDs were different, the available telemetry did not establish that PowerShell initiated the network connection.

## Key SOC Finding

Matching Process IDs can help correlate Sysmon events to the same process instance.

Different Process IDs should not automatically be treated as the same process activity.

## Analyst Conclusion

The use of PowerShell `-EncodedCommand` and an external network connection can raise suspicion and should be investigated. However, these indicators alone do not prove malicious activity.

Further investigation may include decoding the command, reviewing EDR telemetry, examining related process activity, and validating the destination IP.

## Evidence

Screenshots and supporting telemetry will be added to this investigation as evidence.

## Lessons Learned

- Encoded PowerShell is not automatically malicious.
- Public IP addresses are not automatically malicious.
- `Initiated: true` indicates that the local side initiated the connection.
- Process ID is useful for correlating process-related telemetry.
- Evidence should be analyzed before reaching a conclusion.
