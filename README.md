# 🔍 Azure VM Threat Hunting Scenario – Microsoft Defender

This project simulates a real-world threat hunting investigation inside a shared Azure environment. I used Microsoft Defender for Endpoint (MDE) and KQL to detect, investigate, and analyze suspicious activity on publicly exposed virtual machines.

---

## 🧠 Scenario Overview

Older VMs were accidentally exposed to the internet without account lockout policies. The hypothesis: an attacker may have brute-forced credentials and accessed a system. My goal was to determine whether a compromise occurred, identify indicators of attack, and assess potential impact.

---

## 🧪 Tools & Data Sources

- **Microsoft Defender for Endpoint (MDE)**
- **KQL (Advanced Hunting)**
- `DeviceNetworkEvents`
- `DeviceLogonEvents`
- `DeviceProcessEvents`

---

## 🔬 Investigation Highlights

- ✅ Identified exposed VMs with inbound connections from public IPs
- ✅ Detected successful logon from unknown external IP using `ds9-cisco` account
- ✅ Traced post-login PowerShell activity accessing the Azure instance metadata service
- ✅ Investigated process lineage and validated suspicious cloud reconnaissance behavior

---

## 📊 Queries Used

You can find the full KQL queries in the [queries](./queries/) folder.

Example:
```kql
DeviceLogonEvents
| where DeviceName == "edr-machine"
| where RemoteIP == "172.98.33.169"
| where ActionType == "LogonSuccess"
| project Timestamp, AccountName, DeviceName, RemoteIP, LogonType
