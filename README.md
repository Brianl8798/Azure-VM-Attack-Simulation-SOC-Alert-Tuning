# Azure VM Attack Simulation & SOC Alert Tuning

![Microsoft Sentinel](https://img.shields.io/badge/Microsoft_Sentinel-0078D4?logo=microsoft-azure&logoColor=white)
![KQL](https://img.shields.io/badge/KQL-FF6D70?logo=kusto&logoColor=white)

## 📌 Overview
Deployed a vulnerable Azure VM to analyze attack patterns and optimize Microsoft Sentinel detections.

**Key Highlights**:
- Logged **150+ attack attempts** in 72 hours
- Identified **8 malicious IPs** via threat intel
- Reduced alert noise by **40%** with KQL tuning

## 🛠️ Technical Implementation
### Infrastructure
- **Azure VM**: Windows 10 with exposed RDP/SSH/SMB
- **Logging**: Azure Monitor → Sentinel workspace
- **Tools**: KQL, AbuseIPDB, AlienVault OTX

### Sample KQL Detections
```kql
// Brute Force Alert
SecurityEvent
| where EventID == 4625
| summarize Attempts=count() by AttackerIP=IpAddress
| where Attempts > 10
| extend Risk="High"

// Geo-Anomaly Detection
let allowedCountries = dynamic(["US","CA","GB"]);
SecurityEvent
| evaluate ip_geo_location(ClientIP)
| where CountryCode !in (allowedCountries)
```
📊 Results

150+ Total attack attempts	

8 Confirmed malicious IPs	

40% Noise reduction

🔥 Key Findings

Top Attack Patterns:

RDP brute-forcing (65%)

SSH credential stuffing (30%)

Threat Intel:

90% of malicious IPs found in AbuseIPDB

Default credentials (admin:password123) most targeted

🎯 Skills Demonstrated
KQL - Azure Security - Threat Detection - SIEM - Incident Response

💡 Lessons Learned
"Geo-based alerting reduced false positives by 50%+"
"VMs attract attacks within minutes of exposure"
