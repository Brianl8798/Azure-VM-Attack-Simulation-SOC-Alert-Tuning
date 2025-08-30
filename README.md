Hands-on threat detection project using Microsoft Sentinel

Project Overview
Deployed an intentionally vulnerable Azure VM (open RDP/SSH/SMB) to:

Monitor real-world attack patterns in a controlled environment

Develop and tune high-signal KQL detection rules for a SOC environment

Validate threat intelligence integration (IOC matching, geo-context)

Key Activities & Results
✔ Logged 150+ attack attempts within 72 hours
✔ Identified 8 confirmed malicious IPs via cross-referencing with AbuseIPDB
✔ Reduced noise by 40% through KQL filtering of known scan-bot traffic

Technical Implementation
Infrastructure:

Azure VM (Windows 10) with exposed high-risk ports (RDP/SSH/SMB)

Log collection via Azure Monitor Agent → Microsoft Sentinel

Detection Rules (KQL Examples):

kql
// Brute Force Prioritization
SecurityEvent
| where EventID == 4625 // Failed logins
| summarize AttemptCount=count() by AttackerIP=IpAddress, TargetAccount=TargetUserName
| where AttemptCount > 10
| extend RiskLevel = case(
    AttemptCount > 50, "Critical",
    AttemptCount > 20, "High",
    "Medium"
)

// Geo-Based Alerting
let allowedRegions = dynamic(["US", "CA", "GB"]); // Business-approved countries
SecurityEvent
| where EventID == 4624 // Successful logins
| evaluate ip_geo_location(ClientIP)
| where CountryCode !in (allowedRegions)
Threat Intelligence Insights
Top Attack Patterns:

RDP brute-forcing (65% of attacks)

SSH credential stuffing (30%)

SMB version scanning (5%)

Notable Observations:

90% of malicious IPs were flagged in public threat feeds (AbuseIPDB, AlienVault OTX)

Attackers leveraged default credentials (admin:password123, root:admin)

Skills Demonstrated
SOC Core Skills: KQL query writing, alert triage, log analysis

Cloud Security: Azure VM hardening, NSG best practices

Threat Intel: IOC enrichment, attacker TTP analysis

Lessons Learned
"Exposed VMs attract malicious traffic within minutes of deployment."

"Geo-context and threat intel feeds reduce false positives by 50%+ in detection rules."
