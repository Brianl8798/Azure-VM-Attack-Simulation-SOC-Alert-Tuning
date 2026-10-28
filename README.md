# Azure VM Attack Simulation & SOC Alert Tuning : A Honeypot in the Cloud

<p align="center">
  A deliberately exposed Azure VM used to capture real attack traffic and tune Microsoft Sentinel detections to cut alert noise.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Microsoft_Sentinel-0078D4?logo=microsoftazure&logoColor=white" alt="Microsoft Sentinel">
  <img src="https://img.shields.io/badge/KQL-Detections-FF6D70" alt="KQL">
  <img src="https://img.shields.io/badge/Azure-VM-0089D6?logo=microsoftazure&logoColor=white" alt="Azure VM">
  <img src="https://img.shields.io/badge/Threat_Intel-AbuseIPDB_%7C_OTX-555555" alt="Threat Intel">
</p>

> [!TIP]
> **Results at a glance** — jump to [Sample KQL detections](#sample-kql-detections) for the queries.
>
> - 🎯 **150+ attack attempts** logged in 72 hours
> - 🚩 **8 malicious IPs** identified via threat intel
> - 🔕 Alert noise reduced by **40%** with KQL tuning

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Infrastructure](#infrastructure)
- [Sample KQL detections](#sample-kql-detections)
- [Why tune alerts at all ?](#why-tune-alerts-at-all-)
- [SOC-ready skills](#soc-ready-skills)
- [Key takeaways](#key-takeaways)
- [Caveats](#caveats)
- [Credits](#credits)

## Introduction

I deployed a **vulnerable Azure VM** to the open internet, streamed its logs into **Microsoft Sentinel**, and used the incoming attack traffic to analyze attacker behavior and **optimize detection rules** so that real threats stand out from the noise.

## Features

- Windows 10 VM with **exposed RDP / SSH / SMB** to attract real-world attacks
- Logs forwarded from **Azure Monitor → Sentinel workspace**
- Custom **KQL alert rules** for brute force and geographic anomalies
- Attacker IPs enriched with **AbuseIPDB** and **AlienVault OTX**
- Alert automation with **Logic Apps**

## Infrastructure

```
 Internet attackers
        │  RDP / SSH / SMB
        ▼
 ┌───────────────────┐      ┌─────────────────┐      ┌──────────────────────┐
 │  Azure VM         │ ───► │  Azure Monitor  │ ───► │  Microsoft Sentinel  │
 │  Windows 10       │ logs │                 │      │  KQL rules + alerts  │
 └───────────────────┘      └─────────────────┘      └──────────┬───────────┘
                                                                │ enrich
                                                                ▼
                                                   AbuseIPDB · AlienVault OTX
```

## Sample KQL detections

**Brute force alert**

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by AttackerIP = IpAddress
| where Attempts > 10
| extend Risk = "High"
```

**Geo-anomaly detection**

```kql
let allowedCountries = dynamic(["US","CA","GB"]);
SecurityEvent
| evaluate ip_geo_location(ClientIP)
| where CountryCode !in (allowedCountries)
```

## Why tune alerts at all ?

An internet-facing VM generates a constant stream of failed logins. Without tuning, every one becomes an alert and analysts drown in noise. Thresholds (like **more than 10 failures**) and **geo-filtering** turn that stream into a short list of alerts worth investigating.

## SOC-ready skills

| Area | What I did |
| --- | --- |
| SIEM | Microsoft Sentinel configuration |
| Threat hunting | IOC matching, TTP analysis |
| Automation | KQL alert rules, Logic Apps |

## Key takeaways

- Exposed VMs get attacked **within minutes**
- Geo-filtering reduces **false positives by 50%+**
- Default credentials are **primary targets**

## Caveats

The VM was intentionally left vulnerable in an **isolated lab** for research purposes. Never expose production systems this way.

## Credits

- Brian Lam — [GitHub](https://github.com/Brianl8798) · [LinkedIn](https://www.linkedin.com/in/brian-lam-282176172/)
