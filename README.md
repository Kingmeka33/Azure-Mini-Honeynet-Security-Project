# Azure-Mini-Honeynet-Security-Project
# 🛡️ Azure Mini Honeynet Security Project

## 📘 Introduction

In this project, I build a **mini honeynet in Azure** and ingest logs from various resources into a **Log Analytics Workspace**, which is then used by **Microsoft Sentinel** to build attack maps, trigger alerts, and create incidents.

I measured key security metrics in the insecure environment for 24 hours, applied security controls to harden the environment, and then measured the metrics again for another 24 hours.

The metrics collected are:

- `SecurityEvent` (Windows Event Logs)
- `Syslog` (Linux Event Logs)
- `SecurityAlert` (Log Analytics Alerts Triggered)
- `SecurityIncident` (Incidents created by Sentinel)
- `AzureNetworkAnalytics_CL` (Malicious Flows allowed into the honeynet)

---

## 🧱 Architecture

### 🔓 Before Hardening / Security Controls

<img width="1468" height="831" alt="Image" src="https://github.com/user-attachments/assets/1c2e6c4f-8fd2-426c-b9e8-c3717c7e7cb7" />

### 🔒 After Hardening / Security Controls

<img width="819" height="472" alt="Image" src="https://github.com/user-attachments/assets/f68d61e3-b55f-4d6a-84fe-a5661483d18a" />

**Components:**

- Virtual Network (VNet)
- Network Security Groups (NSG)
- 2 Windows VMs
- 1 Linux VM
- Log Analytics Workspace
- Azure Key Vault
- Azure Storage Account
- Microsoft Sentinel

---

## 🗺️ Attack Maps

### 📉 Before Hardening

![Attack Map 1](./images/attackmap1.png)  
![Attack Map 2](./images/attackmap2.png)  
![Attack Map 3](./images/attackmap3.png)

### 📈 After Hardening

> No attack map results — Sentinel detected **no malicious activity** during the hardened 24-hour period.

---

## 📊 Metrics Overview

### ⏳ Metrics Before Hardening

📅 **Start Time:** `2024-04-13 13:53:48`  
📅 **Stop Time:** `2024-04-14 13:53:48`

| Metric                    | Count |
|---------------------------|-------|
| `SecurityEvent`           | 7671  |
| `Syslog`                  | 833   |
| `SecurityAlert`           | 4     |
| `SecurityIncident`        | 59    |
| `AzureNetworkAnalytics_CL`| 620   |

---

### ✅ Metrics After Hardening

📅 **Start Time:** `2024-04-15 11:50:28`  
📅 **Stop Time:** `2024-04-16 11:50:28`

| Metric                    | Count |
|---------------------------|-------|
| `SecurityEvent`           | 3894  |
| `Syslog`                  | 6     |
| `SecurityAlert`           | 0     |
| `SecurityIncident`        | 0     |
| `AzureNetworkAnalytics_CL`| 0     |

![Metrics After Hardening](./images/metrics-after.png)

---

## 🧪 KQL Queries Used

<details>
<summary><strong>Click to expand</strong></summary>

### 📌 Start/Stop Time
```kql
range x from 1 to 1 step 1
| project StartTime = ago(24h), StopTime = now()
SecurityEvent
| where TimeGenerated >= ago(24h)
| count
Syslog
| where TimeGenerated >= ago(24h)
| count
SecurityAlert
| where DisplayName !startswith "CUSTOM" and DisplayName !startswith "TEST"
| where TimeGenerated >= ago(24h)
| count
SecurityIncident
| where TimeGenerated >= ago(24h)
| count
AzureNetworkAnalytics_CL
| where FlowType_s == "MaliciousFlow" and AllowedInFlows_d > 0
| where TimeGenerated >= ago(24h)
| count
