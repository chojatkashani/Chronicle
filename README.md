# Chronicle

<img width="1212" alt="Screenshot 2025-02-07 at 3 27 13 PM" src="https://github.com/user-attachments/assets/d6402c55-0981-4233-a2eb-6c70979bf305" />


# Threat Detection and Analysis with Google Chronicle

## Project Overview
This project demonstrates the deployment of Google Chronicle, a cloud-native security analytics platform, to ingest, analyze, and detect security threats across enterprise networks. The goal is to centralize security telemetry, create detection rules, and generate alerts for suspicious activity.

## Objectives
- Configure Google Chronicle for log ingestion
- Parse and normalize security event data
- Create YARA-L detection rules to identify threats
- Monitor and analyze alerts
- Integrate Chronicle with a SIEM for enhanced visibility

## Setup

### Prerequisites
- Google Chronicle account with administrative access
- Log sources configured for ingestion (e.g., firewall, endpoint logs, DNS logs)
- Google Cloud SDK installed
- Access to a SIEM for integration (e.g., Splunk, Elastic Security)

### Configuring Chronicle Log Ingestion
1. Access Google Chronicle and navigate to **Ingestion Settings**.
2. Configure log sources by integrating Chronicle with:
   - Firewalls (e.g., Palo Alto, Fortinet)
   - Endpoint Detection and Response (EDR) tools
   - DNS logs (e.g., Cisco Umbrella, Cloudflare)
3. Ensure logs are properly formatted in **Unified Data Model (UDM)** format.

Verify log ingestion:
```bash
gcloud auth login
gcloud chronicle feeds list
```
If logs are successfully ingested, they will appear in the feed list.

## Implementation

### Creating a YARA-L Detection Rule
Chronicle uses YARA-L, a custom rule language for threat detection. To detect SSH brute force attempts, create a rule in **Google Chronicle Rules Engine**:

```yaml
rule ssh_brute_force_attempt {
    meta:
        author = "Cyber Analyst"
        description = "Detect multiple SSH login failures within a short time"
        severity = "high"
    events:
        $ssh_failed_login.events {
            metadata.event_type = "AUTH_FAILURE"
            metadata.device_type = "linux"
        }
    condition:
        count($ssh_failed_login) > 5 within 1m
}
```

### Deploying and Testing the Rule
1. Save the rule and deploy it in **Google Chronicle Detection Engine**.
2. Simulate an SSH brute force attack using Hydra:
   ```bash
   hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://<target-ip>
   ```
3. Monitor alerts in the **Chronicle Investigations Console**:
   ```bash
   gcloud chronicle alerts list
   ```

### Integrating with SIEM for Alerting
To send Chronicle alerts to a SIEM (e.g., Splunk):
```bash
gcloud chronicle alerts export --format=json > chronicle_alerts.json
curl -X POST -H "Authorization: Bearer $SPLUNK_TOKEN" \
    -d @chronicle_alerts.json \
    https://splunk-instance:8088/services/collector/event
```


This project successfully demonstrated how to use Google Chronicle for real-time security monitoring and threat detection. Chronicle efficiently ingested logs, applied YARA-L rules, and generated alerts for suspicious SSH activity. Future improvements include automating threat intelligence enrichment and integrating Chronicle with a SOAR platform for automated response actions.
