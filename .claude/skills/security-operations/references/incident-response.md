# Incident Response Workflows

Step-by-step procedures for investigating and documenting security incidents.

## IR Process Overview

```
Detect → Triage → Investigate → Contain → Document → Recover
```

## Workflow 1: Honeytoken Alert

**Trigger:** ntfy alert from honeytoken-watcher sidecar

### Step 1: Identify

From the alert, extract:
- **Service name** — which container was accessed
- **File accessed** — which honeytoken file (aws-credentials, .kube-config, etc.)
- **Timestamp** — when the access occurred

### Step 2: Triage

```bash
# Check container logs around alert time
docker --context ugreen-nas logs <service> --since <timestamp> --until <timestamp+5min>

# Check honeytoken watcher logs for details
docker --context ugreen-nas logs <service>-honeytoken-monitor --tail 50
```

### Step 3: Investigate

```bash
# Check who/what accessed the container
docker --context ugreen-nas exec <service> ps aux
docker --context ugreen-nas exec <service> netstat -tlnp

# Check Wazuh for correlated events
# Go to wazuh.infinity.ntry.home > Security Events
# Filter by timestamp range and agent
```

### Step 4: Assess Severity

| Scenario | Severity | Action |
|---|---|---|
| Automated scanner (port scan, web crawler) | LOW | Log and monitor |
| Misconfigured app reading all files | LOW | Fix config, close |
| Unknown process reading credentials | HIGH | Isolate container |
| External actor confirmed | CRITICAL | Full IR procedure |

### Step 5: Contain (if HIGH/CRITICAL)

```bash
# Stop the compromised container
docker --context ugreen-nas stop <service>

# Preserve evidence (don't destroy)
docker --context ugreen-nas export <service> > /tmp/<service>-evidence.tar

# Check for lateral movement
docker --context ugreen-nas ps --format "{{.Names}} {{.Status}}"
```

### Step 6: Document

Create a MISP event with all discovered IOCs (see MISP event creation below).

---

## Workflow 2: Suspicious IP in Logs

**Trigger:** Unusual IP addresses found in service logs or Wazuh alerts

### Step 1: Extract the IP

```bash
# From container logs
docker --context ugreen-nas logs <service> --tail 500 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | sort -u

# From Wazuh
# Go to wazuh.infinity.ntry.home > Security Events > filter by rule.groups
```

### Step 2: Check in CTI Platforms

```bash
# OpenCTI
curl -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { stixCyberObservables(search: \"<IP>\") { edges { node { observable_value x_opencti_score created_at } } } }"}'

# MISP
curl -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  https://misp.infinity.ntry.home/attributes/restSearch/value:<IP>
```

### Step 3: External OSINT (if not in CTI)

- Check AbuseIPDB: `https://www.abuseipdb.com/check/<IP>`
- Check Shodan: `https://www.shodan.io/host/<IP>`
- Check GreyNoise: `https://www.greynoise.io/viz/ip/<IP>`

### Step 4: Assess and Act

- **Known scanner (GreyNoise benign):** Log, no action
- **Known malicious (high CTI score):** Block at firewall, document in MISP
- **Unknown:** Monitor for 24h, escalate if pattern continues

---

## Workflow 3: Phishing Campaign Analysis

### Step 1: Extract IOCs from Email

Collect:
- Sender email address and domain
- Reply-to address (if different)
- URLs in email body
- Attachment hashes (SHA256)
- Email headers (especially Received, X-Originating-IP)

### Step 2: Analyze in CyberChef

At `cyberchef.infinity.ntry.home`:

**Defang URLs:**
```
Input: http://evil.com/payload
Recipe: Defang URL
Output: hxxp://evil[.]com/payload
```

**Extract all URLs:**
```
Recipe: Extract URLs > Sort > Unique > Defang URL
```

**Decode Base64 attachment:**
```
Recipe: From Base64 > Strings (min: 4)
```

### Step 3: Check IOCs

Search each IOC in OpenCTI and MISP (see Workflow 2).

### Step 4: Document in MISP

Create a new event:

```bash
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  https://misp.infinity.ntry.home/events/add \
  -d '{
    "Event": {
      "info": "Phishing campaign - <brief description>",
      "distribution": "0",
      "threat_level_id": "2",
      "analysis": "1",
      "Attribute": [
        {"type": "email-src", "value": "attacker@evil.com", "category": "Payload delivery"},
        {"type": "url", "value": "hxxp://evil.com/payload", "category": "Network activity"},
        {"type": "sha256", "value": "<hash>", "category": "Payload delivery"}
      ]
    }
  }'
```

---

## Workflow 4: Compromised Host Investigation

### Step 1: Collect Artifacts

```bash
# Container processes
docker --context <context> exec <container> ps aux

# Network connections
docker --context <context> exec <container> netstat -tlnp

# Open files
docker --context <context> exec <container> ls -la /proc/*/fd 2>/dev/null | head -50

# Recent file modifications
docker --context <context> exec <container> find / -mtime -1 -type f 2>/dev/null
```

### Step 2: Check Wazuh

1. Go to `wazuh.infinity.ntry.home`
2. Filter by the compromised agent/host
3. Look for:
   - File integrity monitoring alerts (syscheck)
   - Authentication failures
   - Network anomalies
   - Rootkit detection alerts

### Step 3: Cross-Reference in CTI

Check every IP, domain, and hash found against OpenCTI and MISP.

### Step 4: Pivot

From discovered IOCs, expand the investigation:
- Found malware hash? Search for related campaigns in OpenCTI
- Found C2 IP? Look for other associated malware
- Found domain? Check registration date (newly registered = suspicious)

### Step 5: Contain and Recover

1. Isolate: Stop container or disconnect from network
2. Preserve: Export container filesystem for evidence
3. Clean: Redeploy from known-good image (GitOps)
4. Verify: Run health checks after redeployment
5. Monitor: Watch for re-infection indicators

---

## MISP Event Creation Standards

### Event Template

| Field | Value |
|---|---|
| Distribution | Organization only (0) |
| Threat Level | 1=High, 2=Medium, 3=Low |
| Analysis | 0=Initial, 1=Ongoing, 2=Completed |
| Tags | TLP:AMBER (default for internal) |

### Attribute Types

| Data | MISP Type | Category |
|---|---|---|
| IP address (destination) | `ip-dst` | Network activity |
| IP address (source) | `ip-src` | Network activity |
| Domain name | `domain` | Network activity |
| URL | `url` | Network activity |
| SHA256 hash | `sha256` | Payload delivery |
| MD5 hash | `md5` | Payload delivery |
| Email sender | `email-src` | Payload delivery |
| Email subject | `email-subject` | Payload delivery |
| Filename | `filename` | Payload delivery |
| YARA rule | `yara` | Payload delivery |

### Tagging Conventions

- `TLP:WHITE` — public, shareable
- `TLP:GREEN` — community, not public
- `TLP:AMBER` — limited distribution (default for homelab)
- `TLP:RED` — restricted, named recipients only
- `misp-galaxy:mitre-attack-pattern` — link to ATT&CK techniques

---

## Evidence Preservation

When investigating a real incident:

1. **Do not restart containers** until evidence is collected
2. **Export container filesystem:** `docker export <container> > evidence.tar`
3. **Save logs:** `docker logs <container> > evidence-logs.txt 2>&1`
4. **Screenshot Wazuh dashboards** at the time of investigation
5. **Create MISP event** with all IOCs and timeline
6. **Store evidence tar** in a secure location with checksum:
   ```bash
   sha256sum evidence.tar > evidence.tar.sha256
   ```
