# Feed Management Reference

Complete catalog of threat intelligence feeds and connector management.

## Currently Active Feeds

### OpenCTI Connectors

| Connector | Status | Interval | Scope |
|---|---|---|---|
| AlienVault OTX | Active | 1 hour | identity, report, indicator, stix-bundle |

**AlienVault OTX Configuration:**
- Base URL: `https://otx.alienvault.com`
- Requires: `ALIENVAULT_KEY` in Portainer
- Confidence Level: 10 (configurable)
- Start Date: 2024-01-01

## Recommended Free Feeds

### For OpenCTI

| Feed | Type | Notes |
|---|---|---|
| AlienVault OTX | Public | Already configured |
| MISP Feed | STIX | Sync from local MISP instance |
| Abuse.ch (URLhaus, MalwareBazaar, ThreatFox) | IOCs | Free, high quality |
| CIRCL OSINT | MISP | Community intelligence |
| OpenCTI Datasets | Enrichment | MITRE ATT&CK, sectors, countries |
| VirusTotal | Enrichment | Freemium, rate limited |

### For MISP

| Feed | Format | Notes |
|---|---|---|
| CIRCL OSINT Feed | MISP | Pre-configured in MISP |
| Botvrij.eu | MISP | European focus |
| abuse.ch Feodo Tracker | CSV/JSON | Banking trojans |
| PhishTank | JSON | Community verified |
| Emerging Threats | Snort/Suricata | IDS rules + IOCs |

## Adding a New OpenCTI Connector

### Step 1: Find the Connector

Browse available connectors:
https://github.com/OpenCTI-Platform/connectors

Connector types:
- **External import** — pulls data from external sources
- **Internal enrichment** — enriches existing data
- **Internal import** — processes uploaded files

### Step 2: Add to Compose

Add a new service to `opencti/compose.yml`:

```yaml
connector-abuse-ssl:
  image: opencti/connector-abuse-ssl:6.3.8
  restart: unless-stopped
  deploy:
    resources:
      limits:
        cpus: '0.50'
        memory: 256M
  environment:
    - OPENCTI_URL=http://opencti:8080
    - OPENCTI_TOKEN=${OPENCTI_ADMIN_TOKEN}
    - CONNECTOR_ID=${ABUSE_SSL_CONNECTOR_ID}      # Generate with: uuidgen
    - CONNECTOR_TYPE=EXTERNAL_IMPORT
    - CONNECTOR_NAME=Abuse.ch SSL Blacklist
    - CONNECTOR_SCOPE=abuse-ssl
    - CONNECTOR_CONFIDENCE_LEVEL=70
    - CONNECTOR_UPDATE_EXISTING_DATA=true
    - CONNECTOR_LOG_LEVEL=info
    - ABUSE_SSL_URL=https://sslbl.abuse.ch/blacklist/sslblacklist.csv
    - ABUSE_SSL_INTERVAL=3600                       # Seconds between fetches
  networks:
    - internal
```

### Step 3: Configure Secrets

In Portainer, add to the OpenCTI stack environment:
- `ABUSE_SSL_CONNECTOR_ID` — generate with `uuidgen`
- Any API keys the connector needs

### Step 4: Deploy

```bash
cd homelab-security
make validate && make preflight
git add opencti/compose.yml
git commit -m "Add abuse.ch SSL connector"
git push
```

### Step 5: Verify

1. Check connector status in OpenCTI: Data > Connectors
2. Verify data is flowing: Data > Entities (sort by creation date)

## Adding MISP Feeds

### Via Web UI

1. Login to `misp.infinity.ntry.home`
2. Sync Actions > List Feeds
3. Load Default Feed Metadata (first time)
4. Toggle "Enabled" for desired feeds
5. Click "Fetch and store all feed data"

### Via API

```bash
# List available feeds
curl -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  https://misp.infinity.ntry.home/feeds/index

# Enable a feed (by ID)
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  https://misp.infinity.ntry.home/feeds/enable/<feed-id>

# Fetch feed data
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  https://misp.infinity.ntry.home/feeds/fetchFromFeed/<feed-id>
```

## Data Retention

CTI data grows fast. Configure retention to prevent disk exhaustion:

### OpenCTI
- Settings > Parameters > Data retention
- Recommended: 90-day retention for indicators
- Monitor Elasticsearch disk: `df -h` on Infinity Node

### MISP
- Server Settings > MISP Settings > default_event_tag_collection
- Prune old events via: Administration > Server Settings > Maintenance

### Elasticsearch (Shared)
- Index lifecycle management (ILM) policies
- Monitor: `curl http://elasticsearch:9200/_cat/indices?v`
- Clean old indices: `curl -X DELETE http://elasticsearch:9200/opencti_history-*`

## Rate Limiting Awareness

| Service | Limit | Impact |
|---|---|---|
| AlienVault OTX | 1000 req/hour | Set connector interval > 3600s |
| VirusTotal Free | 4 req/minute | Set enrichment interval > 15s |
| Abuse.ch | No hard limit | Be reasonable (hourly) |
| PhishTank | No hard limit | Hourly recommended |

## Feed Categories

### Malware Intelligence
- **MalwareBazaar** (abuse.ch) — malware samples and hashes
- **URLhaus** (abuse.ch) — malware distribution URLs
- **ThreatFox** (abuse.ch) — IOCs from malware families

### Network Threats
- **Feodo Tracker** — banking trojan C2 servers
- **SSL Blacklist** — malicious SSL certificates
- **Blocklist.de** — brute force attacker IPs

### Phishing & Fraud
- **PhishTank** — verified phishing URLs
- **OpenPhish** — phishing URLs

### APT & Threat Actors
- **MITRE ATT&CK** — TTP framework (OpenCTI dataset)
- **Malpedia** — APT malware reference

## New Feed Checklist

1. Identify feed URL and format (STIX, MISP, CSV, JSON)
2. Check if OpenCTI connector exists
3. Generate unique `CONNECTOR_ID` with `uuidgen`
4. Add connector service to compose.yml
5. Configure secrets in Portainer
6. Test with short interval, then adjust to production
7. Monitor data flow in OpenCTI/MISP
8. Document in this file
