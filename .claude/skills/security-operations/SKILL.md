---
name: security-operations
description: >
  ALWAYS consult this skill for ANY security-related task in the HomeLab — threat
  investigation, incident response, threat intelligence, or security monitoring. This
  includes investigating suspicious IPs, analyzing suspicious files, ingesting threat
  feeds into OpenCTI or MISP, exporting IOCs, OSINT investigations, decoding payloads
  with CyberChef, responding to Wazuh alerts, honeytoken alerts, phishing analysis,
  threat hunting, STIX/TAXII feeds, or SIEM operations. If a user mentions anything
  security-related — suspicious activity, malicious IPs, threat feeds, IOCs, security
  alerts, incident response, Wazuh, MISP, OpenCTI, CyberChef, honeytokens, or threat
  actors — you MUST use this skill. It contains the Infinity Node security stack
  architecture and operational procedures.
version: 0.1.0
---

# Security Operations

Procedural guide for threat intelligence, incident response, and security operations
using the HomeLab's CTI platform on the Infinity Node.

## Platform Overview

| Service | URL | Purpose |
|---|---|---|
| OpenCTI | `opencti.infinity.ntry.home` | Threat intelligence platform (relationships, campaigns, STIX) |
| MISP | `misp.infinity.ntry.home` | IOC management and sharing (events, attributes, feeds) |
| CyberChef | `cyberchef.infinity.ntry.home` | Data analysis, decoding, transformation |
| Wazuh | `wazuh.infinity.ntry.home` | SIEM/XDR, log correlation, compliance |
| MCP-Maigret | via MCP | OSINT username search |

All services run on the **Infinity Node** (Docker context: `cti-infinity`).

## Common Operations

### Check if an IP/Domain/Hash is Malicious

**Quick path — OpenCTI:**
1. Navigate to `opencti.infinity.ntry.home`
2. Search bar: enter the IOC (IP, domain, hash)
3. Review: associated campaigns, threat actors, confidence score

**Alternative — MISP:**
1. Navigate to `misp.infinity.ntry.home`
2. Search > Quick Search > enter IOC
3. Check correlation with existing events

**API method:**
```bash
# OpenCTI GraphQL
curl -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "query { stixCyberObservables(search: \"<IOC>\") { edges { node { observable_value x_opencti_score } } } }"}'

# MISP REST
curl -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  https://misp.infinity.ntry.home/attributes/restSearch/value:<IOC>
```

### Ingest a Threat Feed

**For OpenCTI:**
1. Check if a connector exists: https://github.com/OpenCTI-Platform/connectors
2. Add connector as a service in `opencti/compose.yml`
3. Set secrets in Portainer (API tokens, connector IDs)
4. Generate unique `CONNECTOR_ID` (UUID) for each connector

**For MISP:**
1. Login to MISP
2. Sync Actions > List Feeds
3. Load Default Feed Metadata (or add custom URL)
4. Enable desired feeds
5. Fetch and store all feed data

Currently active: **AlienVault OTX** (hourly sync to OpenCTI).
See `references/feed-management.md` for the full feed catalog and adding new feeds.

### Create a MISP Event

For documenting incidents, phishing campaigns, or discovered IOCs:

1. Login to `misp.infinity.ntry.home`
2. Add Event > New Event
3. Set distribution, threat level, and analysis state
4. Add attributes:
   - IP addresses (type: `ip-dst` or `ip-src`)
   - Domains (type: `domain`)
   - URLs (type: `url`)
   - File hashes (type: `sha256`, `md5`)
   - Email addresses (type: `email-src`)
5. Tag with TLP (Traffic Light Protocol) for sharing control
6. Publish when ready for correlation

### Export IOCs for Blocking

**From MISP:**
- Events > Select > Export as CSV, STIX, Snort/Suricata rules, or plain text

**From OpenCTI:**
- Data > Indicators > Filter by confidence > 70, recent dates
- Export as CSV or STIX bundle

### OSINT Investigation

Use MCP-Maigret (available via MCP tool) for username searches across platforms.
For IP/domain OSINT, cross-reference in OpenCTI with ingested feed data.

## CyberChef Quick Recipes

Common analysis recipes at `cyberchef.infinity.ntry.home`:

| Task | Recipe |
|---|---|
| Decode Base64 PowerShell | `From Base64` > `Decode text (UTF-16LE)` |
| Extract URLs from text | `Extract URLs` > `Defang URL` |
| Defang IOCs for sharing | `Defang URL` > `Defang IP Addresses` |
| Analyze file entropy | `Entropy` |
| Extract strings from binary | `Strings (min length: 4)` |
| Decode XOR'd malware config | `From Base64` > `XOR (key)` > `Strings` |

## Honeytoken Alerts

When a honeytoken alert fires (via ntfy), investigate immediately:

1. **Identify**: Which service, which file, what timestamp?
2. **Check container logs**: `docker logs <service> --since <alert-time>`
3. **Check Wazuh**: Look for correlated events around the same timestamp
4. **Assess**: Was it a scanner, misconfiguration, or actual breach?
5. **Document**: Create a MISP event if it's a real incident

Honeytoken monitoring test: `./homelab-dev-scripts/scripts/test-honeytokens.sh`

## Wazuh SIEM

Wazuh provides security event correlation, compliance monitoring, and intrusion detection.

### Key Dashboards
- Security events overview
- File integrity monitoring
- Vulnerability detection
- Compliance (PCI DSS, HIPAA)

### Common Queries
- Failed logins: filter by `rule.groups: authentication_failed`
- File changes: filter by `rule.groups: syscheck`
- Network anomalies: filter by `rule.groups: network`

## Service Health

```bash
# Quick status via Makefile
cd homelab-security && make status

# Individual services
make misp-status
make opencti-status

# Via Docker context
docker --context cti-infinity ps
```

## Deployment (Security Stack)

Security services follow the same GitOps flow but deploy to the Infinity Node:

1. Edit `<service>/compose.yml`
2. Validate: `make validate && make preflight`
3. Push: `git push`
4. Portainer on Infinity Node auto-deploys

**Key difference from main stack:** Security services use
`<service>.infinity.ntry.home` domain (not `<service>.ntry.home`).

## Anti-Patterns

- Never share raw (fanged) IOCs in chat — always defang first
- Never expose MISP/OpenCTI to the internet — internal access only
- Never store API tokens in compose files — use Portainer env vars
- Do not run analysis tools on production hosts — use the Infinity Node

## Additional Resources

### Reference Files

- **`references/feed-management.md`** - Complete feed catalog, connector setup, data retention
- **`references/incident-response.md`** - Step-by-step IR workflows, evidence collection, MISP documentation
- **`references/cti-api-reference.md`** - OpenCTI GraphQL and MISP REST API examples

### Example Files

- **`examples/opencti-query-examples.sh`** - Common OpenCTI API queries
- **`examples/misp-event-template.json`** - Template for creating standardized MISP events
