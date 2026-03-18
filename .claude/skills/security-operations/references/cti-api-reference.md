# CTI API Reference

API examples for OpenCTI (GraphQL) and MISP (REST).

## Authentication

### OpenCTI
Get token from: OpenCTI > Settings > Profile > API Token

```bash
export OPENCTI_TOKEN="your-token-here"
```

### MISP
Get key from: MISP > Administration > My Profile > Auth key

```bash
export MISP_API_KEY="your-key-here"
```

## OpenCTI GraphQL API

Base URL: `https://opencti.infinity.ntry.home/graphql`

### Search for an Observable (IP, Domain, Hash)

```bash
curl -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($search: String!) {
      stixCyberObservables(search: $search, first: 10) {
        edges {
          node {
            id
            entity_type
            observable_value
            x_opencti_score
            created_at
            createdBy { name }
          }
        }
      }
    }",
    "variables": {"search": "1.2.3.4"}
  }'
```

### List Recent Indicators

```bash
curl -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query {
      indicators(first: 20, orderBy: created_at, orderMode: desc) {
        edges {
          node {
            name
            pattern
            x_opencti_score
            valid_from
            created_at
          }
        }
      }
    }"
  }'
```

### Search Threat Actors

```bash
curl -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($search: String!) {
      threatActors(search: $search, first: 5) {
        edges {
          node {
            name
            description
            aliases
            first_seen
            last_seen
          }
        }
      }
    }",
    "variables": {"search": "APT29"}
  }'
```

### Get Connector Status

```bash
curl -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query {
      connectorsForImport {
        id
        name
        active
        connector_state
        updated_at
      }
    }"
  }'
```

### Search Reports

```bash
curl -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($search: String!) {
      reports(search: $search, first: 10, orderBy: published, orderMode: desc) {
        edges {
          node {
            name
            published
            confidence
            createdBy { name }
          }
        }
      }
    }",
    "variables": {"search": "ransomware"}
  }'
```

## MISP REST API

Base URL: `https://misp.infinity.ntry.home`

### Search Attributes (IOCs)

```bash
# Search by value
curl -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  "https://misp.infinity.ntry.home/attributes/restSearch/value:1.2.3.4"

# Search by type
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  "https://misp.infinity.ntry.home/attributes/restSearch" \
  -d '{"type": "ip-dst", "last": "7d"}'
```

### List Events

```bash
# Recent events
curl -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  "https://misp.infinity.ntry.home/events/index?limit=10&sort=timestamp&direction=desc"

# Search events
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  "https://misp.infinity.ntry.home/events/restSearch" \
  -d '{"searchall": "phishing", "limit": 10}'
```

### Create Event

```bash
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  "https://misp.infinity.ntry.home/events/add" \
  -d '{
    "Event": {
      "info": "Incident: <description>",
      "distribution": "0",
      "threat_level_id": "2",
      "analysis": "0",
      "Tag": [
        {"name": "tlp:amber"}
      ]
    }
  }'
```

### Add Attribute to Event

```bash
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Content-Type: application/json" \
  "https://misp.infinity.ntry.home/attributes/add/<event-id>" \
  -d '{
    "Attribute": {
      "type": "ip-dst",
      "value": "1.2.3.4",
      "category": "Network activity",
      "to_ids": true,
      "comment": "C2 server observed in logs"
    }
  }'
```

### Export IOCs

```bash
# CSV export of IPs
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  -H "Accept: text/csv" \
  "https://misp.infinity.ntry.home/attributes/restSearch" \
  -d '{"type": "ip-dst", "to_ids": true, "last": "30d"}'

# STIX export
curl -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  "https://misp.infinity.ntry.home/events/restSearch?returnFormat=stix2&last=7d"
```

### Feed Management

```bash
# List feeds
curl -H "Authorization: $MISP_API_KEY" \
  -H "Accept: application/json" \
  "https://misp.infinity.ntry.home/feeds/index"

# Enable feed
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  "https://misp.infinity.ntry.home/feeds/enable/<feed-id>"

# Fetch feed data
curl -X POST \
  -H "Authorization: $MISP_API_KEY" \
  "https://misp.infinity.ntry.home/feeds/fetchFromFeed/<feed-id>"
```

## Useful Patterns

### Bulk IOC Check

```bash
# Check multiple IPs against OpenCTI
for ip in 1.2.3.4 5.6.7.8 9.10.11.12; do
  echo "=== $ip ==="
  curl -s -X POST https://opencti.infinity.ntry.home/graphql \
    -H "Authorization: Bearer $OPENCTI_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"query\": \"{ stixCyberObservables(search: \\\"$ip\\\") { edges { node { observable_value x_opencti_score } } } }\"}" | \
    jq '.data.stixCyberObservables.edges[].node'
done
```

### Daily New Indicators Report

```bash
# Get indicators created in last 24 hours
curl -s -X POST https://opencti.infinity.ntry.home/graphql \
  -H "Authorization: Bearer $OPENCTI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query {
      indicators(
        first: 50,
        orderBy: created_at,
        orderMode: desc,
        filters: {
          mode: and,
          filters: [{key: \"created_at\", values: [\"now-1d/d\"], operator: gte}]
        }
      ) {
        edges { node { name pattern x_opencti_score valid_from } }
      }
    }"
  }' | jq '.data.indicators.edges[].node'
```
