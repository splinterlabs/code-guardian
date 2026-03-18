#!/bin/bash
# OpenCTI API query examples
# Requires: OPENCTI_TOKEN environment variable

OPENCTI_URL="https://opencti.infinity.ntry.home/graphql"

# Check if token is set
if [[ -z "$OPENCTI_TOKEN" ]]; then
    echo "ERROR: Set OPENCTI_TOKEN first"
    echo "Get it from: OpenCTI > Settings > Profile > API Token"
    exit 1
fi

query_opencti() {
    curl -s -X POST "$OPENCTI_URL" \
        -H "Authorization: Bearer $OPENCTI_TOKEN" \
        -H "Content-Type: application/json" \
        -d "$1"
}

echo "=== Search Observable ==="
echo "Usage: Searches for an IP, domain, or hash"
query_opencti '{"query": "{ stixCyberObservables(search: \"1.2.3.4\", first: 5) { edges { node { observable_value x_opencti_score entity_type } } } }"}' | jq '.'

echo ""
echo "=== Recent Indicators ==="
query_opencti '{"query": "{ indicators(first: 5, orderBy: created_at, orderMode: desc) { edges { node { name pattern x_opencti_score } } } }"}' | jq '.data.indicators.edges[].node'

echo ""
echo "=== Connector Status ==="
query_opencti '{"query": "{ connectorsForImport { name active connector_state updated_at } }"}' | jq '.data.connectorsForImport[]'

echo ""
echo "=== Platform Stats ==="
query_opencti '{"query": "{ stixCyberObservables { pageInfo { globalCount } } indicators { pageInfo { globalCount } } reports { pageInfo { globalCount } } }"}' | jq '.'
