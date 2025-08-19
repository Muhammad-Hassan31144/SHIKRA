#!/bin/bash

# Quick check of agent store status
# Usage: ./check_agents.sh

HOST="http://localhost:8080"

echo "=== Agent Store Status Check ==="
echo ""

# Check what's in agents.json file
echo "1. File content (agents.json):"
cat data/agents.json | jq '.' 2>/dev/null || cat data/agents.json
echo ""

# Check via API health endpoint (if available)
echo "2. API Health Check:"
curl -s "${HOST}/api/health" | jq '.' 2>/dev/null || echo "API not running"
echo ""

# Try listing agents via enrollment API
echo "3. Enrollment API - List Keys:"
curl -s "${HOST}/api/v1/enrollment/keys/list" | jq '.' 2>/dev/null || echo "Enrollment API not available"
echo ""

# Try enrollment status
echo "4. Enrollment API - Status:"
curl -s "${HOST}/api/v1/enrollment/status" | jq '.' 2>/dev/null || echo "Enrollment API not available"
echo ""

echo "=== Summary ==="
AGENT_COUNT=$(cat data/agents.json 2>/dev/null | jq '. | length' 2>/dev/null || echo "0")
echo "Agents in file: $AGENT_COUNT"
echo ""

if [ "$AGENT_COUNT" -eq 0 ]; then
  echo "✓ No agents configured (clean state)"
else
  echo "⚠ Found $AGENT_COUNT agent(s) in file"
  echo "Agent IDs:"
  cat data/agents.json | jq -r 'keys[]' 2>/dev/null
fi
