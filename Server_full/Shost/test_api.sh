#!/bin/bash

API_BASE="http://127.0.0.1:5000/api"

echo "🧪 Testing Shikra Host API..."

echo "1. Health Check:"
curl -s "$API_BASE/health" | python3 -m json.tool

echo -e "\n2. Agent Registration Test:"
curl -s -X POST "$API_BASE/v1/agent/register" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "test-agent-001", "name": "Test Agent"}' | python3 -m json.tool

echo -e "\n3. Sample List:"
curl -s "$API_BASE/v1/samples" | python3 -m json.tool

echo -e "\n4. VM Status:"
curl -s "$API_BASE/v1/vm/status" | python3 -m json.tool

echo -e "\n🎉 API Test Complete!"
