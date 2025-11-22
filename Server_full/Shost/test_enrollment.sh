#!/bin/bash

# Test enrollment key management for Agent v2.0
# Usage: ./test_enrollment.sh

HOST="http://localhost:8080"

echo "=== Testing Enrollment Key Management ==="
echo ""

# Test 1: Generate enrollment key for win10 VM
echo "1. Generating enrollment key for win10 VM..."
RESPONSE=$(curl -s -X POST "${HOST}/api/v1/enrollment/keys/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "vm_name": "win10-analysis",
    "description": "Windows 10 analysis VM",
    "expires_in_days": 7
  }')

echo "$RESPONSE" | jq '.'

# Extract enrollment key for later use
ENROLLMENT_KEY=$(echo "$RESPONSE" | jq -r '.enrollment_key // empty')
AGENT_ID=$(echo "$RESPONSE" | jq -r '.agent_id // empty')

if [ -z "$ENROLLMENT_KEY" ]; then
  echo "ERROR: Failed to generate enrollment key"
  exit 1
fi

echo ""
echo "✓ Enrollment key generated: $ENROLLMENT_KEY"
echo "✓ Agent ID: $AGENT_ID"
echo ""

# Test 2: List all enrollment keys
echo "2. Listing all enrollment keys..."
curl -s -X GET "${HOST}/api/v1/enrollment/keys/list" | jq '.'
echo ""

# Test 3: Get enrollment status
echo "3. Getting enrollment statistics..."
curl -s -X GET "${HOST}/api/v1/enrollment/status" | jq '.'
echo ""

# Test 4: Simulate agent registration using the enrollment key
echo "4. Simulating agent registration with enrollment key..."
curl -s -X POST "${HOST}/api/v1/agent/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"enrollment_key\": \"$ENROLLMENT_KEY\",
    \"hostname\": \"WIN10-VM\",
    \"os_version\": \"Windows 10 Pro 22H2\",
    \"machine_fingerprint\": \"ABC123-WIN10-TEST\"
  }" | jq '.'
echo ""

# Test 5: Check enrollment status after registration
echo "5. Checking enrollment status after registration..."
curl -s -X GET "${HOST}/api/v1/enrollment/status" | jq '.'
echo ""

# Test 6: Try to revoke a used key (should fail)
echo "6. Attempting to revoke used enrollment key (should fail)..."
curl -s -X POST "${HOST}/api/v1/enrollment/keys/${AGENT_ID}/revoke" | jq '.'
echo ""

# Test 7: Generate and revoke unused key
echo "7. Generating new key and revoking it..."
RESPONSE2=$(curl -s -X POST "${HOST}/api/v1/enrollment/keys/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "vm_name": "win7-test",
    "description": "Test VM to revoke",
    "expires_in_days": 1
  }')

AGENT_ID_2=$(echo "$RESPONSE2" | jq -r '.agent_id // empty')
echo "Generated: $AGENT_ID_2"

if [ -n "$AGENT_ID_2" ]; then
  curl -s -X POST "${HOST}/api/v1/enrollment/keys/${AGENT_ID_2}/revoke" | jq '.'
  echo ""
fi

echo "=== All tests completed ==="
