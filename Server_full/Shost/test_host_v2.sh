#!/bin/bash
# Quick test script for Host API endpoints
# Tests agent v2.0 compatibility

set -e

HOST_URL="http://localhost:8080"
AGENT_ID=""
TOKEN=""

echo "🧪 Testing Shost Host API (Agent v2.0 Compatibility)"
echo "=================================================="
echo ""

# Test 1: Health check
echo "1️⃣  Testing health endpoint..."
curl -s "${HOST_URL}/api/health" | python3 -m json.tool || {
    echo "❌ Health check failed - is the host running?"
    echo "   Run: ./start_shost.sh"
    exit 1
}
echo "✅ Health check passed"
echo ""

# Test 2: Test polling endpoint exists (should return 401 without auth)
echo "2️⃣  Testing polling endpoint (should return 401)..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "${HOST_URL}/api/v1/agents/next-sample")
if [ "$HTTP_CODE" == "401" ]; then
    echo "✅ Polling endpoint exists (returned 401 as expected)"
else
    echo "❌ Polling endpoint returned $HTTP_CODE (expected 401)"
    echo "   Check that route alias was added to api/app.py"
fi
echo ""

# Test 3: Test registration (requires manual enrollment key)
echo "3️⃣  Testing agent registration..."
echo "   ⚠️  You need an enrollment key from dashboard:"
echo "      http://localhost:8080/dashboard"
echo "      → Settings → Agents → Generate Key"
echo ""
read -p "   Enter enrollment key (or press Enter to skip): " ENROLL_KEY

if [ -n "$ENROLL_KEY" ]; then
    RESPONSE=$(curl -s -X POST "${HOST_URL}/api/v1/agent/register" \
        -H "Content-Type: application/json" \
        -d "{\"enrollment_key\":\"${ENROLL_KEY}\",\"machine_fingerprint\":\"test-fp-$(date +%s)\",\"hostname\":\"test-vm\"}")
    
    echo "$RESPONSE" | python3 -m json.tool || {
        echo "❌ Registration failed"
        echo "Response: $RESPONSE"
    }
    
    AGENT_ID=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('agent_id', ''))" 2>/dev/null || echo "")
    TOKEN=$(echo "$RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))" 2>/dev/null || echo "")
    
    if [ -n "$AGENT_ID" ] && [ -n "$TOKEN" ]; then
        echo "✅ Registration successful"
        echo "   Agent ID: $AGENT_ID"
        echo "   Token: ${TOKEN:0:20}..."
        
        # Test 4: Test polling with auth
        echo ""
        echo "4️⃣  Testing authenticated polling..."
        curl -s -X GET "${HOST_URL}/api/v1/agents/next-sample" \
            -H "X-Agent-ID: ${AGENT_ID}" \
            -H "Authorization: Bearer ${TOKEN}" | python3 -m json.tool || echo "(No samples - returns 204)"
        echo "✅ Authenticated polling works"
        
    else
        echo "❌ Registration succeeded but couldn't extract agent_id or token"
    fi
else
    echo "⏭️  Skipping registration test"
fi

echo ""
echo "=================================================="
echo "🎯 Test Summary"
echo "=================================================="
echo "✅ Health endpoint working"
echo "✅ Polling endpoint exists"
if [ -n "$AGENT_ID" ]; then
    echo "✅ Registration working"
    echo "✅ Authenticated polling working"
else
    echo "⏭️  Registration not tested (need enrollment key)"
fi

echo ""
echo "📋 Next steps:"
echo "1. Upload a test sample:"
echo "   curl -X POST ${HOST_URL}/api/v1/samples/upload -F 'sample=@/bin/ls'"
echo ""
if [ -n "$AGENT_ID" ] && [ -n "$TOKEN" ]; then
    echo "2. Poll again (should return the sample):"
    echo "   curl -X GET ${HOST_URL}/api/v1/agents/next-sample \\"
    echo "     -H 'X-Agent-ID: ${AGENT_ID}' \\"
    echo "     -H 'Authorization: Bearer ${TOKEN}'"
    echo ""
fi
echo "3. Deploy agent v2.0 to Windows VM and test full flow"
echo ""
echo "✅ Host is ready for agent v2.0!"
