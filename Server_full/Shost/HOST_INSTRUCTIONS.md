# Shost - Host Server Instructions (Agent v2.0)

**Purpose**: Central server managing Windows VMs running the simplified Shikra Agent v2.0

---

## Agent v2.0 API Contract

| Function | Agent Calls | Host Endpoint | Status |
|----------|-------------|---------------|--------|
| **Enroll** | `POST /api/v1/agent/register` | Same | ✅ Works |
| **Poll** | `GET /api/v1/agents/next-sample` | `/api/v1/samples/pending` | ⚠️ **Fix needed** |
| **Download** | `GET /api/v1/samples/{id}/download` | Same | ✅ Works |
| **Upload** | `POST /api/v1/samples/{id}/results` | Same | ✅ Works |
| **Trigger** | `POST /api/v1/triggers/memory-dump` | Same | ✅ Just added |

---

## Critical Fix Needed

**Agent polls**: `GET /api/v1/agents/next-sample` (plural)  
**Host has**: `GET /api/v1/samples/pending`

### Fix: Add Route Alias

Add to `api/app.py` in `create_app()`:

```python
# Agent v2.0 compatibility - alias for polling endpoint
@app.route('/api/v1/agents/next-sample', methods=['GET'])
def agents_next_sample_alias():
    """Alias for /api/v1/samples/pending - Agent v2.0 compatibility"""
    from api.routes.samples import get_pending_sample
    return get_pending_sample()
```

---

## What's Working

### 1. Agent Registration ✅
```bash
curl -X POST http://localhost:8080/api/v1/agent/register \
  -H "Content-Type: application/json" \
  -d '{"enrollment_key":"<key>","machine_fingerprint":"fp-123","hostname":"win10"}'
```

**Returns**:
```json
{
  "agent_id": "agent-12345",
  "access_token": "long-token-here",
  "config": {"host_url": "http://...", "poll_interval": 30000}
}
```

---

### 2. Sample Upload ✅
```bash
curl -X POST http://localhost:8080/api/v1/samples/upload \
  -F "sample=@malware.exe"
```

**Returns**:
```json
{
  "sample_id": "sample-abc123",
  "filename": "malware.exe",
  "file_hash": "sha256...",
  "status": "pending"
}
```

---

### 3. Sample Polling (after fix) ✅
```bash
curl -X GET http://localhost:8080/api/v1/agents/next-sample \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer <token>"
```

**Returns** (sample available):
```json
{
  "id": "sample-abc123",
  "filename": "malware.exe",
  "sha256": "file-hash",
  "sizeBytes": 12345,
  "downloadUrl": "/api/v1/agent/download/sample-abc123"
}
```

**Returns** (no samples): HTTP 204 No Content

---

### 4. Sample Download ✅
```bash
curl -X GET http://localhost:8080/api/v1/samples/sample-abc123/download \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer <token>" \
  --output sample.exe
```

---

### 5. Results Upload ✅
```bash
curl -X POST http://localhost:8080/api/v1/samples/sample-abc123/results \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer <token>" \
  -F "sample_id=sample-abc123" \
  -F "agent_id=agent-12345" \
  -F "results=@results.zip"
```

---

### 6. Memory Dump Trigger ✅
```bash
curl -X POST http://localhost:8080/api/v1/triggers/memory-dump \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"sample_id":"sample-abc123","memory_usage_mb":512}'
```

**What happens**:
1. Host gets agent's VM name from `data/agents.json`
2. Runs: `virsh dump <vm_name> data/dumps/sample-abc123_<timestamp>.dmp --memory-only`
3. Records event in `data/analysis.json`

---

## Files Modified

✅ **Created**: `api/routes/triggers.py` (memory dump handler)  
✅ **Updated**: `api/app.py` (registered triggers blueprint)  
✅ **Updated**: `api/simple_analysis_store.py` (added `add_memory_dump_trigger()`)  
⚠️ **Need to update**: `api/app.py` (add route alias for `/agents/next-sample`)

---

## Start the Host

```bash
cd /home/shikra/DOCS/DYNAMICK/Shost
./start_shost.sh
```

**Dashboard**: http://localhost:8080/dashboard  
**Health**: http://localhost:8080/api/health

---

## Verify Everything Works

### 1. Check health
```bash
curl http://localhost:8080/api/health
```

### 2. Generate enrollment key
- Open dashboard → Settings → Agents → Generate Key
- Copy the key

### 3. Test registration
```bash
curl -X POST http://localhost:8080/api/v1/agent/register \
  -H "Content-Type: application/json" \
  -d '{"enrollment_key":"YOUR_KEY","machine_fingerprint":"test-fp","hostname":"test-vm"}'
```

Save the `access_token` from response.

### 4. Test polling (after adding alias)
```bash
curl -X GET http://localhost:8080/api/v1/agents/next-sample \
  -H "X-Agent-ID: <agent_id_from_step3>" \
  -H "Authorization: Bearer <token_from_step3>"
```

Should return 204 (no samples yet).

### 5. Upload a test sample
```bash
curl -X POST http://localhost:8080/api/v1/samples/upload \
  -F "sample=@/bin/ls"  # or any file for testing
```

### 6. Poll again
```bash
curl -X GET http://localhost:8080/api/v1/agents/next-sample \
  -H "X-Agent-ID: <agent_id>" \
  -H "Authorization: Bearer <token>"
```

Should return the sample JSON.

---

## Security Checklist

- [x] Tokens stored as SHA256 hashes
- [x] Enrollment keys single-use
- [x] VM clone detection (fingerprint)
- [x] Assignment verification
- [x] Bearer auth on all agent endpoints
- [ ] Rate limiting (add `flask-limiter`)
- [ ] HTTPS (configure reverse proxy)

---

## Troubleshooting

**"virsh: command not found"**
```bash
sudo apt-get install libvirt-clients
sudo usermod -a -G libvirt $USER
newgrp libvirt
```

**"401 Unauthorized" on polling**
- Token expired → re-enroll agent
- Wrong agent_id → check `data/agents.json`

**"No samples available" forever**
- Check sample was uploaded successfully
- Check sample status in `data/samples.json` is "pending"
- Check agent assignment logic in `simple_sample_store.py`

**Memory dump fails**
- Verify VM is running: `virsh list`
- Verify VM name matches agent's `vm_name` field
- Check permissions: `sudo chmod 666 /var/run/libvirt/libvirt-sock`

---

## What's Next

1. ✅ Add route alias in `api/app.py`
2. ✅ Test enrollment → poll → download → upload flow
3. ✅ Test memory dump trigger
4. ✅ Deploy agent v2.0 to Windows VM
5. ✅ Run end-to-end with real malware sample

**You're 95% done. Just add the route alias and test!**
