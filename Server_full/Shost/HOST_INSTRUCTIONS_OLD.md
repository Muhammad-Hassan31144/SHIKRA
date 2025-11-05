# Shost - Host Server Instructions (Agent v2.0 Compatible)

**Purpose**: Central server that manages malware analysis VMs running the simplified Agent v2.0

---

## Agent v2.0 Expectations

The new agent is **simple and clean** (1,700 lines, single-threaded, uses ProcMon). It expects these exact endpoints:

### Required Endpoints

| Agent Calls | Expected Endpoint | Status |
|-------------|------------------|--------|
| Enrollment (once) | `POST /api/v1/agent/register` | ✅ Exists |
| Poll for work (every 30s) | `GET /api/v1/agents/next-sample` | ⚠️ **MISMATCH** |
| Download binary | `GET /api/v1/samples/{id}/download` | ✅ Exists |
| Upload results | `POST /api/v1/samples/{id}/results` | ✅ Exists |
| Memory trigger | `POST /api/v1/triggers/memory-dump` | ✅ Just created |

### Critical Issue: Endpoint Mismatch

**Agent v2.0 polls**: `GET /api/v1/agents/next-sample` (plural)  
**Your host has**: `GET /api/v1/agent/next-sample` (singular)

**Two options**:
1. Add alias route in `api/routes/samples.py`
2. Fix agent to use `/agent/` instead of `/agents/`

---

## What You Have vs What You Need

### 1. Agent Registration ✅ WORKING
**Endpoint**: `POST /api/v1/agent/register`  
**File**: `api/routes/agents.py::register_agent()`

**How it works**:
- Admin creates enrollment key in dashboard
- Agent sends: `{enrollment_key, machine_fingerprint, hostname}`
- Host returns: `{agent_id, access_token, config}`

**Security**: Tokens hashed (SHA256), fingerprint prevents VM clones

**Test**:
```bash
curl -X POST http://localhost:8080/api/v1/agent/register \
  -H "Content-Type: application/json" \
  -d '{"enrollment_key":"test-key","machine_fingerprint":"fp-123","hostname":"win10"}'
```

---

### 2. Sample Upload ✅ WORKING
**Endpoint**: `POST /api/v1/samples/upload`  
**File**: `api/routes/samples.py::upload_sample()`

**Test**:
```bash
curl -X POST http://localhost:8080/api/v1/samples/upload \
  -F "sample=@malware.exe"
```

---

### 3. Sample Polling ⚠️ ENDPOINT MISMATCH
**Agent expects**: `GET /api/v1/agents/next-sample` (plural)  
**Host has (option A)**: `GET /api/v1/agent/next-sample` (singular, in agents_bp)  
**Host has (option B)**: `GET /api/v1/samples/pending` (in samples_bp)

**Current working endpoint**: `/api/v1/samples/pending`  
**File**: `api/routes/samples.py::get_pending_sample()`

**Response format** (matches agent v2.0):
```json
{
  "id": "sample-abc123",
  "filename": "malware.exe",
  "sha256": "file-hash-here",
  "sizeBytes": 12345,
  "downloadUrl": "/api/v1/agent/download/sample-abc123"
}
```

**Returns 204 if no samples available**

**Test**:
```bash
curl -X GET http://localhost:8080/api/v1/samples/pending \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token"
```

---

### 4. Sample Download ✅ WORKING
**Endpoint**: `GET /api/v1/samples/{id}/download`  
**File**: `api/routes/agents.py::download_sample()` (also aliased in samples_bp)

**Security**: Verifies sample is assigned to requesting agent

**Test**:
```bash
curl -X GET http://localhost:8080/api/v1/samples/sample-abc123/download \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token" \
  --output sample.bin
```

---

### 5. Results Upload ✅ WORKING
**Endpoint**: `POST /api/v1/samples/{id}/results`  
**File**: `api/routes/samples.py::upload_results()`

**Expects**: Multipart form-data with:
- Form field `sample_id`
- Form field `agent_id`  
- File field `results` (ZIP file)

**Test**:
```bash
curl -X POST http://localhost:8080/api/v1/samples/sample-abc123/results \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token" \
  -F "sample_id=sample-abc123" \
  -F "agent_id=agent-12345" \
  -F "results=@results.zip"
```

---

### 6. Memory Dump Trigger ✅ JUST CREATED
**Endpoint**: `POST /api/v1/triggers/memory-dump`  
**File**: `api/routes/triggers.py::trigger_memory_dump()` *(newly created)*

**Request body**:
```json
{
  "sample_id": "sample-abc123",
  "memory_usage_mb": 512
}
```

**What it does**:
1. Gets agent's VM name from `data/agents.json`
2. Runs: `virsh dump <vm_name> <dump_path> --memory-only`
3. Saves dump to: `data/dumps/sample-abc123_<timestamp>.dmp`
4. Records event in `data/analysis.json`

**Test**:
```bash
curl -X POST http://localhost:8080/api/v1/triggers/memory-dump \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token" \
  -H "Content-Type: application/json" \
  -d '{"sample_id":"sample-abc123","memory_usage_mb":512}'
```

---

## Quick Fix for Endpoint Mismatch

### Option 1: Add Alias in samples.py (Recommended)

### 1. Agent Registration ✅
**Endpoint**: `POST /api/v1/agent/register`  
**File**: `api/routes/agents.py::register_agent()`

**How it works**:
- Admin creates enrollment key in dashboard
- VM agent sends enrollment key + machine fingerprint
- Host returns agent_id + access_token
- Token stored as SHA256 hash in `data/agents.json`

**What's already secure**:
- Enrollment keys are hashed (SHA256)
- Tokens are hashed (SHA256), never stored plaintext
- VM clone detection via machine fingerprint
- Re-registration blocked if fingerprint doesn't match

**Test it**:
```bash
curl -X POST http://localhost:8080/api/v1/agent/register \
  -H "Content-Type: application/json" \
  -d '{
    "enrollment_key": "your-key-here",
    "machine_fingerprint": "test-fp-123",
    "hostname": "win10-vm"
  }'
```

**Expected response**:
```json
{
  "agent_id": "agent-12345",
  "access_token": "long-random-token",
  "config": {
    "host_url": "http://localhost:8080/api/v1",
    "poll_interval": 30000
  }
}
```

---

### 2. Sample Upload ⚠️ (Need to verify)
**Expected Endpoint**: `POST /api/v1/samples/upload`  
**File**: `api/routes/samples.py`

**What it should do**:
- Accept file upload via multipart form
- Validate file size (< 100MB)
- Check file extension is allowed
- Calculate SHA256 hash
- Save to `data/samples/<hash>.bin`
- Add entry to `data/samples.json`

**Check if it exists**:
```bash
# Look for the route
grep -n "upload" api/routes/samples.py
```

**If missing, create this route**:
```python
@samples_bp.route('/upload', methods=['POST'])
def upload_sample():
    """Upload a malware sample"""
    try:
        # 1. Check file in request
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'Empty filename'}), 400
        
        # 2. Validate extension
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in Config.ALLOWED_EXTENSIONS:
            return jsonify({'error': f'File type not allowed: {ext}'}), 400
        
        # 3. Read file and calculate hash
        file_data = file.read()
        if len(file_data) > Config.MAX_SAMPLE_SIZE:
            return jsonify({'error': 'File too large'}), 400
        
        file_hash = hashlib.sha256(file_data).hexdigest()
        
        # 4. Check if already exists
        from api.simple_sample_store import sample_store
        existing = sample_store.get_sample_by_hash(file_hash)
        if existing:
            return jsonify({
                'message': 'Sample already exists',
                'sample_id': existing['id']
            }), 200
        
        # 5. Save file
        timestamp = int(time.time())
        filename = f"{file_hash}_{timestamp}.bin"
        file_path = os.path.join(Config.SAMPLE_STORAGE, filename)
        
        os.makedirs(Config.SAMPLE_STORAGE, exist_ok=True)
        with open(file_path, 'wb') as f:
            f.write(file_data)
        
        # 6. Create sample record
        sample_id = f"sample-{secrets.token_hex(8)}"
        sample_data = {
            'id': sample_id,
            'filename': file.filename,
            'file_hash': file_hash,
            'file_size': len(file_data),
            'file_path': file_path,
            'status': 'pending',
            'uploaded_at': datetime.utcnow().isoformat()
        }
        
        sample_store.add_sample(sample_id, sample_data)
        
        logger.info(f"Sample uploaded: {sample_id} ({file.filename})")
        
        return jsonify({
            'sample_id': sample_id,
            'filename': file.filename,
            'file_hash': file_hash,
            'file_size': len(file_data),
            'status': 'pending'
        }), 201
        
    except Exception as e:
        logger.error(f"Upload error: {e}", exc_info=True)
        return jsonify({'error': 'Upload failed'}), 500
```

**Test it**:
```bash
curl -X POST http://localhost:8080/api/v1/samples/upload \
  -F "file=@test_malware.exe"
```

---

### 3. Sample Assignment ✅
**Endpoint**: `GET /api/v1/agent/next-sample`  
**File**: `api/routes/agents.py::get_next_sample()`

**How it works**:
- Agent polls every 30 seconds with Bearer token
- Host checks if agent already has an active sample (one at a time)
- If not, assigns next pending sample from queue
- Returns sample metadata + download URL

**What's already good**:
- Single-assignment policy (one sample per agent)
- Stale sample recovery (if agent crashes)
- Assignment verification on download

**Test it**:
```bash
# Agent polls (requires valid token from registration)
curl -X GET http://localhost:8080/api/v1/agent/next-sample \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token-here"
```

**Response when sample available**:
```json
{
  "sample_id": "sample-abc123",
  "filename": "malware.exe",
  "file_hash": "sha256-hash",
  "file_size": 12345,
  "download_url": "/api/v1/agent/download/sample-abc123"
}
```

**Response when no samples**:
```json
{
  "message": "No samples available"
}
```
*(HTTP 204 No Content)*

---

### 4. Sample Download ✅
**Endpoint**: `GET /api/v1/agent/download/<sample_id>`  
**File**: `api/routes/agents.py::download_sample()`

**How it works**:
- Agent downloads binary after getting assignment
- Host verifies sample is assigned to requesting agent
- Returns raw binary file
- Updates sample status to `downloading`

**Security**:
- Checks assignment before serving file
- Prevents agents from downloading each other's samples

**Test it**:
```bash
curl -X GET http://localhost:8080/api/v1/agent/download/sample-abc123 \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token-here" \
  --output downloaded_sample.bin
```

---

### 5. Results Upload ✅
**Endpoint**: `POST /api/v1/agent/upload/artifacts`  
**File**: `api/routes/agents.py::upload_artifacts()`

**How it works**:
- Agent packages analysis artifacts (logs, JSON, etc.)
- Uploads as multipart form-data
- Includes `metadata` field with sample_id
- Files saved to `data/artifacts/<sample_id>/`

**What it receives**:
- `metadata` (JSON): `{"sample_id": "...", "analysis_id": "..."}`
- `api_calls` (file): JSON log of API calls
- `behavior` (file): Behavior summary
- Additional files (optional)

**Test it**:
```bash
curl -X POST http://localhost:8080/api/v1/agent/upload/artifacts \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token-here" \
  -F 'metadata={"sample_id":"sample-abc123","analysis_id":"analysis-xyz"}' \
  -F "api_calls=@api_calls.json" \
  -F "behavior=@behavior_summary.json"
```

---

### 6. Memory Dump Trigger ❌ (MISSING - Critical)
**Expected Endpoint**: `POST /api/v1/triggers/memory-dump`  
**File**: Need to create `api/routes/triggers.py`

**What it should do**:
- Agent sends trigger when malware does suspicious activity
- Host captures VM memory using `virsh dump`
- Memory dump saved to `data/dumps/<sample_id>_<timestamp>.dmp`

**Create this file**: `api/routes/triggers.py`
```python
"""
Memory dump trigger handling
"""

from flask import Blueprint, request, jsonify
import logging
import os
import time
import subprocess

from ..auth import require_agent_auth
from ..simple_store import agent_store
from ..simple_analysis_store import analysis_store
from config.config import Config

logger = logging.getLogger(__name__)
triggers_bp = Blueprint('triggers', __name__)

@triggers_bp.route('/memory-dump', methods=['POST'])
@require_agent_auth
def trigger_memory_dump():
    """
    Agent triggers memory dump when suspicious activity detected
    
    Request body:
    {
        "sample_id": "sample-abc123",
        "trigger_type": "suspicious" or "critical",
        "score": 150,
        "reason": "CreateRemoteThread detected"
    }
    """
    try:
        agent_id = request.agent_id
        data = request.get_json()
        
        sample_id = data.get('sample_id')
        trigger_type = data.get('trigger_type', 'suspicious')
        score = data.get('score', 0)
        reason = data.get('reason', 'Unknown')
        
        if not sample_id:
            return jsonify({'error': 'Missing sample_id'}), 400
        
        # Get agent's VM name
        agent = agent_store.get_agent(agent_id)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        vm_name = agent.get('vm_name') or agent.get('hostname')
        if not vm_name:
            logger.error(f"No VM name configured for agent {agent_id}")
            return jsonify({'error': 'VM name not configured'}), 500
        
        # Create dump filename
        timestamp = int(time.time())
        dump_filename = f"{sample_id}_{timestamp}.dmp"
        dump_path = os.path.join(Config.DUMP_STORAGE, dump_filename)
        
        # Ensure dump directory exists
        os.makedirs(Config.DUMP_STORAGE, exist_ok=True)
        
        # Capture memory dump using virsh
        logger.info(f"Triggering memory dump for VM {vm_name}: {reason} (score: {score})")
        
        try:
            result = subprocess.run(
                ['virsh', 'dump', vm_name, dump_path, '--memory-only'],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info(f"Memory dump captured: {dump_path}")
                
                # Record trigger in analysis store
                analysis_store.add_memory_dump_trigger(
                    sample_id=sample_id,
                    trigger_type=trigger_type,
                    score=score,
                    reason=reason,
                    dump_path=dump_path
                )
                
                return jsonify({
                    'message': 'Memory dump triggered successfully',
                    'dump_path': dump_path,
                    'trigger_type': trigger_type,
                    'score': score
                }), 200
            else:
                logger.error(f"virsh dump failed: {result.stderr}")
                return jsonify({'error': 'Memory dump failed', 'details': result.stderr}), 500
                
        except subprocess.TimeoutExpired:
            logger.error(f"Memory dump timeout for VM {vm_name}")
            return jsonify({'error': 'Memory dump timeout'}), 500
        
    except Exception as e:
        logger.error(f"Memory dump trigger error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500
```

**Register the blueprint** in `api/app.py`:
```python
from .routes.triggers import triggers_bp

def create_app():
    # ... existing code ...
    app.register_blueprint(triggers_bp, url_prefix='/api/v1/triggers')
    # ... rest of code ...
```

**Test it**:
```bash
curl -X POST http://localhost:8080/api/v1/triggers/memory-dump \
  -H "X-Agent-ID: agent-12345" \
  -H "Authorization: Bearer your-token-here" \
  -H "Content-Type: application/json" \
  -d '{
    "sample_id": "sample-abc123",
    "trigger_type": "critical",
    "score": 500,
    "reason": "CreateRemoteThread + RegSetValueEx detected"
  }'
```

---

## Quick Security Checklist

### Already Implemented ✅
- [x] Tokens stored as SHA256 hashes (never plaintext)
- [x] Enrollment keys validated and marked used
- [x] VM clone detection (machine fingerprint)
- [x] Sample assignment verification (can't download others' samples)
- [x] Bearer token authentication on all agent endpoints

### Need to Add ⚠️
- [ ] Rate limiting on `/register` endpoint (10/hour per IP)
- [ ] File upload size validation (check `MAX_SAMPLE_SIZE`)
- [ ] File extension whitelist (check `ALLOWED_EXTENSIONS`)
- [ ] Path traversal prevention (sanitize filenames)
- [ ] Error logging with request IDs
- [ ] Input validation on all JSON fields

---

## What to Do Right Now

### Step 1: Verify Sample Upload Exists
```bash
cd /home/shikra/DOCS/DYNAMICK/Shost
grep -n "def upload" api/routes/samples.py
```

If you see an upload function, great! If not, copy the code from section 2 above.

### Step 2: Create Memory Dump Trigger
```bash
# Create the new file
cat > api/routes/triggers.py << 'EOF'
# (Paste the code from section 6 above)
EOF
```

### Step 3: Register Triggers Blueprint
```bash
# Edit api/app.py and add this import at top:
# from .routes.triggers import triggers_bp

# Add this line in create_app() function:
# app.register_blueprint(triggers_bp, url_prefix='/api/v1/triggers')
```

### Step 4: Add Missing Store Method
Check if `analysis_store` has `add_memory_dump_trigger()` method:
```bash
grep -n "add_memory_dump_trigger" api/simple_analysis_store.py
```

If missing, add this to `api/simple_analysis_store.py`:
```python
def add_memory_dump_trigger(self, sample_id, trigger_type, score, reason, dump_path):
    """Record a memory dump trigger event"""
    with self.lock:
        analysis_id = self.ensure_analysis_for_sample(sample_id, None, None)
        
        if analysis_id not in self._analyses:
            return False
        
        if 'memory_dumps' not in self._analyses[analysis_id]:
            self._analyses[analysis_id]['memory_dumps'] = []
        
        trigger_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'trigger_type': trigger_type,
            'score': score,
            'reason': reason,
            'dump_path': dump_path
        }
        
        self._analyses[analysis_id]['memory_dumps'].append(trigger_event)
        return self._save_data(self._analyses)
```

### Step 5: Test Everything
```bash
# Start server
./start_shost.sh

# In another terminal, run tests:
# 1. Test health
curl http://localhost:8080/api/health

# 2. Test upload (if you have a test file)
curl -X POST http://localhost:8080/api/v1/samples/upload -F "file=@test.exe"

# 3. Test registration (you'll need an enrollment key from dashboard)
curl -X POST http://localhost:8080/api/v1/agent/register \
  -H "Content-Type: application/json" \
  -d '{"enrollment_key":"test","machine_fingerprint":"fp123","hostname":"test"}'
```

---

## Common Issues

**Issue**: "virsh: command not found"  
**Fix**: Install libvirt: `sudo apt-get install libvirt-clients`

**Issue**: "Permission denied" when capturing memory dump  
**Fix**: Run shost as root OR add user to libvirt group:
```bash
sudo usermod -a -G libvirt $USER
newgrp libvirt
```

**Issue**: Agent registration returns 401  
**Fix**: Check enrollment key is created in `data/agents.json` first

**Issue**: Sample upload fails  
**Fix**: Check `data/samples/` directory exists and is writable

---

## File Structure

```
Shost/
├── api/
│   ├── routes/
│   │   ├── agents.py       ✅ Registration, polling, download, upload
│   │   ├── samples.py      ⚠️ Check if upload exists
│   │   └── triggers.py     ❌ Need to create
│   ├── simple_store.py            ✅ Agent storage
│   ├── simple_sample_store.py     ✅ Sample queue
│   └── simple_analysis_store.py   ⚠️ May need add_memory_dump_trigger()
├── data/
│   ├── agents.json         ✅ Agent records
│   ├── samples.json        ✅ Sample queue
│   ├── samples/            ✅ Binary files
│   ├── artifacts/          ✅ Analysis results
│   └── dumps/              ⚠️ Memory dumps (create if missing)
└── config/
    └── config.py           ✅ Configuration
```

---

## That's It

You have 4 endpoints already working:
1. ✅ Agent registration
2. ⚠️ Sample upload (verify)
3. ✅ Sample assignment
4. ✅ Results upload

You need to add:
5. ❌ Memory dump trigger (code provided above)

Then test end-to-end and ship.
