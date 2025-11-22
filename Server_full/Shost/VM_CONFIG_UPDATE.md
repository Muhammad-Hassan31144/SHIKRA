# VM Configuration Update for Agent v2.0

## Problem Solved ✅

The old VM configuration system generated `Shikra.ini` files with pre-configured `agent_id` and `agent_secret`. This is **incompatible** with Agent v2.0's enrollment-based workflow.

## New Enrollment System

### How It Works

**Old System (DEPRECATED):**
```
Admin → Create VM Config → Generate Shikra.ini → Deploy to VM → Agent reads config
```

**New System (Agent v2.0 Compatible):**
```
Admin → Generate Enrollment Key → Deploy ShikraAgent.exe → Agent enrolls → Gets agent_id/token → Saves agent_config.json
```

### New API Endpoints

Created `/api/v1/enrollment/` with these endpoints:

1. **POST `/api/v1/enrollment/keys/generate`** - Generate enrollment key
2. **GET `/api/v1/enrollment/keys/list`** - List all keys  
3. **GET `/api/v1/enrollment/status`** - Get statistics
4. **POST `/api/v1/enrollment/keys/<agent_id>/revoke`** - Revoke unused key

### Files Changed

1. **Created:** `api/routes/enrollment.py` (197 lines)
   - Complete enrollment key management
   - Generates secure random keys
   - Stores SHA256 hash only
   - Tracks usage and expiry

2. **Updated:** `api/app.py`
   - Imported `enrollment_bp`
   - Registered at `/api/v1/enrollment`

3. **Created:** `test_enrollment.sh`
   - Full test suite for enrollment workflow
   - Tests key generation, listing, revocation

4. **Created:** `check_agents.sh`
   - Quick status check script
   - Shows file content and API status

## How to Use (Admin Workflow)

### Step 1: Generate Enrollment Key

```bash
curl -X POST http://localhost:8080/api/v1/enrollment/keys/generate \
  -H "Content-Type: application/json" \
  -d '{
    "vm_name": "win10-analysis",
    "description": "Windows 10 analysis VM",
    "expires_in_days": 7
  }'
```

**Response:**
```json
{
  "success": true,
  "enrollment_key": "xK9mP2nQ7vR4wS8tU1yZ3aB5cD6eF0gH1iJ2kL3mN4oP5qR6sT7uV8wX9yZ0",
  "agent_id": "agent-win10-analysis",
  "vm_name": "win10-analysis",
  "expires_at": "2025-11-16T06:12:00",
  "instructions": [...]
}
```

⚠️ **IMPORTANT:** Copy the `enrollment_key` immediately - it's shown **only once**!

### Step 2: Deploy Agent to Windows VM

1. Copy `ShikraAgent.exe` to VM (e.g., `C:\SecurityHealth\`)
2. Run enrollment command:
   ```cmd
   cd C:\SecurityHealth
   ShikraAgent.exe --enroll xK9mP2nQ7vR4wS8tU1yZ3aB5cD6eF0gH1iJ2kL3mN4oP5qR6sT7uV8wX9yZ0
   ```
3. Enter Shost URL when prompted:
   ```
   http://192.168.100.1:8080/api/v1
   ```
4. Agent automatically creates `agent_config.json` with received credentials

### Step 3: Start Agent

```cmd
ShikraAgent.exe
```

The agent will:
- Load config from `agent_config.json`
- Start polling `/api/v1/agents/next-sample`
- Process samples and upload results

## How to Verify Clean State

### Check File Content

```bash
cat data/agents.json
```

Should show: `{}`

### Check via API

```bash
./check_agents.sh
```

Should show:
```
Agents in file: 0
✓ No agents configured (clean state)
```

### Check Enrollment Status

```bash
curl -s http://localhost:8080/api/v1/enrollment/status | jq
```

Should show all counts at 0:
```json
{
  "statistics": {
    "total_keys": 0,
    "pending": 0,
    "enrolled": 0,
    "revoked": 0,
    "expired": 0
  }
}
```

## Troubleshooting "Old Agent Still Showing"

### Issue: Web dashboard shows old agents after clearing agents.json

**Cause:** Browser caching or Flask app using in-memory cache

**Solutions:**

1. **Hard refresh browser:**
   - Chrome/Firefox: Ctrl+Shift+R (or Cmd+Shift+R on Mac)
   - Or open in incognito/private mode

2. **Restart Flask app:**
   ```bash
   # Stop current server (Ctrl+C)
   ./start_shost.sh
   ```

3. **Verify file is actually empty:**
   ```bash
   cat data/agents.json
   # Should show: {}
   ```

4. **Check API directly (bypasses templates):**
   ```bash
   curl http://localhost:8080/api/v1/enrollment/keys/list
   ```

### Issue: Old admin enrollment form still uses Shikra.ini

**Solution:** The old admin form at `/admin/enroll` is still there but **uses the new enrollment system**. It:
- Generates enrollment keys (not INI files)
- Shows enrollment key on success page
- Stores in same `agents.json` with new format

The form UI is the same, but the backend has been updated.

## Testing the Complete Flow

Run the full test suite:

```bash
./test_enrollment.sh
```

This tests:
1. ✅ Generate enrollment key
2. ✅ List keys
3. ✅ Get statistics  
4. ✅ Simulate agent registration with key
5. ✅ Verify key marked as "used"
6. ✅ Revoke unused key
7. ✅ Block revocation of used key

## Migration from Old System

If you have old VM configs with `Shikra.ini` files:

1. **Don't use them** - Agent v2.0 doesn't read INI files
2. **Generate new enrollment keys** for each VM
3. **Re-deploy Agent v2.0** with new enrollment workflow
4. **Delete old `Shikra.ini`** files from VMs

## Summary

✅ **Problem:** Old VM config system incompatible with Agent v2.0  
✅ **Solution:** New enrollment key system implemented  
✅ **Status:** Fully tested and working  
✅ **Files:** Empty `agents.json = {}` means clean state  
✅ **Next:** Generate enrollment keys and deploy Agent v2.0  

The VM configuration system is now **fully updated** to work with ShikraAgent.exe v2.0! 🎉
