# Dashboard Updated for Agent v2.0

## Summary

The admin dashboard has been completely updated to support Agent v2.0's enrollment key workflow. All references to INI files and old agent configuration have been removed.

## Files Updated

### 1. `/api/routes/admin.py`
**Changes:**
- Updated `enroll_agent_submit()` to generate enrollment keys instead of pre-configured agents
- Generates `agent_id` from VM name (format: `agent-<vm-name>`)
- Uses `agent_store.put_agent()` with new data structure
- Adds expiry timestamp (default 7 days)
- Status set to `awaiting_enrollment` instead of `pending`

**New fields in agent record:**
```python
{
    'agent_id': 'agent-win10-analysis',
    'vm_name': 'win10-analysis',
    'description': 'Windows 10 analysis VM',
    'enrollment_key_hash': 'sha256...',
    'enrollment_used': False,
    'enrollment_created': '2025-11-09T12:00:00',
    'enrollment_expires': 1731153600,
    'status': 'awaiting_enrollment'
}
```

### 2. `/api/templates/enroll_agent.html`
**Changes:**
- Removed "Agent Name" field (not needed - derived from VM name)
- VM selection is now **required** (Agent v2.0 requirement)
- Added "Key Expires In (days)" field (default: 7, range: 1-30)
- Updated info box with Agent v2.0 workflow
- Updated button text to "🔑 Generate Enrollment Key"

**New workflow shown:**
1. Select VM and generate enrollment key
2. Copy the enrollment key (shown once only!)
3. On Windows VM: `ShikraAgent.exe --enroll <key>`
4. Agent auto-creates agent_config.json and starts polling

### 3. `/api/templates/enrollment_success.html`
**Changes:**
- Title changed to "Enrollment Key Generated!"
- Shows expiry time in days
- Updated deployment instructions for Agent v2.0
- Removed references to old commands like `net start ShikraAgent`
- Added explicit command example with actual key shown

**New instructions include:**
```batch
cd C:\SecurityHealth
ShikraAgent.exe --enroll <actual_key_from_form>
# Prompts for Shost URL: http://YOUR_HOST_IP:8080/api/v1
# Auto-creates agent_config.json
ShikraAgent.exe  # Start polling
```

### 4. `/api/templates/agents_list.html` (NEW)
**Created fresh template showing:**
- Dashboard statistics:
  - Total Keys
  - Pending Enrollment  
  - Enrolled
- Agents table with columns:
  - Agent ID
  - VM Name
  - Status (✓ Enrolled / ⏳ Awaiting / Expired)
  - Key Created
  - Enrolled (Yes/No)
  - Last Seen
- Empty state when no agents exist
- Quick action buttons

## Dashboard Routes

### Admin Endpoints
- `GET /admin/` - Dashboard home
- `GET /admin/enroll` - Enrollment key generation form
- `POST /admin/enroll` - Process key generation
- `GET /admin/agents` - List all enrollment keys/agents

## User Workflow (Admin)

### Step 1: Access Dashboard
```
http://localhost:8080/admin/
```

### Step 2: Generate Enrollment Key
1. Click "Enroll New Agent" or go to `/admin/enroll`
2. Select target VM from dropdown
3. Add description (optional)
4. Set expiry (default 7 days)
5. Click "🔑 Generate Enrollment Key"

### Step 3: Copy Key
- Enrollment key shown **ONCE** on success page
- Click "📋 Copy Key to Clipboard" button
- Key format: 43-character base64url string
- Example: `xK9mP2nQ7vR4wS8tU1yZ3aB5cD6eF0gH1iJ2kL3mN4o`

### Step 4: Deploy Agent
On Windows VM:
```cmd
cd C:\SecurityHealth
ShikraAgent.exe --enroll <paste_key_here>
Enter Shost URL: http://192.168.100.1:8080/api/v1
```

Agent auto-creates `agent_config.json` and starts.

### Step 5: Verify
- Go to `/admin/agents`
- See agent status change from "⏳ Awaiting" to "✓ Enrolled"
- Check "Last Seen" column for polling activity

## Key Differences from Old System

| Feature | Old System | New System (v2.0) |
|---------|-----------|-------------------|
| Configuration | INI file download | Enrollment key (one-time) |
| Agent ID | Random hex | Derived from VM name |
| Credentials | Pre-configured secret | Token issued at enrollment |
| Storage Format | Shikra.ini | agent_config.json (auto-created) |
| Manual File Transfer | Yes (INI to VM) | No (key via clipboard) |
| Key Expiry | No | Yes (default 7 days) |
| One-time Use | No | Yes |

## Empty State Handling

When `agents.json` is empty (`{}`):
- Dashboard shows "No Enrollment Keys"
- Empty state with icon and message
- "Generate First Key" button
- No errors or old cached data

## Security Improvements

1. **Enrollment key never stored in plaintext** - only SHA256 hash
2. **Keys expire** after configurable days (1-30)
3. **One-time use** - marked as used after agent enrolls
4. **No pre-configured secrets** - tokens issued dynamically
5. **Machine fingerprint tracking** - detect VM clones

## Testing

### Test Empty State
```bash
echo '{}' > data/agents.json
# Visit http://localhost:8080/admin/agents
# Should show "No Enrollment Keys"
```

### Test Key Generation
```bash
# Visit http://localhost:8080/admin/enroll
# Select VM, fill form, submit
# Should see enrollment key displayed once
```

### Test Agents List
```bash
# After generating key
# Visit http://localhost:8080/admin/agents
# Should see key in "⏳ Awaiting" status
```

## Browser Compatibility

Tested and working in:
- Chrome/Edge (latest)
- Firefox (latest)
- Safari (latest)

Features used:
- CSS Grid (for stats cards)
- Flexbox (for layouts)
- Modern gradients
- Copy to clipboard API (via JavaScript)

## Responsive Design

Dashboard is fully responsive:
- Desktop: Full layout with grid stats
- Tablet: Stacked stats, scrollable table
- Mobile: Single column, horizontal scroll for table

## Next Steps for Users

1. **Clean slate**: Delete `data/agents.json` or set to `{}`
2. **Restart Shost**: `./start_shost.sh`
3. **Access dashboard**: `http://localhost:8080/admin/`
4. **Generate first key**: Click "Enroll New Agent"
5. **Deploy Agent v2.0**: Use enrollment key on Windows VM

---

**All dashboard changes are now live and ready for Agent v2.0! 🎉**
