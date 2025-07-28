# Shikra Host (Shost) - MVP Implementation

## 🎯 Overview
The Shost is the control system that manages malware analysis workflows by orchestrating the Shikra agent running inside QEMU-KVM VMs. This MVP provides a simple but complete flow for automated malware analysis.

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Host System   │    │    QEMU-KVM VM   │    │  Analysis DB    │
│   (Shost)       │    │  (Shikra Agent)  │    │   (SQLite)      │
├─────────────────┤    ├──────────────────┤    ├─────────────────┤
│ • REST API      │◄──►│ • HttpClient     │    │ • Samples       │
│ • VM Manager    │    │ • Hook Engine    │    │ • Results       │
│ • Sample Store  │    │ • Analysis Logs  │    │ • Artifacts     │
│ • Web Dashboard │    │ • Memory Dumps   │    │ • Metadata      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 📁 Directory Structure

```
Shost/
├── api/                    # REST API server (Flask)
│   ├── __init__.py
│   ├── app.py             # Main Flask application
│   ├── routes/            # API endpoints
│   │   ├── __init__.py
│   │   ├── agents.py      # Agent management
│   │   ├── samples.py     # Sample distribution
│   │   └── analysis.py    # Analysis results
│   └── models/            # Database models
│       ├── __init__.py
│       ├── agent.py
│       ├── sample.py
│       └── analysis.py
├── vm_manager/            # QEMU-KVM VM control
│   ├── __init__.py
│   ├── qemu_manager.py    # VM operations
│   ├── agent_deployer.py # Agent deployment
│   └── network_setup.py  # Network configuration
├── storage/               # File storage system
│   ├── __init__.py
│   ├── sample_store.py    # Sample file management
│   ├── artifact_store.py  # Analysis artifacts
│   └── dump_processor.py  # Memory dump handling
├── dashboard/             # Web interface
│   ├── static/           # CSS, JS, images
│   ├── templates/        # HTML templates
│   └── dashboard.py      # Dashboard routes
├── config/               # Configuration files
│   ├── config.py         # Main configuration
│   ├── vm_templates/     # VM configuration templates
│   └── agent_configs/    # Agent configuration templates
├── scripts/              # Utility scripts
│   ├── setup_host.py     # Initial setup
│   ├── deploy_agent.py   # Agent deployment
│   └── cleanup.py        # Cleanup utilities
├── database/             # Database initialization
│   ├── __init__.py
│   ├── init_db.py        # Database setup
│   └── migrations/       # Schema changes
└── logs/                 # Log files directory
```

## 🚀 Core Components

### 1. REST API Server (`api/`)
**Purpose**: Handle communication with Shikra agents
**Key Features**:
- Agent registration and authentication (HMAC)
- Sample distribution to agents
- Status updates and progress tracking
- Artifact collection from agents
- Memory dump trigger commands

### 2. VM Manager (`vm_manager/`)
**Purpose**: Control QEMU-KVM virtual machines
**Key Features**:
- Start/stop/reset VMs
- Deploy Shikra agent to VMs
- Network isolation setup
- Snapshot management
- VM status monitoring

### 3. Storage System (`storage/`)
**Purpose**: Manage files and analysis data
**Key Features**:
- Sample file storage and retrieval
- Analysis artifact collection
- Memory dump processing
- Secure file handling
- Metadata extraction

### 4. Web Dashboard (`dashboard/`)
**Purpose**: Visual interface for monitoring and control
**Key Features**:
- Real-time analysis status
- Sample upload interface
- VM management controls
- Analysis results viewer
- System health monitoring

## 🎯 MVP Workflow

### Simple Analysis Flow:
1. **Upload Sample** → Web dashboard or API
2. **Queue Sample** → Store in database
3. **Start VM** → Launch QEMU-KVM instance
4. **Deploy Agent** → Copy agent files to VM
5. **Send Sample** → Agent polls and downloads
6. **Monitor Analysis** → Real-time status updates
7. **Collect Results** → Artifacts and memory dumps
8. **Stop VM** → Cleanup and reset

### Key Simplifications for MVP:
- ✅ Single VM at a time (no queue)
- ✅ SQLite database (no complex DB)
- ✅ File-based sample storage
- ✅ Simple HMAC authentication
- ✅ Basic web interface
- ✅ Manual VM network setup

## 📊 Database Schema (SQLite)

### Tables:
```sql
-- Agents table
CREATE TABLE agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    secret_key TEXT NOT NULL,
    vm_id TEXT,
    status TEXT DEFAULT 'offline',
    last_seen TIMESTAMP,
    capabilities TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Samples table
CREATE TABLE samples (
    id TEXT PRIMARY KEY,
    filename TEXT NOT NULL,
    file_hash TEXT UNIQUE NOT NULL,
    file_size INTEGER,
    file_path TEXT NOT NULL,
    status TEXT DEFAULT 'pending',
    assigned_agent TEXT,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    analysis_started_at TIMESTAMP,
    analysis_completed_at TIMESTAMP
);

-- Analysis results table
CREATE TABLE analysis_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sample_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    status TEXT NOT NULL,
    progress INTEGER DEFAULT 0,
    artifacts_path TEXT,
    memory_dump_path TEXT,
    api_calls_log TEXT,
    behavior_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sample_id) REFERENCES samples (id),
    FOREIGN KEY (agent_id) REFERENCES agents (id)
);
```

## 🔧 Configuration

### Environment Variables:
```bash
# API Configuration
SHOST_API_HOST=0.0.0.0
SHOST_API_PORT=5000
SHOST_SECRET_KEY=your-secret-key-here

# VM Configuration  
SHOST_VM_IMAGE_PATH=/path/to/windows-vm.qcow2
SHOST_VM_RAM=4096
SHOST_VM_CORES=2
SHOST_VM_VNC_PORT=5900

# Storage Configuration
SHOST_SAMPLE_STORAGE=/var/shost/samples
SHOST_ARTIFACT_STORAGE=/var/shost/artifacts
SHOST_DATABASE_PATH=/var/shost/shost.db

# Agent Configuration
SHOST_AGENT_PATH=/path/to/shikra-agent.exe
SHOST_HOOKENGINE_PATH=/path/to/hookengine.dll
```

## 🛠️ Installation & Setup

### Prerequisites:
- Python 3.8+
- QEMU-KVM with libvirt
- Windows VM image (pre-configured)
- Network bridge setup

### Quick Start:
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Initialize database
python database/init_db.py

# 3. Configure environment
cp config/config.example.py config/config.py
# Edit config.py with your settings

# 4. Start the host system
python run.py

# 5. Access dashboard
# http://localhost:5000/dashboard
```

## 🔌 API Endpoints

### Agent Communication:
```
GET  /api/v1/agent/next-sample      # Get next sample to analyze
GET  /api/v1/agent/download/{id}    # Download sample file
POST /api/v1/agent/status           # Update analysis status
POST /api/v1/agent/upload/artifacts # Upload analysis results
HEAD /api/v1/agent/health           # Health check
```

### VM Management:
```
POST /api/v1/vm/start               # Start VM instance
POST /api/v1/vm/stop                # Stop VM instance
POST /api/v1/vm/reset               # Reset VM to snapshot
GET  /api/v1/vm/status              # Get VM status
```

### Sample Management:
```
POST /api/v1/samples/upload         # Upload new sample
GET  /api/v1/samples                # List samples
GET  /api/v1/samples/{id}           # Get sample details
DELETE /api/v1/samples/{id}         # Delete sample
```

## 🎮 Hook Engine Integration

Based on the DLLMain.cpp analysis, the hook engine provides:

### External Control Functions:
- `IsHookEngineActive()` - Check if hooks are running
- `GetActiveHookCount()` - Number of active hooks
- `FlushHookLogs()` - Force log flush
- `GetLogFilePath()` - Get current log file
- `SetCategoryEnabled()` - Enable/disable hook categories
- `GetHookStatistics()` - Get JSON statistics
- `ConfigureHooks()` - Configure specific API hooks
- `StartHooking()` - Begin API monitoring
- `StopHooking()` - Stop API monitoring

### Integration Points:
1. **Sample Analysis Start**: Call `ConfigureHooks()` and `StartHooking()`
2. **Progress Monitoring**: Use `GetHookStatistics()` for real-time stats
3. **Memory Dump Triggers**: Monitor `GetActiveHookCount()` for anomalies
4. **Analysis Complete**: Call `StopHooking()` and `FlushHookLogs()`

## 📈 Scaling Considerations

### Current MVP Limitations:
- Single VM analysis at a time
- No analysis queue management
- Basic file storage (no cloud storage)
- Simple authentication (no OAuth/JWT)
- SQLite database (no PostgreSQL/MySQL)

### Future Enhancements:
- Multiple VM pool management
- Priority-based analysis queue
- Cloud storage integration (S3, Azure Blob)
- Advanced authentication and authorization
- Distributed database with clustering
- Real-time WebSocket communication
- Advanced memory dump analysis
- Machine learning behavior detection

## 🔒 Security Considerations

### Current Security Measures:
- HMAC-SHA256 agent authentication
- Isolated VM network (pre-configured)
- File type validation for uploads
- Path traversal protection
- Input sanitization

### Additional Security (Future):
- TLS/SSL for all communication
- Certificate-based agent authentication
- Encrypted sample storage
- Audit logging
- Rate limiting and DDoS protection

## 🐛 Troubleshooting

### Common Issues:
1. **VM won't start**: Check QEMU-KVM configuration and image path
2. **Agent can't connect**: Verify network bridge and firewall settings
3. **Sample upload fails**: Check file permissions and storage space
4. **Analysis stalls**: Monitor VM resources and agent logs
5. **Database errors**: Verify SQLite file permissions

### Log Locations:
- API logs: `logs/api.log`
- VM manager logs: `logs/vm_manager.log`
- Analysis logs: `logs/analysis.log`
- Agent logs: Retrieved from VM via API

This MVP provides a complete, functional malware analysis system that can be easily deployed and scaled as requirements grow.
