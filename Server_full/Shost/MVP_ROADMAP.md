# Shikra MVP Roadmap - 20-Day Ship Plan

**Goal**: Ship a working malware analysis system where host can register agents, queue samples, receive results, and trigger memory dumps.

**Critical Path**: Register agent → Upload sample → Assign to VM → Execute & monitor → Trigger memory dump → Upload results → View in dashboard

---

## Week 1: Core Infrastructure (Days 1-7)

### HOST SIDE - Must Have

#### 1. Agent Registration & Authentication ✓ (Already Implemented)
**File**: `api/routes/agents.py::register_agent()`

**What it does**:
- Agent sends enrollment key
- Host validates and returns `agent_id` + `access_token`
- Token stored as SHA256 hash in `data/agents.json`

**Required fixes**:
- [x] ✅ Already validates enrollment key hash
- [x] ✅ Already detects re-registration via `machine_fingerprint`
- [ ] **TODO**: Add token expiry check and renewal endpoint
  - Location: `api/auth.py::require_agent_auth` already checks `token_expires`
  - Action: Test with expired token and confirm 401 response triggers agent re-enrollment

**Security checklist**:
- [x] Tokens never stored plaintext (only `token_sha`)
- [x] Enrollment key single-use enforced
- [x] Machine fingerprint prevents VM clones
- [ ] **TODO**: Add rate limiting on `/api/v1/agent/register` (10 attempts/hour per IP)

**Verification**:
```bash
# Test enrollment
curl -X POST http://localhost:8080/api/v1/agent/register \
  -H "Content-Type: application/json" \
  -d '{"enrollment_key":"test-key-123","machine_fingerprint":"VM-ABC","hostname":"win10-test"}'

# Expected: {"agent_id":"agent-xyz","access_token":"<token>","config":{...}}
```

---

#### 2. Sample Upload & Queue ✓ (Partially Implemented)
**File**: `api/routes/samples.py`

**What it does**:
- Analyst uploads malware via dashboard or API
- File saved to `data/samples/<hash>.bin`
- Sample metadata stored in `data/samples.json`

**Required fixes**:
- [ ] **TODO**: Verify `samples.py` has upload endpoint
  - Expected route: `POST /api/v1/samples/upload`
  - Action: Read `api/routes/samples.py` and confirm implementation
  
- [ ] **TODO**: Add upload validation
  - File size check: `<= Config.MAX_SAMPLE_SIZE` (100MB default)
  - Extension whitelist: `Config.ALLOWED_EXTENSIONS`
  - Hash collision check (reject duplicate SHA256)
  - Virus Total API check (optional, low priority)

**Security checklist**:
- [ ] Validate MIME type matches extension
- [ ] Sanitize filename (remove path traversal: `../`, `..\\`)
- [ ] Store files outside webroot
- [ ] Generate random storage filename: `<sha256>_<timestamp>.bin`

**Verification**:
```bash
# Upload sample
curl -X POST http://localhost:8080/api/v1/samples/upload \
  -F "file=@malware.exe" \
  -F "description=Test malware"

# Expected: {"sample_id":"abc123","status":"pending","filename":"malware.exe"}
```

---

#### 3. Sample Assignment to Agent ✓ (Already Implemented)
**File**: `api/routes/agents.py::get_next_sample()`

**What it does**:
- Agent polls `GET /api/v1/agent/next-sample` with Bearer token
- Host checks for pending samples
- Single-assignment policy: one sample per agent at a time
- Returns sample metadata + download URL

**Current implementation**:
```python
# Already implements:
- One-at-a-time policy (get_active_for_agent)
- Stale sample recovery (recover_stale_samples)
- Sample assignment (assign_sample_to_agent)
```

**Required fixes**:
- [ ] **TODO**: Add assignment timeout
  - If agent doesn't start download within 60s, return sample to queue
  - Location: `api/simple_sample_store.py::recover_stale_samples`
  
- [ ] **TODO**: Add assignment logging
  - Log: `"Sample {id} assigned to agent {agent_id} at {timestamp}"`
  - Already exists, just verify it's working

**Verification**:
```bash
# Agent polls for sample
curl -X GET http://localhost:8080/api/v1/agent/next-sample \
  -H "X-Agent-ID: agent-xyz" \
  -H "Authorization: Bearer <token>"

# Expected: {"sample_id":"abc123","filename":"malware.exe","download_url":"/api/v1/agent/download/abc123"}
```

---

#### 4. Sample Download ✓ (Already Implemented)
**File**: `api/routes/agents.py::download_sample()`

**What it does**:
- Agent downloads binary via `GET /api/v1/agent/download/{sample_id}`
- Host verifies sample is assigned to requesting agent
- Returns raw binary file

**Security checklist**:
- [x] Verify assignment before serving file
- [x] Update sample status to `downloading`
- [ ] **TODO**: Add download timeout (kill connection after 5 minutes)

**Verification**:
```bash
# Download sample
curl -X GET http://localhost:8080/api/v1/agent/download/abc123 \
  -H "X-Agent-ID: agent-xyz" \
  -H "Authorization: Bearer <token>" \
  --output sample.bin

# Verify file hash matches
sha256sum sample.bin
```

---

#### 5. Memory Dump Trigger Reception ⚠️ (CRITICAL - Not Implemented)
**File**: `api/routes/vm_management.py` or new `api/routes/triggers.py`

**What it does**:
- Agent sends trigger notification when suspicious activity detected
- Host captures VM memory via libvirt/virsh
- Memory dump saved to `data/dumps/<sample_id>_<timestamp>.dmp`

**Required implementation**:
```python
# File: api/routes/triggers.py
from flask import Blueprint, request, jsonify
from ..auth import require_agent_auth
from vm_manager.qemu_manager import QEMUManager
import logging

triggers_bp = Blueprint('triggers', __name__)
logger = logging.getLogger(__name__)

@triggers_bp.route('/memory-dump', methods=['POST'])
@require_agent_auth
def trigger_memory_dump():
    """
    Agent sends trigger when suspicious activity detected
    
    Request body:
    {
        "sample_id": "abc123",
        "trigger_type": "suspicious|critical",
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
        from api.simple_store import agent_store
        agent = agent_store.get_agent(agent_id)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        vm_name = agent.get('vm_name') or agent.get('hostname')
        if not vm_name:
            logger.error(f"No VM name configured for agent {agent_id}")
            return jsonify({'error': 'VM name not configured'}), 500
        
        # Trigger memory dump via QEMU manager
        vm_manager = QEMUManager()
        dump_path = f"data/dumps/{sample_id}_{int(time.time())}.dmp"
        
        success = vm_manager.capture_memory_dump(vm_name, dump_path)
        
        if success:
            logger.info(f"Memory dump triggered for sample {sample_id}: {reason} (score: {score})")
            
            # Record trigger in analysis store
            from api.simple_analysis_store import analysis_store
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
            logger.error(f"Failed to capture memory dump for VM {vm_name}")
            return jsonify({'error': 'Memory dump capture failed'}), 500
        
    except Exception as e:
        logger.error(f"Memory dump trigger error: {e}")
        return jsonify({'error': 'Internal server error'}), 500
```

**Required QEMU manager update**:
```python
# File: vm_manager/qemu_manager.py
def capture_memory_dump(self, vm_name: str, output_path: str) -> bool:
    """
    Capture memory dump of running VM
    
    Uses: virsh dump <vm_name> <output_path> --memory-only
    """
    try:
        import subprocess
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        # Execute virsh dump command
        result = subprocess.run(
            ['virsh', 'dump', vm_name, output_path, '--memory-only'],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        if result.returncode == 0:
            logger.info(f"Memory dump captured: {output_path}")
            return True
        else:
            logger.error(f"virsh dump failed: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        logger.error(f"Memory dump timeout for VM {vm_name}")
        return False
    except Exception as e:
        logger.error(f"Memory dump error: {e}")
        return False
```

**Register blueprint**:
```python
# File: api/app.py
from .routes.triggers import triggers_bp

def create_app():
    # ...
    app.register_blueprint(triggers_bp, url_prefix='/api/v1/triggers')
```

**Verification**:
```bash
# Agent triggers dump
curl -X POST http://localhost:8080/api/v1/triggers/memory-dump \
  -H "X-Agent-ID: agent-xyz" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"sample_id":"abc123","trigger_type":"critical","score":500,"reason":"CreateRemoteThread + RegSetValueEx"}'

# Expected: {"message":"Memory dump triggered successfully","dump_path":"data/dumps/abc123_1234567890.dmp"}

# Verify dump file
ls -lh data/dumps/
```

---

#### 6. Results Upload ✓ (Already Implemented)
**File**: `api/routes/agents.py::upload_artifacts()`

**What it does**:
- Agent uploads analysis results as multipart form-data
- Files: `api_calls.json`, `behavior_summary.json`, `screenshots/*.png`, etc.
- Metadata stored in `data/artifacts/<sample_id>/metadata.json`

**Security checklist**:
- [x] Verify sample assignment
- [ ] **TODO**: Validate uploaded file types
- [ ] **TODO**: Add total upload size limit (500MB per sample)
- [ ] **TODO**: Scan uploaded JSON for malicious content (optional)

**Verification**:
```bash
# Upload results
curl -X POST http://localhost:8080/api/v1/agent/upload/artifacts \
  -H "X-Agent-ID: agent-xyz" \
  -H "Authorization: Bearer <token>" \
  -F "metadata={\"sample_id\":\"abc123\",\"analysis_id\":\"xyz\"}" \
  -F "api_calls=@api_calls.json" \
  -F "behavior=@behavior_summary.json"

# Expected: {"message":"Artifacts uploaded successfully","uploaded_files":[...]}
```

---

### AGENT SIDE - Must Have

#### 1. Enrollment & Config Storage
**File**: `src/Agent/ConfigManager.cpp`

**What it does**:
- Agent runs: `ShikraAgent.exe --enroll <key>`
- Prompts for Shost URL
- Sends enrollment request to host
- Saves `agent_id` + `access_token` to `C:\SecurityHealth\agent_config.json`

**Required implementation**:
```cpp
// ConfigManager::EnrollWithHost()
bool ConfigManager::EnrollWithHost(const std::string& enrollmentKey) {
    // 1. Prompt for Shost URL
    std::string hostUrl;
    std::cout << "Enter Shost URL (e.g., http://192.168.100.1:8080): ";
    std::getline(std::cin, hostUrl);
    
    // 2. Get machine fingerprint
    std::string fingerprint = GetMachineFingerprint();
    std::string hostname = GetHostname();
    
    // 3. Build enrollment request
    nlohmann::json requestBody = {
        {"enrollment_key", enrollmentKey},
        {"machine_fingerprint", fingerprint},
        {"hostname", hostname}
    };
    
    // 4. Send POST /api/v1/agent/register
    HttpClient client(hostUrl + "/api/v1/agent/register");
    auto response = client.Post(requestBody.dump(), "application/json");
    
    if (response.status_code != 200) {
        Logger::Instance().LogError("Enrollment failed: " + response.body);
        return false;
    }
    
    // 5. Parse response
    auto responseJson = nlohmann::json::parse(response.body);
    std::string agentId = responseJson["agent_id"];
    std::string accessToken = responseJson["access_token"];
    
    // 6. Save config to agent_config.json
    nlohmann::json config = {
        {"agent", {
            {"agentId", agentId},
            {"authToken", "Bearer " + accessToken},
            {"hostUrl", hostUrl + "/api/v1"},
            {"pollIntervalMs", responseJson["config"]["poll_interval"]},
            {"workingDirectory", "C:\\SecurityHealth"}
        }}
    };
    
    std::ofstream configFile("C:\\SecurityHealth\\agent_config.json");
    configFile << config.dump(2);
    configFile.close();
    
    Logger::Instance().LogInfo("Enrollment successful: " + agentId);
    return true;
}

std::string ConfigManager::GetMachineFingerprint() {
    // Use: CPU ID + Volume Serial + MAC Address
    // Returns: SHA256 hash of combined values
    std::stringstream ss;
    
    // Get volume serial (C: drive)
    DWORD volumeSerial = 0;
    GetVolumeInformationA("C:\\", nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0);
    ss << volumeSerial;
    
    // Get first MAC address
    // TODO: Implement MAC address retrieval (use GetAdaptersInfo)
    
    // Hash the combined string
    // TODO: Implement SHA256 (use Windows CryptoAPI or library)
    
    return "FINGERPRINT_PLACEHOLDER"; // Replace with actual hash
}
```

**Security checklist**:
- [ ] **TODO**: Encrypt `agent_config.json` with DPAPI
- [ ] **TODO**: Set file ACL to SYSTEM/Admin only
- [ ] Validate host URL format before saving

**Verification**:
```cmd
# Run enrollment
ShikraAgent.exe --enroll enrollment-key-from-dashboard

# Check config file
type C:\SecurityHealth\agent_config.json

# Expected: {"agent":{"agentId":"agent-xyz","authToken":"Bearer xyz..."}}
```

---

#### 2. Polling Loop
**File**: `src/Agent/ExecutionPipeline.cpp` or new `src/Agent/PollingService.cpp`

**What it does**:
- Agent polls `GET /api/v1/agent/next-sample` every 30 seconds
- If sample available, download and execute
- If no sample (204 response), sleep and retry

**Required implementation**:
```cpp
void PollingService::Run() {
    while (!m_shouldStop) {
        try {
            // 1. Load config
            auto config = ConfigManager::Instance().GetAgentConfig();
            std::string hostUrl = config["hostUrl"];
            std::string agentId = config["agentId"];
            std::string authToken = config["authToken"];
            int pollInterval = config["pollIntervalMs"];
            
            // 2. Poll for next sample
            HttpClient client(hostUrl + "/agent/next-sample");
            client.SetHeader("X-Agent-ID", agentId);
            client.SetHeader("Authorization", authToken);
            
            auto response = client.Get();
            
            if (response.status_code == 200) {
                // Sample available
                auto sampleJson = nlohmann::json::parse(response.body);
                
                Logger::Instance().LogInfo("Received sample: " + sampleJson["sample_id"].get<std::string>());
                
                // 3. Execute pipeline
                ExecutionPipeline pipeline;
                pipeline.Execute(sampleJson);
                
            } else if (response.status_code == 204) {
                // No samples available
                Logger::Instance().LogDebug("No samples available, sleeping...");
                
            } else if (response.status_code == 401) {
                // Token expired or invalid
                Logger::Instance().LogError("Authentication failed, please re-enroll");
                m_shouldStop = true;
                
            } else {
                Logger::Instance().LogWarning("Unexpected response: " + std::to_string(response.status_code));
            }
            
            // 4. Sleep before next poll
            std::this_thread::sleep_for(std::chrono::milliseconds(pollInterval));
            
        } catch (const std::exception& e) {
            Logger::Instance().LogError("Polling error: " + std::string(e.what()));
            std::this_thread::sleep_for(std::chrono::seconds(30));
        }
    }
}
```

**Error handling**:
- [ ] Network timeout (5 seconds per request)
- [ ] Exponential backoff on repeated failures
- [ ] Log all HTTP errors with full response body

**Verification**:
```cmd
# Run agent in console mode
ShikraAgent.exe --console

# Check logs
type C:\SecurityHealth\logs\agent.log | findstr "Polling"

# Expected: Repeated "Polling for new samples" or "Received sample: abc123"
```

---

#### 3. Sample Download & Execute
**File**: `src/Agent/ExecutionPipeline.cpp`

**What it does**:
- Download binary from `GET /api/v1/agent/download/{sample_id}`
- Save to `C:\SecurityHealth\work\{sample_id}\malware.exe`
- Create suspended process
- Inject `ShikraHooks.dll`
- Resume process

**Required implementation**:
```cpp
bool ExecutionPipeline::DownloadSample(const std::string& sampleId, const std::string& downloadUrl) {
    try {
        auto config = ConfigManager::Instance().GetAgentConfig();
        std::string hostUrl = config["hostUrl"];
        std::string agentId = config["agentId"];
        std::string authToken = config["authToken"];
        
        // 1. Download binary
        HttpClient client(hostUrl + downloadUrl);
        client.SetHeader("X-Agent-ID", agentId);
        client.SetHeader("Authorization", authToken);
        
        auto response = client.Get();
        
        if (response.status_code != 200) {
            Logger::Instance().LogError("Download failed: " + std::to_string(response.status_code));
            return false;
        }
        
        // 2. Save to disk
        std::string workDir = "C:\\SecurityHealth\\work\\" + sampleId;
        CreateDirectoryA(workDir.c_str(), nullptr);
        
        std::string binaryPath = workDir + "\\malware.exe";
        std::ofstream outFile(binaryPath, std::ios::binary);
        outFile.write(response.body.data(), response.body.size());
        outFile.close();
        
        Logger::Instance().LogInfo("Sample downloaded: " + binaryPath);
        
        m_samplePath = binaryPath;
        return true;
        
    } catch (const std::exception& e) {
        Logger::Instance().LogError("Download error: " + std::string(e.what()));
        return false;
    }
}

bool ExecutionPipeline::StartProcess() {
    try {
        // 1. Set environment variable for DLL
        std::wstring wideSampleId = StringToWString(m_sampleId);
        SetEnvironmentVariableW(L"SHIKRA_SAMPLE_ID", wideSampleId.c_str());
        
        // 2. Create job object for resource limits
        m_jobHandle = CreateJobObjectW(nullptr, nullptr);
        if (!m_jobHandle) {
            Logger::Instance().LogError("Failed to create job object");
            return false;
        }
        
        // Set memory limit (1GB)
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION jobLimits = {0};
        jobLimits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        jobLimits.ProcessMemoryLimit = 1024 * 1024 * 1024; // 1GB
        
        SetInformationJobObject(m_jobHandle, JobObjectExtendedLimitInformation, &jobLimits, sizeof(jobLimits));
        
        // 3. Create suspended process
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        std::wstring cmdLine = StringToWString(m_samplePath);
        
        BOOL success = CreateProcessW(
            nullptr,
            &cmdLine[0],
            nullptr,
            nullptr,
            FALSE,
            CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
            nullptr,
            nullptr,
            &si,
            &pi
        );
        
        if (!success) {
            Logger::Instance().LogError("Failed to create process: " + std::to_string(GetLastError()));
            return false;
        }
        
        m_processHandle = pi.hProcess;
        m_threadHandle = pi.hThread;
        m_processId = pi.dwProcessId;
        
        // 4. Assign to job object
        AssignProcessToJobObject(m_jobHandle, m_processHandle);
        
        Logger::Instance().LogInfo("Process created (PID: " + std::to_string(m_processId) + ")");
        return true;
        
    } catch (const std::exception& e) {
        Logger::Instance().LogError("Process creation error: " + std::string(e.what()));
        return false;
    }
}
```

**Security checklist**:
- [x] Create suspended process (prevent execution before injection)
- [x] Use job object for resource limits
- [ ] **TODO**: Add DEP/ASLR enforcement
- [ ] **TODO**: Validate binary is PE format before execution

---

#### 4. DLL Injection
**File**: `src/Agent/ExecutionPipeline.cpp`

**What it does**:
- Inject `ShikraHooks.dll` into suspended process
- Use `CreateRemoteThread` + `LoadLibraryW`

**Required implementation**:
```cpp
bool ExecutionPipeline::InjectHookDLL() {
    try {
        std::string dllPath = "C:\\SecurityHealth\\ShikraHooks.dll";
        
        // 1. Allocate memory in target process
        size_t pathSize = (dllPath.size() + 1) * sizeof(wchar_t);
        std::wstring wideDllPath = StringToWString(dllPath);
        
        LPVOID remoteMem = VirtualAllocEx(
            m_processHandle,
            nullptr,
            pathSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        
        if (!remoteMem) {
            Logger::Instance().LogError("VirtualAllocEx failed: " + std::to_string(GetLastError()));
            return false;
        }
        
        // 2. Write DLL path to remote process
        SIZE_T bytesWritten = 0;
        WriteProcessMemory(
            m_processHandle,
            remoteMem,
            wideDllPath.c_str(),
            pathSize,
            &bytesWritten
        );
        
        // 3. Get LoadLibraryW address
        HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
        LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(kernel32, "LoadLibraryW");
        
        // 4. Create remote thread
        HANDLE remoteThread = CreateRemoteThread(
            m_processHandle,
            nullptr,
            0,
            (LPTHREAD_START_ROUTINE)loadLibraryAddr,
            remoteMem,
            0,
            nullptr
        );
        
        if (!remoteThread) {
            Logger::Instance().LogError("CreateRemoteThread failed: " + std::to_string(GetLastError()));
            VirtualFreeEx(m_processHandle, remoteMem, 0, MEM_RELEASE);
            return false;
        }
        
        // 5. Wait for injection to complete
        WaitForSingleObject(remoteThread, 5000);
        
        // 6. Clean up
        CloseHandle(remoteThread);
        VirtualFreeEx(m_processHandle, remoteMem, 0, MEM_RELEASE);
        
        Logger::Instance().LogInfo("DLL injected successfully");
        return true;
        
    } catch (const std::exception& e) {
        Logger::Instance().LogError("Injection error: " + std::string(e.what()));
        return false;
    }
}
```

**Error handling**:
- [ ] Check DLL file exists before injection
- [ ] Verify injection success (check remote thread exit code)
- [ ] Handle architecture mismatch (x64 vs x86)

---

#### 5. Monitor & Trigger Memory Dumps
**File**: `src/Agent/TriggerEngine.cpp`

**What it does**:
- Poll shared memory for API call events from DLL
- Score events based on `config/default.json::triggers.apiScores`
- When threshold exceeded, send trigger to host

**Required implementation**:
```cpp
void TriggerEngine::MonitorAndScore() {
    int currentScore = 0;
    bool suspiciousTriggered = false;
    bool criticalTriggered = false;
    
    while (m_isMonitoring) {
        // 1. Read events from shared memory
        auto events = m_triggerInterface->ReadEvents();
        
        for (const auto& event : events) {
            // 2. Score event
            std::string apiName = event["api_name"];
            int score = m_apiScores[apiName]; // From config
            
            currentScore += score;
            
            Logger::Instance().LogDebug("API: " + apiName + " (Score: +" + std::to_string(score) + ", Total: " + std::to_string(currentScore) + ")");
            
            // 3. Check thresholds
            if (currentScore >= 500 && !criticalTriggered) {
                // Critical threshold
                SendMemoryDumpTrigger("critical", currentScore, "Multiple high-risk API calls detected");
                criticalTriggered = true;
                
            } else if (currentScore >= 100 && !suspiciousTriggered) {
                // Suspicious threshold
                SendMemoryDumpTrigger("suspicious", currentScore, "Suspicious API pattern detected");
                suspiciousTriggered = true;
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void TriggerEngine::SendMemoryDumpTrigger(const std::string& triggerType, int score, const std::string& reason) {
    try {
        auto config = ConfigManager::Instance().GetAgentConfig();
        std::string hostUrl = config["hostUrl"];
        std::string agentId = config["agentId"];
        std::string authToken = config["authToken"];
        
        // Build trigger request
        nlohmann::json triggerBody = {
            {"sample_id", m_sampleId},
            {"trigger_type", triggerType},
            {"score", score},
            {"reason", reason}
        };
        
        // Send POST /api/v1/triggers/memory-dump
        HttpClient client(hostUrl + "/triggers/memory-dump");
        client.SetHeader("X-Agent-ID", agentId);
        client.SetHeader("Authorization", authToken);
        client.SetHeader("Content-Type", "application/json");
        
        auto response = client.Post(triggerBody.dump());
        
        if (response.status_code == 200) {
            Logger::Instance().LogInfo("Memory dump triggered: " + triggerType + " (score: " + std::to_string(score) + ")");
        } else {
            Logger::Instance().LogError("Failed to trigger memory dump: " + std::to_string(response.status_code));
        }
        
    } catch (const std::exception& e) {
        Logger::Instance().LogError("Trigger send error: " + std::string(e.what()));
    }
}
```

**Configuration** (`config/default.json`):
```json
{
  "triggers": {
    "apiScores": {
      "CreateRemoteThread": 100,
      "WriteProcessMemory": 50,
      "VirtualAllocEx": 30,
      "RegSetValueEx": 20,
      "CreateFileW": 10,
      "CreateProcessW": 40,
      "ShellExecuteW": 60
    },
    "suspiciousThreshold": 100,
    "criticalThreshold": 500
  }
}
```

---

#### 6. Results Upload
**File**: `src/Agent/ExecutionPipeline.cpp`

**What it does**:
- Package analysis artifacts (logs, JSON, screenshots)
- Upload via `POST /api/v1/agent/upload/artifacts`

**Required implementation**:
```cpp
bool ExecutionPipeline::UploadResults() {
    try {
        auto config = ConfigManager::Instance().GetAgentConfig();
        std::string hostUrl = config["hostUrl"];
        std::string agentId = config["agentId"];
        std::string authToken = config["authToken"];
        
        // 1. Build metadata
        nlohmann::json metadata = {
            {"sample_id", m_sampleId},
            {"analysis_id", m_analysisId},
            {"completed_at", GetCurrentTimestamp()},
            {"total_api_calls", m_apiCallCount},
            {"trigger_score", m_finalScore}
        };
        
        // 2. Prepare multipart upload
        HttpClient client(hostUrl + "/agent/upload/artifacts");
        client.SetHeader("X-Agent-ID", agentId);
        client.SetHeader("Authorization", authToken);
        
        // Add metadata
        client.AddFormField("metadata", metadata.dump());
        
        // Add files
        std::string workDir = "C:\\SecurityHealth\\work\\" + m_sampleId;
        client.AddFormFile("api_calls", workDir + "\\api_calls.json");
        client.AddFormFile("behavior", workDir + "\\behavior_summary.json");
        
        // 3. Send upload
        auto response = client.PostMultipart();
        
        if (response.status_code == 200) {
            Logger::Instance().LogInfo("Results uploaded successfully");
            return true;
        } else {
            Logger::Instance().LogError("Upload failed: " + std::to_string(response.status_code));
            return false;
        }
        
    } catch (const std::exception& e) {
        Logger::Instance().LogError("Upload error: " + std::string(e.what()));
        return false;
    }
}
```

---

## Week 2: Integration & Safety (Days 8-14)

### HOST SIDE

#### 7. Error Handling & Logging
**Files**: All `api/routes/*.py`

**Required fixes**:
- [ ] Wrap all route handlers in try/except
- [ ] Log all errors with traceback
- [ ] Return consistent error JSON: `{"error": "message", "code": "ERROR_CODE"}`
- [ ] Add request ID for tracing

**Example**:
```python
@agents_bp.route('/next-sample', methods=['GET'])
@require_agent_auth
def get_next_sample():
    request_id = str(uuid.uuid4())
    try:
        logger.info(f"[{request_id}] Agent {request.agent_id} polling for sample")
        # ... existing code ...
    except Exception as e:
        logger.error(f"[{request_id}] Error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error', 'request_id': request_id}), 500
```

---

#### 8. Rate Limiting
**File**: `api/app.py`

**Required implementation**:
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per minute"]
)

# Apply to specific routes
@limiter.limit("10 per hour")
@agents_bp.route('/register', methods=['POST'])
def register_agent():
    # ...
```

---

#### 9. Input Validation
**Files**: All `api/routes/*.py`

**Required validations**:
- [ ] JSON schema validation for all POST requests
- [ ] Sample ID format: `^[a-zA-Z0-9_-]{8,64}$`
- [ ] Agent ID format: `^agent-[a-zA-Z0-9_-]{8,32}$`
- [ ] File upload size limits
- [ ] Path traversal prevention

**Example**:
```python
import re

def validate_sample_id(sample_id: str) -> bool:
    if not re.match(r'^[a-zA-Z0-9_-]{8,64}$', sample_id):
        raise ValueError(f"Invalid sample_id format: {sample_id}")
    return True
```

---

### AGENT SIDE

#### 10. Memory Safety
**Files**: All C++ files

**Required fixes**:
- [ ] Replace raw pointers with smart pointers (`std::unique_ptr`, `std::shared_ptr`)
- [ ] Add bounds checking for all array/buffer access
- [ ] Use RAII for all resource management (handles, memory)
- [ ] Add null checks before dereferencing

**Example**:
```cpp
// BEFORE (unsafe)
char* buffer = new char[1024];
strcpy(buffer, input); // Buffer overflow risk!
delete[] buffer;

// AFTER (safe)
std::unique_ptr<char[]> buffer(new char[1024]);
strncpy(buffer.get(), input, 1023);
buffer[1023] = '\0';
// Automatic cleanup
```

---

#### 11. Error Handling
**Files**: All C++ files

**Required patterns**:
- [ ] Check all Win32 API return values
- [ ] Use exceptions for critical errors
- [ ] Log all errors before propagating
- [ ] Clean up resources in destructors

**Example**:
```cpp
HANDLE handle = CreateFileW(...);
if (handle == INVALID_HANDLE_VALUE) {
    DWORD error = GetLastError();
    Logger::Instance().LogError("CreateFile failed: " + std::to_string(error));
    throw std::runtime_error("Failed to open file");
}

// Use RAII wrapper
class HandleGuard {
    HANDLE m_handle;
public:
    HandleGuard(HANDLE h) : m_handle(h) {}
    ~HandleGuard() { if (m_handle != INVALID_HANDLE_VALUE) CloseHandle(m_handle); }
    HANDLE get() const { return m_handle; }
};

HandleGuard fileHandle(CreateFileW(...));
```

---

#### 12. Shared Memory Robustness
**Files**: `src/HookEngine/TriggerEngineInterface.cpp`

**Required implementation**:
```cpp
// Shared memory header
struct SharedMemoryHeader {
    uint32_t magic;          // 0x53484B52 ('SHKR')
    uint32_t version;        // Protocol version
    uint32_t capacity;       // Total buffer size
    uint32_t writeIndex;     // Current write position (atomic)
    uint32_t readIndex;      // Current read position (atomic)
    uint64_t sequenceNumber; // Event sequence counter
};

// Event frame
struct EventFrame {
    uint32_t magic;          // 0x4556544E ('EVTN')
    uint32_t sequence;       // Sequence number
    uint32_t length;         // Payload length
    uint32_t crc32;          // Checksum of payload
    char payload[MAX_PAYLOAD_SIZE];
};

bool TriggerEngineInterface::WriteEvent(const std::string& jsonPayload) {
    std::lock_guard<std::mutex> lock(m_writeMutex);
    
    // 1. Validate payload size
    if (jsonPayload.size() > MAX_PAYLOAD_SIZE) {
        return false;
    }
    
    // 2. Build frame
    EventFrame frame;
    frame.magic = 0x4556544E;
    frame.sequence = ++m_header->sequenceNumber;
    frame.length = jsonPayload.size();
    frame.crc32 = CalculateCRC32(jsonPayload);
    memcpy(frame.payload, jsonPayload.data(), jsonPayload.size());
    
    // 3. Write to ring buffer
    uint32_t writePos = m_header->writeIndex % m_header->capacity;
    memcpy(m_buffer + writePos, &frame, sizeof(EventFrame));
    
    // 4. Update write index (atomic)
    InterlockedIncrement(&m_header->writeIndex);
    
    return true;
}
```

---

## Week 3: Testing & Polish (Days 15-20)

### Testing Checklist

#### Integration Tests
- [ ] **Test 1**: Agent enrollment
  - Start agent with enrollment key
  - Verify config file created
  - Verify agent appears in host dashboard

- [ ] **Test 2**: Sample upload & assignment
  - Upload sample via dashboard
  - Verify agent receives sample in next poll
  - Verify download succeeds

- [ ] **Test 3**: Execution & monitoring
  - Agent downloads and executes sample
  - DLL injects successfully
  - API calls logged to shared memory

- [ ] **Test 4**: Memory dump trigger
  - Agent detects suspicious activity
  - Host receives trigger
  - Memory dump file created

- [ ] **Test 5**: Results upload
  - Agent uploads artifacts
  - Host stores files correctly
  - Dashboard displays results

#### Security Tests
- [ ] Test enrollment key reuse (should fail)
- [ ] Test VM clone detection (different fingerprint, same key)
- [ ] Test expired token (should return 401)
- [ ] Test file upload size limit
- [ ] Test SQL injection in sample metadata
- [ ] Test path traversal in file upload

#### Performance Tests
- [ ] Test with 10 concurrent agents polling
- [ ] Test with 100MB sample download
- [ ] Test with 1000 API calls per second (shared memory)

---

## Critical Files Summary

### HOST (Python/Flask)
```
✓ api/routes/agents.py          - Agent registration, polling, download, upload
⚠️ api/routes/triggers.py        - NEW: Memory dump trigger handler
✓ api/auth.py                    - Bearer token authentication
✓ api/simple_store.py            - Agent storage (JSON)
✓ api/simple_sample_store.py     - Sample queue (JSON)
⚠️ vm_manager/qemu_manager.py    - NEW: capture_memory_dump() method
✓ config/config.py               - Configuration
```

### AGENT (C++/Win32)
```
⚠️ src/Agent/ConfigManager.cpp        - NEW: EnrollWithHost(), GetMachineFingerprint()
⚠️ src/Agent/PollingService.cpp       - NEW: Polling loop
⚠️ src/Agent/ExecutionPipeline.cpp    - Download, execute, inject, upload
⚠️ src/Agent/TriggerEngine.cpp        - NEW: MonitorAndScore(), SendMemoryDumpTrigger()
⚠️ src/HookEngine/TriggerEngineInterface.cpp - Shared memory IPC
✓ src/HookEngine/APIHooks.cpp         - Hook implementations
✓ src/Common/Logger.cpp               - JSON logging
```

### Configuration
```
✓ config/default.json            - Agent configuration (API scores, thresholds)
⚠️ C:\SecurityHealth\agent_config.json - NEW: Agent enrollment result
```

---

## Deployment Checklist

### Host Server
- [ ] Install dependencies: `pip install -r requirements.txt`
- [ ] Run setup: `./setup.sh`
- [ ] Configure VM image path in `config/config.py`
- [ ] Start server: `./start_shost.sh`
- [ ] Access dashboard: `http://localhost:8080/dashboard`
- [ ] Generate enrollment key in dashboard

### VM Agent
- [ ] Build agent: `.\build.bat` (on Windows dev machine)
- [ ] Copy binaries to VM:
  - `ShikraAgent.exe`
  - `ShikraHooks.dll`
  - `config/default.json`
- [ ] Create directory: `C:\SecurityHealth`
- [ ] Run enrollment: `ShikraAgent.exe --enroll <key>`
- [ ] Install service: `ShikraAgent.exe --install`
- [ ] Start service: `net start ShikraSecurityService`

### Verification
- [ ] Host dashboard shows VM as "Online"
- [ ] Upload test sample (e.g., `calc.exe`)
- [ ] Verify agent downloads and executes
- [ ] Verify memory dump triggered
- [ ] Verify results uploaded
- [ ] Download analysis report from dashboard

---

## Priority Order (If Time Constrained)

### Week 1 (Core Flow)
1. Agent enrollment (Host + Agent)
2. Sample upload/assignment (Host)
3. Polling loop (Agent)
4. Sample download/execute (Agent)
5. Memory dump trigger (Host + Agent) **CRITICAL**
6. Results upload (Agent + Host)

### Week 2 (Safety)
7. Error handling (both sides)
8. Memory safety (Agent)
9. Input validation (Host)

### Week 3 (Testing)
10. Integration tests
11. Security tests
12. Performance tests

---

## FAQ / Troubleshooting

**Q: Agent not polling?**
- Check `agent_config.json` exists and has valid token
- Check network connectivity to host
- Check host logs for 401 errors (token expired)

**Q: Sample download fails?**
- Verify sample is assigned to requesting agent
- Check file exists in `data/samples/`
- Check agent has disk space

**Q: DLL injection fails?**
- Verify `ShikraHooks.dll` exists in `C:\SecurityHealth\`
- Check process architecture (x64 vs x86)
- Check SeDebugPrivilege enabled

**Q: Memory dump not triggered?**
- Verify `/api/v1/triggers` blueprint registered
- Check `vm_manager.capture_memory_dump()` implemented
- Check agent has `vm_name` configured
- Verify `virsh dump` command works manually

**Q: Shared memory not working?**
- Check `SHIKRA_SAMPLE_ID` environment variable set
- Verify DLL initializes `TriggerEngineInterface`
- Check for sequence number mismatches

---

## Next Steps After MVP

- Add multi-VM pool support
- Add dashboard real-time updates (WebSocket)
- Add YARA rule scanning
- Add VirusTotal integration
- Add encrypted artifact storage
- Add signed binaries
- Add automated VM snapshot/restore
- Add CI/CD pipeline

---

**SHIP DEADLINE: Day 20**
**FOCUS: Core flow working end-to-end, basic security, basic error handling**
**DEFER: Advanced features, optimization, polish**
