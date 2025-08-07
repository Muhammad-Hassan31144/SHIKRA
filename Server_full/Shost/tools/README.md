# Agent Auto-Registration Tools

This directory contains scripts to automatically register Windows agents with the Shikra Host.

## Scripts

### 1. `auto_register_agent.bat` (Batch Script)
- **Usage**: Run as Administrator from Windows VM
- **Purpose**: Reads registry configuration and registers with host
- **Requirements**: `curl.exe` (available in Windows 10+)

### 2. `auto_register_agent.ps1` (PowerShell Script)  
- **Usage**: `PowerShell -ExecutionPolicy Bypass -File auto_register_agent.ps1`
- **Purpose**: Same as batch script but with better error handling
- **Requirements**: PowerShell 3.0+

### 3. `agent_sim.py` (Python Simulator)
- **Usage**: `python3 agent_sim.py --agent-id your-agent-id`
- **Purpose**: Simulate agent behavior for testing
- **Requirements**: Python 3.6+, requests library

## Registry Configuration

The scripts read these registry values from `HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent`:

| Registry Value | Purpose | Default |
|----------------|---------|---------|
| `AgentId` | Unique agent identifier | `agent-COMPUTERNAME-RANDOM` |
| `AgentSecretPlain` | HMAC secret for authentication | `secret-RANDOM-RANDOM` |
| `HostUrl` | API endpoint URL | `http://192.168.100.1:8080/api/v1/` |
| `WorkingDirectory` | Agent working directory | `C:\Temp\SecurityHealth` |
| `PollInterval` | Polling interval in milliseconds | `30000` |
| `LogLevel` | Logging verbosity (0-4) | `2` |
| `MaxRetries` | Connection retry limit | `3` |
| `ExecutionTimeout` | Sample execution timeout | `300000` |
| `EnableHooking` | Enable API hooking | `1` |
| `EnableMemoryDumps` | Enable memory dumps | `1` |
| `EnableNetworkCapture` | Enable network capture | `1` |

## Quick Start

1. **Configure the registry** (use the main configuration script first)
2. **Run auto-registration**:
   ```cmd
   REM As Administrator
   auto_register_agent.bat
   ```
   
   Or with PowerShell:
   ```powershell
   # As Administrator  
   PowerShell -ExecutionPolicy Bypass -File auto_register_agent.ps1
   ```

3. **Start the agent**:
   ```cmd
   ShikraAgent.exe -start
   ```

## Registration Flow

1. Script reads Windows registry values
2. Creates JSON payload with agent configuration
3. Tests connectivity to host (`/api/health`)
4. Sends POST request to `/api/v1/agent/register`
5. Host validates and stores agent credentials
6. Agent can now authenticate with HMAC and poll for samples

## Troubleshooting

- **"Cannot reach host"**: Check network connectivity and host URL
- **"Registration failed"**: Verify host is running on correct port
- **"Access denied"**: Run script as Administrator
- **"curl not found"**: Install curl or use PowerShell script instead

## Testing

After registration, test with:

```cmd
REM Test next-sample endpoint (requires HMAC auth)
ShikraAgent.exe -test

REM Or use Python simulator
python3 agent_sim.py --agent-id your-registered-agent-id
```
