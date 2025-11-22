@echo off
setlocal enabledelayedexpansion

:: Shikra Agent Auto-Registration Script (Fixed Version)
:: Reads Windows registry and sends configuration to host

echo ========::Send registration request with detailed output
echo Sending registration request...
echo Command: curl -X POST "!REGISTER_URL!" -H "Content-Type: application/json" -d @"!JSON_FILE!"
echo.

:: Debug: Show the actual JSON being sent
echo DEBUG: JSON payload being sent:
echo ==========================================
type "!JSON_FILE!"
echo ==========================================
echo.

set "RESPONSE_FILE=%TEMP%\shikra_response.json"==================================================
echo           Shikra Agent Auto-Registration
echo ================================================================
echo.

:: Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    echo.
    pause
    exit /b 1
)

:: Registry path
set "REG_PATH=HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent"

:: Default host URL if not found in registry
set "DEFAULT_HOST=http://192.168.100.1:8080"

echo Reading agent configuration from registry...
echo Registry path: %REG_PATH%
echo.

:: Check if registry key exists
reg query "%REG_PATH%" >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Registry key not found: %REG_PATH%
    echo Please run the configuration script first!
    echo.
    pause
    exit /b 1
)

:: Read values from registry using improved method
call :ReadRegValue "AgentId" AGENT_ID
call :ReadRegValue "AgentSecretPlain" AGENT_SECRET
call :ReadRegValue "HostUrl" HOST_URL
call :ReadRegValue "WorkingDirectory" WORKING_DIR
call :ReadRegValue "PollInterval" POLL_INTERVAL
call :ReadRegValue "LogLevel" LOG_LEVEL
call :ReadRegValue "MaxRetries" MAX_RETRIES
call :ReadRegValue "ExecutionTimeout" EXECUTION_TIMEOUT
call :ReadRegValue "EnableHooking" ENABLE_HOOKING
call :ReadRegValue "EnableMemoryDumps" ENABLE_MEMORY_DUMPS
call :ReadRegValue "EnableNetworkCapture" ENABLE_NETWORK_CAPTURE

:: Debug: Show what was read from registry
echo Debug - Raw registry values:
echo   AGENT_ID=!AGENT_ID!
echo   AGENT_SECRET=!AGENT_SECRET!
echo   HOST_URL=!HOST_URL!
echo   WORKING_DIR=!WORKING_DIR!
echo.

:: Set defaults for missing values and save to registry
set "VALUES_UPDATED=0"

if "!AGENT_ID!"=="" (
    set "AGENT_ID=agent-%COMPUTERNAME%-%RANDOM%"
    echo Setting default AgentId: !AGENT_ID!
    call :WriteRegValue "AgentId" "!AGENT_ID!"
    set "VALUES_UPDATED=1"
)

if "!AGENT_SECRET!"=="" (
    set "AGENT_SECRET=secret-%RANDOM%-%RANDOM%"
    echo Setting default AgentSecretPlain: !AGENT_SECRET!
    call :WriteRegValue "AgentSecretPlain" "!AGENT_SECRET!"
    set "VALUES_UPDATED=1"
)

if "!HOST_URL!"=="" (
    set "HOST_URL=%DEFAULT_HOST%/api/v1/"
    echo Setting default HostUrl: !HOST_URL!
    call :WriteRegValue "HostUrl" "!HOST_URL!"
    set "VALUES_UPDATED=1"
)

if "!WORKING_DIR!"=="" (
    set "WORKING_DIR=C:\Temp\SecurityHealth"
    call :WriteRegValue "WorkingDirectory" "!WORKING_DIR!"
    set "VALUES_UPDATED=1"
)

if "!POLL_INTERVAL!"=="" (
    set "POLL_INTERVAL=30000"
    call :WriteRegValue "PollInterval" "!POLL_INTERVAL!"
    set "VALUES_UPDATED=1"
)

if "!LOG_LEVEL!"=="" (
    set "LOG_LEVEL=2"
    call :WriteRegValue "LogLevel" "!LOG_LEVEL!"
    set "VALUES_UPDATED=1"
)

if "!MAX_RETRIES!"=="" (
    set "MAX_RETRIES=3"
    call :WriteRegValue "MaxRetries" "!MAX_RETRIES!"
    set "VALUES_UPDATED=1"
)

if "!EXECUTION_TIMEOUT!"=="" (
    set "EXECUTION_TIMEOUT=300000"
    call :WriteRegValue "ExecutionTimeout" "!EXECUTION_TIMEOUT!"
    set "VALUES_UPDATED=1"
)

if "!ENABLE_HOOKING!"=="" (
    set "ENABLE_HOOKING=1"
    call :WriteRegValue "EnableHooking" "!ENABLE_HOOKING!"
    set "VALUES_UPDATED=1"
)

if "!ENABLE_MEMORY_DUMPS!"=="" (
    set "ENABLE_MEMORY_DUMPS=1"
    call :WriteRegValue "EnableMemoryDumps" "!ENABLE_MEMORY_DUMPS!"
    set "VALUES_UPDATED=1"
)

if "!ENABLE_NETWORK_CAPTURE!"=="" (
    set "ENABLE_NETWORK_CAPTURE=1"
    call :WriteRegValue "EnableNetworkCapture" "!ENABLE_NETWORK_CAPTURE!"
    set "VALUES_UPDATED=1"
)

if "!VALUES_UPDATED!"=="1" (
    echo.
    echo Registry values updated with defaults. The agent service will use these values.
    echo.
)

:: Clean up HOST_URL to get base URL for registration
set "HOST_URL_CLEAN=!HOST_URL!"

:: Remove /api/v1/ or /api/v1 from the end using string replacement
set "HOST_URL_CLEAN=!HOST_URL_CLEAN:/api/v1/=!"
set "HOST_URL_CLEAN=!HOST_URL_CLEAN:/api/v1=!"

:: Remove any trailing slashes
:remove_trailing_slash
if "!HOST_URL_CLEAN:~-1!"=="/" (
    set "HOST_URL_CLEAN=!HOST_URL_CLEAN:~0,-1!"
    goto remove_trailing_slash
)

set "REGISTER_URL=!HOST_URL_CLEAN!/api/v1/agent/register"

echo Configuration found:
echo   Agent ID:        !AGENT_ID!
echo   Agent Secret:    [Hidden - Length: !AGENT_SECRET:~0,8!...]
echo   Host URL:        !HOST_URL!
echo   Working Dir:     !WORKING_DIR!
echo   Poll Interval:   !POLL_INTERVAL! ms
echo   Log Level:       !LOG_LEVEL!
echo   Max Retries:     !MAX_RETRIES!
echo   Exec Timeout:    !EXECUTION_TIMEOUT! ms
echo   Enable Hooking:  !ENABLE_HOOKING!
echo   Memory Dumps:    !ENABLE_MEMORY_DUMPS!
echo   Network Capture: !ENABLE_NETWORK_CAPTURE!
echo.
echo Registration URL: !REGISTER_URL!
echo.

:: Convert boolean values for JSON
if "!ENABLE_HOOKING!"=="1" (set "HOOKING_BOOL=true") else (set "HOOKING_BOOL=false")
if "!ENABLE_MEMORY_DUMPS!"=="1" (set "DUMPS_BOOL=true") else (set "DUMPS_BOOL=false")
if "!ENABLE_NETWORK_CAPTURE!"=="1" (set "CAPTURE_BOOL=true") else (set "CAPTURE_BOOL=false")

:: Escape JSON special characters in strings
call :EscapeJSON "!AGENT_ID!" AGENT_ID_ESC
call :EscapeJSON "!AGENT_SECRET!" AGENT_SECRET_ESC
call :EscapeJSON "!HOST_URL!" HOST_URL_ESC
call :EscapeJSON "!WORKING_DIR!" WORKING_DIR_ESC

:: Debug: Show escaped values
echo DEBUG: Escaped JSON values:
echo   AGENT_ID_ESC:     "!AGENT_ID_ESC!"
echo   AGENT_SECRET_ESC: "!AGENT_SECRET_ESC!"
echo   HOST_URL_ESC:     "!HOST_URL_ESC!"  
echo   WORKING_DIR_ESC:  "!WORKING_DIR_ESC!"
echo   COMPUTERNAME:     "!COMPUTERNAME!"
echo.

:: Create temporary JSON file (more reliable than inline JSON)
set "JSON_FILE=%TEMP%\shikra_registration.json"
(
  echo {
  echo   "agent_id": "!AGENT_ID_ESC!",
  echo   "agent_secret": "!AGENT_SECRET_ESC!",
  echo   "name": "Agent !COMPUTERNAME!",
  echo   "capabilities": "file,registry,process,network,memory",
  echo   "host_url": "!HOST_URL_ESC!",
  echo   "poll_interval": !POLL_INTERVAL!,
  echo   "working_directory": "!WORKING_DIR_ESC!",
  echo   "log_level": !LOG_LEVEL!,
  echo   "max_retries": !MAX_RETRIES!,
  echo   "execution_timeout": !EXECUTION_TIMEOUT!,
  echo   "enable_hooking": !HOOKING_BOOL!,
  echo   "enable_memory_dumps": !DUMPS_BOOL!,
  echo   "enable_network_capture": !CAPTURE_BOOL!
  echo }
) > "!JSON_FILE!"

echo Generated registration payload:
type "!JSON_FILE!"
echo.

:: Extract hostname from URL for ping test
set "PING_HOST=!HOST_URL_CLEAN!"
if "!PING_HOST:~0,7!"=="http://" set "PING_HOST=!PING_HOST:~7!"
if "!PING_HOST:~0,8!"=="https://" set "PING_HOST=!PING_HOST:~8!"
:: Remove port if present
for /f "tokens=1 delims=:" %%A in ("!PING_HOST!") do set "PING_HOST=%%A"

echo Testing connectivity to host...
echo Pinging !PING_HOST!...
ping -n 1 !PING_HOST! >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Host !PING_HOST! may not be reachable via ping
    echo Continuing with registration attempt...
) else (
    echo ✓ Host !PING_HOST! is reachable via ping
)
echo.

:: Check if curl is available
curl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: curl is not available!
    echo Please install curl or use Windows 10/11 which includes it
    echo Download from: https://curl.se/download.html
    echo.
    pause
    del "!JSON_FILE!" 2>nul
    exit /b 1
)

:: Send registration request with detailed output
echo Sending registration request...
echo Command: curl -X POST "!REGISTER_URL!" -H "Content-Type: application/json" -d @"!JSON_FILE!"
echo.

set "RESPONSE_FILE=%TEMP%\shikra_response.json"

curl -X POST "!REGISTER_URL!" ^
  -H "Content-Type: application/json" ^
  -H "User-Agent: ShikraAgent/1.0" ^
  -d @"!JSON_FILE!" ^
  -w "Response Status: %%{http_code}^nResponse Time: %%{time_total}s^nTotal Time: %%{time_total}s^n" ^
  -o "!RESPONSE_FILE!" ^
  -m 30 ^
  --connect-timeout 10 ^
  -s -S

set "CURL_RESULT=%errorlevel%"

echo.
echo Curl exit code: !CURL_RESULT!

:: Show response if available
if exist "!RESPONSE_FILE!" (
    echo Server response:
    type "!RESPONSE_FILE!"
    echo.
    
    :: Check for success indicators in response
    findstr /i "success\|registered\|created" "!RESPONSE_FILE!" >nul 2>&1
    if !errorlevel! equ 0 (
        echo ✓ Registration appears successful!
    ) else (
        echo ! Check response above for registration status
    )
    
    del "!RESPONSE_FILE!" 2>nul
) else (
    echo No response file created - check network connectivity
)

:: Cleanup temp files
del "!JSON_FILE!" 2>nul

echo.
if !CURL_RESULT! equ 0 (
    echo ✓ Registration request sent successfully!
    echo.
    echo Next steps:
    echo   1. Check host logs for registration confirmation
    echo   2. Install service if not done: ShikraAgent.exe -install
    echo   3. Test configuration: ShikraAgent.exe -test
    echo   4. Start the service: ShikraAgent.exe -start
    echo   5. Monitor agent logs for sample polling
    echo.
    
    :: Test agent configuration if executable is available
    if exist "ShikraAgent.exe" (
        echo Testing agent configuration...
        ShikraAgent.exe -test
    ) else (
        echo ShikraAgent.exe not found in current directory
        echo Please run this script from the agent directory
    )
    
) else (
    echo ✗ Registration failed! (Curl exit code: !CURL_RESULT!)
    echo.
    echo Troubleshooting:
    echo   1. Check if host is running: !REGISTER_URL!
    echo   2. Verify host URL in registry is correct
    echo   3. Check firewall/network connectivity  
    echo   4. Try accessing URL in browser: !HOST_URL_CLEAN!
    echo   5. Check host logs for errors
    echo   6. Ensure registration endpoint exists on host
    echo.
    echo Common curl exit codes:
    echo   6 = Couldn't resolve host
    echo   7 = Failed to connect to host
    echo   28 = Operation timeout
    echo   52 = Empty response from server
    echo.
)

echo.
echo Auto-registration complete!
pause
exit /b !CURL_RESULT!

:: Function to read registry value with better error handling
:ReadRegValue
setlocal EnableDelayedExpansion
set "ValueName=%~1"
set "VarName=%~2"
set "Value="

echo [DEBUG] Reading registry value: !ValueName!

:: Method 1: Try to read the value using skip=1
for /f "skip=1 tokens=1,2*" %%A in ('reg query "%REG_PATH%" /v "!ValueName!" 2^>nul') do (
    echo [DEBUG] Registry line: "%%A" "%%B" "%%C"
    if /i "%%A"=="!ValueName!" (
        set "Value=%%C"
        echo [DEBUG] Found value: !Value!
    )
)

:: Method 2: If still empty, try alternative approach
if "!Value!"=="" (
    echo [DEBUG] Method 1 failed, trying method 2...
    for /f "tokens=2*" %%A in ('reg query "%REG_PATH%" /v "!ValueName!" 2^>nul ^| find "!ValueName!"') do (
        set "Value=%%B"
        echo [DEBUG] Method 2 found: !Value!
    )
)

:: Method 3: Handle REG_DWORD values
if "!Value!"=="" (
    echo [DEBUG] Method 2 failed, trying for DWORD...
    for /f "tokens=3" %%A in ('reg query "%REG_PATH%" /v "!ValueName!" 2^>nul ^| find "!ValueName!"') do (
        set "Value=%%A"
        echo [DEBUG] DWORD value: !Value!
    )
)

echo [DEBUG] Final value for !ValueName!: "!Value!"

endlocal & set "%VarName%=!Value!"
goto :eof

:: Function to escape JSON special characters
:EscapeJSON
setlocal EnableDelayedExpansion
set "input=%~1"
set "varname=%~2"

:: Replace backslashes first (must be first!)
set "input=!input:\=\\!"

:: Replace quotes
set "input=!input:"=\"!"

:: Don't remove spaces - they're valid in JSON strings!
:: set "input=!input: = !" <- This was corrupting the JSON!

endlocal & set "%varname%=!input!"
goto :eof

:: Function to write registry value
:WriteRegValue
setlocal EnableDelayedExpansion
set "ValueName=%~1"
set "ValueData=%~2"

echo [DEBUG] Writing registry value: !ValueName! = "!ValueData!"

reg add "%REG_KEY%" /v "!ValueName!" /t REG_SZ /d "!ValueData!" /f >nul 2>&1
if !errorlevel! neq 0 (
    echo [WARNING] Failed to write registry value: !ValueName!
    echo [WARNING] You may need to run this script as Administrator
) else (
    echo [INFO] Successfully wrote !ValueName! to registry
)

endlocal
goto :eof