@echo off
:: Shikra Agent Configuration Applier
:: Reads local Shikra.ini and applies to Windows Registry
setlocal enabledelayedexpansion

echo ================================================================
echo              Shikra Agent Configuration Applier
echo ================================================================
echo.

:: Check administrator privileges
echo Checking administrator privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator!
    echo Right-click Command Prompt and select "Run as administrator"
    pause
    exit /b 1
)
echo ✓ Running as Administrator
echo.

:: Check if Shikra.ini exists
if not exist "Shikra.ini" (
    echo ERROR: Shikra.ini not found in current directory!
    echo.
    echo Please ensure Shikra.ini is in the same folder as this script.
    echo You can download it from the host dashboard.
    pause
    exit /b 1
)

echo ✓ Found Shikra.ini configuration file
echo.

:: Create registry path if it doesn't exist
echo Creating registry structure...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth" /f >nul 2>&1
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /f >nul 2>&1
echo ✓ Registry path created/verified
echo.

:: Parse INI file and apply to registry
echo Reading configuration from Shikra.ini...
echo.

:: Initialize variables
set "HOST_API_URL="
set "AGENT_ID="
set "AGENT_SECRET="
set "POLL_INTERVAL_MS="
set "WORKING_DIRECTORY="
set "LOG_LEVEL="
set "MAX_RETRIES="
set "EXECUTION_TIMEOUT_MS="
set "ENABLE_HOOKING="
set "ENABLE_MEMORY_DUMPS="
set "ENABLE_NETWORK_CAPTURE="

:: Read INI file line by line
for /f "usebackq eol=# tokens=1,2 delims==" %%A in ("Shikra.ini") do (
    set "KEY=%%A"
    set "VALUE=%%B"
    
    :: Remove leading/trailing spaces
    for /f "tokens=* delims= " %%X in ("!KEY!") do set "KEY=%%X"
    for /f "tokens=* delims= " %%Y in ("!VALUE!") do set "VALUE=%%Y"
    
    :: Parse each configuration value
    if /i "!KEY!"=="host_api_url" (
        set "HOST_API_URL=!VALUE!"
        echo [✓] Host API URL: !VALUE!
    )
    if /i "!KEY!"=="agent_id" (
        set "AGENT_ID=!VALUE!"
        echo [✓] Agent ID: !VALUE!
    )
    if /i "!KEY!"=="agent_secret" (
        set "AGENT_SECRET=!VALUE!"
        echo [✓] Agent Secret: [Hidden for security]
    )
    if /i "!KEY!"=="poll_interval_ms" (
        set "POLL_INTERVAL_MS=!VALUE!"
        echo [✓] Poll Interval: !VALUE! ms
    )
    if /i "!KEY!"=="working_directory" (
        set "WORKING_DIRECTORY=!VALUE!"
        echo [✓] Working Directory: !VALUE!
    )
    if /i "!KEY!"=="log_level" (
        set "LOG_LEVEL=!VALUE!"
        echo [✓] Log Level: !VALUE!
    )
    if /i "!KEY!"=="max_retries" (
        set "MAX_RETRIES=!VALUE!"
        echo [✓] Max Retries: !VALUE!
    )
    if /i "!KEY!"=="execution_timeout_ms" (
        set "EXECUTION_TIMEOUT_MS=!VALUE!"
        echo [✓] Execution Timeout: !VALUE! ms
    )
    if /i "!KEY!"=="enable_hooking" (
        set "ENABLE_HOOKING=!VALUE!"
        echo [✓] API Hooking: !VALUE!
    )
    if /i "!KEY!"=="enable_memory_dumps" (
        set "ENABLE_MEMORY_DUMPS=!VALUE!"
        echo [✓] Memory Dumps: !VALUE!
    )
    if /i "!KEY!"=="enable_network_capture" (
        set "ENABLE_NETWORK_CAPTURE=!VALUE!"
        echo [✓] Network Capture: !VALUE!
    )
)

echo.

:: Validate required values
if "!HOST_API_URL!"=="" (
    echo ERROR: host_api_url not found in Shikra.ini
    goto :error
)

if "!AGENT_ID!"=="" (
    echo ERROR: agent_id not found in Shikra.ini
    goto :error
)

if "!AGENT_SECRET!"=="" (
    echo ERROR: agent_secret not found in Shikra.ini
    goto :error
)

:: Apply configuration to registry
echo Applying configuration to Windows registry...
set "REG_PATH=HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent"

:: Core configuration
echo Writing core configuration...
reg add "!REG_PATH!" /v "HostUrl" /t REG_SZ /d "!HOST_API_URL!" /f >nul
if %errorlevel% neq 0 echo [ERROR] Failed to write HostUrl

reg add "!REG_PATH!" /v "AgentId" /t REG_SZ /d "!AGENT_ID!" /f >nul
if %errorlevel% neq 0 echo [ERROR] Failed to write AgentId

reg add "!REG_PATH!" /v "AgentSecret" /t REG_SZ /d "!AGENT_SECRET!" /f >nul
if %errorlevel% neq 0 echo [ERROR] Failed to write AgentSecret

:: Optional settings (with defaults)
if not "!POLL_INTERVAL_MS!"=="" (
    reg add "!REG_PATH!" /v "PollInterval" /t REG_DWORD /d !POLL_INTERVAL_MS! /f >nul
)

if not "!WORKING_DIRECTORY!"=="" (
    reg add "!REG_PATH!" /v "WorkingDirectory" /t REG_SZ /d "!WORKING_DIRECTORY!" /f >nul
)

if not "!LOG_LEVEL!"=="" (
    reg add "!REG_PATH!" /v "LogLevel" /t REG_DWORD /d !LOG_LEVEL! /f >nul
)

if not "!MAX_RETRIES!"=="" (
    reg add "!REG_PATH!" /v "MaxRetries" /t REG_DWORD /d !MAX_RETRIES! /f >nul
)

if not "!EXECUTION_TIMEOUT_MS!"=="" (
    reg add "!REG_PATH!" /v "ExecutionTimeout" /t REG_DWORD /d !EXECUTION_TIMEOUT_MS! /f >nul
)

:: Feature flags
if not "!ENABLE_HOOKING!"=="" (
    reg add "!REG_PATH!" /v "EnableHooking" /t REG_DWORD /d !ENABLE_HOOKING! /f >nul
)

if not "!ENABLE_MEMORY_DUMPS!"=="" (
    reg add "!REG_PATH!" /v "EnableMemoryDumps" /t REG_DWORD /d !ENABLE_MEMORY_DUMPS! /f >nul
)

if not "!ENABLE_NETWORK_CAPTURE!"=="" (
    reg add "!REG_PATH!" /v "EnableNetworkCapture" /t REG_DWORD /d !ENABLE_NETWORK_CAPTURE! /f >nul
)

echo ✓ All configuration values written to registry
echo.

:: Display current registry configuration
echo Current registry configuration:
reg query "!REG_PATH!" 2>nul | findstr REG_
echo.

echo ================================================================
echo                   Configuration Applied Successfully!
echo ================================================================
echo.
echo The Shikra Agent is now configured and ready to run.
echo.

:: Ask about service restart
set /p "RESTART=Would you like to restart the ShikraAgent service now? (Y/N): "

if /i "!RESTART!"=="Y" (
    echo.
    echo Restarting ShikraAgent service...
    
    :: Stop service
    net stop ShikraAgent >nul 2>&1
    if !errorlevel! equ 0 (
        echo ✓ Service stopped successfully
    ) else (
        echo [!] Service was not running or stop failed
    )
    
    :: Wait a moment
    timeout /t 2 >nul
    
    :: Start service
    net start ShikraAgent >nul 2>&1
    if !errorlevel! equ 0 (
        echo ✓ Service started successfully
        echo.
        echo The agent should now connect to the host automatically.
        echo Check the host dashboard for agent status.
    ) else (
        echo [!] Service start failed
        echo.
        echo You may need to:
        echo 1. Install the service first: ShikraAgent.exe --install
        echo 2. Or run manually: ShikraAgent.exe
    )
) else (
    echo.
    echo Configuration applied. Remember to start/restart the ShikraAgent service.
    echo.
    echo Commands:
    echo   Start service:   net start ShikraAgent
    echo   Stop service:    net stop ShikraAgent
    echo   Install service: ShikraAgent.exe --install
    echo   Run manually:    ShikraAgent.exe
)

echo.
echo Configuration complete!
pause
exit /b 0

:error
echo.
echo Configuration failed! Please check Shikra.ini file.
pause
exit /b 1
