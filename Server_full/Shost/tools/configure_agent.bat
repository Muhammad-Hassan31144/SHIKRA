@echo off
setlocal enabledelayedexpansion

echo ================================================================
echo                 Shikra Agent Configuration
echo                     Debug Version
echo ================================================================
echo.
echo Starting configuration script...
echo Current directory: %CD%
echo Computer name: %COMPUTERNAME%
echo User: %USERNAME%
echo.

:: Force visible output
echo This script will configure the Shikra Agent Windows service.
echo Press Enter to use default values, or type custom values.
echo.

:: Better administrator check
echo Checking administrator privileges...
whoami /groups | find "S-1-16-12288" >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo WARNING: Not running as Administrator!
    echo Some operations may fail.
    echo.
    echo To run as administrator:
    echo 1. Right-click on Command Prompt
    echo 2. Select "Run as administrator"  
    echo 3. Navigate to this directory
    echo 4. Run this script again
    echo.
    echo Continue anyway? (Y/N):
    set /p "CONTINUE="
    if /i "!CONTINUE!" neq "Y" (
        echo Exiting...
        pause
        exit /b 1
    )
) else (
    echo ✓ Running as Administrator
)

echo.
echo Setting up default values...

:: Default values - using simpler approach
set DEFAULT_HOST_URL=http://192.168.100.1:8080/api/v1/
set DEFAULT_AGENT_ID=agent-%COMPUTERNAME%-%RANDOM%
set DEFAULT_AGENT_SECRET=secret-%RANDOM%-%RANDOM%
set DEFAULT_WORKING_DIR=C:\ProgramData\SecurityHealth
set DEFAULT_POLL_INTERVAL=30000
set DEFAULT_LOG_LEVEL=2
set DEFAULT_MAX_RETRIES=3
set DEFAULT_EXECUTION_TIMEOUT=300000

echo Default values set:
echo   Host URL: %DEFAULT_HOST_URL%
echo   Agent ID: %DEFAULT_AGENT_ID%
echo   Working Dir: %DEFAULT_WORKING_DIR%

echo.
echo ================================================================
echo                    Configuration Input
echo ================================================================

:: Collect configuration with simpler prompts
echo.
echo [1/8] Analysis Host Configuration
echo ----------------------------------------
echo Default: %DEFAULT_HOST_URL%
echo.
set /p HOST_URL="Enter Host URL (or press Enter for default): "
if "%HOST_URL%"=="" set HOST_URL=%DEFAULT_HOST_URL%
echo Selected: %HOST_URL%

echo.
echo [2/8] Agent Identity
echo ----------------------------------------
echo Default: %DEFAULT_AGENT_ID%
echo.
set /p AGENT_ID="Enter Agent ID (or press Enter for default): "
if "%AGENT_ID%"=="" set AGENT_ID=%DEFAULT_AGENT_ID%
echo Selected: %AGENT_ID%

echo.
echo [3/8] Agent Authentication
echo ----------------------------------------
echo Default: %DEFAULT_AGENT_SECRET%
echo.
set /p AGENT_SECRET="Enter Agent Secret (or press Enter for default): "
if "%AGENT_SECRET%"=="" set AGENT_SECRET=%DEFAULT_AGENT_SECRET%
echo Selected: %AGENT_SECRET%

echo.
echo [4/8] Working Directory
echo ----------------------------------------
echo Default: %DEFAULT_WORKING_DIR%
echo.
set /p WORKING_DIR="Enter Working Directory (or press Enter for default): "
if "%WORKING_DIR%"=="" set WORKING_DIR=%DEFAULT_WORKING_DIR%
echo Selected: %WORKING_DIR%

echo.
echo [5/8] Polling Configuration
echo ----------------------------------------
echo Default: %DEFAULT_POLL_INTERVAL% milliseconds (30 seconds)
echo.
set /p POLL_INTERVAL="Enter Poll Interval in ms (or press Enter for default): "
if "%POLL_INTERVAL%"=="" set POLL_INTERVAL=%DEFAULT_POLL_INTERVAL%
echo Selected: %POLL_INTERVAL%

echo.
echo [6/8] Logging Configuration
echo ----------------------------------------
echo Log Levels: 0=Debug, 1=Info, 2=Warning, 3=Error, 4=Critical
echo Default: %DEFAULT_LOG_LEVEL% (Warning)
echo.
set /p LOG_LEVEL="Enter Log Level (or press Enter for default): "
if "%LOG_LEVEL%"=="" set LOG_LEVEL=%DEFAULT_LOG_LEVEL%
echo Selected: %LOG_LEVEL%

echo.
echo [7/8] Connection Settings
echo ----------------------------------------
echo Default: %DEFAULT_MAX_RETRIES% retries
echo.
set /p MAX_RETRIES="Enter Max Retries (or press Enter for default): "
if "%MAX_RETRIES%"=="" set MAX_RETRIES=%DEFAULT_MAX_RETRIES%
echo Selected: %MAX_RETRIES%

echo.
echo [8/8] Sample Execution Settings
echo ----------------------------------------
echo Default: %DEFAULT_EXECUTION_TIMEOUT% milliseconds (5 minutes)
echo.
set /p EXECUTION_TIMEOUT="Enter Execution Timeout in ms (or press Enter for default): "
if "%EXECUTION_TIMEOUT%"=="" set EXECUTION_TIMEOUT=%DEFAULT_EXECUTION_TIMEOUT%
echo Selected: %EXECUTION_TIMEOUT%

:: Confirmation
echo.
echo ================================================================
echo                    Configuration Summary
echo ================================================================
echo Host URL:           %HOST_URL%
echo Agent ID:           %AGENT_ID%
echo Agent Secret:       %AGENT_SECRET%
echo Working Directory:  %WORKING_DIR%
echo Poll Interval:      %POLL_INTERVAL% ms
echo Log Level:          %LOG_LEVEL%
echo Max Retries:        %MAX_RETRIES%
echo Execution Timeout:  %EXECUTION_TIMEOUT% ms
echo ================================================================
echo.

set /p CONFIRM="Apply this configuration? (Y/N): "
if /i "%CONFIRM%" neq "Y" (
    echo Configuration cancelled by user.
    pause
    exit /b 0
)

echo.
echo ================================================================
echo                 Applying Configuration
echo ================================================================

:: Create Shikra.ini file first
echo.
echo Step 1: Creating Shikra.ini configuration file...

:: Use a more reliable method to create the file
echo # Shikra Agent Configuration File> Shikra.ini
echo # Generated on %DATE% %TIME%>> Shikra.ini
echo.>> Shikra.ini
echo [agent]>> Shikra.ini
echo host_api_url=%HOST_URL%>> Shikra.ini
echo agent_id=%AGENT_ID%>> Shikra.ini
echo agent_secret=%AGENT_SECRET%>> Shikra.ini
echo working_directory=%WORKING_DIR%>> Shikra.ini
echo poll_interval_ms=%POLL_INTERVAL%>> Shikra.ini
echo log_level=%LOG_LEVEL%>> Shikra.ini
echo max_retries=%MAX_RETRIES%>> Shikra.ini
echo execution_timeout_ms=%EXECUTION_TIMEOUT%>> Shikra.ini
echo.>> Shikra.ini
echo [features]>> Shikra.ini
echo hooks_enabled=true>> Shikra.ini
echo compression=true>> Shikra.ini
echo memory_dumps=true>> Shikra.ini
echo network_capture=true>> Shikra.ini
echo.>> Shikra.ini
echo [registration]>> Shikra.ini
echo hostname=%COMPUTERNAME%>> Shikra.ini
echo os_version=%OS%>> Shikra.ini
echo timestamp=%DATE% %TIME%>> Shikra.ini
echo.>> Shikra.ini
echo [network]>> Shikra.ini
echo connection_timeout_ms=10000>> Shikra.ini
echo request_timeout_ms=30000>> Shikra.ini
echo validate_certificates=false>> Shikra.ini
echo.>> Shikra.ini
echo [logging]>> Shikra.ini
echo destinations=eventlog,file>> Shikra.ini
echo max_file_size_mb=10>> Shikra.ini
echo max_files=5>> Shikra.ini
echo debug_output=true>> Shikra.ini

if exist Shikra.ini (
    echo ✓ Shikra.ini created successfully
    dir Shikra.ini
) else (
    echo ✗ Failed to create Shikra.ini file
    echo Current directory: %CD%
    echo Permissions: 
    icacls .
    pause
    goto :error
)

:: Create JSON format
echo.
echo Step 2: Creating Shikra.json configuration file...

echo {> Shikra.json
echo   "agent": {>> Shikra.json
echo     "host_api_url": "%HOST_URL%",>> Shikra.json
echo     "agent_id": "%AGENT_ID%",>> Shikra.json
echo     "agent_secret": "%AGENT_SECRET%",>> Shikra.json
echo     "working_directory": "%WORKING_DIR%",>> Shikra.json
echo     "poll_interval_ms": %POLL_INTERVAL%,>> Shikra.json
echo     "log_level": %LOG_LEVEL%,>> Shikra.json
echo     "max_retries": %MAX_RETRIES%,>> Shikra.json
echo     "execution_timeout_ms": %EXECUTION_TIMEOUT%>> Shikra.json
echo   },>> Shikra.json
echo   "features": {>> Shikra.json
echo     "hooks_enabled": true,>> Shikra.json
echo     "compression": true,>> Shikra.json
echo     "memory_dumps": true,>> Shikra.json
echo     "network_capture": true>> Shikra.json
echo   },>> Shikra.json
echo   "registration": {>> Shikra.json
echo     "hostname": "%COMPUTERNAME%",>> Shikra.json
echo     "os_version": "%OS%",>> Shikra.json
echo     "timestamp": "%DATE% %TIME%">> Shikra.json
echo   },>> Shikra.json
echo   "network": {>> Shikra.json
echo     "connection_timeout_ms": 10000,>> Shikra.json
echo     "request_timeout_ms": 30000,>> Shikra.json
echo     "validate_certificates": false>> Shikra.json
echo   },>> Shikra.json
echo   "logging": {>> Shikra.json
echo     "destinations": ["eventlog", "file"],>> Shikra.json
echo     "max_file_size_mb": 10,>> Shikra.json
echo     "max_files": 5,>> Shikra.json
echo     "debug_output": true>> Shikra.json
echo   }>> Shikra.json
echo }>> Shikra.json

if exist Shikra.json (
    echo ✓ Shikra.json created successfully
    dir Shikra.json
) else (
    echo ✗ Failed to create Shikra.json file
    pause
    goto :error
)

:: Registry operations with better error handling
echo.
echo Step 3: Setting up Windows Registry...

echo Creating registry structure...
reg add "HKLM\SOFTWARE\Microsoft" /f >nul 2>&1
echo Registry - Microsoft key: %errorlevel%

reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth" /f >nul 2>&1
echo Registry - SecurityHealth key: %errorlevel%

reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /f >nul 2>&1
echo Registry - Agent key: %errorlevel%

:: Delete existing values first to avoid conflicts
echo Clearing existing registry values...
reg delete "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "HostUrl" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "AgentId" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "WorkingDirectory" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "PollInterval" /f >nul 2>&1
reg delete "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "AgentSecretPlain" /f >nul 2>&1

:: Set main configuration values one by one with error checking
echo Setting main configuration values...

echo Setting HostUrl...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "HostUrl" /t REG_SZ /d "%HOST_URL%" /f
if %errorlevel% neq 0 (
    echo ✗ Failed to set HostUrl (Error: %errorlevel%)
    echo Trying alternative method...
    reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "HostUrl" /t REG_SZ /d "%HOST_URL%" /f
) else (
    echo ✓ HostUrl set successfully
)

echo Setting AgentId...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "AgentId" /t REG_SZ /d "%AGENT_ID%" /f
if %errorlevel% neq 0 (
    echo ✗ Failed to set AgentId (Error: %errorlevel%)
) else (
    echo ✓ AgentId set successfully
)

echo Setting WorkingDirectory...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "WorkingDirectory" /t REG_SZ /d "%WORKING_DIR%" /f
if %errorlevel% neq 0 (
    echo ✗ Failed to set WorkingDirectory (Error: %errorlevel%)
) else (
    echo ✓ WorkingDirectory set successfully
)

echo Setting PollInterval...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "PollInterval" /t REG_DWORD /d "%POLL_INTERVAL%" /f
if %errorlevel% neq 0 (
    echo ✗ Failed to set PollInterval (Error: %errorlevel%)
) else (
    echo ✓ PollInterval set successfully
)

echo Setting other values...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "LogLevel" /t REG_DWORD /d "%LOG_LEVEL%" /f
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "MaxRetries" /t REG_DWORD /d "%MAX_RETRIES%" /f
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "ExecutionTimeout" /t REG_DWORD /d "%EXECUTION_TIMEOUT%" /f

:: Set feature flags
echo Setting feature flags...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "EnableHooking" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "EnableMemoryDumps" /t REG_DWORD /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "EnableNetworkCapture" /t REG_DWORD /d "1" /f

:: Store agent secret
echo Setting agent secret...
reg add "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "AgentSecretPlain" /t REG_SZ /d "%AGENT_SECRET%" /f
if %errorlevel% neq 0 (
    echo ✗ Failed to set AgentSecretPlain (Error: %errorlevel%)
) else (
    echo ✓ AgentSecretPlain set successfully
)

:: Verify registry entries
echo.
echo Step 4: Verifying registry entries...
reg query "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v "HostUrl" 2>nul
if %errorlevel% equ 0 (
    echo ✓ HostUrl verified in registry
) else (
    echo ✗ HostUrl not found in registry
)

:: Create working directory with detailed output
echo.
echo Step 5: Creating working directory...
echo Target directory: %WORKING_DIR%

if not exist "%WORKING_DIR%" (
    echo Directory does not exist, creating...
    mkdir "%WORKING_DIR%" 2>nul
    if %errorlevel% equ 0 (
        echo ✓ Working directory created successfully
    ) else (
        echo ✗ Failed to create working directory (Error: %errorlevel%)
        echo Trying to create parent directories...
        
        :: Create parent directories step by step
        if not exist "C:\ProgramData" mkdir "C:\ProgramData"
        if not exist "C:\ProgramData\SecurityHealth" mkdir "C:\ProgramData\SecurityHealth"
        
        if exist "C:\ProgramData\SecurityHealth" (
            echo ✓ Working directory created with parent directory creation
        ) else (
            echo ✗ Still failed to create working directory
            echo Using fallback directory: C:\Temp\SecurityHealth
            set WORKING_DIR=C:\Temp\SecurityHealth
            mkdir "C:\Temp\SecurityHealth" 2>nul
        )
    )
) else (
    echo ✓ Working directory already exists
)

:: Set directory permissions
echo Setting directory permissions...
if exist "%WORKING_DIR%" (
    icacls "%WORKING_DIR%" /grant "SYSTEM:(OI)(CI)F" /grant "Administrators:(OI)(CI)F" >nul 2>&1
    if %errorlevel% equ 0 (
        echo ✓ Directory permissions set successfully
    ) else (
        echo ✗ Failed to set directory permissions (Error: %errorlevel%)
    )
    
    :: Create subdirectories
    echo Creating subdirectories...
    if not exist "%WORKING_DIR%\logs" mkdir "%WORKING_DIR%\logs"
    if not exist "%WORKING_DIR%\artifacts" mkdir "%WORKING_DIR%\artifacts"
    if not exist "%WORKING_DIR%\samples" mkdir "%WORKING_DIR%\samples"
    
    echo ✓ Subdirectories created
)

:: Create registration files
echo.
echo Step 6: Creating registration files...

:: Create registration payload JSON
echo {> registration_payload.json
echo   "agent_id": "%AGENT_ID%",>> registration_payload.json
echo   "hostname": "%COMPUTERNAME%",>> registration_payload.json
echo   "os_version": "%OS%",>> registration_payload.json
echo   "agent_version": "1.0.0",>> registration_payload.json
echo   "capabilities": [>> registration_payload.json
echo     "sample_execution",>> registration_payload.json
echo     "api_hooking",>> registration_payload.json
echo     "memory_dumps",>> registration_payload.json
echo     "network_capture",>> registration_payload.json
echo     "artifact_collection">> registration_payload.json
echo   ],>> registration_payload.json
echo   "timestamp": "%DATE% %TIME%",>> registration_payload.json
echo   "working_directory": "%WORKING_DIR%",>> registration_payload.json
echo   "poll_interval_ms": %POLL_INTERVAL%>> registration_payload.json
echo }>> registration_payload.json

if exist registration_payload.json (
    echo ✓ Registration payload created
) else (
    echo ✗ Failed to create registration payload
)

:: Create registration script
echo @echo off> register_agent.bat
echo echo ================================================================>> register_agent.bat
echo echo              Shikra Agent Registration>> register_agent.bat  
echo echo ================================================================>> register_agent.bat
echo echo.>> register_agent.bat
echo echo Registering agent with host...>> register_agent.bat
echo echo Host: %HOST_URL%>> register_agent.bat
echo echo Agent ID: %AGENT_ID%>> register_agent.bat
echo echo.>> register_agent.bat
echo echo Registration payload file: registration_payload.json>> register_agent.bat
echo echo.>> register_agent.bat
echo if exist registration_payload.json (>> register_agent.bat
echo     echo Registration data:>> register_agent.bat
echo     type registration_payload.json>> register_agent.bat
echo     echo.>> register_agent.bat
echo     echo To complete registration, send POST request to:>> register_agent.bat
echo     echo   %HOST_URL%/api/v1/agent/register>> register_agent.bat
echo     echo.>> register_agent.bat
echo     echo Example curl command:>> register_agent.bat
echo     echo curl -X POST "%HOST_URL%/api/v1/agent/register" \>> register_agent.bat
echo     echo      -H "Content-Type: application/json" \>> register_agent.bat
echo     echo      -H "X-Agent-ID: %AGENT_ID%" \>> register_agent.bat
echo     echo      -H "X-Agent-Secret: %AGENT_SECRET%" \>> register_agent.bat
echo     echo      --data @registration_payload.json>> register_agent.bat
echo ^) else (>> register_agent.bat
echo     echo ERROR: registration_payload.json not found>> register_agent.bat
echo ^)>> register_agent.bat
echo echo.>> register_agent.bat
echo pause>> register_agent.bat

if exist register_agent.bat (
    echo ✓ Registration script created
) else (
    echo ✗ Failed to create registration script
)

echo.
echo ================================================================
echo                 Configuration Complete!
echo ================================================================
echo.
echo Files created:
if exist Shikra.ini echo ✓ Shikra.ini
if exist Shikra.json echo ✓ Shikra.json  
if exist registration_payload.json echo ✓ registration_payload.json
if exist register_agent.bat echo ✓ register_agent.bat

echo.
echo Registry entries created:
reg query "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" 2>nul
if %errorlevel% equ 0 (
    echo ✓ Registry configuration applied
) else (
    echo ✗ Registry configuration may have failed
)

echo.
echo Directories created:
if exist "%WORKING_DIR%" (
    echo ✓ %WORKING_DIR%
    dir "%WORKING_DIR%" /AD /B 2>nul
) else (
    echo ✗ Working directory creation failed
)

:: Test with ShikraAgent.exe if available
echo.
echo ================================================================
echo                      Testing
echo ================================================================

if exist "ShikraAgent.exe" (
    echo Found ShikraAgent.exe, running test...
    echo.
    
    echo Running configuration test...
    ShikraAgent.exe -test
    set TEST_RESULT=%errorlevel%
    
    echo.
    echo Test result: %TEST_RESULT%
    
    if %TEST_RESULT% equ 0 (
        echo ✓ Configuration test PASSED
        echo.
        set /p INSTALL_SERVICE="Install service now? (Y/N): "
        if /i "%INSTALL_SERVICE%" equ "Y" (
            echo Installing service...
            ShikraAgent.exe -install
            if %errorlevel% equ 0 (
                echo ✓ Service installed successfully
                echo.
                set /p START_SERVICE="Start service now? (Y/N): "
                if /i "%START_SERVICE%" equ "Y" (
                    echo Starting service...
                    ShikraAgent.exe -start
                    if %errorlevel% equ 0 (
                        echo ✓ Service started successfully
                        echo.
                        echo Service status:
                        sc query "Shikra Security Health Service"
                    ) else (
                        echo ✗ Failed to start service
                    )
                )
            ) else (
                echo ✗ Service installation failed
            )
        )
    ) else (
        echo ✗ Configuration test FAILED
        echo Check the output above for specific errors
    )
) else (
    echo ShikraAgent.exe not found - configuration saved for later use
    echo.
    echo To test: ShikraAgent.exe -test
    echo To install: ShikraAgent.exe -install  
    echo To start: ShikraAgent.exe -start
)

echo.
echo ================================================================
echo                    Next Steps
echo ================================================================
echo.
echo 1. Register with host: register_agent.bat
echo 2. Test configuration: ShikraAgent.exe -test
echo 3. Install service: ShikraAgent.exe -install
echo 4. Start service: ShikraAgent.exe -start
echo.
echo Files to keep:
echo - Shikra.ini (main configuration)
echo - Shikra.json (JSON format)
echo - registration_payload.json (for host registration)
echo - register_agent.bat (registration helper)
echo.
echo For troubleshooting:
echo - Check Windows Event Viewer (eventvwr.msc)
echo - Look for events from "ShikraAgent" or "SecurityHealth"
echo - Run ShikraAgent.exe in console mode (without -install)
echo.
pause
exit /b 0

:error
echo.
echo ================================================================
echo                Configuration Failed
echo ================================================================
echo.
echo Please check the error messages above.
echo.
echo Common solutions:
echo 1. Run as Administrator
echo 2. Check antivirus software isn't blocking
echo 3. Verify disk space and permissions
echo 4. Try running from C:\temp directory
echo.
pause
exit /b 1