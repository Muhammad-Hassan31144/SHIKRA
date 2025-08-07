@echo off
setlocal

echo ================================================================
echo                 Shikra Agent Configuration
echo ================================================================
echo.
echo This script will configure the Shikra Agent Windows service.
echo Press Enter to use default values, or type custom values.
echo.

:: Check administrator privileges (simplified)
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo WARNING: Not running as Administrator!
    echo Some registry operations may fail.
    echo.
    set /p "CONTINUE=Continue anyway? (Y/N): "
    if /i not "%CONTINUE%"=="Y" (
        echo Exiting...
        pause
        exit /b 1
    )
) else (
    echo Running as Administrator - Good!
)

echo.

:: Set default values (using simpler variable names)
set "DEF_HOST=http://192.168.100.1:8080/api/v1/"
set "DEF_WORKING=C:\ProgramData\SecurityHealth"
set "DEF_POLL=30000"
set "DEF_LOG=2"
set "DEF_RETRIES=3"
set "DEF_TIMEOUT=300000"

:: Generate random values for ID and secret
set /a "RAND1=%RANDOM%"
set /a "RAND2=%RANDOM%"
set /a "RAND3=%RANDOM%"
set "DEF_ID=agent-%COMPUTERNAME%-%RAND1%"
set "DEF_SECRET=secret-%RAND2%-%RAND3%"

echo Default values generated:
echo   Host URL: %DEF_HOST%
echo   Agent ID: %DEF_ID%
echo   Working Directory: %DEF_WORKING%
echo.

:: Get user input
echo [1/6] Host URL Configuration
echo Current default: %DEF_HOST%
set /p "HOST_URL=Enter Host URL (or press Enter for default): "
if "%HOST_URL%"=="" set "HOST_URL=%DEF_HOST%"

echo.
echo [2/6] Agent ID
echo Current default: %DEF_ID%
set /p "AGENT_ID=Enter Agent ID (or press Enter for default): "
if "%AGENT_ID%"=="" set "AGENT_ID=%DEF_ID%"

echo.
echo [3/6] Agent Secret
echo Current default: %DEF_SECRET%
set /p "AGENT_SECRET=Enter Agent Secret (or press Enter for default): "
if "%AGENT_SECRET%"=="" set "AGENT_SECRET=%DEF_SECRET%"

echo.
echo [4/6] Working Directory
echo Current default: %DEF_WORKING%
set /p "WORKING_DIR=Enter Working Directory (or press Enter for default): "
if "%WORKING_DIR%"=="" set "WORKING_DIR=%DEF_WORKING%"

echo.
echo [5/6] Poll Interval (milliseconds)
echo Current default: %DEF_POLL%
set /p "POLL_INTERVAL=Enter Poll Interval (or press Enter for default): "
if "%POLL_INTERVAL%"=="" set "POLL_INTERVAL=%DEF_POLL%"

echo.
echo [6/6] Log Level (0=Debug, 1=Info, 2=Warning, 3=Error)
echo Current default: %DEF_LOG%
set /p "LOG_LEVEL=Enter Log Level (or press Enter for default): "
if "%LOG_LEVEL%"=="" set "LOG_LEVEL=%DEF_LOG%"

:: Set remaining defaults
set "MAX_RETRIES=%DEF_RETRIES%"
set "EXECUTION_TIMEOUT=%DEF_TIMEOUT%"

:: Show summary
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
set /p "CONFIRM=Apply this configuration? (Y/N): "
if /i not "%CONFIRM%"=="Y" (
    echo Configuration cancelled.
    pause
    exit /b 0
)

echo.
echo Creating configuration files...

:: Create Shikra.ini file
echo Creating Shikra.ini...
(
echo # Shikra Agent Configuration File
echo # Generated on %DATE% %TIME%
echo.
echo [agent]
echo host_api_url=%HOST_URL%
echo agent_id=%AGENT_ID%
echo agent_secret=%AGENT_SECRET%
echo working_directory=%WORKING_DIR%
echo poll_interval_ms=%POLL_INTERVAL%
echo log_level=%LOG_LEVEL%
echo max_retries=%MAX_RETRIES%
echo execution_timeout_ms=%EXECUTION_TIMEOUT%
echo.
echo [features]
echo hooks_enabled=true
echo compression=true
echo memory_dumps=true
echo network_capture=true
echo.
echo [registration]
echo hostname=%COMPUTERNAME%
echo os_version=%OS%
echo timestamp=%DATE% %TIME%
) > "Shikra.ini"

if exist "Shikra.ini" (
    echo ✓ Shikra.ini created successfully
) else (
    echo ✗ Failed to create Shikra.ini
    goto error
)

:: Create Shikra.json file
echo Creating Shikra.json...
(
echo {
echo   "agent": {
echo     "host_api_url": "%HOST_URL%",
echo     "agent_id": "%AGENT_ID%",
echo     "agent_secret": "%AGENT_SECRET%",
echo     "working_directory": "%WORKING_DIR%",
echo     "poll_interval_ms": %POLL_INTERVAL%,
echo     "log_level": %LOG_LEVEL%,
echo     "max_retries": %MAX_RETRIES%,
echo     "execution_timeout_ms": %EXECUTION_TIMEOUT%
echo   },
echo   "features": {
echo     "hooks_enabled": true,
echo     "compression": true,
echo     "memory_dumps": true,
echo     "network_capture": true
echo   },
echo   "registration": {
echo     "hostname": "%COMPUTERNAME%",
echo     "os_version": "%OS%",
echo     "timestamp": "%DATE% %TIME%"
echo   }
echo }
) > "Shikra.json"

if exist "Shikra.json" (
    echo ✓ Shikra.json created successfully
) else (
    echo ✗ Failed to create Shikra.json
    goto error
)

:: Try to create working directory
echo Creating working directory: %WORKING_DIR%
if not exist "%WORKING_DIR%" (
    mkdir "%WORKING_DIR%" 2>nul
    if exist "%WORKING_DIR%" (
        echo ✓ Working directory created
    ) else (
        echo ⚠ Could not create working directory (will be created by service)
    )
) else (
    echo ✓ Working directory already exists
)

echo.
echo ================================================================
echo                    Configuration Complete!
echo ================================================================
echo.
echo Files created:
echo   ✓ Shikra.ini    - Configuration file
echo   ✓ Shikra.json   - JSON configuration
echo.
echo Next steps:
echo   1. Run: register_from_ini.bat (to register with host)
echo   2. Start the agent service
echo.
echo Configuration saved successfully!
pause
exit /b 0

:error
echo.
echo ✗ Configuration failed!
echo Check permissions and try again.
pause
exit /b 1
