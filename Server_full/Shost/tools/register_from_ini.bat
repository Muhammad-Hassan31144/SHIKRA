@echo off
setlocal enabledelayedexpansion

:: Shikra Agent Registration Script
:: Reads configuration from Shikra.ini and registers with host

echo ================================================================
echo                 Shikra Agent Registration
echo ================================================================
echo.

:: Check if Shikra.ini exists
if not exist "Shikra.ini" (
    echo ERROR: Shikra.ini not found!
    echo Please run configure_agent.bat first to create the configuration file.
    echo.
    pause
    exit /b 1
)

echo Reading configuration from Shikra.ini...
echo.

:: Initialize variables
set "HOST_URL="
set "AGENT_ID="
set "AGENT_SECRET="
set "WORKING_DIR="
set "POLL_INTERVAL="
set "LOG_LEVEL="
set "MAX_RETRIES="
set "EXECUTION_TIMEOUT="

:: Read INI file values
for /f "usebackq delims== tokens=1,2" %%A in ("Shikra.ini") do (
    set "KEY=%%A"
    set "VALUE=%%B"
    
    :: Remove any leading/trailing spaces
    for /f "tokens=* delims= " %%X in ("!KEY!") do set "KEY=%%X"
    for /f "tokens=* delims= " %%Y in ("!VALUE!") do set "VALUE=%%Y"
    
    :: Parse configuration values
    if /i "!KEY!"=="host_api_url" set "HOST_URL=!VALUE!"
    if /i "!KEY!"=="agent_id" set "AGENT_ID=!VALUE!"
    if /i "!KEY!"=="agent_secret" set "AGENT_SECRET=!VALUE!"
    if /i "!KEY!"=="working_directory" set "WORKING_DIR=!VALUE!"
    if /i "!KEY!"=="poll_interval_ms" set "POLL_INTERVAL=!VALUE!"
    if /i "!KEY!"=="log_level" set "LOG_LEVEL=!VALUE!"
    if /i "!KEY!"=="max_retries" set "MAX_RETRIES=!VALUE!"
    if /i "!KEY!"=="execution_timeout_ms" set "EXECUTION_TIMEOUT=!VALUE!"
)

:: Validate required values
if "!HOST_URL!"=="" (
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

:: Display configuration
echo Configuration loaded:
echo   Host URL:           !HOST_URL!
echo   Agent ID:           !AGENT_ID!
echo   Agent Secret:       [Hidden - Length: !AGENT_SECRET:~0,8!...]
echo   Working Directory:  !WORKING_DIR!
echo   Poll Interval:      !POLL_INTERVAL! ms
echo   Log Level:          !LOG_LEVEL!
echo   Max Retries:        !MAX_RETRIES!
echo   Execution Timeout:  !EXECUTION_TIMEOUT! ms
echo.

:: Construct registration URL
set "REGISTER_URL=!HOST_URL!"
if "!REGISTER_URL:~-1!"=="/" set "REGISTER_URL=!REGISTER_URL:~0,-1!"
set "REGISTER_URL=!REGISTER_URL!/agent/register"

echo Registration URL: !REGISTER_URL!
echo.

:: Escape JSON special characters in strings
call :EscapeJSON "!AGENT_ID!" AGENT_ID_ESC
call :EscapeJSON "!AGENT_SECRET!" AGENT_SECRET_ESC  
call :EscapeJSON "!HOST_URL!" HOST_URL_ESC
call :EscapeJSON "!WORKING_DIR!" WORKING_DIR_ESC

:: Create JSON payload
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
  echo   "enable_hooking": true,
  echo   "enable_memory_dumps": true,
  echo   "enable_network_capture": true
  echo }
) > "!JSON_FILE!"

:: Debug: Show the JSON being sent
echo DEBUG: JSON payload being sent:
echo ==========================================
type "!JSON_FILE!"
echo ==========================================
echo.

:: Check if curl is available
curl --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: curl is not available!
    echo Please install curl or use Windows 10/11 which includes it
    echo.
    pause
    del "!JSON_FILE!" 2>nul
    exit /b 1
)

echo Sending registration request...
echo.

set "RESPONSE_FILE=%TEMP%\shikra_response.json"

:: Send registration request
curl -X POST "!REGISTER_URL!" ^
  -H "Content-Type: application/json" ^
  -H "User-Agent: ShikraAgent/1.0" ^
  -d @"!JSON_FILE!" ^
  -w "Response Status: %%{http_code}^nResponse Time: %%{time_total}s^n" ^
  -o "!RESPONSE_FILE!" ^
  -m 30 ^
  --connect-timeout 10 ^
  -s -S

set "CURL_RESULT=%errorlevel%"

echo.
echo Curl exit code: !CURL_RESULT!

:: Show response if available
if exist "!RESPONSE_FILE!" (
    echo.
    echo Server response:
    echo ==========================================
    type "!RESPONSE_FILE!"
    echo ==========================================
    echo.
) else (
    echo No response file created
)

:: Clean up temporary files
del "!JSON_FILE!" 2>nul
del "!RESPONSE_FILE!" 2>nul

:: Check result
if !CURL_RESULT! equ 0 (
    echo ✓ Registration request sent successfully!
    echo.
    echo The agent should now be registered with the host.
    echo You can now start the agent service to begin polling for samples.
) else (
    echo ✗ Registration failed!
    echo.
    echo Common issues:
    echo   1. Host is not accessible: !REGISTER_URL!
    echo   2. Network connectivity problems
    echo   3. Invalid agent credentials
    echo   4. Host server is not running
    echo.
    echo Try testing connectivity:
    echo   ping !HOST_URL:~7!
    echo   curl -I !HOST_URL!
)

echo.
pause
exit /b !CURL_RESULT!

:error
echo.
echo ✗ Configuration error!
echo.
echo Please check Shikra.ini file for missing or invalid values.
echo Run configure_agent.bat to recreate the configuration.
echo.
pause
exit /b 1

:: Function to escape JSON special characters
:EscapeJSON
setlocal enabledelayedexpansion
set "input=%~1"
set "output="

:: Replace backslashes first (must be first)
set "input=!input:\=\\!"

:: Replace quotes
set "input=!input:"=\"!"

:: Replace newlines and other control characters
set "input=!input:\n=\\n!"
set "input=!input:\r=\\r!"
set "input=!input:\t=\\t!"

:: Return the escaped string
endlocal & set "%~2=%input%"
goto :eof
