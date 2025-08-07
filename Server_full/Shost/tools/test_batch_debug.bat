@echo off
setlocal EnableDelayedExpansion

:: Simulate empty registry values like on the Windows VM
set "AGENT_ID="
set "AGENT_SECRET="
set "HOST_URL="
set "WORKING_DIR="
set "POLL_INTERVAL="
set "LOG_LEVEL="
set "MAX_RETRIES="
set "EXECUTION_TIMEOUT="
set "ENABLE_HOOKING="
set "ENABLE_MEMORY_DUMPS="
set "ENABLE_NETWORK_CAPTURE="

echo Debug - Raw registry values (simulated empty):
echo   AGENT_ID=!AGENT_ID!
echo   AGENT_SECRET=!AGENT_SECRET!
echo   HOST_URL=!HOST_URL!
echo   WORKING_DIR=!WORKING_DIR!
echo.

:: Set defaults for missing values
if "!AGENT_ID!"=="" set "AGENT_ID=agent-%COMPUTERNAME%-%RANDOM%"
if "!AGENT_SECRET!"=="" set "AGENT_SECRET=secret-%RANDOM%-%RANDOM%"
if "!HOST_URL!"=="" set "HOST_URL=http://192.168.100.1:8080/api/v1/"
if "!WORKING_DIR!"=="" set "WORKING_DIR=C:\Temp\SecurityHealth"
if "!POLL_INTERVAL!"=="" set "POLL_INTERVAL=30000"
if "!LOG_LEVEL!"=="" set "LOG_LEVEL=2"
if "!MAX_RETRIES!"=="" set "MAX_RETRIES=3"
if "!EXECUTION_TIMEOUT!"=="" set "EXECUTION_TIMEOUT=300000"
if "!ENABLE_HOOKING!"=="" set "ENABLE_HOOKING=1"
if "!ENABLE_MEMORY_DUMPS!"=="" set "ENABLE_MEMORY_DUMPS=1"
if "!ENABLE_NETWORK_CAPTURE!"=="" set "ENABLE_NETWORK_CAPTURE=1"

echo After setting defaults:
echo   AGENT_ID=!AGENT_ID!
echo   AGENT_SECRET=!AGENT_SECRET!
echo   HOST_URL=!HOST_URL!
echo   WORKING_DIR=!WORKING_DIR!
echo.

:: EscapeJSON function (simplified)
call :EscapeJSON "!AGENT_ID!" AGENT_ID_ESC
call :EscapeJSON "!AGENT_SECRET!" AGENT_SECRET_ESC
call :EscapeJSON "!HOST_URL!" HOST_URL_ESC
call :EscapeJSON "!WORKING_DIR!" WORKING_DIR_ESC

echo Escaped values:
echo   AGENT_ID_ESC=!AGENT_ID_ESC!
echo   AGENT_SECRET_ESC=!AGENT_SECRET_ESC!
echo   HOST_URL_ESC=!HOST_URL_ESC!
echo   WORKING_DIR_ESC=!WORKING_DIR_ESC!
echo.

:: Create test JSON
set "JSON_FILE=%TEMP%\test_registration.json"
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

echo Generated JSON:
type "!JSON_FILE!"
echo.

del "!JSON_FILE!" 2>nul
pause
goto :eof

:EscapeJSON
setlocal EnableDelayedExpansion
set "input=%~1"
set "varname=%~2"

:: Replace backslashes first
set "input=!input:\=\\!"
:: Replace quotes
set "input=!input:"=\"!"

endlocal & set "%varname%=!input!"
goto :eof
