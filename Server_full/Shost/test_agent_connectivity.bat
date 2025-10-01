@echo off
echo Testing Shikra Agent Network Connectivity
echo =========================================

echo.
echo 1. Testing basic network connectivity to host...
ping -n 4 192.168.100.1
if %errorlevel% == 0 (
    echo ✓ Host is reachable
) else (
    echo ✗ Cannot reach host - check VM network configuration
    goto :error
)

echo.
echo 2. Testing HTTP connectivity to API server...
echo Attempting to connect to http://192.168.100.1:5000/api/health
curl -f -s http://192.168.100.1:5000/api/health > nul 2>&1
if %errorlevel% == 0 (
    echo ✓ API server is responding
) else (
    echo ✗ API server not responding - ensure Shost is running
    echo   Run on host: cd Shost && ./start_shost.sh
)

echo.
echo 3. Testing agent registration endpoint...
curl -f -s -X POST http://192.168.100.1:5000/api/v1/agent/register ^
  -H "Content-Type: application/json" ^
  -d "{\"agent_id\": \"test-agent-001\", \"name\": \"Test Agent\"}" > nul 2>&1
if %errorlevel% == 0 (
    echo ✓ Agent registration endpoint working
) else (
    echo ! Agent registration test failed (may be normal)
)

echo.
echo 4. Checking Windows Firewall status...
netsh advfirewall show allprofiles state | findstr "State"

echo.
echo 5. Checking if agent working directory exists...
if exist "C:\Temp\ShikraAgent" (
    echo ✓ Working directory exists: C:\Temp\ShikraAgent
) else (
    echo ! Working directory missing - run configure_agent.bat first
)

echo.
echo 6. Checking registry configuration...
reg query "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v HostUrl > nul 2>&1
if %errorlevel% == 0 (
    echo ✓ Registry configuration exists
    reg query "HKLM\SOFTWARE\Microsoft\SecurityHealth\Agent" /v HostUrl
) else (
    echo ! Registry configuration missing - run configure_agent.bat first
)

echo.
echo Network test complete!
echo.
echo If all tests pass, try running ShikraAgent.exe again.
echo If issues persist, check:
echo • Shost server is running on the host
echo • Windows Firewall is not blocking connections
echo • VM can reach 192.168.122.1 (host IP)
echo.
goto :end

:error
echo.
echo ✗ Network connectivity test failed!
echo.
echo Troubleshooting steps:
echo 1. Check if host machine IP is 192.168.122.1:
echo    On host run: ip addr show virbr0
echo 2. Check if Shost is running:
echo    On host run: curl http://127.0.0.1:5000/api/health
echo 3. Check VM network configuration:
echo    In VM run: ipconfig
echo 4. Try different host IP if needed
echo.

:end
pause
