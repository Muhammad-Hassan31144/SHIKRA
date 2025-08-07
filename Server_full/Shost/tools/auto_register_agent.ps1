# Shikra Agent Auto-Registration Script (PowerShell)
# Reads Windows registry and automatically registers with host

param(
    [string]$HostOverride = "",
    [switch]$Verbose = $false
)

# Check if running as administrator
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "This script must be run as Administrator!"
    Write-Host "Right-click PowerShell and select 'Run as administrator'"
    exit 1
}

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "           Shikra Agent Auto-Registration (PowerShell)" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host

$RegPath = "HKLM:\SOFTWARE\Microsoft\SecurityHealth\Agent"
$DefaultHost = "http://192.168.100.1:8080"

Write-Host "Reading agent configuration from registry..." -ForegroundColor Yellow
Write-Host "Registry path: $RegPath"
Write-Host

# Function to read registry value with default
function Get-RegValue {
    param($Path, $Name, $Default = "")
    try {
        $value = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
        if ($value) {
            return $value.$Name
        }
    } catch {}
    return $Default
}

# Read registry values
$AgentId = Get-RegValue $RegPath "AgentId" "agent-$env:COMPUTERNAME-$(Get-Random)"
$AgentSecret = Get-RegValue $RegPath "AgentSecretPlain" "secret-$(Get-Random)-$(Get-Random)"
$HostUrl = Get-RegValue $RegPath "HostUrl" "$DefaultHost/api/v1/"
$WorkingDir = Get-RegValue $RegPath "WorkingDirectory" "C:\Temp\SecurityHealth"
$PollInterval = [int](Get-RegValue $RegPath "PollInterval" "30000")
$LogLevel = [int](Get-RegValue $RegPath "LogLevel" "2")
$MaxRetries = [int](Get-RegValue $RegPath "MaxRetries" "3")
$ExecutionTimeout = [int](Get-RegValue $RegPath "ExecutionTimeout" "300000")
$EnableHooking = [int](Get-RegValue $RegPath "EnableHooking" "1") -eq 1
$EnableMemoryDumps = [int](Get-RegValue $RegPath "EnableMemoryDumps" "1") -eq 1
$EnableNetworkCapture = [int](Get-RegValue $RegPath "EnableNetworkCapture" "1") -eq 1

# Override host if provided
if ($HostOverride) {
    $HostUrl = $HostOverride
    if (-not $HostUrl.EndsWith("/")) {
        $HostUrl += "/"
    }
}

# Extract host for registration URL
$uri = [System.Uri]$HostUrl
$RegisterUrl = "$($uri.Scheme)://$($uri.Host):$($uri.Port)/api/v1/agent/register"

Write-Host "Configuration found:" -ForegroundColor Green
Write-Host "  Agent ID:        $AgentId"
Write-Host "  Agent Secret:    $AgentSecret"
Write-Host "  Host URL:        $HostUrl"
Write-Host "  Working Dir:     $WorkingDir"
Write-Host "  Poll Interval:   $PollInterval ms"
Write-Host "  Log Level:       $LogLevel"
Write-Host "  Max Retries:     $MaxRetries"
Write-Host "  Exec Timeout:    $ExecutionTimeout ms"
Write-Host "  Enable Hooking:  $EnableHooking"
Write-Host "  Memory Dumps:    $EnableMemoryDumps"
Write-Host "  Network Capture: $EnableNetworkCapture"
Write-Host
Write-Host "Registration URL: $RegisterUrl" -ForegroundColor Cyan
Write-Host

# Create registration payload
$payload = @{
    agent_id = $AgentId
    agent_secret = $AgentSecret
    name = "Agent $env:COMPUTERNAME"
    host_url = $HostUrl
    poll_interval = $PollInterval
    working_directory = $WorkingDir
    log_level = $LogLevel
    max_retries = $MaxRetries
    execution_timeout = $ExecutionTimeout
    enable_hooking = $EnableHooking
    enable_memory_dumps = $EnableMemoryDumps
    enable_network_capture = $EnableNetworkCapture
    capabilities = "file,registry,process,network,memory"
}

Write-Host "Registering agent with host..." -ForegroundColor Yellow
Write-Host

# Test connectivity first
Write-Host "Testing connectivity to host..." -ForegroundColor Gray
$healthUrl = "$($uri.Scheme)://$($uri.Host):$($uri.Port)/api/health"

try {
    $healthResponse = Invoke-RestMethod -Uri $healthUrl -Method GET -TimeoutSec 5
    Write-Host "✓ Host is reachable" -ForegroundColor Green
    if ($Verbose) {
        Write-Host "Health check response: $($healthResponse | ConvertTo-Json -Compress)"
    }
} catch {
    Write-Error "Cannot reach host at $healthUrl"
    Write-Host "Make sure:" -ForegroundColor Red
    Write-Host "  1. Shost server is running"
    Write-Host "  2. Network connectivity is working"
    Write-Host "  3. Host URL in registry is correct"
    Write-Host "Error: $($_.Exception.Message)"
    exit 1
}

Write-Host

# Send registration request
Write-Host "Sending registration request..." -ForegroundColor Gray

try {
    $jsonPayload = $payload | ConvertTo-Json
    if ($Verbose) {
        Write-Host "Payload: $jsonPayload" -ForegroundColor Gray
    }
    
    $response = Invoke-RestMethod -Uri $RegisterUrl -Method POST -Body $jsonPayload -ContentType "application/json" -TimeoutSec 30
    
    Write-Host "✓ Registration request sent successfully!" -ForegroundColor Green
    Write-Host
    Write-Host "Server response:" -ForegroundColor Cyan
    Write-Host ($response | ConvertTo-Json -Depth 3)
    
    if ($response.message -like "*successfully*") {
        Write-Host
        Write-Host "✓ Agent registered successfully!" -ForegroundColor Green
        Write-Host
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Start the Shikra Agent service"
        Write-Host "  2. Monitor logs for sample polling"
        Write-Host "  3. Check host dashboard for agent status"
        
        # Optionally save the response for reference
        $response | ConvertTo-Json -Depth 3 | Out-File -FilePath "registration_response.json" -Encoding UTF8
        Write-Host "  4. Registration details saved to: registration_response.json"
    } else {
        Write-Host
        Write-Host "! Registration completed but check response above for details" -ForegroundColor Yellow
    }
    
} catch {
    Write-Error "Registration failed!"
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    if ($_.Exception.Response) {
        $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        $responseBody = $reader.ReadToEnd()
        Write-Host "Server response: $responseBody" -ForegroundColor Red
    }
    exit 1
}

Write-Host
Write-Host "Auto-registration complete!" -ForegroundColor Green

# Optionally test agent health endpoint
$testHealth = Read-Host "Test agent health endpoint? (y/N)"
if ($testHealth -eq "y" -or $testHealth -eq "Y") {
    Write-Host
    Write-Host "Testing agent health endpoint..." -ForegroundColor Gray
    
    # This would require HMAC authentication, which is complex
    # For now, just show the endpoint
    $healthEndpoint = "$($uri.Scheme)://$($uri.Host):$($uri.Port)/api/v1/agent/health"
    Write-Host "Agent health endpoint: $healthEndpoint"
    Write-Host "Note: Health endpoint requires HMAC authentication - use ShikraAgent.exe for testing"
}
