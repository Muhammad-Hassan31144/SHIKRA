# Simulate empty registry values
$agentId = ""
$agentSecret = ""
$hostUrl = ""
$workingDir = ""

Write-Host "Debug - Raw registry values (simulated empty):"
Write-Host "  AGENT_ID=$agentId"
Write-Host "  AGENT_SECRET=$agentSecret"
Write-Host "  HOST_URL=$hostUrl"
Write-Host "  WORKING_DIR=$workingDir"
Write-Host ""

# Set defaults
if ([string]::IsNullOrEmpty($agentId)) { $agentId = "agent-$env:COMPUTERNAME-$(Get-Random)" }
if ([string]::IsNullOrEmpty($agentSecret)) { $agentSecret = "secret-$(Get-Random)-$(Get-Random)" }
if ([string]::IsNullOrEmpty($hostUrl)) { $hostUrl = "http://192.168.100.1:8080/api/v1/" }
if ([string]::IsNullOrEmpty($workingDir)) { $workingDir = "C:\Temp\SecurityHealth" }

Write-Host "After setting defaults:"
Write-Host "  AGENT_ID=$agentId"
Write-Host "  AGENT_SECRET=$agentSecret"
Write-Host "  HOST_URL=$hostUrl"
Write-Host "  WORKING_DIR=$workingDir"
Write-Host ""

# Create JSON
$jsonPayload = @{
    agent_id = $agentId
    agent_secret = $agentSecret
    name = "Agent $env:COMPUTERNAME"
    capabilities = "file,registry,process,network,memory"
    host_url = $hostUrl
    poll_interval = 30000
    working_directory = $workingDir
    log_level = 2
    max_retries = 3
    execution_timeout = 300000
    enable_hooking = $true
    enable_memory_dumps = $true
    enable_network_capture = $true
} | ConvertTo-Json -Depth 3

Write-Host "Generated JSON:"
Write-Host $jsonPayload
Write-Host ""

# Show what would be sent
Write-Host "This is the JSON that would be sent to http://192.168.100.1:8080/api/v1/agent/register"

Read-Host "Press Enter to continue"
