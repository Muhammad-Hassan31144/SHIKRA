#!/usr/bin/env bash
#
# run_analysis_winrm.sh
# Automates ransomware analysis with QEMU-based Win10 VM and WinRM-based remote commands.
# Now integrated with Shikra malware analysis framework.
#
# Prerequisites:
#   - WinRM enabled on Windows (Enable-PSRemoting -Force).
#   - 'winrm' CLI installed on host (https://github.com/masterzen/winrm-cli).
#   - Working sandbox_orchestrator.sh (for VM start/stop/snapshot/memdump).
#   - SSH or direct terminal usage on Linux host.
#   - Shikra code in the same directory as this script.
#
# Usage:
#   ./run_analysis_winrm.sh
#

set -e

function prompt_user() {
  echo "===== Ransomware Analysis with Shikra (WinRM) ====="
  read -p "VM Name (as used in sandbox_orchestrator): " VM_NAME
  read -p "IP Address of Windows VM (for WinRM): " VM_IP
  read -p "WinRM Username (e.g. Administrator): " VM_USER
  read -p "WinRM Password: " -s VM_PASS
  echo
  read -p "Path to Windows QCOW2 (if needed, or press Enter to skip): " DISK_IMG
  read -p "Local Path to Ransomware Sample: " MAL_SAMPLE
  read -p "Local Path to Obfuscated Procmon: " PROCMON_EXE
  read -p "Remote Path for Tools on VM (e.g. C:\\Tools): " REMOTE_DIR
  read -p "Remote Log Folder on VM (e.g. C:\\Logs): " REMOTE_LOG_DIR
  echo
  echo "[Info] Example usage will copy $MAL_SAMPLE, $PROCMON_EXE, and Shikra to $REMOTE_DIR inside the VM."
  echo "========================================"
}

function revert_snapshot() {
  if [[ -n "$DISK_IMG" ]]; then
    echo "[+] Reverting VM snapshot to 'clean_state' (example)"
    ./sandbox_orchestrator.sh rollback clean_state "$DISK_IMG"
  else
    echo "[!] No QCOW2 path provided, skipping snapshot revert..."
  fi
}

function start_vm() {
  if [[ -n "$DISK_IMG" ]]; then
    echo "[+] Starting VM using $DISK_IMG"
    ./sandbox_orchestrator.sh start "$DISK_IMG"
  else
    echo "[+] Starting VM (no QCOW2 specified, using default orchestrator config)."
    ./sandbox_orchestrator.sh start
  fi
}

function start_tshark_capture() {
  read -p "Network interface to capture on (e.g. br0, tap0): " NET_IF
  echo "[+] Starting tshark capture on interface $NET_IF (filter: host $VM_IP)."
  tshark -i "$NET_IF" host "$VM_IP" -w "/tmp/${VM_NAME}_capture.pcap" &
  CAP_PID=$!
  echo "    [tshark PID=$CAP_PID]"
}

function prepare_shikra_package() {
  echo "[+] Preparing Shikra package..."
  
  # Check if shikra directory exists
  if [[ ! -d "./shikra" ]]; then
    echo "[!] Error: Shikra directory not found in current path"
    exit 1
  fi
  
  # Create temp directory for packaging
  TEMP_DIR=$(mktemp -d)
  cp -r ./shikra $TEMP_DIR/
  
  # Package it
  SHIKRA_ZIP="/tmp/shikra_package.zip"
  (cd $TEMP_DIR && zip -r $SHIKRA_ZIP shikra)
  
  echo "[+] Shikra package created at $SHIKRA_ZIP"
}

function copy_files_winrm() {
  echo "[+] Copying obfuscated Procmon and ransomware sample to VM..."

  # 1) Copy PROCMON_EXE
  echo "    - Copying $PROCMON_EXE -> $REMOTE_DIR"
  winrm cp "$PROCMON_EXE" "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" "$REMOTE_DIR" 2>/dev/null

  # 2) Copy Malware
  echo "    - Copying $MAL_SAMPLE -> $REMOTE_DIR"
  winrm cp "$MAL_SAMPLE" "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" "$REMOTE_DIR" 2>/dev/null
  
  # 3) Copy Shikra package
  echo "    - Copying Shikra package -> $REMOTE_DIR"
  winrm cp "$SHIKRA_ZIP" "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" "$REMOTE_DIR" 2>/dev/null
  
  # 4) Extract Shikra package on VM
  echo "    - Extracting Shikra package on VM"
  local cmd="
  cd \"$REMOTE_DIR\";
  Add-Type -AssemblyName System.IO.Compression.FileSystem;
  [System.IO.Compression.ZipFile]::ExtractToDirectory('${REMOTE_DIR}\\$(basename "$SHIKRA_ZIP")', '$REMOTE_DIR');
  "
  winrm command "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" powershell.exe "$cmd" 2>/dev/null
}

function run_user_sim() {
  echo "[+] (Optional) Running user simulation script inside VM..."
  read -p "Path to user simulation script on VM (e.g. C:\\Tools\\simulate.ps1) or leave blank: " SIM_PATH
  if [[ -n "$SIM_PATH" ]]; then
    local cmd="& \"$SIM_PATH\""
    winrm command "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" powershell.exe "$cmd" 2>/dev/null
  else
    echo "    Skipped user simulation."
  fi
}

function run_shikra_analysis() {
  local malware_remote="${REMOTE_DIR}\\$(basename "$MAL_SAMPLE")"
  local procmon_remote="${REMOTE_DIR}\\$(basename "$PROCMON_EXE")"
  
  echo "[+] Configuring and executing Shikra analysis in VM..."
  
  # Create command to set up and run Shikra
  local cmd="
  # Prepare paths
  \$SAMPLE_PATH='$malware_remote';
  \$PROCMON_PATH='$procmon_remote';
  \$SHIKRA_DIR='${REMOTE_DIR}\\shikra';
  \$LOG_DIR='$REMOTE_LOG_DIR';
  
  # Create necessary directories
  if(-not (Test-Path \$LOG_DIR)) {
    New-Item -ItemType Directory -Path \$LOG_DIR -Force | Out-Null
  }
  
  # Create config.json with actual paths 
  \$CONFIG = @{
    'procmon_path' = \$PROCMON_PATH;
    'virustotal_api_key' = '';
    'yara_rules_path' = \"\$SHIKRA_DIR\\rules\";
    'approvelist_file' = \"\$SHIKRA_DIR\\approvelist.json\";
    'debug' = \$true
  };
  
  # Write config to file
  ConvertTo-Json \$CONFIG | Out-File \"\$SHIKRA_DIR\\config.json\" -Encoding UTF8;
  
  # Install and run Shikra
  cd \$SHIKRA_DIR;
  if(-not (Get-Command pip -ErrorAction SilentlyContinue)) {
    Write-Output 'Error: pip not found. Please install Python and pip on the VM.'
    exit 1
  }
  
  # Install pip requirements
  pip install -e . 2>&1;
  
  # Run Shikra analysis
  Write-Output 'Starting Shikra analysis...';
  python -m shikra.main --sample \$SAMPLE_PATH --procmon --output \$LOG_DIR;
  Write-Output 'Shikra analysis completed.';
  "
  
  echo "[+] Executing Shikra on the VM..."
  winrm command "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" powershell.exe "$cmd" 2>/dev/null
  echo "[+] Shikra analysis completed on VM"
}

function wait_for_malware() {
  echo "[+] Waiting some time for malware activity..."
  sleep 30
  # In practice, you might watch logs or poll a status to see if encryption started.
}

function mem_dump() {
  echo "[+] Triggering VM memory dump..."
  ./sandbox_orchestrator.sh memdump
  # This presumably saves memory to /tmp/vmcore.* or similar for volatility.
}

function collect_logs() {
  echo "[+] Collecting logs from VM..."
  local local_output="/tmp/${VM_NAME}_analysis_logs"
  mkdir -p "$local_output"

  # Create a zip archive of all logs on the VM for easier transfer
  echo "    - Creating log archive on VM..."
  local cmd="
  cd \"$REMOTE_LOG_DIR\";
  Compress-Archive -Path \"$REMOTE_LOG_DIR\\*\" -DestinationPath \"$REMOTE_LOG_DIR\\shikra_results.zip\" -Force;
  "
  winrm command "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" powershell.exe "$cmd" 2>/dev/null
  
  # Copy the zip file
  echo "    - Copying logs from VM to $local_output"
  winrm cp "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" "${REMOTE_LOG_DIR}\\shikra_results.zip" "${local_output}/shikra_results.zip" 2>/dev/null
  
  # Extract logs
  echo "    - Extracting logs..."
  unzip -q -o "${local_output}/shikra_results.zip" -d "$local_output" || echo "    - Warning: Could not extract logs, archive may be empty or corrupted"
  
  echo "[+] Analysis logs collected to $local_output"
}

function stop_tshark_capture() {
  if [[ -n "$CAP_PID" ]]; then
    echo "[+] Stopping tshark capture (PID=$CAP_PID)."
    kill "$CAP_PID"
  fi
}

function shutdown_vm() {
  echo "[+] Stopping the VM..."
  ./sandbox_orchestrator.sh stop
}

function main() {
  prompt_user
  revert_snapshot
  start_vm
  start_tshark_capture
  prepare_shikra_package
  copy_files_winrm
  run_user_sim
  run_shikra_analysis
  wait_for_malware
  mem_dump
  stop_tshark_capture
  collect_logs
  shutdown_vm

  echo "[+] Done. See /tmp/${VM_NAME}_capture.pcap for network, /tmp/${VM_NAME}_analysis_logs for logs."
}

main
