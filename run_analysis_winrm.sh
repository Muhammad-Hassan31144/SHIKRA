#!/usr/bin/env bash
#
# run_analysis_winrm.sh
# Automates ransomware analysis with QEMU-based Win10 VM and WinRM-based remote commands.
#
# Prerequisites:
#   - WinRM enabled on Windows (Enable-PSRemoting -Force).
#   - 'winrm' CLI installed on host (https://github.com/masterzen/winrm-cli).
#   - Working sandbox_orchestrator.sh (for VM start/stop/snapshot/memdump).
#   - SSH or direct terminal usage on Linux host.
#
# Usage:
#   ./run_analysis_winrm.sh
#

set -e

function prompt_user() {
  echo "===== Ransomware Analysis (WinRM) ====="
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
  echo "[Info] Example usage will copy $MAL_SAMPLE and $PROCMON_EXE to $REMOTE_DIR inside the VM."
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

function copy_files_winrm() {
  echo "[+] Copying obfuscated Procmon and ransomware sample to VM..."

  # 1) Copy PROCMON_EXE
  echo "    - Copying $PROCMON_EXE -> $REMOTE_DIR"
  winrm cp "$PROCMON_EXE" "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" "$REMOTE_DIR" 2>/dev/null

  # 2) Copy Malware
  echo "    - Copying $MAL_SAMPLE -> $REMOTE_DIR"
  winrm cp "$MAL_SAMPLE" "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" "$REMOTE_DIR" 2>/dev/null
}

function start_procmon_in_vm() {
  local procmon_remote="${REMOTE_DIR}\\$(basename "$PROCMON_EXE")"
  echo "[+] Launching Procmon (obfuscated) in silent mode on VM..."

  # Adjust the command line flags as you prefer
  local cmd="& \"$procmon_remote\" /AcceptEula /Quiet /BackingFile \"${REMOTE_LOG_DIR}\\procmon.pml\" /NoFilter"
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

function run_malware() {
  local malware_remote="${REMOTE_DIR}\\$(basename "$MAL_SAMPLE")"
  echo "[+] Executing ransomware sample in VM..."
  local cmd="Start-Process -FilePath \"$malware_remote\""
  winrm command "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" powershell.exe "$cmd" 2>/dev/null
}

function wait_for_malware() {
  echo "[+] Waiting some time for ransomware activity..."
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
  # Use winrm cp to retrieve procmon.pml or other logs from $REMOTE_LOG_DIR
  # e.g. "http://192.168.56.10:5985" ...
  local local_output="/tmp/${VM_NAME}_analysis_logs"
  mkdir -p "$local_output"

  local remote_pml="${REMOTE_LOG_DIR}\\procmon.pml"
  echo "    - Copying $remote_pml -> $local_output"
  # We need an absolute local path for winrm cp
  winrm cp "http://${VM_IP}:5985" "$VM_USER" "$VM_PASS" "$remote_pml" "${local_output}/procmon.pml" 2>/dev/null
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
  copy_files_winrm
  start_procmon_in_vm
  run_user_sim
  run_malware
  wait_for_malware
  mem_dump
  stop_tshark_capture
  collect_logs
  shutdown_vm

  echo "[+] Done. See /tmp/${VM_NAME}_capture.pcap for network, /tmp/${VM_NAME}_analysis_logs for logs."
}

main
