#!/usr/bin/env bash
#
# shikra_sandbox.sh
# Enhanced orchestration script with:
#   1) Dynamic/scripted CPU & RAM changes for evading certain checks
#   2) Timing/environmental randomization (via QEMU's -rtc)
#   3) Ability to pass the QCOW2 path as an argument at runtime
#
# Usage:
#   ./shikra_sandbox.sh start /path/to/disk.qcow2
#   ./shikra_sandbox.sh snapshot <snap_name> /path/to/disk.qcow2
#   ./shikra_sandbox.sh rollback <snap_name> /path/to/disk.qcow2
#   ./shikra_sandbox.sh stop
#   ./shikra_sandbox.sh memdump
#
# Notes:
#  - This script demonstrates "pre-orchestration" evasion: random CPU/memory,
#    and random date/time in the VM via QEMU -rtc. 
#  - If no path is given, it defaults to DISK_IMAGE below.
#

set -e

# Default if user doesn't provide a path
DEFAULT_DISK_IMAGE="/path/to/default_windows.qcow2"
VM_NAME="Win10AdvEvasion"
TAP_IF="tap0"
MEM_DEFAULT="4096"
CPU_DEFAULT="2"
VNC_DISPLAY=":0"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"

########################################

function rand_mac() {
  # Generate a random MAC that doesn't use typical QEMU/VMware prefixes
  echo "52:54:$(od -An -N3 -tx1 /dev/urandom | tr ' ' ':')"
}

# Pick random CPU cores from an array, or range
function pick_random_cpu_cores() {
  # Example: we allow 2, 3, or 4 cores randomly
  local options=(2 3 4)
  echo "${options[$((RANDOM % ${#options[@]}))]}"
}

# Pick random memory from an array, or range
function pick_random_memory() {
  # Example: 3GB, 4GB, 6GB
  local options=(3072 4096 6144)
  echo "${options[$((RANDOM % ${#options[@]}))]}"
}

# Random date/time offset for QEMU's -rtc
function pick_random_rtc_base() {
  # We'll pick a random year between 2020 and 2023, random month/day
  local year=$((2020 + RANDOM % 4))
  local month=$((1 + RANDOM % 12))
  local day=$((1 + RANDOM % 28))
  # Format: YYYY-MM-DD
  printf "%04d-%02d-%02d\n" "$year" "$month" "$day"
}

########################################

function usage() {
  echo "Usage:"
  echo "  $0 start [qcow2_path]"
  echo "  $0 snapshot <snapshot_name> [qcow2_path]"
  echo "  $0 rollback <snapshot_name> [qcow2_path]"
  echo "  $0 stop"
  echo "  $0 memdump"
  echo
  echo "If [qcow2_path] is omitted, it uses the default path: $DEFAULT_DISK_IMAGE"
  exit 1
}

function resolve_disk_path() {
  # If user provided a path, use it; otherwise use the default
  local last_arg="${@: -1}"  # last param
  if [[ -f "$last_arg" ]]; then
    # We assume the last argument is a valid file path
    echo "$last_arg"
  else
    echo "$DEFAULT_DISK_IMAGE"
  fi
}

########################################

function start_vm() {
  local image="$1"
  if [[ ! -f "$image" ]]; then
    echo "[orchestrator] Disk image not found at $image."
    exit 1
  fi

  # Pre-orchestration evasion:
  # 1) Random CPU count & memory size
  local CPU_COUNT
  CPU_COUNT=$(pick_random_cpu_cores)
  local MEM_SIZE
  MEM_SIZE=$(pick_random_memory)

  # 2) Random date/time
  local RTC_DATE
  RTC_DATE=$(pick_random_rtc_base)

  local MAC
  MAC=$(rand_mac)

  echo "[orchestrator] Starting VM:"
  echo "    Disk:       $image"
  echo "    CPU cores:  $CPU_COUNT"
  echo "    Memory MB:  $MEM_SIZE"
  echo "    RTC date:   $RTC_DATE"
  echo "    MAC addr:   $MAC"

  qemu-system-x86_64 \
    -enable-kvm \
    -name "$VM_NAME" \
    -cpu host \
    -smp "$CPU_COUNT" \
    -m "$MEM_SIZE" \
    -drive file="$image",if=virtio,format=qcow2 \
    -netdev tap,id=net0,ifname="$TAP_IF",script=no,downscript=no \
    -device e1000,netdev=net0,mac="$MAC" \
    -smbios type=1,manufacturer="GenericPC",product="NonVirtualModel",version="1.0" \
    -vnc "$VNC_DISPLAY" \
    -drive if=pflash,format=raw,readonly=on,file="$OVMF_CODE" \
    -drive if=pflash,format=raw,file="$OVMF_VARS" \
    -rtc base="$RTC_DATE"
}

function snapshot_create() {
  local snap_name="$1"
  local image="$2"
  if [[ -z "$snap_name" ]]; then
    echo "[orchestrator] No snapshot name provided."
    exit 1
  fi
  echo "[orchestrator] Creating snapshot '$snap_name' for $image"
  qemu-img snapshot -c "$snap_name" "$image"
  echo "[orchestrator] Snapshot created."
}

function snapshot_rollback() {
  local snap_name="$1"
  local image="$2"
  if [[ -z "$snap_name" ]]; then
    echo "[orchestrator] No snapshot name provided."
    exit 1
  fi
  echo "[orchestrator] Rolling back to snapshot '$snap_name' for $image"
  qemu-img snapshot -a "$snap_name" "$image"
  echo "[orchestrator] Rollback completed."
}

function stop_vm() {
  local pid
  pid=$(pgrep -f "$VM_NAME") || true
  if [[ -n "$pid" ]]; then
    echo "[orchestrator] Stopping VM $VM_NAME (PID=$pid)..."
    kill "$pid"
  else
    echo "[orchestrator] No VM named $VM_NAME is running."
  fi
}

function capture_mem() {
  local pid
  pid=$(pgrep -f "$VM_NAME") || true
  if [[ -z "$pid" ]]; then
    echo "[orchestrator] VM not running; cannot capture memory."
    exit 1
  fi
  echo "[orchestrator] Attempting memory capture with gcore (quick hack)."
  gcore -o /tmp/vmcore "$pid"
  echo "[orchestrator] Memory dump done: /tmp/vmcore.$pid"
  echo "    (Analyze with: volatility -f /tmp/vmcore.$pid ... )"
}

########################################

CMD="$1"
case "$CMD" in
  start)
    # e.g. ./shikra_sandbox.sh start /my/win.qcow2
    if [[ $# -eq 1 ]]; then
      DISK_IMG="$(resolve_disk_path)"  # no path provided, fallback
    else
      DISK_IMG="${@: -1}"  # last argument
    fi
    start_vm "$DISK_IMG"
    ;;
  snapshot)
    # e.g. ./shikra_sandbox.sh snapshot snap_name /my/win.qcow2
    if [[ $# -lt 2 ]]; then usage; fi
    SNAP_NAME="$2"
    if [[ $# -gt 2 && -f "${@: -1}" ]]; then
      DISK_IMG="${@: -1}"
    else
      DISK_IMG="$(resolve_disk_path)"
    fi
    snapshot_create "$SNAP_NAME" "$DISK_IMG"
    ;;
  rollback)
    # e.g. ./shikra_sandbox.sh rollback snap_name /my/win.qcow2
    if [[ $# -lt 2 ]]; then usage; fi
    SNAP_NAME="$2"
    if [[ $# -gt 2 && -f "${@: -1}" ]]; then
      DISK_IMG="${@: -1}"
    else
      DISK_IMG="$(resolve_disk_path)"
    fi
    snapshot_rollback "$SNAP_NAME" "$DISK_IMG"
    ;;
  stop)
    stop_vm
    ;;
  memdump)
    capture_mem
    ;;
  *)
    usage
    ;;
esac
