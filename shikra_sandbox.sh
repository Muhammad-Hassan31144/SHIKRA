#!/usr/bin/env bash
#
# shikra_orchestrator.sh
# 
# Advanced VM management script for malware analysis with anti-detection features:
#   1) Dynamic hardware profile randomization (CPU, RAM, disk serial)
#   2) System timing randomization to evade temporal checks
#   3) Hardware ID customization to avoid VM detection
#   4) Comprehensive VM lifecycle management (start, snapshot, rollback, stop)
#   5) Memory forensics capabilities for analysis
#
# Usage:
#   ./shikra_orchestrator.sh start [qcow2_path] [options]
#   ./shikra_orchestrator.sh snapshot <snapshot_name> [qcow2_path]
#   ./shikra_orchestrator.sh rollback <snapshot_name> [qcow2_path]
#   ./shikra_orchestrator.sh stop
#   ./shikra_orchestrator.sh memdump [output_path]
#   ./shikra_orchestrator.sh list-snapshots [qcow2_path]
#   ./shikra_orchestrator.sh status
#
# Options:
#   --bridge BRIDGE     Bridge interface name (default: br0)
#   --tap TAP          TAP interface name (default: tap0)
#   --memory SIZE      Memory size in MB (default: random between 2048-6144)
#   --cpu CORES        CPU cores (default: random between 1-4)
#   --vnc DISPLAY      VNC display number (default: :0)
#   --disable-evasion  Disable anti-VM detection features
#
# Example:
#   ./shikra_orchestrator.sh start /path/to/windows.qcow2 --memory 4096 --cpu 2
#

set -e

# Default configuration
DEFAULT_DISK_IMAGE="/var/lib/libvirt/images/windows10.qcow2"
VM_NAME="ShikraSandbox"
BRIDGE_IF="br0"
TAP_IF="tap0"
MEM_MIN=2048
MEM_MAX=6144
CPU_MIN=1
CPU_MAX=4
VNC_DISPLAY=":0"
OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"
SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MEMORY_DUMPS_DIR="$SCRIPTS_DIR/memory_dumps"
ENABLE_EVASION=1
QEMU_PID_FILE="/tmp/shikra_qemu.pid"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Log functions
log() {
  echo -e "[${GREEN}SHIKRA${NC}] $1"
}

info() {
  echo -e "[${BLUE}INFO${NC}] $1"
}

warn() {
  echo -e "[${YELLOW}WARNING${NC}] $1"
}

error() {
  echo -e "[${RED}ERROR${NC}] $1"
  exit 1
}

#######################################
# Hardware & timing randomization functions
#######################################

# Generate a random MAC address that doesn't use typical VM prefixes
rand_mac() {
  # Avoid common VM MAC prefixes (52:54:00 for QEMU, 00:0C:29 for VMware)
  # First byte should have bit 1 unset (unicast) and bit 0 unset (globally unique)
  local first_byte=$(printf "%02x" $((RANDOM % 256 & 0xFC)))
  local remaining_bytes=$(od -An -N5 -tx1 /dev/urandom | tr -d ' ')
  echo "$first_byte:${remaining_bytes:0:2}:${remaining_bytes:2:2}:${remaining_bytes:4:2}:${remaining_bytes:6:2}:${remaining_bytes:8:2}"
}

# Generate random UUID to avoid fixed identifiers
rand_uuid() {
  uuidgen
}

# Pick random CPU cores
rand_cpu_cores() {
  echo $((CPU_MIN + RANDOM % (CPU_MAX - CPU_MIN + 1)))
}

# Pick random memory size (in MB)
rand_memory() {
  # Round to nearest 128MB
  local range=$((MEM_MAX - MEM_MIN))
  local rand=$((RANDOM % (range / 128)))
  echo $((MEM_MIN + rand * 128))
}

# Random date/time offset for QEMU's -rtc
rand_rtc_base() {
  # Pick a random date between 2015 and 2023
  local year=$((2015 + RANDOM % 9))
  local month=$((1 + RANDOM % 12))
  local day=$((1 + RANDOM % 28))
  # Format: YYYY-MM-DD
  printf "%04d-%02d-%02d\n" "$year" "$month" "$day"
}

# Generate random disk serial
rand_disk_serial() {
  # Generate 20-character alphanumeric serial
  cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 20 | head -n 1
}

# Generate random SMBIOS data
rand_smbios_manufacturer() {
  local vendors=(
    "ASUSTeK" "Dell" "HP" "Lenovo" "Acer" "TOSHIBA" "MSI" "Gigabyte" 
    "Fujitsu" "NEC" "Samsung" "Sony" "LG" "Intel" "EVGA"
  )
  echo "${vendors[$((RANDOM % ${#vendors[@]}))]}"
}

rand_smbios_product() {
  local products=(
    "Latitude" "ThinkPad" "ProBook" "EliteBook" "Precision" "Aspire" 
    "Satellite" "VAIO" "ROG" "Spectre" "XPS" "Inspiron" "ZenBook" 
    "Pavilion" "Omen" "Legion" "IdeaPad" "Surface" "Alienware"
  )
  echo "${products[$((RANDOM % ${#products[@]}))]}"
}

rand_smbios_version() {
  echo "$((RANDOM % 10)).$((RANDOM % 10)).$((RANDOM % 100))"
}

#######################################
# VM operations
#######################################

start_vm() {
  local image="$1"
  shift
  
  # Check if VM is already running
  if is_vm_running; then
    warn "A VM is already running. Stop it first with ./shikra_orchestrator.sh stop"
    exit 1
  fi
  
  # Check if disk image exists
  if [[ ! -f "$image" ]]; then
    error "Disk image not found at $image"
  fi

  # Parse additional options
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --bridge)
        BRIDGE_IF="$2"
        shift 2
        ;;
      --tap)
        TAP_IF="$2"
        shift 2
        ;;
      --memory)
        MEM_MIN="$2"
        MEM_MAX="$2"
        shift 2
        ;;
      --cpu)
        CPU_MIN="$2"
        CPU_MAX="$2"
        shift 2
        ;;
      --vnc)
        VNC_DISPLAY="$2"
        shift 2
        ;;
      --disable-evasion)
        ENABLE_EVASION=0
        shift
        ;;
      *)
        warn "Unknown option: $1 (ignored)"
        shift
        ;;
    esac
  done
  
  # Create memory dumps directory if it doesn't exist
  mkdir -p "$MEMORY_DUMPS_DIR"

  # Setup hardware profile
  local cpu_count
  local mem_size
  local rtc_date
  local mac_addr
  local disk_serial
  local uuid
  local manufacturer
  local product
  local version
  
  if [[ $ENABLE_EVASION -eq 1 ]]; then
    # Randomize hardware if evasion is enabled
    cpu_count=$(rand_cpu_cores)
    mem_size=$(rand_memory)
    rtc_date=$(rand_rtc_base)
    mac_addr=$(rand_mac)
    disk_serial=$(rand_disk_serial)
    uuid=$(rand_uuid)
    manufacturer=$(rand_smbios_manufacturer)
    product=$(rand_smbios_product)
    version=$(rand_smbios_version)
    log "Starting VM with randomized hardware profile (anti-detection)"
  else
    # Use fixed values if evasion is disabled
    cpu_count="${CPU_MIN}"
    mem_size="${MEM_MIN}"
    rtc_date="2023-01-01"
    mac_addr="52:54:00:12:34:56"
    disk_serial="SHIKRA00000000000000"
    uuid="00000000-0000-0000-0000-000000000000"
    manufacturer="QEMU"
    product="Standard PC"
    version="1.0"
    log "Starting VM with standard hardware profile (evasion disabled)"
  fi
  
  # Print VM configuration
  info "VM Configuration:"
  info "  Disk image:   $image"
  info "  CPU cores:    $cpu_count"
  info "  Memory (MB):  $mem_size"
  info "  Bridge:       $BRIDGE_IF"
  info "  TAP:          $TAP_IF"
  info "  MAC Address:  $mac_addr"
  if [[ $ENABLE_EVASION -eq 1 ]]; then
    info "  RTC Date:     $rtc_date"
    info "  Manufacturer: $manufacturer"
    info "  Product:      $product"
    info "  Version:      $version"
  fi
  info "  VNC Display:  $VNC_DISPLAY"
  
  # Check if TAP interface exists
  if ! ip link show "$TAP_IF" &>/dev/null; then
    error "TAP interface $TAP_IF doesn't exist. Run shikra_provisioner.sh first."
  fi
  
  # Check if bridge interface exists
  if ! ip link show "$BRIDGE_IF" &>/dev/null; then
    error "Bridge interface $BRIDGE_IF doesn't exist. Run shikra_provisioner.sh first."
  fi

  # Base QEMU command
  local qemu_cmd="qemu-system-x86_64"
  local qemu_args=(
    -enable-kvm
    -name "$VM_NAME"
    -pidfile "$QEMU_PID_FILE"
    -cpu host,hv_relaxed,hv_spinlocks=0x1fff,hv_vapic,hv_time
    -smp "$cpu_count"
    -m "$mem_size"
    -drive "file=$image,if=virtio,format=qcow2,serial=$disk_serial"
    -netdev "tap,id=net0,ifname=$TAP_IF,script=no,downscript=no"
    -device "e1000,netdev=net0,mac=$mac_addr"
    -vnc "$VNC_DISPLAY"
  )
  
  # Add UEFI firmware if it exists
  if [[ -f "$OVMF_CODE" && -f "$OVMF_VARS" ]]; then
    qemu_args+=(
      -drive "if=pflash,format=raw,readonly=on,file=$OVMF_CODE"
      -drive "if=pflash,format=raw,file=$OVMF_VARS"
    )
  else
    warn "OVMF firmware not found, using default BIOS"
  fi
  
  # Add evasion options if enabled
  if [[ $ENABLE_EVASION -eq 1 ]]; then
    qemu_args+=(
      -rtc "base=$rtc_date"
      -uuid "$uuid"
      -smbios "type=1,manufacturer=$manufacturer,product=$product,version=$version"
      -no-hpet
      -global "kvm-pit.lost_tick_policy=discard"
      -cpu host,kvm=off,hv_vendor_id=null
      -machine "pc-q35-7.0,accel=kvm,usb=off,vmport=off,dump-guest-core=off,hpet=off"
    )
  fi
  
  # Start the VM
  log "Starting VM..."
  "$qemu_cmd" "${qemu_args[@]}" &
  
  # Wait a moment to ensure process started
  sleep 2
  
  if is_vm_running; then
    log "VM started successfully!"
    info "Connect to VM using: vncviewer $VNC_DISPLAY"
    info "To stop the VM: ./shikra_orchestrator.sh stop"
  else
    error "Failed to start VM"
  fi
}

snapshot_create() {
  local snap_name="$1"
  local image="$2"
  
  if [[ -z "$snap_name" ]]; then
    error "No snapshot name provided"
  fi
  
  if [[ ! -f "$image" ]]; then
    error "Disk image not found at $image"
  fi
  
  log "Creating snapshot '$snap_name' for $image"
  if qemu-img snapshot -c "$snap_name" "$image"; then
    log "Snapshot created successfully"
  else
    error "Failed to create snapshot"
  fi
}

snapshot_rollback() {
  local snap_name="$1"
  local image="$2"
  
  if [[ -z "$snap_name" ]]; then
    error "No snapshot name provided"
  fi
  
  if [[ ! -f "$image" ]]; then
    error "Disk image not found at $image"
  fi
  
  # Check if VM is running
  if is_vm_running; then
    warn "VM is currently running. Stop it first before rolling back to a snapshot."
    exit 1
  fi
  
  log "Rolling back to snapshot '$snap_name' for $image"
  if qemu-img snapshot -a "$snap_name" "$image"; then
    log "Rollback completed successfully"
  else
    error "Failed to rollback to snapshot"
  fi
}

list_snapshots() {
  local image="$1"
  
  if [[ ! -f "$image" ]]; then
    error "Disk image not found at $image"
  fi
  
  log "Listing snapshots for $image"
  qemu-img snapshot -l "$image"
}

is_vm_running() {
  if [[ -f "$QEMU_PID_FILE" ]]; then
    local pid=$(cat "$QEMU_PID_FILE")
    if kill -0 "$pid" 2>/dev/null; then
      return 0  # VM is running
    fi
  fi
  
  # Try to find the VM by name if pid file doesn't exist or is invalid
  if pgrep -f "$VM_NAME" &>/dev/null; then
    return 0  # VM is running
  fi
  
  return 1  # VM is not running
}

stop_vm() {
  if ! is_vm_running; then
    warn "No VM is currently running"
    return 0
  fi
  
  local pid
  if [[ -f "$QEMU_PID_FILE" ]]; then
    pid=$(cat "$QEMU_PID_FILE")
  else
    pid=$(pgrep -f "$VM_NAME" | head -1)
  fi
  
  if [[ -n "$pid" ]]; then
    log "Stopping VM with PID $pid..."
    kill "$pid"
    
    # Wait for VM to shutdown gracefully
    local timeout=30
    while kill -0 "$pid" 2>/dev/null && [[ $timeout -gt 0 ]]; do
      sleep 1
      ((timeout--))
    done
    
    # Force kill if necessary
    if kill -0 "$pid" 2>/dev/null; then
      warn "VM did not stop gracefully, forcing shutdown..."
      kill -9 "$pid"
    fi
    
    log "VM stopped successfully"
    
    # Clean up PID file
    rm -f "$QEMU_PID_FILE"
  else
    error "Could not find VM process"
  fi
}

capture_memory() {
  local output_path="$1"
  
  if ! is_vm_running; then
    error "VM is not running, cannot capture memory"
  fi
  
  local pid
  if [[ -f "$QEMU_PID_FILE" ]]; then
    pid=$(cat "$QEMU_PID_FILE")
  else
    pid=$(pgrep -f "$VM_NAME" | head -1)
  fi
  
  if [[ -z "$pid" ]]; then
    error "Could not find VM process"
  fi
  
  # If no output path specified, create one with timestamp
  if [[ -z "$output_path" ]]; then
    local timestamp=$(date +%Y%m%d_%H%M%S)
    output_path="$MEMORY_DUMPS_DIR/memory_dump_${timestamp}.raw"
  fi
  
  # Ensure directory exists
  mkdir -p "$(dirname "$output_path")"
  
  log "Capturing memory dump from VM (PID: $pid)..."
  
  # First try with virsh if available (better method)
  if command -v virsh &>/dev/null && virsh list --all | grep -q "$VM_NAME"; then
    log "Using virsh for memory dump (recommended method)"
    virsh dump "$VM_NAME" "$output_path" --memory-only
  # Then try with gcore if available
  elif command -v gcore &>/dev/null; then
    log "Using gcore for memory dump"
    gcore -o "${output_path}.core" "$pid"
    mv "${output_path}.core.$pid" "$output_path"
  else
    error "No suitable memory dumping tool found. Install gdb or libvirt-clients."
  fi
  
  log "Memory dump saved to: $output_path"
  info "Analyze with: volatility3 -f $output_path ..."
}

show_vm_status() {
  log "Checking VM status..."
  
  if is_vm_running; then
    local pid
    if [[ -f "$QEMU_PID_FILE" ]]; then
      pid=$(cat "$QEMU_PID_FILE")
    else
      pid=$(pgrep -f "$VM_NAME" | head -1)
    fi
    
    log "VM Status: RUNNING"
    info "  Process ID: $pid"
    info "  VM Name: $VM_NAME"
    info "  VNC Display: $VNC_DISPLAY"
    
    # Show runtime info if possible
    if command -v qemu-monitor-command &>/dev/null && [[ -n "$pid" ]]; then
      echo -e "${BLUE}Runtime Information:${NC}"
      qemu-monitor-command --pretty --hmp "$pid" "info status" 2>/dev/null || true
    fi
  else
    log "VM Status: NOT RUNNING"
  fi
}

resolve_disk_path() {
  # If user provided a path, use it; otherwise use the default
  if [[ -n "$1" && -f "$1" ]]; then
    echo "$1"
  else
    # Ask user for path if default doesn't exist
    if [[ ! -f "$DEFAULT_DISK_IMAGE" ]]; then
      echo -n "Default disk image not found. Please enter path to QCOW2 image: "
      read -r custom_path
      if [[ -f "$custom_path" ]]; then
        echo "$custom_path"
      else
        error "Invalid disk image path"
      fi
    else
      echo "$DEFAULT_DISK_IMAGE"
    fi
  fi
}

usage() {
  cat << EOF
Usage:
  $0 start [qcow2_path] [options]
  $0 snapshot <snapshot_name> [qcow2_path]
  $0 rollback <snapshot_name> [qcow2_path]
  $0 list-snapshots [qcow2_path]
  $0 stop
  $0 memdump [output_path]
  $0 status

Options:
  --bridge BRIDGE     Bridge interface name (default: $BRIDGE_IF)
  --tap TAP          TAP interface name (default: $TAP_IF)
  --memory SIZE      Memory size in MB (default: random between $MEM_MIN-$MEM_MAX)
  --cpu CORES        CPU cores (default: random between $CPU_MIN-$CPU_MAX)
  --vnc DISPLAY      VNC display number (default: $VNC_DISPLAY)
  --disable-evasion  Disable anti-VM detection features

Examples:
  $0 start /path/to/windows.qcow2 --memory 4096 --cpu 2
  $0 snapshot clean_state /path/to/windows.qcow2
  $0 rollback clean_state /path/to/windows.qcow2
  $0 memdump /path/to/save/memory.raw
EOF
  exit 1
}

#######################################
# Main execution
#######################################

# Check if at least one command is given
if [[ $# -lt 1 ]]; then
  usage
fi

# Process command
CMD="$1"
shift

case "$CMD" in
  start)
    # Find disk image path (either provided or default)
    DISK_IMG=$(resolve_disk_path "$@")
    start_vm "$DISK_IMG" "$@"
    ;;
  snapshot)
    if [[ $# -lt 1 ]]; then
      error "Snapshot name required"
    fi
    SNAP_NAME="$1"
    shift
    DISK_IMG=$(resolve_disk_path "$@")
    snapshot_create "$SNAP_NAME" "$DISK_IMG"
    ;;
  rollback)
    if [[ $# -lt 1 ]]; then
      error "Snapshot name required"
    fi
    SNAP_NAME="$1"
    shift
    DISK_IMG=$(resolve_disk_path "$@")
    snapshot_rollback "$SNAP_NAME" "$DISK_IMG"
    ;;
  list-snapshots)
    DISK_IMG=$(resolve_disk_path "$@")
    list_snapshots "$DISK_IMG"
    ;;
  stop)
    stop_vm
    ;;
  memdump)
    capture_memory "$1"
    ;;
  status)
    show_vm_status
    ;;
  *)
    usage
    ;;
esac

exit 0
