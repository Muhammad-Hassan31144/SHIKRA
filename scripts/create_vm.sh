#!/bin/bash
# Shikra VM Creation Script
#
# Purpose:
# This script automates the creation and configuration of virtual machines specifically
# tailored for malware analysis within the Shikra environment.
#
# Version: 1.2
# Last Updated: 2024-06-09

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
CONFIG_DIR="$PROJECT_ROOT/config"
VM_PROFILES_DIR="$CONFIG_DIR/vm_profiles"
LOG_FILE="$PROJECT_ROOT/logs/vm_creation.log"

# Default VM storage locations. Can be overridden by environment variables.
VM_STORAGE_DIR="${VM_STORAGE_DIR:-/var/lib/libvirt/images}"
ISO_STORAGE_DIR="${ISO_STORAGE_DIR:-/root/isos}"
LIBVIRT_ISO_DIR="/var/lib/libvirt/isos"

# --- Command Line Arguments (initialized to empty) ---
VM_NAME=""
PROFILE_NAME=""
OS_ISO_PATH=""
MEMORY_MB=""
DISK_SIZE_GB=""
VCPUS=""
OS_TYPE=""
NETWORK=""
ENABLE_STEALTH=false
FORCE_RECREATE=false
DRY_RUN=false

# Extended profile-driven options (defaults applied in load_vm_profile)
CPU_MODE=""
MACHINE_TYPE=""
FIRMWARE=""
TOPOLOGY_SOCKETS=""
TOPOLOGY_CORES=""
TOPOLOGY_THREADS=""
RNG_ENABLE=false
SMBIOS_VENDOR=""
SMBIOS_PRODUCT=""
SMBIOS_SERIAL=""
SMBIOS_UUID=""
NETWORK_ADAPTERS_JSON="[]"
ADDITIONAL_STORAGE_JSON="[]"
SERIAL_PATH=""

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# --- Utility Functions ---

log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

show_usage() {
    echo "Usage: $0 --name <vm_name> --profile <profile_name> [options]"
    echo ""
    echo "Required Arguments:"
    echo "  --name <name>            Name for the new VM."
    echo "  --profile <profile>      VM profile to use (from $VM_PROFILES_DIR/)."
    echo ""
    echo "Optional Arguments:"
    echo "  --os-iso <path>          Path to OS installation ISO (place ISOs in $ISO_STORAGE_DIR)."
    echo "  --memory <mb>            Memory in MB (overrides profile setting)."
    echo "  --disk <gb>              Disk size in GB (overrides profile setting)."
    echo "  --force                  Force recreate if VM already exists (deletes existing VM)."
    echo "  --stealth                Enable stealth/anti-detection features."
    echo "  --dry-run                Show what would be done without executing."
    echo "  -h, --help               Show this help message."
    echo ""
    echo "ISO Storage:"
    echo "  Place your ISO files in: $ISO_STORAGE_DIR"
    echo "  They will be copied to: $LIBVIRT_ISO_DIR"
    echo ""
    echo "Available VM Profiles:"
    # Safely list available profiles.
    if [[ -d "$VM_PROFILES_DIR" ]]; then
        ls -1 "$VM_PROFILES_DIR"/*.json 2>/dev/null | sed 's/.*\///;s/\.json$//' | sed 's/^/  - /' || echo "  No profiles found in $VM_PROFILES_DIR"
    fi
}

parse_arguments() {
    log "${BLUE}Parsing command line arguments...${NC}"
    if [[ $# -eq 0 ]]; then show_usage; exit 1; fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --name) VM_NAME="$2"; shift 2 ;;
            --profile) PROFILE_NAME="$2"; shift 2 ;;
            --os-iso) OS_ISO_PATH="$2"; shift 2 ;;
            --memory) MEMORY_MB="$2"; shift 2 ;;
            --disk) DISK_SIZE_GB="$2"; shift 2 ;;
            --force) FORCE_RECREATE=true; shift ;;
            --stealth) ENABLE_STEALTH=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if [[ -z "$VM_NAME" ]] || [[ -z "$PROFILE_NAME" ]]; then
        log "${RED}Error: --name and --profile are required arguments.${NC}"; show_usage; exit 1;
    fi
}

load_vm_profile() {
    log "${BLUE}Loading VM profile: $PROFILE_NAME${NC}"
    local profile_file="$VM_PROFILES_DIR/${PROFILE_NAME}.json"

    if [[ ! -f "$profile_file" ]]; then
        log "${RED}Error: VM profile not found: $profile_file${NC}"; exit 1;
    fi

    # Load normalized profile values (creation-only), with sensible defaults
    MEMORY_MB=${MEMORY_MB:-$(jq -r '.vm_config.memory_mb // 4096' "$profile_file")}
    DISK_SIZE_GB=${DISK_SIZE_GB:-$(jq -r '.vm_config.disk_size_gb // 60' "$profile_file")}
    VCPUS=$(jq -r '.vm_config.vcpus // 2' "$profile_file")
    OS_TYPE=$(jq -r '.vm_config.os_type // "generic"' "$profile_file")
    NETWORK=$(jq -r '.vm_config.network // "shikra-isolated"' "$profile_file")

    CPU_MODE=$(jq -r '.vm_config.cpu_mode // "host-passthrough"' "$profile_file")
    MACHINE_TYPE=$(jq -r '.vm_config.machine_type // "q35"' "$profile_file")
    FIRMWARE=$(jq -r '.vm_config.firmware // "bios"' "$profile_file")

    TOPOLOGY_SOCKETS=$(jq -r '.vm_config.cpu_topology.sockets // 1' "$profile_file")
    TOPOLOGY_CORES=$(jq -r '.vm_config.cpu_topology.cores // 1' "$profile_file")
    TOPOLOGY_THREADS=$(jq -r '.vm_config.cpu_topology.threads // 1' "$profile_file")

    RNG_ENABLE=$(jq -r '.vm_config.rng // false' "$profile_file")

    SMBIOS_VENDOR=$(jq -r '.vm_config.smbios.vendor // empty' "$profile_file")
    SMBIOS_PRODUCT=$(jq -r '.vm_config.smbios.product // empty' "$profile_file")
    SMBIOS_SERIAL=$(jq -r '.vm_config.smbios.serial // empty' "$profile_file")
    SMBIOS_UUID=$(jq -r '.vm_config.smbios.uuid // empty' "$profile_file")

    NETWORK_ADAPTERS_JSON=$(jq -c '.vm_config.network_adapters // []' "$profile_file")
    ADDITIONAL_STORAGE_JSON=$(jq -c '.vm_config.additional_storage // []' "$profile_file")

    SERIAL_PATH=$(jq -r '.vm_config.serial_path // empty' "$profile_file")

    log "Configuration loaded:"
    log "  - Memory: ${MEMORY_MB}MB, Root Disk: ${DISK_SIZE_GB}GB, vCPUs: ${VCPUS} (topology: ${TOPOLOGY_SOCKETS}s/${TOPOLOGY_CORES}c/${TOPOLOGY_THREADS}t)"
    log "  - OS Type: ${OS_TYPE}, Default Network: ${NETWORK}"
    log "  - CPU Mode: ${CPU_MODE}, Machine: ${MACHINE_TYPE}, Firmware: ${FIRMWARE}"
    log "  - RNG: ${RNG_ENABLE}, SMBIOS(vendor='${SMBIOS_VENDOR}', product='${SMBIOS_PRODUCT}', serial='${SMBIOS_SERIAL}')"
}

cleanup_existing_vm() {
    log "${BLUE}Cleaning up existing VM: $VM_NAME${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would cleanup existing VM"
        return 0
    fi

    # Stop VM if running
    if [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "running" ]]; then
        log "Stopping running VM..."
        virsh destroy "$VM_NAME" 2>/dev/null || true
    fi

    # Delete all snapshots first
    log "Removing snapshots..."
    local snapshots
    snapshots=$(virsh snapshot-list "$VM_NAME" --name 2>/dev/null || true)
    
    if [[ -n "$snapshots" ]]; then
        while IFS= read -r snapshot; do
            if [[ -n "$snapshot" ]]; then
                log "Deleting snapshot: $snapshot"
                virsh snapshot-delete "$VM_NAME" "$snapshot" 2>/dev/null || true
            fi
        done <<< "$snapshots"
    fi

    # Undefine the domain and remove storage
    log "Undefining VM domain and removing storage..."
    virsh undefine "$VM_NAME" --remove-all-storage 2>/dev/null || virsh undefine "$VM_NAME" 2>/dev/null || true

    # Ensure disk file is removed
    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    if [[ -f "$disk_path" ]]; then
        log "Removing remaining disk file: $disk_path"
        rm -f "$disk_path"
    fi

    # Remove any additional extra disks
    local extra_pattern="$VM_STORAGE_DIR/${VM_NAME}-extra*.qcow2"
    shopt -s nullglob
    local extras=( $extra_pattern )
    if (( ${#extras[@]} > 0 )); then
        for f in "${extras[@]}"; do
            log "Removing extra disk file: $f"
            rm -f "$f"
        done
    fi
    shopt -u nullglob

    # Remove stale unix serial socket if present
    local serial_socket="/tmp/${VM_NAME}-serial.sock"
    if [[ -S "$serial_socket" ]]; then
        log "Removing stale serial socket: $serial_socket"
        rm -f "$serial_socket"
    fi

    log "${GREEN}Existing VM cleaned up successfully${NC}"
}

copy_iso_to_libvirt() {
    if [[ -z "$OS_ISO_PATH" ]]; then
        return 0
    fi

    log "${BLUE}Copying ISO to libvirt storage...${NC}"
    
    # Create libvirt ISO directory
    mkdir -p "$LIBVIRT_ISO_DIR"
    
    # Get just the filename from the path
    local iso_filename=$(basename "$OS_ISO_PATH")
    local dest_iso_path="$LIBVIRT_ISO_DIR/$iso_filename"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would copy $OS_ISO_PATH to $dest_iso_path"
        return 0
    fi

    # Check if source ISO exists
    if [[ ! -f "$OS_ISO_PATH" ]]; then
        log "${RED}Error: OS ISO not found at: $OS_ISO_PATH${NC}"
        log "${YELLOW}Please place your ISO file in $ISO_STORAGE_DIR/${NC}"
        exit 1
    fi

    # Copy ISO if it doesn't already exist or is different
    if [[ ! -f "$dest_iso_path" ]] || ! cmp -s "$OS_ISO_PATH" "$dest_iso_path"; then
        log "Copying ISO: $OS_ISO_PATH -> $dest_iso_path"
        if ! cp "$OS_ISO_PATH" "$dest_iso_path"; then
            log "${RED}Failed to copy ISO file${NC}"
            exit 1
        fi
        log "${GREEN}ISO copied successfully${NC}"
    else
        log "ISO already exists in libvirt storage: $dest_iso_path"
    fi
    
    # Update OS_ISO_PATH to point to the copied file
    OS_ISO_PATH="$dest_iso_path"
}

check_prerequisites() {
    log "${BLUE}Checking prerequisites...${NC}"
    if [[ $EUID -ne 0 ]]; then log "${RED}This script must be run as root.${NC}"; exit 1; fi
    
    local commands=("virsh" "virt-install" "qemu-img" "jq")
    for cmd in "${commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then log "${RED}Required command not found: $cmd${NC}"; exit 1; fi
    done
    
    if ! systemctl is-active --quiet libvirtd; then log "${RED}libvirtd service is not running.${NC}"; exit 1; fi
    
    # Check if VM exists and handle accordingly
    if virsh dominfo "$VM_NAME" &>/dev/null; then
        if [[ "$FORCE_RECREATE" == "true" ]]; then
            cleanup_existing_vm
        else
            log "${RED}VM '$VM_NAME' already exists. Use --force to recreate.${NC}"; exit 1;
        fi
    fi
    
    mkdir -p "$VM_STORAGE_DIR"
    log "${GREEN}Prerequisites check passed.${NC}"
}

create_disk_image() {
    log "${BLUE}Creating disk image for $VM_NAME...${NC}"
    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    local final_disk_size="${DISK_SIZE_GB}G"

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create disk image at $disk_path with size $final_disk_size."
        return
    fi

    log "Creating disk: $disk_path ($final_disk_size)"
    if ! qemu-img create -f qcow2 "$disk_path" "$final_disk_size"; then
        log "${RED}Failed to create disk image.${NC}"; exit 1;
    fi
    log "${GREEN}Disk image created successfully.${NC}"
}

create_additional_disks() {
    # Create any additional storage disks defined in the profile
    local idx=0
    local count=$(echo "$ADDITIONAL_STORAGE_JSON" | jq 'length')
    if [[ "$count" -eq 0 ]]; then
        return 0
    fi
    log "${BLUE}Creating ${count} additional disk(s)...${NC}"
    while [[ $idx -lt $count ]]; do
        local size_gb=$(echo "$ADDITIONAL_STORAGE_JSON" | jq -r ".[$idx].size_gb // 0")
        local bus=$(echo "$ADDITIONAL_STORAGE_JSON" | jq -r ".[$idx].bus // \"sata\"")
        local file=$(echo "$ADDITIONAL_STORAGE_JSON" | jq -r ".[$idx].file // empty")
        if [[ -z "$file" || "$file" == "null" ]]; then
            file="$VM_STORAGE_DIR/${VM_NAME}-extra$((idx+1)).qcow2"
        fi
        if [[ "$DRY_RUN" == "true" ]]; then
            log "Dry run: would create additional disk $file (${size_gb}G) bus=$bus"
        else
            log "Creating additional disk: $file (${size_gb}G), bus=$bus"
            if ! qemu-img create -f qcow2 "$file" "${size_gb}G" >/dev/null; then
                log "${RED}Failed to create additional disk: $file${NC}"; exit 1;
            fi
        fi
        idx=$((idx+1))
    done
    log "${GREEN}Additional disks provisioning step complete.${NC}"
}

install_os() {
    log "${BLUE}Starting OS installation for $VM_NAME...${NC}"
    if [[ -z "$OS_ISO_PATH" ]]; then
        log "${YELLOW}No --os-iso specified. VM will be created without an OS.${NC}"; return;
    fi

    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    local os_variant="generic" # Default
    local disk_bus="sata" # Better compatibility for Windows
    
    case "${OS_TYPE,,}" in
        windows*|win*) 
            os_variant="win10"
            disk_bus="sata" # Windows needs SATA for disk detection
            ;;
        ubuntu*) 
            os_variant="ubuntu22.04"
            disk_bus="virtio" # Linux works fine with virtio
            ;;
        debian*) 
            os_variant="debian11"
            disk_bus="virtio"
            ;;
    esac

    # Prepare serial socket path for agent/manager communication
    local serial_socket
    if [[ -n "$SERIAL_PATH" ]]; then
        serial_socket="${SERIAL_PATH//\{VM_NAME\}/$VM_NAME}"
    else
        serial_socket="/tmp/${VM_NAME}-serial.sock"
    fi
    # Remove any stale socket before starting the VM
    if [[ -S "$serial_socket" ]]; then
        log "Removing existing serial socket at $serial_socket"
        rm -f "$serial_socket"
    fi

    # Build vCPU topology option
    local vcpus_opt
    vcpus_opt="$VCPUS"
    if [[ -n "$TOPOLOGY_SOCKETS" && -n "$TOPOLOGY_CORES" && -n "$TOPOLOGY_THREADS" ]]; then
        vcpus_opt+=" ,sockets=${TOPOLOGY_SOCKETS},cores=${TOPOLOGY_CORES},threads=${TOPOLOGY_THREADS}"
        vcpus_opt="${vcpus_opt// /}"
    fi

    # Start building virt-install command
    local virt_install_cmd=(
        "virt-install"
        "--name" "$VM_NAME"
        "--memory" "$MEMORY_MB"
        "--vcpus" "$vcpus_opt"
        "--disk" "path=$disk_path,format=qcow2,bus=$disk_bus"
        "--cdrom" "$OS_ISO_PATH"
        # network added later (supports multi-NIC)
        "--os-variant" "$os_variant"
        "--graphics" "vnc,listen=127.0.0.1"
        "--boot" "cdrom,hd,menu=on"
        "--noautoconsole"
        "--wait" "-1"
        "--noreboot"
        "--serial" "type=unix,mode=bind,path=$serial_socket,target.type=isa-serial,target.port=0"
    )

    # Machine type
    if [[ -n "$MACHINE_TYPE" && "$MACHINE_TYPE" != "null" ]]; then
        virt_install_cmd+=("--machine" "$MACHINE_TYPE")
    fi

    # CPU mode (host or host-passthrough recommended)
    if [[ -n "$CPU_MODE" && "$CPU_MODE" != "null" ]]; then
        virt_install_cmd+=("--cpu" "$CPU_MODE")
    fi

    # Firmware / UEFI handling
    if [[ "${FIRMWARE,,}" == "uefi" ]]; then
        local OVMF_CODE="/usr/share/OVMF/OVMF_CODE.fd"
        local OVMF_VARS="/usr/share/OVMF/OVMF_VARS.fd"
        if [[ -f "$OVMF_CODE" && -f "$OVMF_VARS" ]]; then
            virt_install_cmd+=("--boot" "loader=$OVMF_CODE,loader.readonly=yes,loader.type=pflash,nvram.template=$OVMF_VARS,loader_secure=no")
            log "Using UEFI firmware via OVMF: $OVMF_CODE (secure boot disabled)"
        else
            virt_install_cmd+=("--boot" "uefi")
            log "OVMF not found at default path; attempting --boot uefi"
        fi
    fi

    # SMBIOS strings (manufacturer/product/serial/uuid) - use --sysinfo instead of --smbios
    local sysinfo_kv=()
    [[ -n "$SMBIOS_VENDOR" && "$SMBIOS_VENDOR" != "null" ]] && sysinfo_kv+=("bios.vendor=${SMBIOS_VENDOR// /_}")
    [[ -n "$SMBIOS_PRODUCT" && "$SMBIOS_PRODUCT" != "null" ]] && sysinfo_kv+=("system.product=${SMBIOS_PRODUCT// /_}")
    [[ -n "$SMBIOS_SERIAL" && "$SMBIOS_SERIAL" != "null" ]] && sysinfo_kv+=("system.serial=${SMBIOS_SERIAL// /_}")
    [[ -n "$SMBIOS_UUID" && "$SMBIOS_UUID" != "null" ]] && sysinfo_kv+=("system.uuid=$SMBIOS_UUID")
    if [[ ${#sysinfo_kv[@]} -gt 0 ]]; then
        local sysinfo_string=""
        local IFS=","
        sysinfo_string="${sysinfo_kv[*]}"
        virt_install_cmd+=("--sysinfo" "$sysinfo_string")
    fi

    # RNG device for better entropy
    if [[ "$RNG_ENABLE" == "true" ]]; then
        virt_install_cmd+=("--rng" "/dev/urandom")
    fi

    # Additional disks: append as --disk entries, preserving bus from profile
    if [[ $(echo "$ADDITIONAL_STORAGE_JSON" | jq 'length') -gt 0 ]]; then
        local idx=0
        while [[ $idx -lt $(echo "$ADDITIONAL_STORAGE_JSON" | jq 'length') ]]; do
            local bus=$(echo "$ADDITIONAL_STORAGE_JSON" | jq -r ".[$idx].bus // \"sata\"")
            local file=$(echo "$ADDITIONAL_STORAGE_JSON" | jq -r ".[$idx].file // empty")
            if [[ -z "$file" || "$file" == "null" ]]; then
                file="$VM_STORAGE_DIR/${VM_NAME}-extra$((idx+1)).qcow2"
            fi
            virt_install_cmd+=("--disk" "path=$file,format=qcow2,bus=$bus")
            idx=$((idx+1))
        done
    fi

    # Networks: if network_adapters defined, use them; else fallback to single NETWORK
    if [[ $(echo "$NETWORK_ADAPTERS_JSON" | jq 'length') -gt 0 ]]; then
        local nidx=0
        while [[ $nidx -lt $(echo "$NETWORK_ADAPTERS_JSON" | jq 'length') ]]; do
            local net_name=$(echo "$NETWORK_ADAPTERS_JSON" | jq -r ".[$nidx].network // \"$NETWORK\"")
            local model=$(echo "$NETWORK_ADAPTERS_JSON" | jq -r ".[$nidx].model // \"e1000\"")
            local mac=$(echo "$NETWORK_ADAPTERS_JSON" | jq -r ".[$nidx].mac // empty")
            local net_arg="network=$net_name,model=$model"
            if [[ -n "$mac" && "$mac" != "null" ]]; then
                net_arg+=" ,mac=$mac"; net_arg="${net_arg// /}"
            fi
            virt_install_cmd+=("--network" "$net_arg")
            nidx=$((nidx+1))
        done
    else
        virt_install_cmd+=("--network" "network=$NETWORK,model=e1000")
    fi

    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would run virt-install with the following command:"
        log "  ${virt_install_cmd[*]}"
        return
    fi

    # Verbose summary of what will be added
    log "Planned VM configuration:"
    log "  - CPU: mode=$CPU_MODE, vcpus=$VCPUS (topology ${TOPOLOGY_SOCKETS}s/${TOPOLOGY_CORES}c/${TOPOLOGY_THREADS}t)"
    log "  - Machine: $MACHINE_TYPE, Firmware: $FIRMWARE"
    log "  - Memory: ${MEMORY_MB}MB"
    log "  - OS Variant: $os_variant"
    log "  - Root Disk: $disk_path (bus=$disk_bus)"
    if [[ $(echo "$ADDITIONAL_STORAGE_JSON" | jq 'length') -gt 0 ]]; then
        local idx=0
        while [[ $idx -lt $(echo "$ADDITIONAL_STORAGE_JSON" | jq 'length') ]]; do
            local bus=$(echo "$ADDITIONAL_STORAGE_JSON" | jq -r ".[$idx].bus // \"sata\"")
            local file=$(echo "$ADDITIONAL_STORAGE_JSON" | jq -r ".[$idx].file // empty")
            [[ -z "$file" || "$file" == "null" ]] && file="$VM_STORAGE_DIR/${VM_NAME}-extra$((idx+1)).qcow2"
            log "  - Extra Disk[$((idx+1))]: $file (bus=$bus)"
            idx=$((idx+1))
        done
    fi
    if [[ $(echo "$NETWORK_ADAPTERS_JSON" | jq 'length') -gt 0 ]]; then
        local nidx=0
        while [[ $nidx -lt $(echo "$NETWORK_ADAPTERS_JSON" | jq 'length') ]]; do
            local net_name=$(echo "$NETWORK_ADAPTERS_JSON" | jq -r ".[$nidx].network // \"$NETWORK\"")
            local model=$(echo "$NETWORK_ADAPTERS_JSON" | jq -r ".[$nidx].model // \"e1000\"")
            local mac=$(echo "$NETWORK_ADAPTERS_JSON" | jq -r ".[$nidx].mac // empty")
            log "  - NIC[$((nidx+1))]: network=$net_name, model=$model${mac:+, mac=$mac}"
            nidx=$((nidx+1))
        done
    else
        log "  - NIC: network=$NETWORK, model=e1000"
    fi
    log "  - Serial (unix): $serial_socket (COM1 in guest)"
    log "  - RNG: $RNG_ENABLE"
    if [[ ${#sysinfo_kv[@]} -gt 0 ]]; then
        log "  - SYSINFO: ${sysinfo_kv[*]}"
    fi

    log "Starting virt-install with $disk_bus disk bus and configured devices..."
    log "${YELLOW}Installation will wait for completion and then automatically finalize...${NC}"
    if ! "${virt_install_cmd[@]}"; then
        log "${RED}virt-install command failed.${NC}"; exit 1;
    fi
    
    log "${GREEN}Installation completed! Now finalizing VM...${NC}"
    
    # Automatically eject installation media (find the actual CD-ROM device)
    log "Ejecting installation media..."
    
    # Get the actual CD-ROM device name from the VM's XML
    CDROM_DEVICE=$(virsh dumpxml "$VM_NAME" | grep -B2 "device='cdrom'" | grep "target dev" | sed -n "s/.*dev='\([^']*\)'.*/\1/p")
    
    if [[ -n "$CDROM_DEVICE" ]]; then
        if virsh change-media "$VM_NAME" "$CDROM_DEVICE" --eject --force 2>/dev/null; then
            log "${GREEN}Installation media ejected from $CDROM_DEVICE successfully${NC}"
        else
            log "${YELLOW}Failed to eject from $CDROM_DEVICE, trying alternative method...${NC}"
            # Alternative: detach the whole CD-ROM device
            virsh detach-disk "$VM_NAME" "$CDROM_DEVICE" --persistent 2>/dev/null || true
        fi
    else
        log "${YELLOW}No CD-ROM device found to eject${NC}"
    fi
    
    # Also update boot order to prioritize hard disk
    virsh detach-disk "$VM_NAME" "$CDROM_DEVICE" --config 2>/dev/null || true
    
    # Start the VM normally (will boot from hard drive)
    log "Starting VM from installed OS..."
    if virsh start "$VM_NAME" 2>/dev/null; then
        log "${GREEN}VM '$VM_NAME' started successfully and should boot from installed OS${NC}"
    else
        log "${YELLOW}VM may already be running or failed to start${NC}"
    fi
    
    log "${GREEN}VM '$VM_NAME' created and finalized successfully!${NC}"
    log "${YELLOW}Connect with: virt-viewer $VM_NAME${NC}"
}

create_snapshot() {
    log "${BLUE}Creating 'clean_baseline' snapshot for $VM_NAME...${NC}"
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create 'clean_baseline' snapshot."
        return
    fi
    
    # More robustly wait for the VM to be shut off before snapshotting.
    local max_wait=60 # Wait up to 60 seconds
    while [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "running" && $max_wait -gt 0 ]]; do
        log "VM is running. Waiting for manual shutdown before creating snapshot... ($max_wait s remaining)"
        sleep 10
        max_wait=$((max_wait - 10))
    done

    if [[ "$(virsh domstate "$VM_NAME" 2>/dev/null)" == "running" ]]; then
        log "${RED}VM did not shut down. Cannot create snapshot. Please shut down the VM manually.${NC}"
        return 1
    fi

    local snapshot_name="clean_baseline"
    local snapshot_desc="Clean state after initial OS installation and setup on $(date)"

    if ! virsh snapshot-create-as --domain "$VM_NAME" --name "$snapshot_name" --description "$snapshot_desc" --atomic; then
        log "${RED}Failed to create snapshot '$snapshot_name'.${NC}"; return 1;
    fi
    
    log "${GREEN}Snapshot '$snapshot_name' created successfully.${NC}"
}

cleanup_on_error() {
    log "${YELLOW}An error occurred. Cleaning up resources for '$VM_NAME'...${NC}"
    
    # Try to undefine the domain first, which might also remove storage
    if virsh dominfo "$VM_NAME" &>/dev/null; then
        log "Undefining VM domain: $VM_NAME..."
        virsh undefine "$VM_NAME" --remove-all-storage &>/dev/null || virsh undefine "$VM_NAME" &>/dev/null
    fi
    
    # Explicitly remove the disk image if it still exists
    local disk_path="$VM_STORAGE_DIR/${VM_NAME}.qcow2"
    if [[ -f "$disk_path" ]]; then
        log "Removing disk image: $disk_path..."
        rm -f "$disk_path"
    fi
    log "Cleanup finished."
}

# --- Main Execution ---
main() {
    trap cleanup_on_error ERR SIGINT SIGTERM
    
    log "${GREEN}--- Shikra VM Creation Script Started ---${NC}"
    
    parse_arguments "$@"
    load_vm_profile
    check_prerequisites
    copy_iso_to_libvirt
    create_disk_image
    create_additional_disks
    install_os
    
    log "${GREEN}--- VM Creation Process Completed for '$VM_NAME' ---${NC}"
    log "${YELLOW}Please complete the OS installation manually via VNC or virt-viewer.${NC}"
    log "${YELLOW}After the OS is fully installed and shut down, you can create a clean snapshot by running:${NC}"
    log "${CYAN}  sudo virsh snapshot-create-as --domain $VM_NAME --name clean_baseline --atomic${NC}"
    log ""
    log "To start the VM: virsh start $VM_NAME"
    log "To connect: virt-viewer $VM_NAME"

    trap - ERR SIGINT SIGTERM # Disable trap on successful exit
}

main "$@"