#!/usr/bin/env bash
#
# improved_shikra_provisioner.sh
# 
# A comprehensive malware analysis environment setup script for ransomware research.
# Creates a secure, isolated sandbox with virtualization tools, network isolation,
# and forensic analysis capabilities.
#
# Version: 2.0
#
# Features:
#   - Installs QEMU/KVM, bridge-utils, virt-manager, OVMF for virtualization
#   - Sets up INetSim for fake internet services within the sandbox
#   - Configures network isolation with TAP/bridge interfaces
#   - Installs analysis tools (Wireshark, Volatility)
#   - Implements proper firewall rules to prevent sandbox escape
#   - Creates persistent network configuration
#   - Supports custom configuration via command-line options
#   - Includes cleanup functionality to revert changes
#   - Performs system compatibility checks
#
# Usage:
#   sudo ./improved_shikra_provisioner.sh [options]
#
# Options:
#   -h, --help                 Show this help message
#   -u, --user USERNAME        Specify sandbox user (default: current non-root user)
#   -i, --ip IP_ADDRESS        Specify sandbox bridge IP (default: 192.168.56.1)
#   -b, --bridge BRIDGE_NAME   Specify bridge interface name (default: br0)
#   -t, --tap TAP_NAME         Specify TAP interface name (default: tap0)
#   -c, --cleanup              Remove all sandbox components and configuration
#   -v, --verbose              Enable verbose output
#   -n, --no-network           Skip network configuration
#   -f, --force                Force reinstallation of components
#
# Requirements:
#   - Ubuntu/Debian-based system (tested on Ubuntu 20.04+)
#   - At least 4GB RAM, 2 CPU cores
#   - 20GB free disk space (for VM storage)
#   - Root/sudo privileges
#
# Author: Improved by Claude based on original script
#

# Exit on error, but allow error handling
set -o errexit
set -o pipefail
set -o nounset

# Global configuration variables with defaults
TAP_IF="tap0"
BR_IF="br0"
BRIDGE_IP="192.168.56.1"
BRIDGE_NETMASK="255.255.255.0"
HOST_USER="$(logname || whoami)"
INETSIM_CONF="/etc/inetsim/inetsim.conf"
VERBOSE=0
CLEANUP=0
SKIP_NETWORK=0
FORCE=0
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/shikra_provisioner.log"
NET_PERSIST_DIR="/etc/networkd-dispatcher/routable.d"
NET_PERSIST_SCRIPT="${NET_PERSIST_DIR}/50-shikra-network"
SUPPORTED_DISTROS=("ubuntu" "debian" "linuxmint" "pop" "elementary" "zorin")

# Minimum hardware requirements
MIN_RAM_MB=4096
MIN_CPU_CORES=2
MIN_DISK_GB=20

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#######################################
# Print message to stdout and log file
# Arguments:
#   Message text to print
#######################################
log() {
  local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
  echo -e "${timestamp} - $1" | tee -a "$LOG_FILE"
}

#######################################
# Print message only when verbose mode is enabled
# Arguments:
#   Message text to print
#######################################
log_verbose() {
  if [[ $VERBOSE -eq 1 ]]; then
    log "$1"
  fi
}

#######################################
# Print error message and exit
# Arguments:
#   Error message
#   Exit code (optional, default: 1)
#######################################
error_exit() {
  log "${RED}ERROR: $1${NC}"
  exit "${2:-1}"
}

#######################################
# Print warning message
# Arguments:
#   Warning message
#######################################
warning() {
  log "${YELLOW}WARNING: $1${NC}"
}

#######################################
# Print success message
# Arguments:
#   Success message
#######################################
success() {
  log "${GREEN}SUCCESS: $1${NC}"
}

#######################################
# Print information message
# Arguments:
#   Info message
#######################################
info() {
  log "${BLUE}INFO: $1${NC}"
}

#######################################
# Print script usage
#######################################
usage() {
  cat << EOF
Usage: sudo $0 [options]

Options:
  -h, --help                 Show this help message
  -u, --user USERNAME        Specify sandbox user (default: $HOST_USER)
  -i, --ip IP_ADDRESS        Specify sandbox bridge IP (default: $BRIDGE_IP)
  -b, --bridge BRIDGE_NAME   Specify bridge interface name (default: $BR_IF)
  -t, --tap TAP_NAME         Specify TAP interface name (default: $TAP_IF)
  -c, --cleanup              Remove all sandbox components and configuration
  -v, --verbose              Enable verbose output
  -n, --no-network           Skip network configuration
  -f, --force                Force reinstallation of components

This script sets up a complete malware/ransomware analysis environment with:
- QEMU/KVM virtualization
- Network isolation via bridge/TAP
- Fake internet services with INetSim
- Analysis tools (Wireshark, Volatility)
- Appropriate firewall rules for security

Requirements:
- Ubuntu/Debian-based system (tested on Ubuntu 20.04+)
- At least 4GB RAM, 2 CPU cores
- 20GB free disk space (for VM storage)
- Root/sudo privileges
EOF
  exit 0
}

#######################################
# Check if running as root
#######################################
check_root() {
  if [[ $EUID -ne 0 ]]; then
    error_exit "Please run this script as root (sudo $0)" 1
  fi
  log_verbose "Running as root: OK"
}

#######################################
# Check system compatibility
# Verifies OS distribution and hardware requirements
#######################################
check_system_compatibility() {
  info "Checking system compatibility..."
  
  # Check distribution
  if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO_ID=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
    DISTRO_VERSION="$VERSION_ID"
    
    local supported=0
    for dist in "${SUPPORTED_DISTROS[@]}"; do
      if [[ "$DISTRO_ID" == *"$dist"* ]]; then
        supported=1
        break
      fi
    done
    
    if [[ $supported -eq 0 ]]; then
      warning "Unsupported distribution: $PRETTY_NAME. This script is tested on Ubuntu/Debian systems."
      read -p "Continue anyway? (y/n) " -n 1 -r
      echo
      if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        error_exit "Aborted by user due to unsupported distribution" 2
      fi
    else
      log_verbose "Distribution check: $PRETTY_NAME - Supported"
    fi
  else
    warning "Could not determine OS distribution. Proceeding anyway."
  fi
  
  # Check RAM
  local total_ram_kb=$(grep MemTotal /proc/meminfo | awk '{print $2}')
  local total_ram_mb=$((total_ram_kb / 1024))
  if [[ $total_ram_mb -lt $MIN_RAM_MB ]]; then
    warning "System has ${total_ram_mb}MB RAM. Recommended minimum is ${MIN_RAM_MB}MB."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      error_exit "Aborted by user due to insufficient RAM" 3
    fi
  else
    log_verbose "RAM check: ${total_ram_mb}MB - Sufficient"
  fi
  
  # Check CPU cores
  local cpu_cores=$(grep -c processor /proc/cpuinfo)
  if [[ $cpu_cores -lt $MIN_CPU_CORES ]]; then
    warning "System has ${cpu_cores} CPU cores. Recommended minimum is ${MIN_CPU_CORES}."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      error_exit "Aborted by user due to insufficient CPU cores" 4
    fi
  else
    log_verbose "CPU check: ${cpu_cores} cores - Sufficient"
  fi
  
  # Check disk space
  local root_partition=$(df -h / | awk 'NR==2 {print $1}')
  local free_space_kb=$(df -k / | awk 'NR==2 {print $4}')
  local free_space_gb=$((free_space_kb / 1024 / 1024))
  if [[ $free_space_gb -lt $MIN_DISK_GB ]]; then
    warning "System has ${free_space_gb}GB free disk space. Recommended minimum is ${MIN_DISK_GB}GB."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      error_exit "Aborted by user due to insufficient disk space" 5
    fi
  else
    log_verbose "Disk space check: ${free_space_gb}GB free - Sufficient"
  fi
  
  # Check KVM support
  if [ -c /dev/kvm ]; then
    log_verbose "KVM device exists: OK"
    if grep -q 'vmx\|svm' /proc/cpuinfo; then
      log_verbose "CPU virtualization support: OK"
    else
      warning "CPU virtualization (VT-x/AMD-V) not detected. VM performance will be poor."
    fi
  else
    warning "KVM device not found. Check if virtualization is enabled in BIOS/UEFI."
  fi
  
  success "System compatibility check completed"
}

#######################################
# Validate user exists or create it
# Arguments:
#   Username to validate
#######################################
validate_user() {
  local username="$1"
  
  # Check if user exists
  if id "$username" &>/dev/null; then
    log_verbose "User $username exists: OK"
  else
    warning "User $username does not exist."
    read -p "Create user $username? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
      info "Creating user $username..."
      adduser --gecos "" "$username"
      
      # Add to sudo group
      read -p "Add $username to sudo group? (y/n) " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        usermod -aG sudo "$username"
        success "Added $username to sudo group"
      fi
      
      # Add to necessary groups for KVM
      usermod -aG kvm,libvirt "$username" 2>/dev/null || true
      success "User $username created and configured"
    else
      error_exit "User $username does not exist and user creation was declined" 6
    fi
  fi
  
  # Ensure user is in necessary groups
  for group in kvm libvirt; do
    if ! groups "$username" | grep -q "\b$group\b"; then
      log_verbose "Adding $username to $group group"
      usermod -aG "$group" "$username" 2>/dev/null || warning "Failed to add user to $group group"
    fi
  done
}

#######################################
# Install all required packages
# Handles different package managers
#######################################
install_all_packages() {
  info "Installing required packages..."
  
  # Identify package manager
  if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
    PKG_UPDATE="apt-get update"
    PKG_INSTALL="apt-get install -y"
  elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
    PKG_UPDATE="dnf check-update || true"  # dnf returns 100 if updates available
    PKG_INSTALL="dnf install -y"
  elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
    PKG_UPDATE="yum check-update || true"
    PKG_INSTALL="yum install -y"
  else
    error_exit "Unsupported package manager. This script requires apt, dnf, or yum." 7
  fi
  
  log_verbose "Using package manager: $PKG_MANAGER"
  
  # Update package lists
  info "Updating package lists..."
  eval "$PKG_UPDATE" || warning "Package list update failed, continuing anyway"
  
  # Base packages for all distributions
  local DEPS=(
    qemu-kvm
    bridge-utils
    virt-manager
    ovmf
    wireshark
    python3-pip
    iptables
    ufw
    tcpdump
    net-tools
    netcat
    networkd-dispatcher
  )
  
  # Handle special cases for different distros
  if [[ "$PKG_MANAGER" == "apt-get" ]]; then
    DEPS+=(inetsim)
    # Add volatility from apt if available, otherwise will install via pip
    apt-cache show volatility &>/dev/null && DEPS+=(volatility)
  else
    # For non-Debian systems, we might need EPEL for some packages
    if [[ "$PKG_MANAGER" == "dnf" || "$PKG_MANAGER" == "yum" ]]; then
      eval "$PKG_INSTALL epel-release" || warning "EPEL repository installation failed"
    fi
  fi
  
  # Install each package and track successes/failures
  local failures=()
  local installed=()
  
  for pkg in "${DEPS[@]}"; do
    # Check if package is already installed (unless force flag is set)
    if [[ $FORCE -eq 0 ]]; then
      case "$PKG_MANAGER" in
        apt-get)
          if dpkg -l | grep -q "^ii\s\+$pkg\b"; then
            log_verbose "$pkg is already installed."
            continue
          fi
          ;;
        dnf|yum)
          if rpm -q "$pkg" &>/dev/null; then
            log_verbose "$pkg is already installed."
            continue
          fi
          ;;
      esac
    fi
    
    # Install package
    info "Installing $pkg..."
    if eval "$PKG_INSTALL $pkg"; then
      installed+=("$pkg")
      success "$pkg installed successfully"
    else
      failures+=("$pkg")
      warning "Failed to install $pkg, continuing with other packages"
    fi
  done
  
  # Try to install INetSim from source if not available via package manager
  if [[ ! " ${DEPS[*]} " =~ " inetsim " ]] || [[ " ${failures[*]} " =~ " inetsim " ]]; then
    install_inetsim_from_source
  fi
  
  # Install Volatility3 via pip if needed
  if ! command -v vol &>/dev/null && ! command -v vol.py &>/dev/null; then
    info "Installing Volatility3 via pip..."
    if pip3 install volatility3; then
      installed+=("volatility3 (pip)")
      success "Volatility3 installed successfully via pip"
    else
      failures+=("volatility3 (pip)")
      warning "Failed to install Volatility3 via pip"
    fi
  fi
  
  # Report on installation results
  if [[ ${#installed[@]} -gt 0 ]]; then
    success "Successfully installed: ${installed[*]}"
  fi
  
  if [[ ${#failures[@]} -gt 0 ]]; then
    warning "Failed to install: ${failures[*]}"
    warning "Some features may not work correctly without these packages."
    read -p "Continue anyway? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
      error_exit "Aborted by user due to package installation failures" 8
    fi
  else
    success "All required packages installed successfully"
  fi
}

#######################################
# Install INetSim from source if not available via package manager
#######################################
install_inetsim_from_source() {
  info "Attempting to install INetSim from source..."
  
  # Check if INetSim is already installed
  if command -v inetsim &>/dev/null; then
    log_verbose "INetSim is already installed."
    return 0
  fi
  
  # Install prerequisites
  local INETSIM_DEPS=(
    perl
    libnet-dns-perl
    libnet-server-perl
    libfork-daemon-perl
    libipc-shareable-perl
  )
  
  for dep in "${INETSIM_DEPS[@]}"; do
    eval "$PKG_INSTALL $dep" || warning "Failed to install INetSim dependency: $dep"
  done
  
  # Create temp directory
  local TEMP_DIR=$(mktemp -d)
  cd "$TEMP_DIR" || error_exit "Failed to create temporary directory" 9
  
  # Download and extract
  info "Downloading INetSim source..."
  if ! curl -L -o inetsim.tar.gz http://www.inetsim.org/downloads/inetsim-1.3.2.tar.gz; then
    warning "Failed to download INetSim source. Skipping INetSim installation."
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    return 1
  fi
  
  tar -xzf inetsim.tar.gz
  cd inetsim-* || {
    warning "Failed to extract INetSim source. Skipping INetSim installation."
    cd - > /dev/null
    rm -rf "$TEMP_DIR"
    return 1
  }
  
  # Install
  info "Installing INetSim from source..."
  if ./setup.sh; then
    success "INetSim installed from source"
  else
    warning "Failed to install INetSim from source"
  fi
  
  # Cleanup
  cd - > /dev/null
  rm -rf "$TEMP_DIR"
}

#######################################
# Configure INetSim for sandbox environment
#######################################
configure_inetsim() {
  info "Configuring INetSim..."
  
  # Check if INetSim is installed
  if ! command -v inetsim &>/dev/null; then
    warning "INetSim not found. Skipping configuration."
    return 1
  fi
  
  # Check if config file exists
  if [[ ! -f "$INETSIM_CONF" ]]; then
    warning "INetSim configuration file not found at $INETSIM_CONF"
    # Try to locate config file
    local alt_conf=$(find /etc -name "inetsim.conf" 2>/dev/null | head -1)
    if [[ -n "$alt_conf" ]]; then
      INETSIM_CONF="$alt_conf"
      info "Found alternative config at $INETSIM_CONF"
    else
      warning "Could not locate INetSim configuration file. Skipping configuration."
      return 1
    fi
  fi
  
  # Backup configuration if not already done
  if [[ ! -f "${INETSIM_CONF}.bak" ]]; then
    cp "$INETSIM_CONF" "${INETSIM_CONF}.bak"
    log_verbose "Backed up original INetSim configuration"
  fi
  
  # Update configuration
  log_verbose "Modifying INetSim configuration..."
  
  # Use sed to modify configuration values with error handling
  update_inetsim_config() {
    local pattern="$1"
    local replacement="$2"
    local result
    
    result=$(sed -i.tmp "s|$pattern|$replacement|" "$INETSIM_CONF" 2>&1) || {
      warning "Failed to update INetSim config: $result"
      return 1
    }
    rm -f "${INETSIM_CONF}.tmp"
    return 0
  }
  
  # Apply configuration changes
  update_inetsim_config '^SERVICE_BIND_ADDRESS="127.0.0.1"' "SERVICE_BIND_ADDRESS=\"$BRIDGE_IP\""
  update_inetsim_config '^DNS_BIND_ADDRESS="127.0.0.1"' "DNS_BIND_ADDRESS=\"$BRIDGE_IP\""
  update_inetsim_config '^START_DNS="no"' 'START_DNS="yes"'
  update_inetsim_config '^DNS_DEFAULT_IP="10.0.0.1"' "DNS_DEFAULT_IP=\"$BRIDGE_IP\""
  
  # Enable HTTP and HTTPS services
  update_inetsim_config '^START_HTTP="no"' 'START_HTTP="yes"'
  update_inetsim_config '^START_HTTPS="no"' 'START_HTTPS="yes"'
  
  # Enable commonly used services for malware analysis
  update_inetsim_config '^START_SMTP="no"' 'START_SMTP="yes"'
  update_inetsim_config '^START_FTP="no"' 'START_FTP="yes"'
  update_inetsim_config '^START_IRC="no"' 'START_IRC="yes"'
  
  success "INetSim configuration updated for sandbox use"
  info "INetSim will serve fake internet services on $BRIDGE_IP"
  info "Start INetSim with: systemctl start inetsim (or run 'inetsim' directly)"
}

#######################################
# Create TAP interface and bridge for VM network
# Sets up persistent configuration
#######################################
create_tap_bridge() {
  if [[ $SKIP_NETWORK -eq 1 ]]; then
    info "Skipping network configuration (--no-network specified)"
    return 0
  fi
  
  info "Setting up isolated network with TAP interface ($TAP_IF) and bridge ($BR_IF)..."
  
  # Check if interfaces already exist
  local bridge_exists=0
  local tap_exists=0
  
  if ip link show "$BR_IF" &>/dev/null; then
    bridge_exists=1
    log_verbose "Bridge $BR_IF already exists"
  fi
  
  if ip link show "$TAP_IF" &>/dev/null; then
    tap_exists=1
    log_verbose "TAP interface $TAP_IF already exists"
  fi
  
  # Create or reconfigure bridge
  if [[ $bridge_exists -eq 0 || $FORCE -eq 1 ]]; then
    if [[ $bridge_exists -eq 1 ]]; then
      ip link set "$BR_IF" down || warning "Failed to bring down existing bridge"
      ip link delete "$BR_IF" type bridge || warning "Failed to delete existing bridge"
    fi
    
    info "Creating bridge $BR_IF..."
    if ! ip link add name "$BR_IF" type bridge; then
      error_exit "Failed to create bridge interface $BR_IF" 10
    fi
    
    # Set bridge properties
    ip link set dev "$BR_IF" up || warning "Failed to bring up bridge"
    ip addr add "$BRIDGE_IP/$BRIDGE_NETMASK" dev "$BR_IF" || warning "Failed to set bridge IP"
    
    # Enable STP (prevents loops if multiple bridges are connected)
    echo 1 > /sys/class/net/"$BR_IF"/bridge/stp_state || warning "Failed to enable STP on bridge"
    
    success "Bridge $BR_IF created with IP $BRIDGE_IP"
  else
    # Just ensure bridge is up and has correct IP
    ip link set dev "$BR_IF" up || warning "Failed to bring up bridge"
    
    # Check if bridge has the correct IP
    if ! ip addr show dev "$BR_IF" | grep -q "$BRIDGE_IP"; then
      ip addr add "$BRIDGE_IP/$BRIDGE_NETMASK" dev "$BR_IF" || warning "Failed to set bridge IP"
    fi
  fi
  
  # Create or reconfigure TAP interface
  if [[ $tap_exists -eq 0 || $FORCE -eq 1 ]]; then
    if [[ $tap_exists -eq 1 ]]; then
      ip link set "$TAP_IF" down || warning "Failed to bring down existing TAP"
      ip tuntap del dev "$TAP_IF" mode tap || warning "Failed to delete existing TAP"
    fi
    
    info "Creating TAP interface $TAP_IF..."
    if ! ip tuntap add dev "$TAP_IF" mode tap user "$HOST_USER"; then
      error_exit "Failed to create TAP interface $TAP_IF" 11
    fi
    
    ip link set "$TAP_IF" up || warning "Failed to bring up TAP interface"
    success "TAP interface $TAP_IF created"
  else
    # Just ensure TAP is up and has correct owner
    ip link set "$TAP_IF" up || warning "Failed to bring up TAP interface"
    
    # Update TAP user ownership if needed
    if ! ip link show "$TAP_IF" | grep -q "owner $HOST_USER"; then
      warning "TAP interface ownership doesn't match specified user"
      # Can't change owner without recreating, so recreate if forced
      if [[ $FORCE -eq 1 ]]; then
        ip link set "$TAP_IF" down
        ip tuntap del dev "$TAP_IF" mode tap
        ip tuntap add dev "$TAP_IF" mode tap user "$HOST_USER"
        ip link set "$TAP_IF" up
        success "TAP interface recreated with correct ownership"
      fi
    fi
  fi
  
  # Attach TAP to bridge if not already attached
  if ! ip link show "$TAP_IF" | grep -q "master $BR_IF"; then
    info "Attaching $TAP_IF to $BR_IF..."
    if ! ip link set "$TAP_IF" master "$BR_IF"; then
      warning "Failed to attach TAP to bridge"
    else
      success "TAP interface $TAP_IF attached to bridge $BR_IF"
    fi
  else
    log_verbose "TAP interface already attached to bridge"
  fi
  
  # Create persistent network configuration
  create_persistent_network_config
}

#######################################
# Set up persistent network configuration
# Creates a script that runs on boot
#######################################
create_persistent_network_config() {
  info "Setting up persistent network configuration..."
  
  # Create parent directory if it doesn't exist
  if [[ ! -d "$NET_PERSIST_DIR" ]]; then
    mkdir -p "$NET_PERSIST_DIR" || {
      warning "Failed to create directory $NET_PERSIST_DIR"
      warning "Network configuration will not persist after reboot"
      return 1
    }
  fi
  
  # Create the persistent network script
  cat > "$NET_PERSIST_SCRIPT" << EOF
#!/bin/bash
# Shikra sandbox persistent network configuration
# Created by improved_shikra_provisioner.sh

# Recreate bridge if needed
if ! ip link show "$BR_IF" &>/dev/null; then
  ip link add name "$BR_IF" type bridge
  ip link set dev "$BR_IF" up
  ip addr add "$BRIDGE_IP/$BRIDGE_NETMASK" dev "$BR_IF"
  echo 1 > /sys/class/net/"$BR_IF"/bridge/stp_state 2>/dev/null || true
fi

# Recreate TAP if needed
if ! ip link show "$TAP_IF" &>/dev/null; then
  ip tuntap add dev "$TAP_IF" mode tap user "$HOST_USER"
  ip link set "$TAP_IF" up
  ip link set "$TAP_IF" master "$BR_IF"
fi

# Ensure interfaces are up
ip link set dev "$BR_IF" up
ip link set dev "$TAP_IF" up

# Apply firewall rules
iptables -F FORWARD
iptables -P FORWARD DROP
iptables -A FORWARD -i "$BR_IF" -o "$BR_IF" -j ACCEPT
iptables -A FORWARD -i "$BR_IF" -o lo -j ACCEPT
iptables -A FORWARD -i lo -o "$BR_IF" -j ACCEPT
iptables -t nat -F POSTROUTING

# Block all other traffic between bridge and physical networks
for iface in \$(ls /sys/class/net/ | grep -v "$BR_IF\\|$TAP_IF\\|lo"); do
  iptables -A FORWARD -i "$BR_IF" -o "\$iface" -j DROP
  iptables -A FORWARD -i "\$iface" -o "$BR_IF" -j DROP
done

# Log status
echo "Shikra sandbox network configuration restored: $BR_IF ($BRIDGE_IP) with $TAP_IF"
exit 0
EOF
  
  # Make script executable
  chmod +x "$NET_PERSIST_SCRIPT" || {
    warning "Failed to make persistence script executable"
    warning "Network configuration will not persist after reboot"
    return 1
  }
  
  success "Created persistent network configuration at $NET_PERSIST_SCRIPT"
  info "Network setup will persist across reboots"
}

#######################################
# Configure firewall rules for sandbox isolation
#######################################
configure_firewall() {
  info "Configuring firewall for sandbox isolation..."
  
  # Check if required tools are installed
  if ! command -v iptables &>/dev/null; then
    warning "iptables not found. Cannot configure firewall."
    return 1
  fi
  
  # Basic firewall configuration
  # 1. Allow traffic within the bridge
  iptables -F FORWARD
  iptables -P FORWARD DROP
  iptables -A FORWARD -i "$BR_IF" -o "$BR_IF" -j ACCEPT
  
  # 2. Allow traffic between bridge and loopback
  iptables -A FORWARD -i "$BR_IF" -o lo -j ACCEPT
  iptables -A FORWARD -i lo -o "$BR_IF" -j ACCEPT
  
  # 3. Block all traffic between bridge and physical networks
  for iface in $(ls /sys/class/net/ | grep -v "$BR_IF\|$TAP_IF\|lo"); do
    log_verbose "Blocking traffic between $BR_IF and $iface"
    iptables -A FORWARD -i "$BR_IF" -o "$iface" -j DROP
    iptables -A FORWARD -i "$iface" -o "$BR_IF" -j DROP
  done
  
  # 4. Clear any NAT rules (to prevent accidental forwarding)
  iptables -t nat -F POSTROUTING
  
  # 5. Add logging for suspicious traffic attempts
  iptables -A FORWARD -i "$BR_IF" -m limit --limit 5/min -j LOG --log-prefix "SANDBOX-ESCAPE-ATTEMPT: " --log-level 4
  
  # Use UFW if available for additional protection
  if command -v ufw &>/dev/null; then
    ufw --force reset >/dev/null
    ufw default deny incoming >/dev/null
    ufw default deny outgoing >/dev/null
    ufw allow in on "$BR_IF" >/dev/null
    ufw allow out on "$BR_IF" >/dev/null
    ufw --force enable >/dev/null
    log_verbose "UFW configured for additional protection"
  fi
  
  success "Firewall configured to isolate sandbox network"
  info "All traffic is isolated to the $BR_IF bridge"
}

#######################################
# Display summary of VM network configuration
# Shows how to connect QEMU to the sandbox
#######################################
display_vm_configuration() {
  info "======== VM CONFIGURATION GUIDE ========="
  echo
  echo "To use this sandbox with QEMU/KVM, configure your VM as follows:"
  echo
  echo "1. NETWORK CONFIGURATION:"
  echo "   - Device model: virtio-net-pci"
  echo "   - Network source: Bridge '$BR_IF'"
  echo "   - MAC address: Generate randomly"
  echo
  echo "2. VM SETTINGS FOR RANSOMWARE ANALYSIS:"
  echo "   - Disable real network card"
  echo "   - Use Windows 7/10 without latest updates (more vulnerable)"
  echo "   - Disable Windows Defender/Security features"
  echo "   - Snapshot the VM before executing malware"
  echo
  echo "3. QEMU COMMAND LINE EXAMPLE:"
  echo "   qemu-system-x86_64 \\"
  echo "     -enable-kvm \\"
  echo "     -m 4096 \\"
  echo "     -cpu host \\"
  echo "     -drive file=windows.qcow2,format=qcow2 \\"
  echo "     -netdev bridge,id=net0,br=$BR_IF \\"
  echo "     -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56"
  echo
  echo "4. SANDBOX NETWORK DETAILS:"
  echo "   - Bridge IP: $BRIDGE_IP"
  echo "   - VM should use static IP in same subnet (e.g., 192.168.56.10)"
  echo "   - Gateway: $BRIDGE_IP"
  echo "   - DNS Server: $BRIDGE_IP (provided by INetSim)"
  echo
  echo "5. STARTING ANALYSIS SERVICES:"
  echo "   - Start INetSim: sudo systemctl start inetsim"
  echo "   - Capture network traffic: sudo tcpdump -i $BR_IF -w capture.pcap"
  echo "   - View network traffic: sudo wireshark -i $BR_IF"
  echo
  echo "IMPORTANT: Always run malware in this isolated environment."
  echo "           Real network access is blocked for safety."
  echo "==========================================="${NC}
}

#######################################
# Verify setup components are working correctly
#######################################
verify_setup() {
  info "Verifying setup components..."
  local failures=0
  
  # Check bridge interface
  if ! ip link show "$BR_IF" &>/dev/null; then
    warning "Bridge interface $BR_IF not found"
    failures=$((failures + 1))
  else
    log_verbose "Bridge interface check: OK"
  fi
  
  # Check TAP interface
  if ! ip link show "$TAP_IF" &>/dev/null; then
    warning "TAP interface $TAP_IF not found"
    failures=$((failures + 1))
  else
    log_verbose "TAP interface check: OK"
  fi
  
  # Check bridge IP
  if ! ip addr show "$BR_IF" | grep -q "$BRIDGE_IP"; then
    warning "Bridge IP $BRIDGE_IP not configured properly"
    failures=$((failures + 1))
  else
    log_verbose "Bridge IP check: OK"
  fi
  
  # Check if INetSim is installed
  if ! command -v inetsim &>/dev/null; then
    warning "INetSim not installed"
    failures=$((failures + 1))
  else
    log_verbose "INetSim installation check: OK"
  fi
  
  # Check if QEMU is installed
  if ! command -v qemu-system-x86_64 &>/dev/null; then
    warning "QEMU not installed"
    failures=$((failures + 1))
  else
    log_verbose "QEMU installation check: OK"
  fi
  
  # Check if persistence script exists
  if [[ ! -f "$NET_PERSIST_SCRIPT" ]]; then
    warning "Network persistence script not created"
    failures=$((failures + 1))
  else
    log_verbose "Network persistence script check: OK"
  fi
  
  # Report results
  if [[ $failures -eq 0 ]]; then
    success "All components verified successfully"
  else
    warning "$failures component(s) failed verification"
    info "You may need to troubleshoot these issues or rerun the script with --force"
  fi
}

#######################################
# Perform cleanup of all created components
#######################################
perform_cleanup() {
  info "Performing cleanup of sandbox environment..."
  
  # 1. Stop and disable INetSim service if running
  if systemctl is-active inetsim &>/dev/null; then
    systemctl stop inetsim || warning "Failed to stop INetSim service"
  fi
  if systemctl is-enabled inetsim &>/dev/null; then
    systemctl disable inetsim || warning "Failed to disable INetSim service"
  fi
  
  # 2. Restore INetSim configuration if backup exists
  if [[ -f "${INETSIM_CONF}.bak" ]]; then
    mv "${INETSIM_CONF}.bak" "$INETSIM_CONF" || warning "Failed to restore INetSim configuration"
  fi
  
  # 3. Remove network interfaces
  log_verbose "Removing network interfaces..."
  if ip link show "$TAP_IF" &>/dev/null; then
    ip link set "$TAP_IF" down
    ip link set "$TAP_IF" nomaster 2>/dev/null || true
    ip tuntap del dev "$TAP_IF" mode tap || warning "Failed to remove TAP interface"
  fi
  
  if ip link show "$BR_IF" &>/dev/null; then
    ip link set "$BR_IF" down
    ip link delete "$BR_IF" type bridge || warning "Failed to remove bridge interface"
  fi
  
  # 4. Remove firewall rules
  log_verbose "Resetting firewall rules..."
  iptables -F FORWARD
  iptables -P FORWARD ACCEPT
  iptables -t nat -F POSTROUTING
  
  # Reset UFW if it was used
  if command -v ufw &>/dev/null && ufw status | grep -q "active"; then
    ufw --force reset >/dev/null
    ufw default allow outgoing >/dev/null
    ufw default deny incoming >/dev/null
  fi
  
  # 5. Remove persistence script
  if [[ -f "$NET_PERSIST_SCRIPT" ]]; then
    rm -f "$NET_PERSIST_SCRIPT" || warning "Failed to remove network persistence script"
  fi
  
  # 6. Remove log file
  if [[ -f "$LOG_FILE" ]]; then
    rm -f "$LOG_FILE" || warning "Failed to remove log file"
  fi
  
  success "Cleanup completed successfully"
  info "All sandbox components have been removed"
  
  # Note about package removal
  info "Note: Installed packages (QEMU, Wireshark, etc.) were not removed"
  info "To remove them, use your package manager's remove/purge functionality"
}

#######################################
# Parse command line arguments
#######################################
parse_arguments() {
  # Initialize variables with defaults
  CLEANUP=0
  VERBOSE=0
  SKIP_NETWORK=0
  FORCE=0
  
  # Parse arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -h|--help)
        usage
        ;;
      -u|--user)
        HOST_USER="$2"
        shift 2
        ;;
      -i|--ip)
        BRIDGE_IP="$2"
        shift 2
        ;;
      -b|--bridge)
        BR_IF="$2"
        shift 2
        ;;
      -t|--tap)
        TAP_IF="$2"
        shift 2
        ;;
      -c|--cleanup)
        CLEANUP=1
        shift
        ;;
      -v|--verbose)
        VERBOSE=1
        shift
        ;;
      -n|--no-network)
        SKIP_NETWORK=1
        shift
        ;;
      -f|--force)
        FORCE=1
        shift
        ;;
      *)
        error_exit "Unknown option: $1. Use --help for usage information." 20
        ;;
    esac
  done
  
  # Validate IP address format
  if ! [[ $BRIDGE_IP =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    error_exit "Invalid IP address format: $BRIDGE_IP" 21
  fi
  
  # Log parsed arguments
  log_verbose "Configuration:"
  log_verbose "  User: $HOST_USER"
  log_verbose "  Bridge IP: $BRIDGE_IP"
  log_verbose "  Bridge Interface: $BR_IF"
  log_verbose "  TAP Interface: $TAP_IF"
  log_verbose "  Cleanup mode: $CLEANUP"
  log_verbose "  Skip network: $SKIP_NETWORK"  
  log_verbose "  Force mode: $FORCE"
}

#######################################
# Main function to orchestrate script execution
#######################################
main() {
  # Initialize log file
  echo "# Shikra Provisioner Log - $(date)" > "$LOG_FILE"
  
  # Parse command line arguments
  parse_arguments "$@"
  
  # Check if running as root
  check_root
  
  # If cleanup mode is enabled, perform cleanup and exit
  if [[ $CLEANUP -eq 1 ]]; then
    perform_cleanup
    exit 0
  fi
  
  # Run the installation/configuration process
  check_system_compatibility
  validate_user "$HOST_USER"
  install_all_packages
  
  if [[ $SKIP_NETWORK -eq 0 ]]; then
    create_tap_bridge
    configure_firewall
    configure_inetsim
  fi
  
  # Verify setup
  verify_setup
  
  # Display VM configuration guidance
  display_vm_configuration
  
  success "Shikra ransomware analysis environment setup completed"
  info "Log file saved to $LOG_FILE"
  
  return 0
}

# Execute main function with all command line arguments
main "$@"
