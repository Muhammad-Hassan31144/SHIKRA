#!/usr/bin/env bash
#
# shikra_provisioner.sh.sh
# 
# Installs QEMU/KVM, bridge-utils, virt-manager, OVMF, INetSim, Wireshark, Volatility,
# plus creates a TAP/bridge for an isolated sandbox network.
#
# Usage:
#   sudo ./shikra_provisioner.sh.sh
#
# Notes:
#  - This script combines the previous separate setup steps into one.
#  - It checks if each package is installed, installs if missing,
#    then configures INetSim and sets up a TAP interface + bridge
#    for your Windows VM environment.
#

set -e

TAP_IF="tap0"
BR_IF="br0"
HOST_USER="sandboxuser"   # Replace with your non-root username who will run QEMU
INETSIM_CONF="/etc/inetsim/inetsim.conf"

function check_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Please run this script as root (sudo)."
    exit 1
  fi
}

function install_all_packages() {
  echo "[shikra_provisioner.sh] Updating package lists..."
  apt-get update -y

  # Combine all dependencies in one list
  local DEPS=(
    qemu-kvm
    bridge-utils
    virt-manager
    ovmf
    inetsim
    wireshark
    volatility
    python3-pip
  )

  for pkg in "${DEPS[@]}"; do
    if ! dpkg -l | grep -q "^ii\s\+$pkg\b"; then
      echo "[shikra_provisioner.sh] Installing $pkg..."
      DEBIAN_FRONTEND=noninteractive apt-get install -y "$pkg"
    else
      echo "[shikra_provisioner.sh] $pkg is already installed."
    fi
  done

  # Optional: upgrade Volatility3 from pip if desired
  # echo "[shikra_provisioner.sh] Installing/upgrading volatility3 via pip..."
  # pip3 install --upgrade volatility3
}

function configure_inetsim() {
  echo "[shikra_provisioner.sh] Backing up and adjusting INetSim config..."

  if [[ ! -f "$INETSIM_CONF.bak" ]]; then
    cp "$INETSIM_CONF" "$INETSIM_CONF.bak"
  fi

  # Minimal customization for a typical sandbox on 192.168.56.1
  sed -i 's/^SERVICE_BIND_ADDRESS="127.0.0.1"/SERVICE_BIND_ADDRESS="0.0.0.0"/' "$INETSIM_CONF"
  sed -i 's/^DNS_BIND_ADDRESS="127.0.0.1"/DNS_BIND_ADDRESS="0.0.0.0"/' "$INETSIM_CONF"
  sed -i 's/^START_DNS="no"/START_DNS="yes"/' "$INETSIM_CONF"
  sed -i 's/^DNS_DEFAULT_IP="10.0.0.1"/DNS_DEFAULT_IP="192.168.56.1"/' "$INETSIM_CONF"

  echo "[shikra_provisioner.sh] INetSim configuration updated. You can adjust $INETSIM_CONF further if needed."
}

function create_tap_bridge() {
  echo "[shikra_provisioner.sh] Creating TAP interface ($TAP_IF) and bridge ($BR_IF)..."
  # Create TAP
  ip tuntap add dev "$TAP_IF" mode tap user "$HOST_USER" 2>/dev/null || true
  ip link set "$TAP_IF" up

  # Create bridge
  ip link add name "$BR_IF" type bridge 2>/dev/null || true
  ip link set "$BR_IF" up

  # Attach TAP to bridge
  ip link set "$TAP_IF" master "$BR_IF"
  echo "[shikra_provisioner.sh] TAP: $TAP_IF attached to Bridge: $BR_IF"

  echo "[shikra_provisioner.sh] If you wish to provide internet, attach your physical NIC with:"
  echo "  ip link set <YourNIC> master $BR_IF"
  echo "Otherwise, you have an isolated sandbox for your Windows VM."
}

function main() {
  check_root
  install_all_packages
  configure_inetsim
  create_tap_bridge

  echo "[shikra_provisioner.sh] Done. Wireshark, Volatility, QEMU, and INetSim are installed."
  echo "[shikra_provisioner.sh] Use 'systemctl start inetsim' or 'inetsim' to run the fake internet services."
  echo "[shikra_provisioner.sh] Then launch your Windows VM with QEMU bridging on $BR_IF/$TAP_IF."
}

main
