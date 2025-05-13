#!/usr/bin/env bash
#
# create_windows_qcow2.sh
# 
# Creates a QCOW2 disk image for Windows installation in the Shikra sandbox
#
# Usage:
#   sudo ./create_windows_qcow2.sh [options]
#
# Options:
#   -s, --size SIZE    Disk size (default: 40G)
#   -p, --path PATH    Output path (default: /var/lib/libvirt/images/windows.qcow2)
#   -i, --iso ISO      Path to Windows ISO (default: none)
#   -h, --help         Show help
#

set -e

# Default values
DISK_SIZE="40G"
OUTPUT_PATH="/var/lib/libvirt/images/windows.qcow2"
ISO_PATH=""

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -s|--size)
      DISK_SIZE="$2"
      shift 2
      ;;
    -p|--path)
      OUTPUT_PATH="$2"
      shift 2
      ;;
    -i|--iso)
      ISO_PATH="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo ""
      echo "Options:"
      echo "  -s, --size SIZE    Disk size (default: 40G)"
      echo "  -p, --path PATH    Output path (default: /var/lib/libvirt/images/windows.qcow2)"
      echo "  -i, --iso ISO      Path to Windows ISO (default: none)"
      echo "  -h, --help         Show help"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      exit 1
      ;;
  esac
done

echo "[INFO] Creating QCOW2 image for Windows"
echo "[INFO] Disk size: $DISK_SIZE"
echo "[INFO] Output path: $OUTPUT_PATH"

# Create directory if it doesn't exist
mkdir -p "$(dirname "$OUTPUT_PATH")"

# Create the QCOW2 image
echo "[INFO] Creating disk image..."
qemu-img create -f qcow2 "$OUTPUT_PATH" "$DISK_SIZE"

echo "[SUCCESS] QCOW2 image created at: $OUTPUT_PATH"

# If ISO path is provided, start installation
if [[ -n "$ISO_PATH" && -f "$ISO_PATH" ]]; then
  echo "[INFO] Starting Windows installation with ISO: $ISO_PATH"
  echo "[INFO] This will create and install Windows to the QCOW2 image"
  echo "[INFO] Connect to VNC display :0 to continue installation"
  
  qemu-system-x86_64 \
    -enable-kvm \
    -m 4096 \
    -smp 2 \
    -cpu host \
    -drive file="$OUTPUT_PATH",format=qcow2 \
    -cdrom "$ISO_PATH" \
    -boot d \
    -vnc :0
else
  echo ""
  echo "[NEXT STEPS]"
  echo "1. Install Windows using:"
  echo "   qemu-system-x86_64 -enable-kvm -m 4096 -cpu host -drive file=$OUTPUT_PATH,format=qcow2 -cdrom ISO=$ISO_PATH -boot d -vnc :0"
  echo ""
  echo "2. After installation, use the image with the Shikra orchestrator:"
  echo "   ./shikra_orchestrator.sh start $OUTPUT_PATH"
fi
