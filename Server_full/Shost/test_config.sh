#!/bin/bash
# Test configuration for Shikra Host

# Export environment variables
export SHOST_ENV=development
export SHOST_API_HOST=0.0.0.0
export SHOST_API_PORT=8080
export SHOST_DEBUG=true

export SHOST_DATABASE_PATH=/tmp/shost/shost.db
export SHOST_SAMPLE_STORAGE=/tmp/shost/samples
export SHOST_ARTIFACT_STORAGE=/tmp/shost/artifacts
export SHOST_DUMP_STORAGE=/tmp/shost/dumps

# VM Configuration (adjust as needed)
export SHOST_VM_IMAGE_PATH=/var/lib/libvirt/images/win10.clean_baseline_20250824_133607
export SHOST_VM_SNAPSHOT=clean_baseline_20250824_133607
export SHOST_VM_RAM=2048
export SHOST_VM_CORES=2
export SHOST_VM_VNC_PORT=5900
export SHOST_VM_SSH_PORT=2222

# Agent Configuration (adjust paths to your built binaries)
export SHOST_AGENT_PATH=../build/windows-release/bin/ShikraAgent.exe
export SHOST_HOOKENGINE_PATH=../build/windows-release/bin/HookEngine.dll
export SHOST_AGENT_SECRET=shikra-dev-secret-key

echo "🔧 Test configuration loaded"
echo "   API Server: http://127.0.0.1:5000"
echo "   Dashboard:  http://127.0.0.1:5000/dashboard"
echo "   Database:   /tmp/shost/shost.db"
