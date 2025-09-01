#!/bin/bash

# Shikra Host (Shost) - Quick Start Script
# This script demonstrates the complete MVP workflow

echo "🚀 Shikra Host (Shost) - Quick Start Setup"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root (needed for QEMU-KVM)
if [[ $EUID -eq 0 ]]; then
   print_warning "Running as root. This is fine for testing but not recommended for production."
fi

# Step 1: Check prerequisites
print_status "Checking prerequisites..."

# Check Python
if ! command -v python3 &> /dev/null; then
    print_error "Python 3 is required but not installed"
    exit 1
fi
print_success "Python 3 found: $(python3 --version)"

# Check pip
if ! command -v pip3 &> /dev/null; then
    print_error "pip3 is required but not installed"
    exit 1
fi
print_success "pip3 found"

# Check QEMU-KVM
if ! command -v qemu-system-x86_64 &> /dev/null; then
    print_error "QEMU-KVM is required but not installed"
    print_error "Install with: sudo apt-get install qemu-kvm libvirt-daemon-system"
    exit 1
fi
print_success "QEMU-KVM found: $(qemu-system-x86_64 --version | head -1)"

# Check KVM support
if [[ ! -e /dev/kvm ]]; then
    print_warning "KVM acceleration not available. VMs will run slower."
else
    print_success "KVM acceleration available"
fi

# Step 2: Setup Python environment
print_status "Setting up Python environment..."

if [[ ! -d "venv" ]]; then
    print_status "Creating virtual environment..."
    python3 -m venv venv
fi

print_status "Activating virtual environment..."
source venv/bin/activate

print_status "Installing Python dependencies..."
pip install -r requirements.txt

if [[ $? -eq 0 ]]; then
    print_success "Python dependencies installed"
else
    print_error "Failed to install Python dependencies"
    exit 1
fi

# Step 3: Setup configuration
print_status "Setting up configuration..."

# Create necessary directories
mkdir -p /tmp/shost/{samples,artifacts,dumps,vms,logs}
print_success "Storage directories created"

# Set environment variables for development
export SHOST_ENV=development
export SHOST_DATABASE_PATH=/tmp/shost/shost.db
export SHOST_SAMPLE_STORAGE=/tmp/shost/samples
export SHOST_ARTIFACT_STORAGE=/tmp/shost/artifacts
export SHOST_DUMP_STORAGE=/tmp/shost/dumps

# Check for VM image
VM_IMAGE_PATH="/var/lib/libvirt/images/windows-analysis.qcow2"
if [[ ! -f "$VM_IMAGE_PATH" ]]; then
    print_warning "VM image not found at: $VM_IMAGE_PATH"
    print_warning "You'll need to configure VM_IMAGE_PATH in config/config.py"
    print_warning "or set SHOST_VM_IMAGE_PATH environment variable"
    
    # Create a dummy VM image path for testing
    export SHOST_VM_IMAGE_PATH="/tmp/shost/dummy-vm.qcow2"
    print_warning "Using dummy VM image path for testing: $SHOST_VM_IMAGE_PATH"
fi

# Step 4: Initialize database
print_status "Initializing database..."
python database/init_db.py

if [[ $? -eq 0 ]]; then
    print_success "Database initialized"
else
    print_error "Database initialization failed"
    exit 1
fi

# Step 5: Create test configuration
print_status "Creating test configuration..."

cat > test_config.sh << 'EOF'
#!/bin/bash
# Test configuration for Shikra Host

# Export environment variables
export SHOST_ENV=development
export SHOST_API_HOST=127.0.0.1
export SHOST_API_PORT=5000
export SHOST_DEBUG=true

export SHOST_DATABASE_PATH=/tmp/shost/shost.db
export SHOST_SAMPLE_STORAGE=/tmp/shost/samples
export SHOST_ARTIFACT_STORAGE=/tmp/shost/artifacts
export SHOST_DUMP_STORAGE=/tmp/shost/dumps

# VM Configuration (adjust as needed)
export SHOST_VM_IMAGE_PATH=/tmp/shost/dummy-vm.qcow2
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
EOF

chmod +x test_config.sh
print_success "Test configuration created: test_config.sh"

# Step 6: Create sample test data
print_status "Creating sample test data..."

python << 'EOF'
import sys
sys.path.append('.')
from api.models.agent import AgentModel
from database.init_db import get_database_connection

# Test data already created during database initialization
print("✅ Sample test data ready")
EOF

# Step 7: Final setup
print_status "Final setup..."

# Create startup script
cat > start_shost.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"

echo "🚀 Starting Shikra Host (Shost)..."

# Load configuration
source test_config.sh

# Activate virtual environment
source venv/bin/activate

# Start the server
python run.py
EOF

chmod +x start_shost.sh
print_success "Startup script created: start_shost.sh"

# Create quick test script
cat > test_api.sh << 'EOF'
#!/bin/bash

API_BASE="http://127.0.0.1:5000/api"

echo "🧪 Testing Shikra Host API..."

echo "1. Health Check:"
curl -s "$API_BASE/health" | python3 -m json.tool

echo -e "\n2. Agent Registration Test:"
curl -s -X POST "$API_BASE/v1/agent/register" \
  -H "Content-Type: application/json" \
  -d '{"agent_id": "test-agent-001", "name": "Test Agent"}' | python3 -m json.tool

echo -e "\n3. Sample List:"
curl -s "$API_BASE/v1/samples" | python3 -m json.tool

echo -e "\n4. VM Status:"
curl -s "$API_BASE/v1/vm/status" | python3 -m json.tool

echo -e "\n🎉 API Test Complete!"
EOF

chmod +x test_api.sh
print_success "API test script created: test_api.sh"

# Summary
echo ""
echo "🎉 Shikra Host (Shost) Setup Complete!"
echo "====================================="
echo ""
echo "📁 Files Created:"
echo "   • start_shost.sh    - Start the Shikra Host server"
echo "   • test_config.sh    - Test configuration"
echo "   • test_api.sh       - API testing script"
echo ""
echo "🚀 Quick Start:"
echo "   1. Start the server:    ./start_shost.sh"
echo "   2. Open dashboard:      http://127.0.0.1:5000/dashboard"
echo "   3. Test API:           ./test_api.sh"
echo ""
echo "📖 Key URLs:"
echo "   • Dashboard:        http://127.0.0.1:5000/dashboard"
echo "   • API Health:       http://127.0.0.1:5000/api/health"
echo "   • API Docs:         http://127.0.0.1:5000/api/docs"
echo ""
echo "⚠️  Important Notes:"
echo "   • This is a development setup using dummy VM image"
echo "   • Configure real Windows VM image for actual malware analysis"
echo "   • Adjust paths in config/config.py for your environment"
echo "   • Build the Shikra agent and hook engine first"
echo ""
echo "🔧 Next Steps:"
echo "   1. Configure a real Windows VM image"
echo "   2. Build the Shikra agent and hook engine"
echo "   3. Set up network bridge for VM isolation"
echo "   4. Upload malware samples for analysis"
echo ""
print_success "Setup complete! Run './start_shost.sh' to start the server."
