#!/bin/bash
# Shikra Dependencies Installation Script (Enhanced with Zeek and INetSim)
#
# Purpose:
# This utility script handles installation and configuration of specialized tools
# and packages required by the Shikra analysis platform. It focuses on analysis-specific
# software that requires custom installation procedures or configuration.
#
# Key Functions Implemented:
# - install_system_packages(): Install essential system packages and libraries
# - install_virtualization(): Install QEMU/KVM and related virtualization tools
# - install_analysis_tools(): Install malware analysis tools (Volatility, YARA, etc.)
# - install_zeek(): Install Zeek network monitor with proper repository setup
# - install_inetsim(): Install INetSim with all dependencies
# - install_monitoring_tools(): Set up behavioral monitoring utilities  
# - install_network_tools(): Install network analysis and simulation tools
# - verify_installation(): Validate that all tools are properly installed
#
# Usage:
#     sudo ./install_dependencies.sh [options]
#
# Options:
#     --category <category>     Install specific category (all, system, virtualization, analysis, monitoring, network)
#     --enable-zeek            Force Zeek installation
#     --enable-inetsim         Force INetSim installation
#     --skip-zeek              Skip Zeek installation
#     --skip-inetsim           Skip INetSim installation
#     --skip-virtualization    Skip virtualization tools
#     --dry-run                Show what would be done
#     --force                  Force reinstallation

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TOOLS_DIR="$PROJECT_ROOT/tools"
LOG_FILE="$PROJECT_ROOT/logs/dependency_install.log"

# Installation flags
INSTALL_CATEGORY="all"
ENABLE_ZEEK=false
ENABLE_INETSIM=false
SKIP_ZEEK=false
SKIP_INETSIM=false
SKIP_VIRTUALIZATION=false
DRY_RUN=false
FORCE_REINSTALL=false

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Logging function
log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# Ensure script is run as root
if [[ $EUID -ne 0 ]]; then
   log "${RED}This script must be run as root (use sudo).${NC}" 
   exit 1
fi

show_usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --category <category>     Install category: all, system, virtualization, analysis, monitoring, network"
    echo "  --enable-zeek            Force Zeek network monitor installation"
    echo "  --enable-inetsim         Force INetSim service simulator installation"
    echo "  --skip-zeek              Skip Zeek installation"
    echo "  --skip-inetsim           Skip INetSim installation"
    echo "  --skip-virtualization    Skip virtualization tools"
    echo "  --dry-run                Show what would be done"
    echo "  --force                  Force reinstallation"
    echo "  --help                   Show this help"
    echo ""
    echo "Categories:"
    echo "  all           Install all dependencies (default)"
    echo "  system        System packages only"
    echo "  virtualization QEMU/KVM and virtualization tools"
    echo "  analysis      Analysis tools (Volatility, YARA, pefile)"
    echo "  monitoring    Monitoring tools (Procmon utilities)"
    echo "  network       Network analysis tools (Zeek, INetSim, Wireshark)"
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --category)
                INSTALL_CATEGORY="$2"
                shift 2
                ;;
            --enable-zeek)
                ENABLE_ZEEK=true
                shift
                ;;
            --enable-inetsim)
                ENABLE_INETSIM=true
                shift
                ;;
            --skip-zeek)
                SKIP_ZEEK=true
                shift
                ;;
            --skip-inetsim)
                SKIP_INETSIM=true
                shift
                ;;
            --skip-virtualization)
                SKIP_VIRTUALIZATION=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            --force)
                FORCE_REINSTALL=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log "${RED}Unknown parameter: $1${NC}"
                show_usage
                exit 1
                ;;
        esac
    done
    
    log "Installation Configuration:"
    log "  Category: $INSTALL_CATEGORY"
    log "  Enable Zeek: $ENABLE_ZEEK"
    log "  Enable INetSim: $ENABLE_INETSIM"
    log "  Skip Zeek: $SKIP_ZEEK"
    log "  Skip INetSim: $SKIP_INETSIM"
    log "  Skip Virtualization: $SKIP_VIRTUALIZATION"
    log "  Dry Run: $DRY_RUN"
    log "  Force: $FORCE_REINSTALL"
}

activate_venv() {
    if [ -f "$PROJECT_ROOT/venv/bin/activate" ]; then
        log "Activating Python virtual environment: $PROJECT_ROOT/venv/bin/activate"
        # shellcheck source=/dev/null
        source "$PROJECT_ROOT/venv/bin/activate"
    else
        log "${YELLOW}Virtual environment not found at $PROJECT_ROOT/venv. Some Python packages may install system-wide.${NC}"
    fi
}

# Enhanced package installation with retry logic
install_package_with_retry() {
    local package="$1"
    local pkg_manager="$2"
    local max_attempts=3
    local attempt=1
    
    while [[ $attempt -le $max_attempts ]]; do
        log "Installing $package (attempt $attempt/$max_attempts)..."
        
        case "$pkg_manager" in
            "apt")
                if apt-get install -y "$package"; then
                    log "${GREEN}Successfully installed: $package${NC}"
                    return 0
                fi
                ;;
            "dnf"|"yum")
                if "$pkg_manager" install -y "$package"; then
                    log "${GREEN}Successfully installed: $package${NC}"
                    return 0
                fi
                ;;
        esac
        
        log "${YELLOW}Attempt $attempt failed for $package, retrying...${NC}"
        ((attempt++))
        sleep 2
    done
    
    log "${YELLOW}Warning: Failed to install $package after $max_attempts attempts${NC}"
    return 1
}

install_system_packages() {
    log "${BLUE}Installing system packages...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install system packages"
        return 0
    fi
    
    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu package installation
        local debian_packages=(
            "build-essential"      # Compilation tools
            "python3-dev"          # Python development headers
            "tcpdump"              # Network packet capture
            "tshark"               # Network protocol analyzer (CLI for Wireshark)
            "binutils"             # Binary manipulation utilities
            "file"                 # File type identification
            "sqlite3"              # Lightweight database
            "unzip"                # Archive extraction
            "curl"                 # Data transfer tool
            "wget"                 # Web content retrieval
            "git"                  # Version control system
            "libpcap-dev"          # Packet capture library
            "libssl-dev"           # SSL development library
            "libffi-dev"           # Foreign function interface library
            "pkg-config"           # Helper tool for compiling
            "libjpeg-dev"          # For Pillow (JPEG support)
            "zlib1g-dev"           # For Pillow (PNG/general compression)
            "libfuzzy-dev"         # For ssdeep fuzzy hashing
            "libmagic-dev"         # For python-magic file type detection
            "gnupg"                # For repository key management
            "software-properties-common" # For adding repositories
        )
        
        apt-get update || {
            log "${RED}Error: Failed to update package lists${NC}"
            return 1
        }
        
        for package in "${debian_packages[@]}"; do
            install_package_with_retry "$package" "apt"
        done
        
        # Handle python3-pip specially
        log "Installing python3-pip with special handling..."
        if ! command -v pip3 &>/dev/null; then
            if ! install_package_with_retry "python3-pip" "apt"; then
                log "${YELLOW}python3-pip failed via apt, trying alternative method...${NC}"
                if curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 -; then
                    log "${GREEN}pip installed via get-pip.py${NC}"
                else
                    log "${RED}Failed to install pip via alternative method${NC}"
                fi
            fi
        else
            log "pip3 already available"
        fi
            
    elif [[ -f /etc/redhat-release ]]; then
        # Red Hat/CentOS/Fedora package installation
        local pkg_manager="yum"
        if command -v dnf &> /dev/null; then
            pkg_manager="dnf"
        fi

        local redhat_packages=(
            "gcc" "gcc-c++" "make" # build-essential equivalent
            "python3-devel"
            "tcpdump"
            "wireshark-cli" # tshark equivalent
            "binutils"
            "file"
            "sqlite"
            "unzip"
            "curl"
            "wget"
            "git"
            "libpcap-devel"
            "openssl-devel"
            "libffi-devel"
            "pkgconf-pkg-config" # pkg-config equivalent
            "libjpeg-turbo-devel" # libjpeg-dev equivalent
            "zlib-devel"          # zlib1g-dev equivalent
            "gnupg2"              # For repository keys
        )
        
        for package in "${redhat_packages[@]}"; do
            install_package_with_retry "$package" "$pkg_manager"
        done
        
        # Handle python3-pip for RHEL/CentOS
        log "Installing python3-pip for RHEL/CentOS..."
        if ! command -v pip3 &>/dev/null; then
            if ! install_package_with_retry "python3-pip" "$pkg_manager"; then
                log "${YELLOW}python3-pip failed via $pkg_manager, trying EPEL or alternative...${NC}"
                "$pkg_manager" install -y epel-release 2>/dev/null
                if ! install_package_with_retry "python3-pip" "$pkg_manager"; then
                    if curl -sSL https://bootstrap.pypa.io/get-pip.py | python3 -; then
                        log "${GREEN}pip installed via get-pip.py${NC}"
                    else
                        log "${RED}Failed to install pip via alternative method${NC}"
                    fi
                fi
            fi
        else
            log "pip3 already available"
        fi
    else
        log "${YELLOW}Unsupported distribution for automatic system package installation.${NC}"
        return 1
    fi
    
    log "${GREEN}System packages installation completed${NC}"
    return 0
}

install_virtualization() {
    if [[ "$SKIP_VIRTUALIZATION" == "true" ]]; then
        log "${YELLOW}Skipping virtualization installation as requested.${NC}"
        return 0
    fi
    
    log "${BLUE}Installing virtualization tools (QEMU/KVM)...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install virtualization tools"
        return 0
    fi
    
    if [[ -f /etc/debian_version ]]; then
        local virt_packages=(
            "qemu-kvm"
            "qemu-system-x86"
            "qemu-utils"
            "libvirt-daemon-system"
            "libvirt-clients"
            "libguestfs-tools" #libguestfs for mounting and analyzing disk images
            "bridge-utils"
            "virt-manager"
            "ovmf"  # UEFI firmware
        )
        
        # Check if virtualization is supported
        if ! grep -E "(vmx|svm)" /proc/cpuinfo > /dev/null; then
            log "${YELLOW}Warning: Hardware virtualization may not be supported on this system${NC}"
        fi
        
        for package in "${virt_packages[@]}"; do
            if [[ "$package" == "virt-manager" ]]; then
                log "Installing virt-manager (may fail in headless environments)..."
                if ! install_package_with_retry "$package" "apt"; then
                    log "${YELLOW}virt-manager failed - this is normal for headless systems${NC}"
                fi
            elif [[ "$package" == "ovmf" ]]; then
                log "Installing OVMF UEFI firmware..."
                if ! install_package_with_retry "$package" "apt"; then
                    log "${YELLOW}OVMF failed - older system may not have this package${NC}"
                fi
            else
                install_package_with_retry "$package" "apt"
            fi
        done
        
        # Add user to necessary groups
        if [[ -n "$SUDO_USER" ]]; then
            log "Adding user $SUDO_USER to libvirt and kvm groups..."
            usermod -a -G libvirt "$SUDO_USER" 2>/dev/null || log "${YELLOW}Failed to add to libvirt group${NC}"
            usermod -a -G kvm "$SUDO_USER" 2>/dev/null || log "${YELLOW}Failed to add to kvm group${NC}"
        fi
        
        # Start and enable libvirt service
        systemctl enable libvirtd 2>/dev/null || log "${YELLOW}Failed to enable libvirtd${NC}"
        systemctl start libvirtd 2>/dev/null || log "${YELLOW}Failed to start libvirtd${NC}"
        
    elif [[ -f /etc/redhat-release ]]; then
        local pkg_manager="yum"
        if command -v dnf &> /dev/null; then
            pkg_manager="dnf"
        fi
        
        local virt_packages=(
            "qemu-kvm"
            "qemu-img"
            "libvirt"
            "libvirt-client"
            "virt-install"
            "virt-manager"
            "bridge-utils"
        )
        
        for package in "${virt_packages[@]}"; do
            install_package_with_retry "$package" "$pkg_manager"
        done
        
        # Add user to groups and start services
        if [[ -n "$SUDO_USER" ]]; then
            usermod -a -G libvirt "$SUDO_USER" 2>/dev/null
            usermod -a -G kvm "$SUDO_USER" 2>/dev/null
        fi
        
        systemctl enable libvirtd 2>/dev/null
        systemctl start libvirtd 2>/dev/null
    fi
    
    log "${GREEN}Virtualization tools installation completed${NC}"
    return 0
}

install_zeek() {
    # Check if we should install Zeek
    if [[ "$SKIP_ZEEK" == "true" ]]; then
        log "${YELLOW}Skipping Zeek installation as requested.${NC}"
        return 0
    fi
    
    if [[ "$INSTALL_CATEGORY" != "all" && "$INSTALL_CATEGORY" != "network" && "$ENABLE_ZEEK" != "true" ]]; then
        log "${YELLOW}Skipping Zeek installation (not in network category and not explicitly enabled).${NC}"
        return 0
    fi
    
    log "${BLUE}Installing Zeek network monitor...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install Zeek"
        return 0
    fi
    
    # Check if Zeek is already installed
    if command -v zeek &>/dev/null; then
        log "${GREEN}Zeek already installed.${NC}"
        zeek --version
        return 0
    fi
    
    if [[ -f /etc/debian_version ]]; then
        # Get Ubuntu version for repository setup
        source /etc/os-release
        local ubuntu_version="$VERSION_ID"
        
        # Use Ubuntu 24.04 repository as provided by user
        local repo_version="xUbuntu_24.04"
        if [[ "$ubuntu_version" != "24.04" ]]; then
            log "${YELLOW}Warning: Using Ubuntu 24.04 Zeek repository for Ubuntu $ubuntu_version${NC}"
            log "If installation fails, you may need to compile Zeek from source"
        fi
        
        log "Adding Zeek repository for $repo_version..."
        
        # Add repository as specified by user
        echo "deb http://download.opensuse.org/repositories/security:/zeek/$repo_version/ /" > /etc/apt/sources.list.d/security:zeek.list
        
        # Add repository key
        if curl -fsSL "https://download.opensuse.org/repositories/security:zeek/$repo_version/Release.key" | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg; then
            log "Repository key added successfully"
        else
            log "${RED}Failed to add Zeek repository key${NC}"
            return 1
        fi
        
        # Update package lists
        if apt-get update; then
            log "Package lists updated"
        else
            log "${RED}Failed to update package lists after adding Zeek repository${NC}"
            return 1
        fi
        
        # Try different Zeek versions as suggested by user
        local zeek_packages=("zeek" "zeek-6.0" "zeek-7.0" "zeek-nightly")
        local installed=false
        
        for zeek_pkg in "${zeek_packages[@]}"; do
            log "Attempting to install $zeek_pkg..."
            if install_package_with_retry "$zeek_pkg" "apt"; then
                log "${GREEN}Successfully installed $zeek_pkg${NC}"
                installed=true
                break
            else
                log "${YELLOW}Failed to install $zeek_pkg, trying next version...${NC}"
            fi
        done
        
        if [[ "$installed" != "true" ]]; then
            log "${RED}Failed to install any Zeek package${NC}"
            return 1
        fi
        
        # Add Zeek to PATH as specified by user
        local zeek_path_export='export PATH=$PATH:/opt/zeek/bin'
        
        # Add to system-wide profile
        if ! grep -q "/opt/zeek/bin" /etc/environment; then
            echo "PATH=\"\$PATH:/opt/zeek/bin\"" >> /etc/environment
            log "Added Zeek to system PATH in /etc/environment"
        fi
        
        # Add to user's bashrc if SUDO_USER is set
        if [[ -n "$SUDO_USER" ]]; then
            local user_bashrc="/home/$SUDO_USER/.bashrc"
            if [[ -f "$user_bashrc" ]] && ! grep -q "/opt/zeek/bin" "$user_bashrc"; then
                echo "$zeek_path_export" >> "$user_bashrc"
                log "Added Zeek to user PATH in $user_bashrc"
            fi
        fi
        
        # Source the PATH change for current session
        export PATH="$PATH:/opt/zeek/bin"
        
        # Create Zeek configuration directory
        mkdir -p "$PROJECT_ROOT/config/zeek"
        
        # Create basic Zeek configuration for malware analysis
        cat > "$PROJECT_ROOT/config/zeek/analysis.zeek" << 'ZEEK_CONFIG'
# Zeek configuration for Shikra malware analysis
# Load common analysis scripts

@load base/frameworks/notice
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp

# Enable additional logging for malware analysis
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps
@load policy/protocols/ssl/known-certs

# Custom logging directory
redef Log::default_logdir = "PROJECT_ROOT/data/zeek_logs";

# Event handlers for malware analysis
event zeek_init() {
    print "Zeek started for Shikra malware analysis";
}

event connection_established(c: connection) {
    print fmt("Connection established: %s:%s -> %s:%s", 
              c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
}
ZEEK_CONFIG
        
        # Replace placeholder with actual project root
        sed -i "s|PROJECT_ROOT|$PROJECT_ROOT|g" "$PROJECT_ROOT/config/zeek/analysis.zeek"
        
        # Verify installation
        if command -v zeek &>/dev/null; then
            log "${GREEN}Zeek installation completed successfully!${NC}"
            zeek --version
            log "Zeek configuration created at: $PROJECT_ROOT/config/zeek/"
            log "${BLUE}Zeek Features:${NC}"
            log "• Event correlation support with Zeek scripting language"
            log "• Use 'zeek-cut' to extract specific columns from logs"
            log "• Comprehensive protocol analysis (HTTP, DNS, SSL, SSH, etc.)"
            return 0
        else
            log "${RED}Zeek installation verification failed${NC}"
            return 1
        fi
        
    else
        log "${YELLOW}Zeek installation not supported on this distribution${NC}"
        log "Please install Zeek manually from https://zeek.org/"
        return 1
    fi
}

install_inetsim() {
    # Check if we should install INetSim
    if [[ "$SKIP_INETSIM" == "true" ]]; then
        log "${YELLOW}Skipping INetSim installation as requested.${NC}"
        return 0
    fi
    
    if [[ "$INSTALL_CATEGORY" != "all" && "$INSTALL_CATEGORY" != "network" && "$ENABLE_INETSIM" != "true" ]]; then
        log "${YELLOW}Skipping INetSim installation (not in network category and not explicitly enabled).${NC}"
        return 0
    fi
    
    log "${BLUE}Installing INetSim service simulator...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install INetSim"
        return 0
    fi
    
    # Check if INetSim is already installed
    if command -v inetsim &>/dev/null; then
        log "${GREEN}INetSim already installed.${NC}"
        inetsim --version 2>/dev/null || echo "INetSim is available"
        return 0
    fi
    
    if [[ -f /etc/debian_version ]]; then
        # Update system first
        log "Updating system packages..."
        apt-get update
        
        # Install required dependencies as specified by user
        log "Installing INetSim dependencies..."
        local inetsim_deps=(
            "libnet-server-perl"
            "libnet-dns-perl"
            "libipc-shareable-perl"
            "libdigest-sha-perl"
            "openssl"
            "libio-socket-ssl-perl"
            "iptables"
        )
        
        for dep in "${inetsim_deps[@]}"; do
            if ! install_package_with_retry "$dep" "apt"; then
                log "${RED}Failed to install critical dependency: $dep${NC}"
                return 1
            fi
        done
        
        # Download and install INetSim as specified by user
        cd "$TOOLS_DIR" || return 1
        
        local inetsim_deb="inetsim_1.3.2-1_all.deb"
        local inetsim_url="https://www.inetsim.org/packages/debian/$inetsim_deb"
        
        log "Downloading INetSim Debian package..."
        if [[ ! -f "$inetsim_deb" ]] || [[ "$FORCE_REINSTALL" == "true" ]]; then
            if wget "$inetsim_url"; then
                log "Downloaded $inetsim_deb successfully"
            else
                log "${RED}Failed to download INetSim package from $inetsim_url${NC}"
                return 1
            fi
        else
            log "Using existing $inetsim_deb"
        fi
        
        # Install INetSim
        log "Installing INetSim..."
        if dpkg -i "$inetsim_deb"; then
            log "${GREEN}INetSim installed successfully${NC}"
        else
            log "${YELLOW}dpkg reported issues, attempting to fix dependencies...${NC}"
            if apt-get -f install -y; then
                log "${GREEN}Dependencies fixed, INetSim should now be installed${NC}"
            else
                log "${RED}Failed to fix INetSim dependencies${NC}"
                return 1
            fi
        fi
        
        # Verify installation
        if command -v inetsim &>/dev/null; then
            log "${GREEN}INetSim installation completed successfully!${NC}"
            
            # Show installation notes as provided by user
            log "${BLUE}Important Installation Notes:${NC}"
            log "• Please edit /etc/inetsim/inetsim.conf to suit your needs"
            log "• Sample Windows executables for HTTP fakefile mode changed with version 1.3.0"
            log "• See /usr/share/inetsim/contrib/sample.README for additional information"
            
            # Create basic configuration directory in project
            mkdir -p "$PROJECT_ROOT/config/inetsim"
            
            # Copy default config as a template if it exists
            if [[ -f "/etc/inetsim/inetsim.conf" ]]; then
                cp "/etc/inetsim/inetsim.conf" "$PROJECT_ROOT/config/inetsim/inetsim.conf.template"
                log "Copied default configuration to: $PROJECT_ROOT/config/inetsim/inetsim.conf.template"
            fi
            
            return 0
        else
            log "${RED}INetSim installation verification failed${NC}"
            return 1
        fi
        
    else
        log "${YELLOW}INetSim installation not supported on this distribution${NC}"
        log "Please install INetSim manually from https://www.inetsim.org/"
        return 1
    fi
}

install_analysis_tools() {
    log "${BLUE}Installing analysis tools (Python packages into venv)...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install analysis tools"
        return 0
    fi
    
    activate_venv

    # Upgrade pip first to avoid installation issues
    log "Upgrading pip in virtual environment..."
    "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip setuptools wheel || log "${YELLOW}Failed to upgrade pip/setuptools/wheel${NC}"

    # Install Volatility 3 for memory analysis
    log "Installing Volatility 3..."
    if "$PROJECT_ROOT/venv/bin/pip" install volatility3; then
        log "${GREEN}Volatility 3 installed successfully${NC}"
    else
        log "${YELLOW}Volatility 3 installation failed, trying git installation...${NC}"
        if "$PROJECT_ROOT/venv/bin/pip" install git+https://github.com/volatilityfoundation/volatility3.git; then
            log "${GREEN}Volatility 3 installed from git${NC}"
        else
            log "${RED}Volatility 3 installation failed completely${NC}"
        fi
    fi

    # Install Python analysis libraries
    local python_analysis_packages=(
        "pefile"             # PE file analysis
        "yara-python"        # YARA Python bindings
        "ssdeep"             # Fuzzy hashing
        "python-magic"       # File type identification
        "requests"           # HTTP library
        "beautifulsoup4"     # HTML/XML parsing
        "lxml"               # XML processing
        "Pillow"             # Image processing
        "matplotlib"         # Plotting and visualization
        "networkx"           # Network analysis
        "pandas"             # Data analysis
        "numpy"              # Numerical computing
        "cryptography"       # Cryptographic functions
        "pyopenssl"          # OpenSSL bindings
        "scapy"              # Packet manipulation
        "dpkt"               # Packet parsing
    )
    
    log "Installing Python analysis packages..."
    for package in "${python_analysis_packages[@]}"; do
        log "Installing $package..."
        if "$PROJECT_ROOT/venv/bin/pip" install "$package"; then
            log "✅ Installed: $package"
        else
            log "${YELLOW}⚠️ Failed to install: $package${NC}"
            if "$PROJECT_ROOT/venv/bin/pip" install --no-cache-dir "$package"; then
                log "✅ Installed $package (with --no-cache-dir)"
            else
                log "${RED}❌ $package failed completely${NC}"
            fi
        fi
    done

    # Install Binwalk
    log "Installing Binwalk..."
    if command -v binwalk &>/dev/null; then
        log "Binwalk already installed."
    else
        if [[ -f /etc/debian_version ]]; then
            if ! install_package_with_retry "binwalk" "apt"; then
                log "${YELLOW}Binwalk system package failed, trying pip install...${NC}"
                "$PROJECT_ROOT/venv/bin/pip" install binwalk || log "${YELLOW}Binwalk pip install also failed${NC}"
            fi
        fi
    fi
    
    log "${GREEN}Analysis tools installation completed${NC}"
    return 0
}

install_monitoring_tools() {
    log "${BLUE}Installing monitoring tools...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install monitoring tools"
        return 0
    fi
    
    mkdir -p "$TOOLS_DIR/procmon"
    cd "$TOOLS_DIR" || return 1
    
    # Download ProcMon tools
    log "Downloading ProcMon utilities..."
    local procmon_tools=(
        "https://live.sysinternals.com/procmon.exe"
        "https://live.sysinternals.com/procmon64.exe"
        "https://live.sysinternals.com/autoruns.exe"
        "https://live.sysinternals.com/autoruns64.exe"
        "https://live.sysinternals.com/psexec.exe"
        "https://live.sysinternals.com/psexec64.exe"
    )
    
    for tool_url in "${procmon_tools[@]}"; do
        local tool_name=$(basename "$tool_url")
        local tool_path="procmon/$tool_name"
        
        if [[ ! -f "$tool_path" ]] || [[ "$FORCE_REINSTALL" == "true" ]]; then
            if wget -q "$tool_url" -O "$tool_path"; then
                log "Downloaded: $tool_name"
            else
                log "${YELLOW}Failed to download: $tool_name${NC}"
            fi
        else
            log "Already have: $tool_name"
        fi
    done
    
    # Set proper ownership
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$TOOLS_DIR"
    fi
    
    log "${GREEN}Monitoring tools setup completed${NC}"
    return 0
}

install_network_tools() {
    log "${BLUE}Installing network analysis tools...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would install network tools"
        return 0
    fi
    
    # Install Zeek and INetSim
    install_zeek
    install_inetsim
    
    # Install additional network analysis tools
    activate_venv
    
    local network_python_packages=(
        "scapy"              # Packet manipulation
        "dpkt"               # Packet parsing
        "pyshark"            # Wireshark Python wrapper
        "impacket"           # Network protocols
        "netaddr"            # Network address manipulation
    )
    
    log "Installing network analysis Python packages..."
    for package in "${network_python_packages[@]}"; do
        log "Installing $package..."
        "$PROJECT_ROOT/venv/bin/pip" install "$package" || log "${YELLOW}Failed to install $package${NC}"
    done
    
    log "${GREEN}Network tools installation completed${NC}"
    return 0
}

verify_installation() {
    log "${BLUE}Verifying installation...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would verify installation"
        return 0
    fi
    
    activate_venv

    local verification_failed=false
    
    # Test critical system tools
    log "Testing system tools..."
    
    if command -v python3 &>/dev/null; then log "✅ Python 3: OK"; else log "❌ Python 3: FAILED"; verification_failed=true; fi
    if command -v pip3 &>/dev/null || [[ -f "$PROJECT_ROOT/venv/bin/pip" ]]; then log "✅ pip: OK"; else log "❌ pip: FAILED"; verification_failed=true; fi
    
    # Test virtualization tools
    if [[ "$SKIP_VIRTUALIZATION" != "true" ]]; then
        if command -v qemu-system-x86_64 &>/dev/null; then log "✅ QEMU: OK"; else log "⚠️ QEMU: FAILED"; fi
        if systemctl is-active --quiet libvirtd 2>/dev/null; then log "✅ libvirtd: Running"; else log "⚠️ libvirtd: Not running"; fi
    fi
    
    # Test network tools
    if command -v tcpdump &>/dev/null; then log "✅ tcpdump: OK"; else log "⚠️ tcpdump: FAILED"; fi
    if command -v tshark &>/dev/null; then log "✅ tshark: OK"; else log "⚠️ tshark: FAILED"; fi
    
    # Test Zeek
    if [[ "$SKIP_ZEEK" != "true" ]] && [[ "$ENABLE_ZEEK" == "true" || "$INSTALL_CATEGORY" == "all" || "$INSTALL_CATEGORY" == "network" ]]; then
        if command -v zeek &>/dev/null; then 
            log "✅ Zeek: OK ($(zeek --version 2>&1 | head -1))"
            if command -v zeek-cut &>/dev/null; then log "✅ zeek-cut: OK"; else log "⚠️ zeek-cut: FAILED"; fi
        else 
            log "⚠️ Zeek: FAILED"
        fi
    fi
    
    # Test INetSim
    if [[ "$SKIP_INETSIM" != "true" ]] && [[ "$ENABLE_INETSIM" == "true" || "$INSTALL_CATEGORY" == "all" || "$INSTALL_CATEGORY" == "network" ]]; then
        if command -v inetsim &>/dev/null; then 
            log "✅ INetSim: OK"
        else 
            log "⚠️ INetSim: FAILED"
        fi
    fi
    
    # Test Python packages
    log "Testing Python packages..."
    "$PROJECT_ROOT/venv/bin/python" -c "
import sys
errors = []
warnings = []

# Critical packages
try:
    import pefile
    print('✅ pefile: OK')
except ImportError as e: 
    errors.append(f'❌ pefile: FAILED ({e})')

try:
    import requests
    print('✅ requests: OK')
except ImportError as e: 
    errors.append(f'❌ requests: FAILED ({e})')

# Analysis packages
try:
    import volatility3
    print('✅ Volatility 3: OK')
except ImportError as e: 
    warnings.append(f'⚠️ Volatility 3: FAILED ({e})')

try:
    import yara
    print('✅ YARA (python): OK')  
except ImportError as e: 
    warnings.append(f'⚠️ YARA (python): FAILED ({e})')

try:
    import scapy
    print('✅ Scapy: OK')
except ImportError as e: 
    warnings.append(f'⚠️ Scapy: FAILED ({e})')

if warnings:
    print('\\nWarnings (non-critical):')
    for w in warnings: print(w)

if errors: 
    print('\\nCritical Errors:')
    for e in errors: print(e)
    sys.exit(1)
else:
    print('\\n✅ All critical Python packages verified!')
" || verification_failed=true
    
    # Summary
    if [[ "$verification_failed" == "false" ]]; then
        log "${GREEN}Verification completed successfully!${NC}"
        return 0
    else
        log "${RED}Some verification checks failed. Please review the output above.${NC}"
        return 1
    fi
}

main_install_deps() {
    log "${GREEN}Starting Shikra dependency installation...${NC}"
    log "Installation category: $INSTALL_CATEGORY"
    log "Installation log: $LOG_FILE"
    
    # Install based on category selection
    local success=true
    case "$INSTALL_CATEGORY" in
        "all")
            install_system_packages || success=false
            install_virtualization || success=false
            install_analysis_tools || success=false
            install_monitoring_tools || success=false
            install_network_tools || success=false
            ;;
        "system") 
            install_system_packages || success=false 
            ;;
        "virtualization") 
            install_virtualization || success=false 
            ;;
        "analysis") 
            install_analysis_tools || success=false 
            ;;
        "monitoring") 
            install_monitoring_tools || success=false 
            ;;
        "network") 
            install_network_tools || success=false 
            ;;
        *)
            log "${RED}Error: Unknown category '$INSTALL_CATEGORY'${NC}"
            exit 1
            ;;
    esac
    
    # Verify installation
    verify_installation || success=false
    
    log "${GREEN}========================================${NC}"
    if $success; then
        log "${GREEN}Dependency installation completed successfully!${NC}"
    else
        log "${YELLOW}Dependency installation completed with some issues.${NC}"
    fi
    log "${GREEN}========================================${NC}"
    
    return $($success && echo 0 || echo 1)
}

# Parse command line arguments and execute
parse_arguments "$@"
main_install_deps