#!/bin/bash
# Shikra Environment Setup - Master Orchestrator
#
# Purpose:
# This is the main setup script that coordinates all aspects of the Shikra analysis environment.
# It provides an interactive interface and orchestrates the execution of specialized setup scripts.
#
# Usage:
#     sudo ./setup_environment.sh [--interactive] [--preset <preset>]
#
# Presets:
#     minimal     - Core system + Python + basic VM setup
#     standard    - Minimal + network tools + analysis tools
#     full        - Everything including Zeek, INetSim, monitoring tools
#     developer   - Full + development tools and debug options

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_ROOT/logs/setup_master.log"
SETUP_STATE_FILE="$PROJECT_ROOT/.setup_state"

# Color codes
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; CYAN='\033[0;36m'; NC='\033[0m'

# --- Default Configuration ---
INTERACTIVE_MODE=true
PRESET=""
INSTALL_TYPE="standard"
SKIP_VIRTUALIZATION=false
SKIP_NETWORK=false
ENABLE_ZEEK=false
ENABLE_INETSIM=false
ENABLE_FAKE_SERVICES=false
ENABLE_PACKET_CAPTURE=false
ENABLE_TRIGGERED_CAPTURE=true
NETWORK_NAME="shikra-isolated"
DRY_RUN=false
FORCE_REINSTALL=false

# --- Logging Functions ---
setup_logging() {
    mkdir -p "$(dirname "$LOG_FILE")"
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$(dirname "$LOG_FILE")"
    fi
}

log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

# --- State Management ---
save_state() {
    local component="$1"
    local status="$2"
    local details="$3"
    
    mkdir -p "$(dirname "$SETUP_STATE_FILE")"
    sed -i "/^${component}=/d" "$SETUP_STATE_FILE" 2>/dev/null || true
    echo "${component}=${status}:${details}" >> "$SETUP_STATE_FILE"
}

check_state() {
    local component="$1"
    
    if [[ -f "$SETUP_STATE_FILE" ]]; then
        grep -q "^${component}=completed" "$SETUP_STATE_FILE"
        return $?
    fi
    return 1
}

# --- Argument Parsing ---
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --interactive) INTERACTIVE_MODE=true; shift ;;
            --non-interactive) INTERACTIVE_MODE=false; shift ;;
            --preset) PRESET="$2"; INTERACTIVE_MODE=false; shift 2 ;;
            --dry-run) DRY_RUN=true; shift ;;
            --force) FORCE_REINSTALL=true; shift ;;
            --help|-h) show_usage; exit 0 ;;
            *)
                log "${RED}Unknown parameter: $1${NC}"
                show_usage; exit 1 ;;
        esac
    done
}

show_usage() {
    echo "Shikra Environment Setup - Master Orchestrator"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  --interactive         Interactive setup (default)"
    echo "  --non-interactive     Non-interactive setup"
    echo "  --preset <preset>     Use predefined configuration"
    echo "  --dry-run            Show what would be done"
    echo "  --force              Force reinstallation"
    echo "  --help               Show this help"
    echo ""
    echo "Presets:"
    echo "  minimal     Core system + Python + basic VM setup"
    echo "  standard    Minimal + network tools + analysis tools (recommended)"
    echo "  full        Everything including Zeek, INetSim, monitoring"
    echo "  developer   Full + development tools"
    echo ""
    echo "Examples:"
    echo "  sudo $0                          # Interactive setup"
    echo "  sudo $0 --preset standard        # Standard preset"
    echo "  sudo $0 --preset full --dry-run  # Preview full installation"
}

# --- Interactive Configuration ---
show_welcome() {
    clear
    echo -e "${CYAN}"
    echo "=================================================================="
    echo "              Shikra Malware Analysis Framework"
    echo "                     Environment Setup"
    echo "=================================================================="
    echo -e "${NC}"
    echo ""
    echo "This script will guide you through setting up a complete"
    echo "malware analysis environment with:"
    echo ""
    echo "• Isolated virtual machines for safe analysis"
    echo "• Network monitoring and traffic capture"
    echo "• Behavioral analysis tools"
    echo "• Memory forensics capabilities"
    echo "• Network service simulation"
    echo ""
    echo "Press Enter to continue..."
    read -r
}

interactive_preset_selection() {
    echo -e "${BLUE}Choose Installation Type:${NC}"
    echo ""
    echo "1) Minimal     - Core system + Python + basic VM (fastest)"
    echo "2) Standard    - Minimal + network tools + analysis tools (recommended)"
    echo "3) Full        - Everything including Zeek + INetSim + monitoring"
    echo "4) Developer   - Full installation + development tools"
    echo "5) Custom      - Choose individual components"
    echo ""
    
    while true; do
        read -p "Enter your choice (1-5): " choice
        case $choice in
            1) INSTALL_TYPE="minimal"; apply_preset_minimal; break ;;
            2) INSTALL_TYPE="standard"; apply_preset_standard; break ;;
            3) INSTALL_TYPE="full"; apply_preset_full; break ;;
            4) INSTALL_TYPE="developer"; apply_preset_developer; break ;;
            5) INSTALL_TYPE="custom"; interactive_custom_config; break ;;
            *) echo "Please enter 1, 2, 3, 4, or 5" ;;
        esac
    done
}

apply_preset_minimal() {
    SKIP_VIRTUALIZATION=false
    SKIP_NETWORK=true
    ENABLE_ZEEK=false
    ENABLE_INETSIM=false
    ENABLE_FAKE_SERVICES=false
    ENABLE_PACKET_CAPTURE=false
    ENABLE_TRIGGERED_CAPTURE=false
}

apply_preset_standard() {
    SKIP_VIRTUALIZATION=false
    SKIP_NETWORK=false
    ENABLE_ZEEK=false
    ENABLE_INETSIM=false
    ENABLE_FAKE_SERVICES=true
    ENABLE_PACKET_CAPTURE=false
    ENABLE_TRIGGERED_CAPTURE=true
}

apply_preset_full() {
    SKIP_VIRTUALIZATION=false
    SKIP_NETWORK=false
    ENABLE_ZEEK=true
    ENABLE_INETSIM=true
    ENABLE_FAKE_SERVICES=true
    ENABLE_PACKET_CAPTURE=false
    ENABLE_TRIGGERED_CAPTURE=true
}

apply_preset_developer() {
    apply_preset_full
    # Developer preset adds debugging and development tools
}

interactive_custom_config() {
    echo -e "${BLUE}Custom Configuration:${NC}"
    echo ""
    
    # Virtualization
    read -p "Setup virtualization (QEMU/KVM)? [Y/n]: " answer
    [[ "$answer" =~ ^[Nn]$ ]] && SKIP_VIRTUALIZATION=true
    
    # Network setup
    if [[ "$SKIP_VIRTUALIZATION" != "true" ]]; then
        read -p "Setup isolated analysis network? [Y/n]: " answer
        [[ "$answer" =~ ^[Nn]$ ]] && SKIP_NETWORK=true
        
        if [[ "$SKIP_NETWORK" != "true" ]]; then
            # Network tools
            read -p "Install Zeek network monitor? [y/N]: " answer
            [[ "$answer" =~ ^[Yy]$ ]] && ENABLE_ZEEK=true
            
            read -p "Install INetSim service simulator? [y/N]: " answer
            [[ "$answer" =~ ^[Yy]$ ]] && ENABLE_INETSIM=true
            
            read -p "Enable basic fake services? [Y/n]: " answer
            [[ ! "$answer" =~ ^[Nn]$ ]] && ENABLE_FAKE_SERVICES=true
            
            read -p "Enable packet capture? [y/N]: " answer
            [[ "$answer" =~ ^[Yy]$ ]] && ENABLE_PACKET_CAPTURE=true
            
            read -p "Setup triggered capture (recommended)? [Y/n]: " answer
            [[ ! "$answer" =~ ^[Nn]$ ]] && ENABLE_TRIGGERED_CAPTURE=true
            
            # Network name
            read -p "Network name [$NETWORK_NAME]: " answer
            [[ -n "$answer" ]] && NETWORK_NAME="$answer"
        fi
    fi
}

show_configuration_summary() {
    echo -e "${YELLOW}"
    echo "=================================================================="
    echo "                    Configuration Summary"
    echo "=================================================================="
    echo -e "${NC}"
    echo "Installation Type: $INSTALL_TYPE"
    echo ""
    echo "Components:"
    echo "  ✓ Core system packages and Python environment"
    [[ "$SKIP_VIRTUALIZATION" != "true" ]] && echo "  ✓ Virtualization (QEMU/KVM + libvirt)"
    [[ "$SKIP_NETWORK" != "true" ]] && echo "  ✓ Isolated network setup"
    [[ "$ENABLE_ZEEK" == "true" ]] && echo "  ✓ Zeek network monitor"
    [[ "$ENABLE_INETSIM" == "true" ]] && echo "  ✓ INetSim service simulator"
    [[ "$ENABLE_FAKE_SERVICES" == "true" ]] && echo "  ✓ Basic fake network services"
    [[ "$ENABLE_PACKET_CAPTURE" == "true" ]] && echo "  ✓ Continuous packet capture"
    [[ "$ENABLE_TRIGGERED_CAPTURE" == "true" ]] && echo "  ✓ Triggered packet capture"
    echo ""
    [[ "$SKIP_NETWORK" != "true" ]] && echo "Network Name: $NETWORK_NAME"
    echo "Installation will be logged to: $LOG_FILE"
    echo ""
    
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}DRY RUN MODE - No changes will be made${NC}"
    else
        read -p "Proceed with installation? [Y/n]: " answer
        if [[ "$answer" =~ ^[Nn]$ ]]; then
            echo "Installation cancelled."
            exit 0
        fi
    fi
}

# --- Prerequisites Check ---
check_prerequisites() {
    log "${BLUE}Checking prerequisites...${NC}"
    
    # Check for root privileges
    if [[ $EUID -ne 0 ]]; then
        log "${RED}Error: This script must be run as root (use sudo).${NC}"
        exit 1
    fi
    
    # Check OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        log "Operating System: $PRETTY_NAME"
        if [[ "$ID" != "ubuntu" && "$ID" != "debian" ]]; then
            log "${YELLOW}Warning: Untested OS ($ID). Ubuntu/Debian recommended.${NC}"
        fi
    else
        log "${RED}Error: Cannot determine operating system.${NC}"
        exit 1
    fi
    
    # Check required scripts exist
    local required_scripts=("$SCRIPT_DIR/install_dependencies.sh" "$SCRIPT_DIR/network_setup.sh")
    for script in "${required_scripts[@]}"; do
        if [[ ! -f "$script" ]]; then
            log "${RED}Error: Required script not found: $script${NC}"
            exit 1
        fi
        if [[ ! -x "$script" ]]; then
            chmod +x "$script"
            log "Made executable: $script"
        fi
    done
    
    # System resources check
    local total_mem_gb=$(( $(grep MemTotal /proc/meminfo | awk '{print $2}') / 1024 / 1024 ))
    if (( total_mem_gb < 8 )); then
        log "${YELLOW}Warning: Only ${total_mem_gb}GB RAM detected. 8GB minimum, 16GB recommended.${NC}"
    else
        log "${GREEN}RAM check passed: ${total_mem_gb}GB available.${NC}"
    fi
    
    local available_space_gb=$(df -BG "$PROJECT_ROOT" | awk 'NR==2 {print int($4)}')
    if (( available_space_gb < 50 )); then
        log "${RED}Error: Insufficient disk space. Need 50GB, only ${available_space_gb}GB available.${NC}"
        exit 1
    else
        log "${GREEN}Disk space check passed: ${available_space_gb}GB available.${NC}"
    fi
    
    log "${GREEN}Prerequisites check completed.${NC}"
}

# --- Core Setup Functions ---
create_project_structure() {
    if check_state "project_structure" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Project structure already exists, skipping.${NC}"
        return 0
    fi
    
    log "${BLUE}Creating project directory structure...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create project directories"
        return 0
    fi
    
    local directories=(
        "data/samples/quarantine"
        "data/vm_images"
        "data/memory_dumps"
        "data/pcap"
        "data/results/behavioral"
        "data/results/network"
        "data/results/memory"
        "data/results/reports"
        "data/yara_rules"
        "data/zeek_logs"
        "data/inetsim"
        "logs/analysis"
        "logs/zeek"
        "logs/inetsim"
        "tools/procmon"
        "config/vm_profiles"
        "config/inetsim"
        "config/zeek"
        "config/procmon"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$PROJECT_ROOT/$dir"
    done
    
    # Set proper ownership
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_ROOT"
    fi
    
    log "${GREEN}Project structure created.${NC}"
    save_state "project_structure" "completed" "$(date)"
}

setup_python_environment() {
    if check_state "python_environment" && [[ "$FORCE_REINSTALL" != "true" ]]; then
        log "${GREEN}Python environment already exists, skipping.${NC}"
        return 0
    fi
    
    log "${BLUE}Setting up Python virtual environment...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would create Python virtual environment"
        return 0
    fi
    
    cd "$PROJECT_ROOT" || exit 1
    
    # Remove existing venv if force reinstall
    if [[ "$FORCE_REINSTALL" == "true" && -d "venv" ]]; then
        log "Removing existing virtual environment..."
        rm -rf venv
    fi
    
    # Create virtual environment
    python3 -m venv venv
    
    # Upgrade pip
    "$PROJECT_ROOT/venv/bin/pip" install --upgrade pip wheel
    
    if [[ $? -ne 0 ]]; then
        log "${RED}Error: Failed to setup Python virtual environment.${NC}"
        return 1
    fi
    
    # Set proper ownership
    if [[ -n "$SUDO_USER" ]]; then
        chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_ROOT/venv/"
    fi
    
    log "${GREEN}Python virtual environment created successfully.${NC}"
    save_state "python_environment" "completed" "$(date)"
}

# --- Script Orchestration Functions ---
run_dependency_installation() {
    log "${BLUE}Running dependency installation...${NC}"
    
    # Build arguments for install_dependencies.sh
    local dep_args=()
    
    # Determine category based on installation type
    case "$INSTALL_TYPE" in
        "minimal")
            dep_args+=(--category system)
            ;;
        "standard")
            dep_args+=(--category all)
            if [[ "$ENABLE_ZEEK" != "true" ]]; then
                dep_args+=(--skip-zeek)
            fi
            if [[ "$ENABLE_INETSIM" != "true" ]]; then
                dep_args+=(--skip-inetsim)
            fi
            ;;
        "full"|"developer")
            dep_args+=(--category all)
            [[ "$ENABLE_ZEEK" == "true" ]] && dep_args+=(--enable-zeek)
            [[ "$ENABLE_INETSIM" == "true" ]] && dep_args+=(--enable-inetsim)
            ;;
    esac
    
    [[ "$SKIP_VIRTUALIZATION" == "true" ]] && dep_args+=(--skip-virtualization)
    [[ "$DRY_RUN" == "true" ]] && dep_args+=(--dry-run)
    [[ "$FORCE_REINSTALL" == "true" ]] && dep_args+=(--force)
    
    log "Executing: $SCRIPT_DIR/install_dependencies.sh ${dep_args[*]}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would execute dependency installation"
        return 0
    fi
    
    # Execute the dependency installation script
    "$SCRIPT_DIR/install_dependencies.sh" "${dep_args[@]}"
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log "${GREEN}Dependency installation completed successfully.${NC}"
        save_state "dependencies" "completed" "$(date)"
        return 0
    else
        log "${RED}Dependency installation failed with exit code: $exit_code${NC}"
        return 1
    fi
}

run_network_setup() {
    if [[ "$SKIP_NETWORK" == "true" ]]; then
        log "${YELLOW}Skipping network setup as requested.${NC}"
        return 0
    fi
    
    log "${BLUE}Running network setup...${NC}"
    
    # Build arguments for network_setup.sh
    local net_args=(--create-isolated --name "$NETWORK_NAME")
    
    [[ "$ENABLE_INETSIM" == "true" ]] && net_args+=(--enable-inetsim)
    [[ "$ENABLE_FAKE_SERVICES" == "true" ]] && net_args+=(--enable-fake-services)
    [[ "$ENABLE_PACKET_CAPTURE" == "true" ]] && net_args+=(--enable-capture)
    [[ "$ENABLE_TRIGGERED_CAPTURE" == "true" ]] && net_args+=(--enable-triggered)
    [[ "$DRY_RUN" == "true" ]] && net_args+=(--dry-run)
    
    log "Executing: $SCRIPT_DIR/network_setup.sh ${net_args[*]}"
    
    if [[ "$DRY_RUN" == "true" ]]; then
        log "Dry run: would execute network setup"
        return 0
    fi
    
    # Execute the network setup script
    "$SCRIPT_DIR/network_setup.sh" "${net_args[@]}"
    local exit_code=$?
    
    if [[ $exit_code -eq 0 ]]; then
        log "${GREEN}Network setup completed successfully.${NC}"
        save_state "network" "completed" "$(date)"
        return 0
    else
        log "${RED}Network setup failed with exit code: $exit_code${NC}"
        return 1
    fi
}

# --- Main Execution ---
main() {
    setup_logging
    
    log "${GREEN}======================================${NC}"
    log "${GREEN}  Shikra Environment Setup - Master   ${NC}"
    log "${GREEN}======================================${NC}"
    log "Project Root: $PROJECT_ROOT"
    log "Log File: $LOG_FILE"
    
    parse_arguments "$@"
    
    # Apply preset if specified
    if [[ -n "$PRESET" ]]; then
        case "$PRESET" in
            "minimal") apply_preset_minimal ;;
            "standard") apply_preset_standard ;;
            "full") apply_preset_full ;;
            "developer") apply_preset_developer ;;
            *)
                log "${RED}Unknown preset: $PRESET${NC}"
                exit 1 ;;
        esac
    fi
    
    # Interactive configuration if enabled
    if [[ "$INTERACTIVE_MODE" == "true" ]]; then
        show_welcome
        interactive_preset_selection
    fi
    
    # Show configuration summary
    show_configuration_summary
    
    # Execute setup steps
    log "${BLUE}Starting environment setup...${NC}"
    
    check_prerequisites
    create_project_structure
    setup_python_environment
    run_dependency_installation
    run_network_setup
    
    # Final status
    log "${GREEN}========================================${NC}"
    log "${GREEN}  Shikra Environment Setup Completed!   ${NC}"
    log "${GREEN}========================================${NC}"
    
    echo -e "\n${CYAN}🎉 Shikra Malware Analysis Framework is ready!${NC}\n"
    
    echo -e "${BLUE}Installation Summary:${NC}"
    echo -e "✅ Core system and Python environment"
    [[ "$SKIP_VIRTUALIZATION" != "true" ]] && echo -e "✅ Virtualization (QEMU/KVM + libvirt)"
    [[ "$SKIP_NETWORK" != "true" ]] && echo -e "✅ Isolated analysis network: $NETWORK_NAME"
    [[ "$ENABLE_ZEEK" == "true" ]] && echo -e "✅ Zeek network monitor"
    [[ "$ENABLE_INETSIM" == "true" ]] && echo -e "✅ INetSim service simulator"
    [[ "$ENABLE_FAKE_SERVICES" == "true" ]] && echo -e "✅ Basic fake network services"
    [[ "$ENABLE_TRIGGERED_CAPTURE" == "true" ]] && echo -e "✅ Triggered packet capture"
    
    echo -e "\n${BLUE}Next Steps:${NC}"
    echo -e "1. ${YELLOW}IMPORTANT: Log out and log back in${NC} for group changes to take effect"
    echo -e "2. Activate Python environment: ${GREEN}source venv/bin/activate${NC}"
    echo -e "3. Create analysis VMs using virt-manager or virsh"
    echo -e "4. Start your malware analysis"
    
    if [[ "$SKIP_NETWORK" != "true" ]]; then
        echo -e "\n${BLUE}Network Commands:${NC}"
        echo -e "• Check network status: ${GREEN}sudo $SCRIPT_DIR/network_setup.sh --status${NC}"
        [[ "$ENABLE_TRIGGERED_CAPTURE" == "true" ]] && echo -e "• Trigger packet capture: ${GREEN}$PROJECT_ROOT/data/pcap/capture_trigger_${NETWORK_NAME}${NC}"
    fi
    
    echo -e "\nFor detailed logs, check: ${GREEN}$LOG_FILE${NC}\n"
}

# --- Script Entry Point ---
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    trap 'log "${RED}Setup interrupted. Check logs for details.${NC}"; exit 1' ERR
    main "$@"
fi