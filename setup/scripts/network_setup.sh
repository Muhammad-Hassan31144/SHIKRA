#!/bin/bash
# Shikra Network Setup Script
#
# Purpose:
# This script configures and manages isolated network environments for malware analysis.
# It handles the creation of virtual bridges, configuration of firewall rules for isolation
# and NAT, DNS sinkholing, and starting of network traffic capture.
#
# Version: 2.0 - Updated for orchestrator integration
# Last Updated: 2024-12-20

# --- Script Configuration ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LOG_FILE="$PROJECT_ROOT/logs/network_setup.log"
PCAP_DIR="$PROJECT_ROOT/data/pcap"

# --- Network Defaults ---
DEFAULT_NETWORK_NAME="shikra-isolated"
DEFAULT_SUBNET="192.168.100.0/24"
DEFAULT_GATEWAY="192.168.100.1"
DEFAULT_DNS_SERVER="192.168.100.1"
DEFAULT_DHCP_RANGE="192.168.100.10,192.168.100.100"

# --- Color Codes ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

# --- Global Variables ---
NETWORK_NAME="$DEFAULT_NETWORK_NAME"
SUBNET="$DEFAULT_SUBNET"
GATEWAY="$DEFAULT_GATEWAY"
DNS_SERVER="$DEFAULT_DNS_SERVER"
DHCP_RANGE="$DEFAULT_DHCP_RANGE"
CREATE_ISOLATED=false
CLEANUP_NETWORK=false
ENABLE_CAPTURE=false
ENABLE_TRIGGERED_CAPTURE=false
ENABLE_INETSIM=false
ENABLE_FAKE_SERVICES=false
ENABLE_ZEEK=false
DRY_RUN=false
BRIDGE_NAME=""

# --- Utility Functions ---

log() {
    mkdir -p "$(dirname "$LOG_FILE")"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

show_usage() {
    echo "Usage: $0 [action] [options]"
    echo ""
    echo "Actions:"
    echo "  --create-isolated        Create an isolated analysis network"
    echo "  --cleanup                Remove the network configuration and all related resources"
    echo "  --status                 Show the status of libvirt networks and related processes"
    echo ""
    echo "Options:"
    echo "  --name <name>            Network name (default: $DEFAULT_NETWORK_NAME)"
    echo "  --enable-capture         Enable continuous packet capture"
    echo "  --enable-triggered       Setup triggered capture interface (recommended)"
    echo "  --enable-inetsim         Enable InetSim service on the gateway"
    echo "  --enable-fake-services   Start basic fake HTTP, FTP, and SMTP services"
    echo "  --enable-zeek            Enable Zeek network monitoring"
    echo "  --dry-run                Show what would be done without making changes"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Service Options:"
    echo "  --enable-inetsim         Comprehensive malware network simulation"
    echo "  --enable-fake-services   Basic netcat-based fake services (lightweight)"
    echo "  --enable-zeek            Deep packet inspection and protocol analysis"
    echo ""
    echo "Capture Options:"
    echo "  --enable-capture         Continuous packet capture (high disk usage)"
    echo "  --enable-triggered       On-demand capture scripts (recommended)"
    echo ""
    echo "Examples:"
    echo "  $0 --create-isolated --enable-triggered --enable-fake-services"
    echo "  $0 --create-isolated --enable-inetsim --enable-zeek --enable-capture"
    echo "  $0 --cleanup --name shikra-isolated"
}

parse_arguments() {
    if [[ $# -eq 0 ]]; then 
        show_usage
        exit 1
    fi

    while [[ $# -gt 0 ]]; do
        case $1 in
            --create-isolated) CREATE_ISOLATED=true; shift ;;
            --cleanup) CLEANUP_NETWORK=true; shift ;;
            --status) show_network_status; exit 0 ;;
            --name) NETWORK_NAME="$2"; shift 2 ;;
            --enable-capture) ENABLE_CAPTURE=true; shift ;;
            --enable-triggered) ENABLE_TRIGGERED_CAPTURE=true; shift ;;
            --enable-inetsim) ENABLE_INETSIM=true; shift ;;
            --enable-fake-services) ENABLE_FAKE_SERVICES=true; shift ;;
            --enable-zeek) ENABLE_ZEEK=true; shift ;;
            --dry-run) DRY_RUN=true; shift ;;
            -h|--help) show_usage; exit 0 ;;
            *) log "${RED}Unknown parameter: $1${NC}"; show_usage; exit 1 ;;
        esac
    done

    if [[ "$CREATE_ISOLATED" != "true" && "$CLEANUP_NETWORK" != "true" ]]; then
        log "${RED}An action is required (--create-isolated or --cleanup).${NC}"
        show_usage
        exit 1
    fi

    # Sanitize network name to create a valid bridge name
    BRIDGE_NAME="br-$(echo "$NETWORK_NAME" | tr '[:upper:]' '[:lower:]' | tr -d ' ' | cut -c 1-12)"
    
    log "Network Configuration:"
    log "  Network Name: $NETWORK_NAME"
    log "  Bridge Name: $BRIDGE_NAME"
    log "  Subnet: $SUBNET"
    log "  Gateway: $GATEWAY"
    log "  Enable Capture: $ENABLE_CAPTURE"
    log "  Enable Triggered: $ENABLE_TRIGGERED_CAPTURE"
    log "  Enable INetSim: $ENABLE_INETSIM"
    log "  Enable Fake Services: $ENABLE_FAKE_SERVICES"
    log "  Enable Zeek: $ENABLE_ZEEK"
    log "  Dry Run: $DRY_RUN"
}

check_prerequisites() {
    log "${BLUE}Checking network setup prerequisites...${NC}"
    
    if [[ $EUID -ne 0 ]]; then 
        log "${RED}Error: This script must be run as root.${NC}"
        exit 1
    fi

    local required_commands=("ip" "iptables" "virsh")
    
    # Check for optional tools based on what's enabled
    [[ "$ENABLE_INETSIM" == "true" ]] && required_commands+=("inetsim")
    [[ "$ENABLE_CAPTURE" == "true" || "$ENABLE_TRIGGERED_CAPTURE" == "true" ]] && required_commands+=("tcpdump")
    [[ "$ENABLE_FAKE_SERVICES" == "true" ]] && required_commands+=("nc")
    [[ "$ENABLE_ZEEK" == "true" ]] && required_commands+=("zeek")

    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            if [[ "$cmd" == "inetsim" && "$ENABLE_INETSIM" == "true" ]]; then
                log "${RED}INetSim not found but is required. Please install it first.${NC}"
                exit 1
            elif [[ "$cmd" == "zeek" && "$ENABLE_ZEEK" == "true" ]]; then
                log "${RED}Zeek not found but is required. Please install it first.${NC}"
                exit 1
            elif [[ "$cmd" == "nc" && "$ENABLE_FAKE_SERVICES" == "true" ]]; then
                log "${RED}Netcat not found but is required for fake services.${NC}"
                exit 1
            else
                log "${RED}Required command not found: '$cmd'${NC}"
                exit 1
            fi
        fi
    done
    
    # Check for netcat compatibility if fake services are enabled
    if [[ "$ENABLE_FAKE_SERVICES" == "true" ]] && ! nc -h 2>&1 | grep -q -- '-k'; then
        log "${RED}The version of 'nc' (netcat) does not support the '-k' flag.${NC}"
        log "${RED}Please install netcat-openbsd or compatible version.${NC}"
        exit 1
    fi
    
    # Check libvirt service
    if ! systemctl is-active --quiet libvirtd; then
        log "${YELLOW}libvirtd service is not running. Attempting to start...${NC}"
        if systemctl start libvirtd; then
            log "${GREEN}libvirtd service started successfully.${NC}"
        else
            log "${RED}Failed to start libvirtd service.${NC}"
            exit 1
        fi
    fi
    
    log "${GREEN}Prerequisites check passed.${NC}"
}

# --- Core Network Functions ---

create_isolated_network() {
    log "${BLUE}Creating isolated network: $NETWORK_NAME${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would create libvirt network '$NETWORK_NAME'"
        return 0
    fi

    if virsh net-info "$NETWORK_NAME" &>/dev/null; then
        log "${YELLOW}Network '$NETWORK_NAME' already exists. Skipping creation.${NC}"
        return 0
    fi

    local network_xml="/tmp/${NETWORK_NAME}-network.xml"
    
    # Determine DHCP configuration based on services
    local dhcp_section=""
    if [[ "$ENABLE_INETSIM" != "true" ]]; then
        log "Using libvirt's built-in DHCP server."
        dhcp_section="
    <dhcp>
      <range start='$(echo "$DHCP_RANGE" | cut -d, -f1)' end='$(echo "$DHCP_RANGE" | cut -d, -f2)'/>
    </dhcp>"
    else
        log "${BLUE}INetSim enabled. Disabling libvirt DHCP to avoid conflicts.${NC}"
    fi

    # Create network XML with no internet forwarding for security
    cat > "$network_xml" << EOF
<network>
  <name>$NETWORK_NAME</name>
  <bridge name='$BRIDGE_NAME' stp='on' delay='0'/>
  <forward mode='none'/>
  <ip address='$GATEWAY' netmask='255.255.255.0'>
    $dhcp_section
  </ip>
</network>
EOF
    
    if virsh net-define "$network_xml"; then
        log "Network definition created successfully"
    else
        log "${RED}Failed to define network${NC}"
        rm -f "$network_xml"
        return 1
    fi
    
    if virsh net-start "$NETWORK_NAME"; then
        log "Network started successfully"
    else
        log "${RED}Failed to start network${NC}"
        rm -f "$network_xml"
        return 1
    fi
    
    if virsh net-autostart "$NETWORK_NAME"; then
        log "Network autostart enabled"
    else
        log "${YELLOW}Warning: Failed to set network autostart${NC}"
    fi
    
    rm -f "$network_xml"
    log "${GREEN}Isolated network '$NETWORK_NAME' created on bridge '$BRIDGE_NAME'.${NC}"
}

configure_firewall_rules() {
    log "${BLUE}Configuring firewall rules for $BRIDGE_NAME...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would configure iptables rules"
        return 0
    fi

    local ext_iface
    ext_iface=$(ip route | grep default | awk '{print $5}')
    if [[ -z "$ext_iface" ]]; then 
        log "${RED}Could not determine external interface. Cannot set up NAT.${NC}"
        return 1
    fi
    
    log "External interface: $ext_iface"

    # Enable controlled internet access through NAT
    iptables -A FORWARD -i "$BRIDGE_NAME" -o "$ext_iface" -j ACCEPT
    iptables -A FORWARD -i "$ext_iface" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$ext_iface" -j MASQUERADE
    
    # Isolate from other private networks
    log "Blocking access to other private networks..."
    iptables -I FORWARD -i "$BRIDGE_NAME" -d 192.168.0.0/16 ! -d "$SUBNET" -j DROP
    iptables -I FORWARD -i "$BRIDGE_NAME" -d 10.0.0.0/8 -j DROP
    iptables -I FORWARD -i "$BRIDGE_NAME" -d 172.16.0.0/12 -j DROP
    
    # Log suspicious traffic
    iptables -I FORWARD -i "$BRIDGE_NAME" -j LOG --log-prefix "SHIKRA-NET: " --log-level 4
    
    log "${GREEN}Firewall rules configured.${NC}"
}

setup_traffic_capture() {
    if [[ "$ENABLE_CAPTURE" != "true" ]]; then 
        return 0
    fi
    
    log "${BLUE}Setting up continuous traffic capture on '$BRIDGE_NAME'...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would start tcpdump"
        return 0
    fi

    local pcap_file="$PCAP_DIR/$(date +%Y%m%d_%H%M%S)_${NETWORK_NAME}.pcap"
    mkdir -p "$(dirname "$pcap_file")"
    
    # Start tcpdump in background
    nohup tcpdump -i "$BRIDGE_NAME" -w "$pcap_file" -s 0 > /dev/null 2>&1 &
    local tcpdump_pid=$!
    echo "$tcpdump_pid" > "/tmp/tcpdump_${NETWORK_NAME}.pid"
    
    # Verify tcpdump started successfully
    sleep 2
    if kill -0 "$tcpdump_pid" 2>/dev/null; then
        log "${GREEN}Traffic capture started (PID: $tcpdump_pid). Saving to: $pcap_file${NC}"
    else
        log "${RED}Failed to start traffic capture${NC}"
        return 1
    fi
}

setup_triggered_capture() {
    if [[ "$ENABLE_TRIGGERED_CAPTURE" != "true" ]]; then 
        return 0
    fi
    
    log "${BLUE}Setting up triggered traffic capture interface for '$BRIDGE_NAME'...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would setup trigger interface"
        return 0
    fi

    mkdir -p "$PCAP_DIR"
    
    # Create trigger script for on-demand packet capture
    local trigger_script="$PCAP_DIR/trigger_capture_${NETWORK_NAME}.sh"
    cat > "$trigger_script" << 'TRIGGER_EOF'
#!/bin/bash
# Auto-generated trigger script for packet capture

BRIDGE_NAME="$1"
DURATION="${2:-60}"
OUTPUT_DIR="${3:-$(dirname "$0")}"

if [[ -z "$BRIDGE_NAME" ]]; then
    echo "Usage: $0 <bridge_name> [duration_seconds] [output_dir]"
    echo "Example: $0 br-shikra-isol 120 /path/to/output"
    exit 1
fi

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PCAP_FILE="$OUTPUT_DIR/triggered_${TIMESTAMP}_${BRIDGE_NAME}.pcap"

echo "Starting triggered capture on $BRIDGE_NAME for $DURATION seconds..."
echo "Output: $PCAP_FILE"
echo "Press Ctrl+C to stop early"

# Start capture with timeout
timeout "$DURATION" tcpdump -i "$BRIDGE_NAME" -w "$PCAP_FILE" -s 0 2>/dev/null

if [[ $? -eq 0 || $? -eq 124 ]]; then  # 124 is timeout exit code
    echo "Capture completed: $PCAP_FILE"
    ls -lh "$PCAP_FILE" 2>/dev/null
    echo "Use: tshark -r \"$PCAP_FILE\" to analyze"
else
    echo "Capture failed or was interrupted"
    exit 1
fi
TRIGGER_EOF
    
    chmod +x "$trigger_script"
    
    # Create simple trigger interface
    local trigger_interface="$PCAP_DIR/capture_trigger_${NETWORK_NAME}"
    cat > "$trigger_interface" << EOF
#!/bin/bash
# Trigger interface for $NETWORK_NAME packet capture
# Usage: $trigger_interface [duration] [output_dir]

SCRIPT_DIR="\$(dirname "\$0")"
TRIGGER_SCRIPT="\$SCRIPT_DIR/trigger_capture_${NETWORK_NAME}.sh"
BRIDGE_NAME="$BRIDGE_NAME"
DURATION="\${1:-60}"
OUTPUT_DIR="\${2:-\$SCRIPT_DIR}"

exec "\$TRIGGER_SCRIPT" "\$BRIDGE_NAME" "\$DURATION" "\$OUTPUT_DIR"
EOF
    chmod +x "$trigger_interface"
    
    # Set proper ownership
    if [[ -n "$SUDO_USER" ]]; then
        chown "$SUDO_USER:$SUDO_USER" "$trigger_script" "$trigger_interface"
    fi
    
    log "${GREEN}Triggered capture interface created:${NC}"
    log "  Interface: $trigger_interface"
    log "  Usage: $trigger_interface [duration] [output_dir]"
    log "  Example: $trigger_interface 120"
}

setup_zeek_monitoring() {
    if [[ "$ENABLE_ZEEK" != "true" ]]; then 
        return 0
    fi
    
    log "${BLUE}Setting up Zeek network monitoring for '$BRIDGE_NAME'...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would setup Zeek monitoring"
        return 0
    fi

    # Check if Zeek is available
    if ! command -v zeek &>/dev/null; then
        log "${RED}Zeek not found. Please install Zeek first.${NC}"
        return 1
    fi

    local zeek_logs_dir="$PROJECT_ROOT/data/zeek_logs/${NETWORK_NAME}"
    local zeek_config_dir="$PROJECT_ROOT/config/zeek"
    
    mkdir -p "$zeek_logs_dir" "$zeek_config_dir"
    
    # Create Zeek configuration for this network
    local zeek_config="$zeek_config_dir/analysis_${NETWORK_NAME}.zeek"
    cat > "$zeek_config" << EOF
# Zeek configuration for Shikra network: $NETWORK_NAME
# Generated automatically by network_setup.sh

@load base/frameworks/notice
@load base/frameworks/logging
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp

# Enable malware detection policies
@load policy/protocols/conn/known-hosts
@load policy/protocols/conn/known-services
@load policy/protocols/http/detect-sqli
@load policy/protocols/http/detect-webapps
@load policy/protocols/ssl/known-certs

# Set custom logging directory
redef Log::default_logdir = "$zeek_logs_dir";

# Configure for malware analysis
redef Site::local_nets = { $SUBNET };

# Event handlers for malware analysis
event zeek_init() {
    print fmt("Zeek monitoring started for network: $NETWORK_NAME on $BRIDGE_NAME");
}

event connection_established(c: connection) {
    print fmt("Connection: %s:%s -> %s:%s [%s]", 
              c\$id\$orig_h, c\$id\$orig_p, c\$id\$resp_h, c\$id\$resp_p, c\$id\$resp_proto);
}

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count) {
    print fmt("DNS Query: %s -> %s (%s)", c\$id\$orig_h, query, dns_query_types[qtype]);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    print fmt("HTTP Request: %s %s -> %s", method, original_URI, c\$id\$resp_h);
}
EOF

    # Create Zeek startup script
    local zeek_start_script="$zeek_config_dir/start_zeek_${NETWORK_NAME}.sh"
    cat > "$zeek_start_script" << EOF
#!/bin/bash
# Zeek startup script for network: $NETWORK_NAME

ZEEK_CONFIG="$zeek_config"
ZEEK_LOGS="$zeek_logs_dir"
INTERFACE="$BRIDGE_NAME"
PID_FILE="/tmp/zeek_\${INTERFACE}.pid"

echo "Starting Zeek monitoring on \$INTERFACE..."
echo "Configuration: \$ZEEK_CONFIG"
echo "Logs: \$ZEEK_LOGS"

# Kill any existing Zeek process for this interface
if [[ -f "\$PID_FILE" ]]; then
    OLD_PID=\$(cat "\$PID_FILE")
    if kill -0 "\$OLD_PID" 2>/dev/null; then
        echo "Stopping existing Zeek process (PID: \$OLD_PID)"
        kill "\$OLD_PID"
        sleep 2
    fi
fi

# Start Zeek
cd "\$ZEEK_LOGS" || exit 1
nohup zeek -i "\$INTERFACE" "\$ZEEK_CONFIG" > zeek_output.log 2>&1 &
ZEEK_PID=\$!

echo "\$ZEEK_PID" > "\$PID_FILE"

# Verify Zeek started
sleep 3
if kill -0 "\$ZEEK_PID" 2>/dev/null; then
    echo "Zeek started successfully (PID: \$ZEEK_PID)"
    echo "Monitor logs: tail -f \$ZEEK_LOGS/*.log"
else
    echo "Failed to start Zeek"
    exit 1
fi
EOF
    chmod +x "$zeek_start_script"
    
    # Start Zeek monitoring
    if "$zeek_start_script"; then
        log "${GREEN}Zeek monitoring started successfully${NC}"
        log "Configuration: $zeek_config"
        log "Logs: $zeek_logs_dir"
        log "Control script: $zeek_start_script"
    else
        log "${RED}Failed to start Zeek monitoring${NC}"
        return 1
    fi
}

configure_inetsim() {
    if [[ "$ENABLE_INETSIM" != "true" ]]; then 
        return 0
    fi
    
    log "${BLUE}Configuring INetSim for malware network simulation...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would configure and start INetSim"
        return 0
    fi

    # Check if INetSim is available
    if ! command -v inetsim &>/dev/null; then
        log "${RED}INetSim not found. Please install INetSim first.${NC}"
        return 1
    fi

    local inetsim_config_dir="$PROJECT_ROOT/config/inetsim"
    local inetsim_conf="$inetsim_config_dir/inetsim_${NETWORK_NAME}.conf"
    local inetsim_data_dir="$PROJECT_ROOT/data/inetsim/${NETWORK_NAME}"
    local inetsim_log_dir="$PROJECT_ROOT/logs/inetsim/${NETWORK_NAME}"
    
    mkdir -p "$inetsim_config_dir" "$inetsim_data_dir" "$inetsim_log_dir"
    
    # Create INetSim configuration
    cat > "$inetsim_conf" << EOF
# INetSim Configuration for Shikra Network: $NETWORK_NAME
# Generated automatically by network_setup.sh

# Service bind address (gateway of isolated network)
service_bind_address    $GATEWAY
dns_bind_address        $GATEWAY

# DNS Configuration
dns_version             0x0001
dns_server              $GATEWAY
dns_default_ip          $GATEWAY

# HTTP Configuration  
http_bind_port          80
http_version            HTTP/1.1
http_default_response   $inetsim_data_dir/default.html

# HTTPS Configuration
https_bind_port         443
https_version           HTTP/1.1

# FTP Configuration
ftp_bind_port           21
ftp_version             220 InetSim FTP Service ready.

# SMTP Configuration  
smtp_bind_port          25
smtp_version            220 InetSim Mail Service ready.

# POP3 Configuration
pop3_bind_port          110
pop3_version            +OK InetSim POP3 Service ready.

# IRC Configuration
irc_bind_port           6667

# Time Server
time_bind_port          37
ntp_bind_port           123

# Logging
log_dir                 $inetsim_log_dir
session_log_file        session_${NETWORK_NAME}.log
service_log_file        service_${NETWORK_NAME}.log
debug_log_file          debug_${NETWORK_NAME}.log

# Data directory
data_dir                $inetsim_data_dir

# Enable services for malware analysis
start_service           dns
start_service           http  
start_service           https
start_service           ftp
start_service           smtp
start_service           pop3
start_service           irc
start_service           time
start_service           ntp
EOF

    # Create default HTML response
    cat > "$inetsim_data_dir/default.html" << 'HTML_EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Shikra Analysis Network</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { color: #333; border-bottom: 2px solid #007acc; padding-bottom: 10px; }
        .info { background: #f0f8ff; padding: 20px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔬 Shikra Malware Analysis Network</h1>
    </div>
    <div class="info">
        <h2>Network Simulation Active</h2>
        <p>This is a simulated HTTP response from the Shikra analysis environment.</p>
        <p><strong>All network requests are being logged and analyzed.</strong></p>
        <ul>
            <li>DNS queries are intercepted and logged</li>
            <li>HTTP/HTTPS traffic is monitored</li>
            <li>Email and FTP connections are simulated</li>
            <li>Network behavior is captured for analysis</li>
        </ul>
        <p><em>Timestamp: $(date)</em></p>
    </div>
</body>
</html>
HTML_EOF

    # Kill any existing INetSim processes for this network
    pkill -f "inetsim.*$NETWORK_NAME" 2>/dev/null || true
    
    # Start INetSim
    log "Starting INetSim with configuration: $inetsim_conf"
    nohup inetsim --config="$inetsim_conf" > "$inetsim_log_dir/inetsim_${NETWORK_NAME}.out" 2>&1 &
    local inetsim_pid=$!
    
    # Store PID for cleanup
    echo "$inetsim_pid" > "/tmp/inetsim_${NETWORK_NAME}.pid"
    
    # Wait and verify INetSim started
    sleep 3
    if kill -0 "$inetsim_pid" 2>/dev/null; then
        log "${GREEN}INetSim started successfully (PID: $inetsim_pid)${NC}"
        log "Services on $GATEWAY: DNS:53, HTTP:80, HTTPS:443, FTP:21, SMTP:25, POP3:110"
        log "Configuration: $inetsim_conf"
        log "Logs: $inetsim_log_dir"
    else
        log "${RED}Failed to start INetSim. Check logs: $inetsim_log_dir/inetsim_${NETWORK_NAME}.out${NC}"
        return 1
    fi
}

start_fake_services() {
    if [[ "$ENABLE_FAKE_SERVICES" != "true" ]]; then 
        return 0
    fi
    
    log "${BLUE}Starting fake network services...${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would start fake services"
        return 0
    fi

    # Kill any existing fake services for this network
    pkill -f "fake_.*_${NETWORK_NAME}" 2>/dev/null || true

    log "Starting fake HTTP service on $GATEWAY:80"
    nohup bash -c "
        while true; do 
            echo -e 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<h1>Fake HTTP Server</h1><p>Network: $NETWORK_NAME</p>' | nc -l -p 80 -s $GATEWAY
            sleep 1
        done
    " &>/dev/null &
    echo $! > "/tmp/fake_http_${NETWORK_NAME}.pid"

    log "Starting fake FTP service on $GATEWAY:21"
    nohup bash -c "
        while true; do 
            echo '220 Fake FTP Server Ready ($NETWORK_NAME)' | nc -l -p 21 -s $GATEWAY
            sleep 1
        done
    " &>/dev/null &
    echo $! > "/tmp/fake_ftp_${NETWORK_NAME}.pid"

    log "Starting fake SMTP service on $GATEWAY:25"
    nohup bash -c "
        while true; do 
            echo '220 fake-mail.local ESMTP Service Ready ($NETWORK_NAME)' | nc -l -p 25 -s $GATEWAY
            sleep 1
        done
    " &>/dev/null &
    echo $! > "/tmp/fake_smtp_${NETWORK_NAME}.pid"

    log "${GREEN}Fake services started on $GATEWAY${NC}"
}

# --- Cleanup Functions ---

cleanup_network() {
    log "${YELLOW}--- Cleaning up network environment for $NETWORK_NAME ---${NC}"
    
    if [[ "$DRY_RUN" == "true" ]]; then 
        log "Dry run: would run all cleanup steps"
        return 0
    fi

    cleanup_fake_services
    cleanup_traffic_capture
    cleanup_zeek_monitoring
    cleanup_inetsim
    cleanup_firewall_rules
    
    if virsh net-info "$NETWORK_NAME" &>/dev/null; then
        log "Destroying and undefining libvirt network '$NETWORK_NAME'..."
        virsh net-destroy "$NETWORK_NAME" 2>/dev/null || true
        virsh net-undefine "$NETWORK_NAME" 2>/dev/null || true
        log "Libvirt network '$NETWORK_NAME' removed."
    fi
    
    log "${GREEN}Network cleanup completed.${NC}"
}

cleanup_firewall_rules() {
    log "Removing firewall rules for $BRIDGE_NAME..."
    
    local ext_iface
    ext_iface=$(ip route | grep default | awk '{print $5}' 2>/dev/null)
    if [[ -z "$ext_iface" ]]; then ext_iface="any"; fi

    # Remove specific rules (ignore errors if rules don't exist)
    iptables -D FORWARD -i "$BRIDGE_NAME" -j LOG --log-prefix "SHIKRA-NET: " --log-level 4 2>/dev/null || true
    iptables -D FORWARD -i "$BRIDGE_NAME" -d 172.16.0.0/12 -j DROP 2>/dev/null || true
    iptables -D FORWARD -i "$BRIDGE_NAME" -d 10.0.0.0/8 -j DROP 2>/dev/null || true
    iptables -D FORWARD -i "$BRIDGE_NAME" -d 192.168.0.0/16 ! -d "$SUBNET" -j DROP 2>/dev/null || true
    iptables -t nat -D POSTROUTING -s "$SUBNET" -o "$ext_iface" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i "$ext_iface" -o "$BRIDGE_NAME" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -i "$BRIDGE_NAME" -o "$ext_iface" -j ACCEPT 2>/dev/null || true
    
    log "Firewall rules cleanup completed."
}

cleanup_process_by_pidfile() {
    local process_name=$1
    local pid_file=$2
    
    if [[ -f "$pid_file" ]]; then
        local pid
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            if kill "$pid" 2>/dev/null; then
                log "Stopped $process_name (PID: $pid)"
            else
                log "${YELLOW}Failed to stop $process_name (PID: $pid)${NC}"
            fi
        fi
        rm -f "$pid_file"
    fi
}

cleanup_fake_services() {
    log "Stopping fake services..."
    cleanup_process_by_pidfile "Fake HTTP" "/tmp/fake_http_${NETWORK_NAME}.pid"
    cleanup_process_by_pidfile "Fake FTP" "/tmp/fake_ftp_${NETWORK_NAME}.pid"
    cleanup_process_by_pidfile "Fake SMTP" "/tmp/fake_smtp_${NETWORK_NAME}.pid"
}

cleanup_traffic_capture() {
    log "Stopping traffic capture..."
    cleanup_process_by_pidfile "tcpdump" "/tmp/tcpdump_${NETWORK_NAME}.pid"
}

cleanup_zeek_monitoring() {
    log "Stopping Zeek monitoring..."
    cleanup_process_by_pidfile "Zeek" "/tmp/zeek_${BRIDGE_NAME}.pid"
    pkill -f "zeek.*${BRIDGE_NAME}" 2>/dev/null || true
}

cleanup_inetsim() {
    log "Stopping INetSim..."
    cleanup_process_by_pidfile "INetSim" "/tmp/inetsim_${NETWORK_NAME}.pid"
    pkill -f "inetsim.*$NETWORK_NAME" 2>/dev/null || true
}

# --- Status Function ---
show_network_status() {
    log "${BLUE}=== Network Status ===${NC}"
    
    echo "Libvirt Networks:"
    virsh net-list --all 2>/dev/null || echo "Failed to list libvirt networks"
    
    echo
    echo "Bridge Interfaces:"
    ip link show type bridge 2>/dev/null | grep -E "(virbr|br-)" || echo "No bridge interfaces found"
    
    echo
    echo "Active Network Processes:"
    
    echo "INetSim processes:"
    pgrep -fl inetsim | grep -E "(shikra|analysis)" || echo "  None"
    
    echo "Zeek processes:"
    pgrep -fl zeek | grep -E "(shikra|br-)" || echo "  None"
    
    echo "TCPDump processes:"
    pgrep -fl tcpdump | grep -E "(virbr|br-)" || echo "  None"
    
    echo "Netcat fake services:"
    pgrep -fl "nc.*-l" || echo "  None"
    
    echo
    echo "Firewall Rules (analysis networks):"
    iptables -L FORWARD | grep -E "(virbr|br-|192.168.100|SHIKRA)" || echo "  No specific rules found"
    
    echo
    echo "Available Trigger Scripts:"
    find "$PCAP_DIR" -name "capture_trigger_*" -type f 2>/dev/null | head -5 || echo "  No trigger scripts found"
    
    echo
    echo "Recent Log Activity:"
    if [[ -d "$PROJECT_ROOT/logs/inetsim" ]]; then
        echo "INetSim logs:"
        find "$PROJECT_ROOT/logs/inetsim" -name "*.log" -mtime -1 2>/dev/null | head -3 || echo "  No recent logs"
    fi
    
    if [[ -d "$PROJECT_ROOT/data/zeek_logs" ]]; then
        echo "Zeek logs:"
        find "$PROJECT_ROOT/data/zeek_logs" -name "*.log" -mtime -1 2>/dev/null | head -3 || echo "  No recent logs"
    fi
}

# --- Main Execution ---

main() {
    trap 'log "${RED}Script interrupted. Running cleanup...${NC}"; cleanup_network; exit 1' SIGINT SIGTERM ERR

    parse_arguments "$@"
    
    if [[ "$CREATE_ISOLATED" == "true" ]]; then
        log "${GREEN}--- Starting Network Setup for '$NETWORK_NAME' ---${NC}"
        check_prerequisites
        create_isolated_network
        configure_firewall_rules
        setup_traffic_capture
        setup_triggered_capture
        setup_zeek_monitoring
        configure_inetsim
        start_fake_services
        
        log "${GREEN}--- Network Setup Completed Successfully ---${NC}"
        echo -e "\n${CYAN}🎉 Network '$NETWORK_NAME' is ready on bridge '$BRIDGE_NAME'${NC}"
        echo ""
        echo "Network Details:"
        echo "  • Network: $NETWORK_NAME ($SUBNET)"
        echo "  • Gateway: $GATEWAY"
        echo "  • Bridge: $BRIDGE_NAME"
        echo ""
        echo "Attach VMs with:"
        echo "  virt-install --network network=$NETWORK_NAME ..."
        echo "  or in virt-manager, select network: $NETWORK_NAME"
        echo ""
        
        # Show enabled services
        if [[ "$ENABLE_INETSIM" == "true" ]]; then
            echo "INetSim Services: HTTP:80, HTTPS:443, DNS:53, FTP:21, SMTP:25"
        fi
        if [[ "$ENABLE_FAKE_SERVICES" == "true" ]]; then
            echo "Fake Services: Basic HTTP, FTP, SMTP"
        fi
        if [[ "$ENABLE_ZEEK" == "true" ]]; then
            echo "Zeek Monitoring: Deep packet inspection active"
        fi
        if [[ "$ENABLE_TRIGGERED_CAPTURE" == "true" ]]; then
            echo "Trigger Capture: $PCAP_DIR/capture_trigger_${NETWORK_NAME}"
        fi
        
    elif [[ "$CLEANUP_NETWORK" == "true" ]]; then
        cleanup_network
    fi
    
    trap - SIGINT SIGTERM ERR
}

# Execute main function if script is run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi