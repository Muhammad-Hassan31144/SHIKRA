"""
Trigger endpoints for runtime analysis control
Handles memory dumps and network capture triggered by agent
"""

from flask import Blueprint, request, jsonify
import logging
import subprocess
import os
import time
from datetime import datetime
import signal

from ..simple_store import agent_store
from ..simple_sample_store import sample_store
from config.config import Config
from ..auth import require_agent_auth

logger = logging.getLogger(__name__)
triggers_bp = Blueprint('triggers', __name__)

# Track active network captures: {sample_id: {'pid': int, 'started': timestamp, 'pcap_path': str}}
_active_captures = {}


def _get_vm_name_for_agent(agent_id: str) -> str:
    """Get VM name from agent record"""
    agent = agent_store.get_agent(agent_id)
    if not agent:
        raise ValueError(f"Agent {agent_id} not found")
    
    vm_name = agent.get('vm_name') or agent.get('vm_id')
    if not vm_name:
        raise ValueError(f"No VM name configured for agent {agent_id}")
    
    return vm_name


def _get_vm_ip_from_sample(sample_id: str) -> str:
    """Extract VM IP from sample assignment"""
    sample = sample_store.get_sample(sample_id)
    if not sample:
        raise ValueError(f"Sample {sample_id} not found")
    
    agent_id = sample.get('assigned_agent')
    if not agent_id:
        raise ValueError(f"Sample {sample_id} not assigned to any agent")
    
    agent = agent_store.get_agent(agent_id)
    if not agent:
        raise ValueError(f"Agent {agent_id} not found")
    
    # Try to get VM IP from agent metadata (would be set during registration)
    vm_ip = agent.get('vm_ip')
    if vm_ip:
        return vm_ip
    
    # Fallback: try to query libvirt for VM IP
    vm_name = _get_vm_name_for_agent(agent_id)
    try:
        result = subprocess.run(
            ['virsh', 'domifaddr', vm_name],
            capture_output=True,
            text=True,
            timeout=5
        )
        # Parse output to extract IP (basic parsing)
        for line in result.stdout.split('\n'):
            if 'ipv4' in line.lower():
                parts = line.split()
                for part in parts:
                    if '/' in part:  # IP in CIDR format
                        return part.split('/')[0]
    except Exception as e:
        logger.warning(f"Could not determine VM IP for {vm_name}: {e}")
    
    # Last resort: assume default VM network
    return "192.168.122.0/24"  # Capture whole subnet


@triggers_bp.route('/samples/<sample_id>/memory-dump', methods=['POST'])
@require_agent_auth
def trigger_memory_dump(sample_id):
    """
    Trigger memory dump of VM running the sample
    
    Request body:
    {
        "trigger_reason": "Suspicious API: CreateRemoteThread",  # Optional
        "dump_format": "raw"  # Optional: raw, elf (default: raw)
    }
    
    Uses virsh dump to capture VM memory state
    """
    try:
        agent_id = request.agent_id
        data = request.get_json() or {}
        
        # Verify sample is assigned to this agent
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        if sample.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403
        
        # Get VM name from agent
        vm_name = _get_vm_name_for_agent(agent_id)
        
        # Prepare dump path
        dump_dir = Config.DUMP_STORAGE
        os.makedirs(dump_dir, exist_ok=True)
        
        timestamp = int(time.time())
        dump_filename = f"{sample_id}-{timestamp}.raw"
        dump_path = os.path.join(dump_dir, dump_filename)
        
        trigger_reason = data.get('trigger_reason', 'Agent-triggered memory dump')
        dump_format = data.get('dump_format', 'raw')
        
        logger.info(f"Triggering memory dump for VM '{vm_name}' (sample: {sample_id})")
        logger.info(f"Reason: {trigger_reason}")
        
        # Execute virsh dump command
        # --memory-only: dump memory state only (faster than full VM state)
        # --live: continue VM execution after dump (non-blocking)
        cmd = [
            'virsh', 'dump', vm_name, dump_path,
            '--memory-only',
            '--live'
        ]
        
        if dump_format == 'elf':
            cmd.append('--format=elf')
        
        logger.info(f"Executing: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 60 second timeout for dump
            )
            
            if result.returncode != 0:
                logger.error(f"virsh dump failed: {result.stderr}")
                return jsonify({
                    'error': 'Memory dump failed',
                    'details': result.stderr
                }), 500
            
            # Get dump file size
            dump_size = os.path.getsize(dump_path) if os.path.exists(dump_path) else 0
            
            logger.info(f"Memory dump completed: {dump_path} ({dump_size} bytes)")
            
            # Update sample metadata with dump info
            sample_store.update_fields(sample_id, {
                'last_memory_dump': datetime.utcnow().isoformat(),
                'memory_dump_path': dump_path,
                'memory_dump_reason': trigger_reason
            })
            
            return jsonify({
                'success': True,
                'dump_path': dump_path,
                'dump_size': dump_size,
                'dump_format': dump_format,
                'vm_name': vm_name,
                'timestamp': datetime.utcnow().isoformat(),
                'trigger_reason': trigger_reason
            }), 200
            
        except subprocess.TimeoutExpired:
            logger.error(f"Memory dump timed out for VM {vm_name}")
            return jsonify({'error': 'Memory dump timed out'}), 504
        
    except Exception as e:
        logger.error(f"Error triggering memory dump: {e}", exc_info=True)
        return jsonify({'error': 'Failed to trigger memory dump'}), 500


@triggers_bp.route('/samples/<sample_id>/network-capture/start', methods=['POST'])
@require_agent_auth
def start_network_capture(sample_id):
    """
    Start network traffic capture for sample analysis
    
    Request body:
    {
        "interface": "virbr0",  # Optional, auto-detect if not provided
        "filter": "tcp or udp"  # Optional BPF filter
    }
    
    Uses tcpdump to capture traffic in PCAP format
    """
    try:
        agent_id = request.agent_id
        data = request.get_json() or {}
        
        # Verify sample is assigned to this agent
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        if sample.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403
        
        # Check if capture already active for this sample
        if sample_id in _active_captures:
            return jsonify({
                'error': 'Network capture already active for this sample',
                'capture_id': _active_captures[sample_id].get('capture_id')
            }), 409
        
        # Get network interface (default to virbr0 for KVM)
        interface = data.get('interface', 'virbr0')
        
        # Get VM IP for filtering
        try:
            vm_ip = _get_vm_ip_from_sample(sample_id)
        except Exception as e:
            logger.warning(f"Could not determine VM IP: {e}, capturing all traffic on interface")
            vm_ip = None
        
        # Prepare PCAP path
        artifacts_dir = os.path.join(Config.ARTIFACT_STORAGE, sample_id)
        os.makedirs(artifacts_dir, exist_ok=True)
        
        timestamp = int(time.time())
        pcap_filename = f"network-{timestamp}.pcap"
        pcap_path = os.path.join(artifacts_dir, pcap_filename)
        
        # Build tcpdump command
        cmd = [
            'tcpdump',
            '-i', interface,
            '-w', pcap_path,
            '-Z', 'root',  # Don't drop privileges (needed for writing to file)
        ]
        
        # Add BPF filter
        bpf_filter = data.get('filter', '')
        if vm_ip and '/' not in vm_ip:  # Single IP, not subnet
            # Filter traffic to/from this specific VM
            bpf_parts = [f'host {vm_ip}']
            if bpf_filter:
                bpf_parts.append(f'and ({bpf_filter})')
            cmd.append(' '.join(bpf_parts))
        elif bpf_filter:
            cmd.append(bpf_filter)
        
        logger.info(f"Starting network capture for sample {sample_id}")
        logger.info(f"Command: {' '.join(cmd)}")
        
        # Start tcpdump as background process
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Give tcpdump a moment to start
            time.sleep(0.5)
            
            # Check if process is still running
            if process.poll() is not None:
                stderr = process.stderr.read().decode()
                logger.error(f"tcpdump failed to start: {stderr}")
                return jsonify({
                    'error': 'Failed to start network capture',
                    'details': stderr
                }), 500
            
            capture_id = f"capture-{sample_id}-{timestamp}"
            
            # Track active capture
            _active_captures[sample_id] = {
                'capture_id': capture_id,
                'pid': process.pid,
                'started': time.time(),
                'pcap_path': pcap_path,
                'interface': interface,
                'vm_ip': vm_ip
            }
            
            logger.info(f"Network capture started: {capture_id} (PID: {process.pid})")
            
            # Update sample metadata
            sample_store.update_fields(sample_id, {
                'network_capture_active': True,
                'network_capture_started': datetime.utcnow().isoformat()
            })
            
            return jsonify({
                'success': True,
                'capture_id': capture_id,
                'status': 'recording',
                'pcap_path': pcap_path,
                'interface': interface,
                'vm_ip': vm_ip,
                'started': datetime.utcnow().isoformat()
            }), 200
            
        except Exception as e:
            logger.error(f"Failed to start tcpdump: {e}")
            return jsonify({
                'error': 'Failed to start network capture',
                'details': str(e)
            }), 500
        
    except Exception as e:
        logger.error(f"Error starting network capture: {e}", exc_info=True)
        return jsonify({'error': 'Failed to start network capture'}), 500


@triggers_bp.route('/samples/<sample_id>/network-capture/stop', methods=['POST'])
@require_agent_auth
def stop_network_capture(sample_id):
    """
    Stop network traffic capture and finalize PCAP file
    
    Returns PCAP file info and packet statistics
    """
    try:
        agent_id = request.agent_id
        
        # Verify sample is assigned to this agent
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        if sample.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403
        
        # Check if capture is active
        if sample_id not in _active_captures:
            return jsonify({'error': 'No active network capture for this sample'}), 404
        
        capture_info = _active_captures[sample_id]
        pid = capture_info['pid']
        pcap_path = capture_info['pcap_path']
        
        logger.info(f"Stopping network capture for sample {sample_id} (PID: {pid})")
        
        try:
            # Send SIGTERM to tcpdump process group
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            
            # Wait for process to terminate
            for i in range(10):  # Wait up to 5 seconds
                try:
                    os.kill(pid, 0)  # Check if process exists
                    time.sleep(0.5)
                except ProcessLookupError:
                    break  # Process terminated
            
            # Force kill if still running
            try:
                os.killpg(os.getpgid(pid), signal.SIGKILL)
            except ProcessLookupError:
                pass  # Already dead
            
        except Exception as e:
            logger.warning(f"Error stopping tcpdump process: {e}")
        
        # Get PCAP file stats
        pcap_size = 0
        packets_captured = 0
        
        if os.path.exists(pcap_path):
            pcap_size = os.path.getsize(pcap_path)
            
            # Try to count packets using tcpdump
            try:
                result = subprocess.run(
                    ['tcpdump', '-r', pcap_path, '-q'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                packets_captured = len(result.stdout.strip().split('\n'))
            except Exception as e:
                logger.warning(f"Could not count packets in PCAP: {e}")
        
        duration = time.time() - capture_info['started']
        
        # Remove from active captures
        del _active_captures[sample_id]
        
        # Update sample metadata
        sample_store.update_fields(sample_id, {
            'network_capture_active': False,
            'network_capture_stopped': datetime.utcnow().isoformat(),
            'network_pcap_path': pcap_path,
            'network_pcap_size': pcap_size,
            'network_packets_captured': packets_captured
        })
        
        logger.info(f"Network capture stopped: {pcap_path} ({pcap_size} bytes, {packets_captured} packets)")
        
        return jsonify({
            'success': True,
            'pcap_path': pcap_path,
            'pcap_size': pcap_size,
            'packets_captured': packets_captured,
            'duration_seconds': int(duration),
            'stopped': datetime.utcnow().isoformat()
        }), 200
        
    except Exception as e:
        logger.error(f"Error stopping network capture: {e}", exc_info=True)
        return jsonify({'error': 'Failed to stop network capture'}), 500


@triggers_bp.route('/samples/<sample_id>/network-capture/status', methods=['GET'])
@require_agent_auth
def network_capture_status(sample_id):
    """Get status of network capture for sample"""
    try:
        agent_id = request.agent_id
        
        # Verify sample is assigned to this agent
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        if sample.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403
        
        if sample_id in _active_captures:
            capture_info = _active_captures[sample_id]
            duration = time.time() - capture_info['started']
            
            # Check if process still alive
            try:
                os.kill(capture_info['pid'], 0)
                status = 'recording'
            except ProcessLookupError:
                status = 'stopped (process died)'
            
            return jsonify({
                'active': True,
                'status': status,
                'capture_id': capture_info['capture_id'],
                'pid': capture_info['pid'],
                'duration_seconds': int(duration),
                'pcap_path': capture_info['pcap_path'],
                'interface': capture_info['interface']
            }), 200
        else:
            return jsonify({
                'active': False,
                'status': 'not_started'
            }), 200
        
    except Exception as e:
        logger.error(f"Error getting capture status: {e}", exc_info=True)
        return jsonify({'error': 'Failed to get capture status'}), 500
