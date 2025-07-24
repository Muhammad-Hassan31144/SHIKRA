"""
Admin routes for Shikra Host web dashboard
Handles agent enrollment and management UI
"""

from flask import Blueprint, render_template, request, jsonify, redirect, url_for
import logging
import secrets
import hashlib
import time

from ..simple_store import agent_store
from config.config import Config

logger = logging.getLogger(__name__)
admin_bp = Blueprint('admin', __name__)


def get_available_vms():
    """Get list of available VMs from libvirt"""
    import subprocess
    
    vms = []
    
    try:
        # List all VMs (running and stopped)
        result = subprocess.run(['virsh', 'list', '--all'], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            # Skip header lines
            for line in lines[2:]:
                if not line.strip():
                    continue
                
                parts = line.split(maxsplit=2)
                if len(parts) >= 3:
                    vm_id = parts[0]
                    vm_name = parts[1]
                    vm_state = parts[2]
                    
                    # Get IP address if VM is running
                    vm_ip = 'N/A'
                    if 'running' in vm_state.lower():
                        vm_ip = get_vm_ip(vm_name)
                    
                    vms.append({
                        'id': vm_name,  # Use name as ID
                        'name': vm_name,
                        'state': vm_state,
                        'ip': vm_ip
                    })
    except subprocess.TimeoutExpired:
        logger.error("virsh command timed out")
    except FileNotFoundError:
        logger.warning("virsh command not found - libvirt may not be installed")
        # Return empty list, enrollment can still work without VM discovery
    except Exception as e:
        logger.error(f"Error listing VMs: {e}")
    
    return vms


def get_vm_ip(vm_name):
    """Get IP address of a running VM"""
    import subprocess
    
    try:
        result = subprocess.run(['virsh', 'domifaddr', vm_name], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            for line in lines[2:]:  # Skip header
                if 'ipv4' in line.lower() or '/' in line:
                    parts = line.split()
                    for part in parts:
                        if '/' in part:  # CIDR notation
                            ip = part.split('/')[0]
                            return ip
    except:
        pass
    
    return 'N/A'


@admin_bp.route('/enroll', methods=['GET'])
def enroll_agent_form():
    """Display agent enrollment form"""
    try:
        # Get list of available VMs
        vms = get_available_vms()
        
        return render_template('enroll_agent.html', vms=vms)
    except Exception as e:
        logger.error(f"Error loading enrollment form: {e}")
        return f"Error loading enrollment form: {e}", 500


@admin_bp.route('/enroll', methods=['POST'])
def enroll_agent_submit():
    """Process agent enrollment - Agent v2.0"""
    try:
        # Get form data
        vm_name = request.form.get('vm_id', '').strip()  # vm_id field contains vm_name
        description = request.form.get('description', '').strip()
        expires_in_days = int(request.form.get('expires_in_days', 7))
        
        if not vm_name:
            return "VM name is required", 400
        
        # Generate agent ID from VM name
        agent_id = f"agent-{vm_name.replace(' ', '-').replace('_', '-').lower()}"
        
        # Generate enrollment key (secure random, 32 bytes)
        enrollment_key = secrets.token_urlsafe(32)
        enrollment_key_hash = hashlib.sha256(enrollment_key.encode()).hexdigest()
        
        # Calculate expiry
        expiry_timestamp = int(time.time()) + (expires_in_days * 24 * 60 * 60)
        
        # Create agent record with enrollment key
        from datetime import datetime
        agent_data = {
            'agent_id': agent_id,
            'vm_name': vm_name,
            'description': description or f'Enrollment key for {vm_name}',
            'enrollment_key_hash': enrollment_key_hash,
            'enrollment_used': False,
            'enrollment_created': datetime.utcnow().isoformat(),
            'enrollment_expires': expiry_timestamp,
            'status': 'awaiting_enrollment'
        }
        
        agent_store.put_agent(agent_id, agent_data)
        
        logger.info(f"Generated enrollment key for VM: {vm_name} (agent_id: {agent_id})")
        
        # Show success page with enrollment key
        return render_template('enrollment_success.html',
                             agent_id=agent_id,
                             agent_name=vm_name,
                             vm_id=vm_name,
                             enrollment_key=enrollment_key,
                             expires_in_days=expires_in_days)
    
    except Exception as e:
        logger.error(f"Error enrolling agent: {e}")
        return f"Error enrolling agent: {e}", 500


@admin_bp.route('/agents', methods=['GET'])
def list_agents():
    """Display list of all agents - Agent v2.0"""
    try:
        agent_store.reload_from_file()
        all_agents = agent_store.get_all_agents()
        
        # Convert to list for template
        agents_list = []
        for agent_id, agent_data in all_agents.items():
            agents_list.append({
                'agent_id': agent_id,
                'vm_name': agent_data.get('vm_name', agent_data.get('name', 'Unknown')),
                'description': agent_data.get('description', ''),
                'status': agent_data.get('status', 'unknown'),
                'enrollment_created': agent_data.get('enrollment_created', ''),
                'enrollment_used': agent_data.get('enrollment_used', False),
                'enrollment_expires': agent_data.get('enrollment_expires', 0),
                'first_seen': agent_data.get('first_seen', ''),
                'last_seen': agent_data.get('last_seen', '')
            })
        
        return render_template('agents_list.html', agents=agents_list)
    
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        return f"Error listing agents: {e}", 500


@admin_bp.route('/')
def admin_home():
    """Admin dashboard home"""
    return render_template('admin_home.html')
