"""
VM management routes for Shikra Host API
"""

from flask import Blueprint, request, jsonify
import logging
from datetime import datetime

from vm_manager.qemu_manager import QEMUManager
from ..simple_store import agent_store

logger = logging.getLogger(__name__)
vm_bp = Blueprint('vm', __name__)

# Global VM manager instance
vm_manager = QEMUManager()

@vm_bp.route('/start', methods=['POST'])
def start_vm():
    """Start a new VM instance"""
    try:
        data = request.get_json() or {}
        vm_name = data.get('name', 'Shikra Analysis VM')
        agent_id = data.get('agent_id', 'shikra-agent-001')
        
        # Create VM instance
        vm_config = vm_manager.create_vm_instance(vm_name=vm_name)
        if not vm_config:
            return jsonify({'error': 'Failed to create VM instance'}), 500
        
        # Start the VM
        if vm_manager.start_vm(vm_config['id']):
            # Assign VM to agent in JSON store (store vm_id under agent data)
            agent = agent_store.get_agent(agent_id) or {}
            agent['vm_id'] = vm_config['id']
            agent_store.register_agent(agent_id, agent)
            
            logger.info(f"VM started: {vm_config['id']} for agent {agent_id}")
            
            return jsonify({
                'message': 'VM started successfully',
                'vm_id': vm_config['id'],
                'vm_name': vm_config['name'],
                'vnc_port': vm_config['vnc_port'],
                'ssh_port': vm_config['ssh_port'],
                'status': 'running',
                'vnc_url': vm_manager.get_vm_vnc_url(vm_config['id'])
            }), 200
        else:
            # Clean up if start failed
            vm_manager.cleanup_vm(vm_config['id'])
            return jsonify({'error': 'Failed to start VM'}), 500
            
    except Exception as e:
        logger.error(f"Error starting VM: {e}")
        return jsonify({'error': 'VM start failed'}), 500

@vm_bp.route('/stop', methods=['POST'])
def stop_vm():
    """Stop a VM instance"""
    try:
        data = request.get_json() or {}
        vm_id = data.get('vm_id')
        force = data.get('force', False)
        
        if not vm_id:
            return jsonify({'error': 'VM ID required'}), 400
        
        if vm_manager.stop_vm(vm_id, force=force):
            logger.info(f"VM stopped: {vm_id}")
            
            return jsonify({
                'message': 'VM stopped successfully',
                'vm_id': vm_id,
                'status': 'stopped'
            })
        else:
            return jsonify({'error': 'Failed to stop VM'}), 500
            
    except Exception as e:
        logger.error(f"Error stopping VM: {e}")
        return jsonify({'error': 'VM stop failed'}), 500

@vm_bp.route('/reset', methods=['POST'])
def reset_vm():
    """Reset VM to clean snapshot state"""
    try:
        data = request.get_json() or {}
        vm_id = data.get('vm_id')
        
        if not vm_id:
            return jsonify({'error': 'VM ID required'}), 400
        
        if vm_manager.reset_vm(vm_id):
            logger.info(f"VM reset: {vm_id}")
            
            return jsonify({
                'message': 'VM reset successfully',
                'vm_id': vm_id,
                'status': 'running'
            })
        else:
            return jsonify({'error': 'Failed to reset VM'}), 500
            
    except Exception as e:
        logger.error(f"Error resetting VM: {e}")
        return jsonify({'error': 'VM reset failed'}), 500

@vm_bp.route('/status', methods=['GET'])
def get_vm_status():
    """Get status of all VMs or specific VM"""
    try:
        vm_id = request.args.get('vm_id')
        
        if vm_id:
            # Get specific VM status
            status = vm_manager.get_vm_status(vm_id)
            if status:
                return jsonify({
                    'vm_id': vm_id,
                    'status': status
                })
            else:
                return jsonify({'error': 'VM not found'}), 404
        else:
            # Get all VMs status
            vms = vm_manager.list_vms()
            return jsonify({
                'vms': vms,
                'total': len(vms)
            })
            
    except Exception as e:
        logger.error(f"Error getting VM status: {e}")
        return jsonify({'error': 'Failed to get VM status'}), 500

@vm_bp.route('/cleanup', methods=['POST'])
def cleanup_vm():
    """Clean up VM resources"""
    try:
        data = request.get_json() or {}
        vm_id = data.get('vm_id')
        
        if not vm_id:
            return jsonify({'error': 'VM ID required'}), 400
        
        if vm_manager.cleanup_vm(vm_id):
            logger.info(f"VM cleaned up: {vm_id}")
            
            return jsonify({
                'message': 'VM cleaned up successfully',
                'vm_id': vm_id
            })
        else:
            return jsonify({'error': 'Failed to cleanup VM'}), 500
            
    except Exception as e:
        logger.error(f"Error cleaning up VM: {e}")
        return jsonify({'error': 'VM cleanup failed'}), 500

@vm_bp.route('/vnc/<vm_id>', methods=['GET'])
def get_vnc_info(vm_id):
    """Get VNC connection information for VM"""
    try:
        status = vm_manager.get_vm_status(vm_id)
        if not status:
            return jsonify({'error': 'VM not found'}), 404
        
        if status['status'] != 'running':
            return jsonify({'error': 'VM is not running'}), 400
        
        vnc_url = vm_manager.get_vm_vnc_url(vm_id)
        
        return jsonify({
            'vm_id': vm_id,
            'vnc_url': vnc_url,
            'vnc_port': status['vnc_port'],
            'status': status['status']
        })
        
    except Exception as e:
        logger.error(f"Error getting VNC info for VM {vm_id}: {e}")
        return jsonify({'error': 'Failed to get VNC info'}), 500
