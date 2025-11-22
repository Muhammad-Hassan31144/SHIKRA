"""
VM Snapshot API routes
Provides REST endpoints for snapshot management
"""

from flask import Blueprint, request, jsonify
import logging
from vm_manager.snapshot_manager import get_snapshot_manager
from config.config import Config

logger = logging.getLogger(__name__)
snapshot_bp = Blueprint('snapshots', __name__)

@snapshot_bp.route('/create', methods=['POST'])
def create_snapshot():
    """Create a VM snapshot"""
    try:
        data = request.get_json() or {}
        vm_name = data.get('vm_name')
        snapshot_name = data.get('snapshot_name')
        description = data.get('description')
        
        if not vm_name:
            return jsonify({'error': 'Missing vm_name parameter'}), 400
        
        manager = get_snapshot_manager()
        result = manager.create_snapshot(vm_name, snapshot_name, description)
        
        return jsonify(result), 200
        
    except RuntimeError as e:
        logger.error(f"Failed to create snapshot: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error creating snapshot: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@snapshot_bp.route('/restore', methods=['POST'])
def restore_snapshot():
    """Restore a VM to a snapshot"""
    try:
        data = request.get_json() or {}
        vm_name = data.get('vm_name')
        snapshot_name = data.get('snapshot_name')
        
        if not vm_name:
            return jsonify({'error': 'Missing vm_name parameter'}), 400
        
        manager = get_snapshot_manager()
        result = manager.restore_snapshot(vm_name, snapshot_name)
        
        return jsonify(result), 200
        
    except RuntimeError as e:
        logger.error(f"Failed to restore snapshot: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error restoring snapshot: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@snapshot_bp.route('/list/<vm_name>', methods=['GET'])
def list_snapshots(vm_name):
    """List all snapshots for a VM"""
    try:
        manager = get_snapshot_manager()
        snapshots = manager.list_snapshots(vm_name)
        
        return jsonify({
            'vm_name': vm_name,
            'snapshots': snapshots,
            'count': len(snapshots)
        }), 200
        
    except Exception as e:
        logger.error(f"Error listing snapshots: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@snapshot_bp.route('/status/<vm_name>', methods=['GET'])
def get_snapshot_status(vm_name):
    """Get comprehensive snapshot status for a VM"""
    try:
        manager = get_snapshot_manager()
        status = manager.get_snapshot_status(vm_name)
        
        return jsonify(status), 200
        
    except Exception as e:
        logger.error(f"Error getting snapshot status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@snapshot_bp.route('/delete', methods=['POST'])
def delete_snapshot():
    """Delete a VM snapshot"""
    try:
        data = request.get_json() or {}
        vm_name = data.get('vm_name')
        snapshot_name = data.get('snapshot_name')
        
        if not vm_name or not snapshot_name:
            return jsonify({'error': 'Missing vm_name or snapshot_name parameter'}), 400
        
        manager = get_snapshot_manager()
        result = manager.delete_snapshot(vm_name, snapshot_name)
        
        return jsonify(result), 200
        
    except RuntimeError as e:
        logger.error(f"Failed to delete snapshot: {e}")
        return jsonify({'error': str(e)}), 500
    except Exception as e:
        logger.error(f"Unexpected error deleting snapshot: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@snapshot_bp.route('/current/<vm_name>', methods=['GET'])
def get_current_snapshot(vm_name):
    """Get the current snapshot name for a VM"""
    try:
        manager = get_snapshot_manager()
        current = manager.get_current_snapshot(vm_name)
        
        return jsonify({
            'vm_name': vm_name,
            'current_snapshot': current
        }), 200
        
    except Exception as e:
        logger.error(f"Error getting current snapshot: {e}")
        return jsonify({'error': 'Internal server error'}), 500
