"""
VM Config API - Agent v2.0 (enrollment keys only)
"""
import subprocess
from flask import Blueprint, request, jsonify

vm_config_bp = Blueprint('vm_config', __name__)

@vm_config_bp.route('/vms', methods=['GET'])
def list_available_vms():
    """List VMs from libvirt"""
    try:
        result = subprocess.run(['virsh', 'list', '--all'], 
                              capture_output=True, text=True, check=True)
        vms = []
        for line in result.stdout.strip().split('\n')[2:]:
            if line.strip():
                parts = line.split()
                if len(parts) >= 3:
                    vms.append({'id': parts[0], 'name': parts[1], 'state': ' '.join(parts[2:])})
        return jsonify({'success': True, 'vms': vms})
    except:
        return jsonify({'success': False, 'vms': []}), 500

@vm_config_bp.route('/create', methods=['POST'])
def create_vm_config():
    return jsonify({'error': 'DEPRECATED - Use /api/v1/enrollment/keys/generate'}), 410

@vm_config_bp.route('/download/<filename>', methods=['GET'])
def download_config_file(filename):
    return jsonify({'error': 'DEPRECATED'}), 410

@vm_config_bp.route('/list', methods=['GET'])
def list_vm_configs():
    return jsonify({'error': 'DEPRECATED'}), 410

@vm_config_bp.route('/templates', methods=['GET'])
def get_templates():
    return jsonify({'error': 'DEPRECATED'}), 410
