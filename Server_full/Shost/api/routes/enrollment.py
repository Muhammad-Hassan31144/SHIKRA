"""
Enrollment key management for Agent v2.0
Replaces the old Shikra.ini configuration system
"""

from flask import Blueprint, request, jsonify
import logging
import secrets
import hashlib
import time
from datetime import datetime

from ..simple_store import agent_store

logger = logging.getLogger(__name__)
enrollment_bp = Blueprint('enrollment', __name__)

@enrollment_bp.route('/keys/generate', methods=['POST'])
def generate_enrollment_key():
    """
    Generate a new enrollment key for agent registration
    
    Request body:
    {
        "vm_name": "win10-analysis",  # Required
        "description": "Windows 10 analysis VM",  # Optional
        "expires_in_days": 7  # Optional, default 7
    }
    """
    try:
        data = request.get_json() or {}
        
        vm_name = data.get('vm_name')
        if not vm_name:
            return jsonify({'error': 'vm_name is required'}), 400
        
        description = data.get('description', f'Enrollment key for {vm_name}')
        expires_in_days = data.get('expires_in_days', 7)
        
        # Generate enrollment key (secure random token)
        enrollment_key = secrets.token_urlsafe(32)
        
        # Hash the key for storage
        key_hash = hashlib.sha256(enrollment_key.encode()).hexdigest()
        
        # Generate agent_id
        agent_id = f"agent-{vm_name.replace(' ', '-').replace('_', '-').lower()}"
        
        # Calculate expiry
        expiry_timestamp = int(time.time()) + (expires_in_days * 24 * 60 * 60)
        
        # Create agent record with enrollment key
        agent_data = {
            'agent_id': agent_id,
            'vm_name': vm_name,
            'description': description,
            'enrollment_key_hash': key_hash,
            'enrollment_used': False,
            'enrollment_created': datetime.utcnow().isoformat(),
            'enrollment_expires': expiry_timestamp,
            'status': 'awaiting_enrollment'
        }
        
        # Store in agent store
        agent_store.put_agent(agent_id, agent_data)
        
        logger.info(f"Generated enrollment key for VM: {vm_name} (agent_id: {agent_id})")
        
        return jsonify({
            'success': True,
            'enrollment_key': enrollment_key,  # Show ONCE, never again
            'agent_id': agent_id,
            'vm_name': vm_name,
            'expires_at': datetime.fromtimestamp(expiry_timestamp).isoformat(),
            'expires_in_days': expires_in_days,
            'instructions': [
                f"1. Copy enrollment key: {enrollment_key}",
                "2. On Windows VM, run:",
                f"   ShikraAgent.exe --enroll {enrollment_key}",
                "3. Enter Shost URL when prompted:",
                "   http://192.168.100.1:8080/api/v1",
                "4. Agent will auto-create C:\\SecurityHealth\\agent_config.json",
                "5. Start agent: ShikraAgent.exe"
            ]
        }), 201
        
    except Exception as e:
        logger.error(f"Error generating enrollment key: {e}", exc_info=True)
        return jsonify({'error': 'Failed to generate enrollment key'}), 500


@enrollment_bp.route('/keys/list', methods=['GET'])
def list_enrollment_keys():
    """List all enrollment keys (without revealing actual keys)"""
    try:
        agent_store.reload_from_file()
        all_agents = agent_store.get_all_agents()
        
        keys = []
        for agent_id, agent_data in all_agents.items():
            if 'enrollment_key_hash' in agent_data:
                keys.append({
                    'agent_id': agent_id,
                    'vm_name': agent_data.get('vm_name', 'Unknown'),
                    'description': agent_data.get('description', ''),
                    'status': agent_data.get('status', 'unknown'),
                    'used': agent_data.get('enrollment_used', False),
                    'created': agent_data.get('enrollment_created', ''),
                    'expires': agent_data.get('enrollment_expires', 0),
                    'enrolled_hostname': agent_data.get('hostname', '') if agent_data.get('enrollment_used') else None
                })
        
        return jsonify({
            'success': True,
            'enrollment_keys': keys
        })
        
    except Exception as e:
        logger.error(f"Error listing enrollment keys: {e}", exc_info=True)
        return jsonify({'error': 'Failed to list enrollment keys'}), 500


@enrollment_bp.route('/keys/<agent_id>/revoke', methods=['POST'])
def revoke_enrollment_key(agent_id):
    """Revoke an enrollment key"""
    try:
        agent = agent_store.get_agent(agent_id)
        if not agent:
            return jsonify({'error': 'Agent not found'}), 404
        
        if agent.get('enrollment_used'):
            return jsonify({'error': 'Cannot revoke - key already used'}), 400
        
        # Mark as revoked
        agent_store.update_fields(agent_id, {
            'status': 'revoked',
            'revoked_at': datetime.utcnow().isoformat()
        })
        
        logger.info(f"Revoked enrollment key for agent: {agent_id}")
        
        return jsonify({
            'success': True,
            'message': f'Enrollment key for {agent_id} revoked'
        })
        
    except Exception as e:
        logger.error(f"Error revoking enrollment key: {e}", exc_info=True)
        return jsonify({'error': 'Failed to revoke enrollment key'}), 500


@enrollment_bp.route('/status', methods=['GET'])
def enrollment_status():
    """Get enrollment statistics"""
    try:
        agent_store.reload_from_file()
        all_agents = agent_store.get_all_agents()
        
        stats = {
            'total_keys': 0,
            'pending': 0,
            'enrolled': 0,
            'revoked': 0,
            'expired': 0
        }
        
        now = int(time.time())
        
        for agent_id, agent_data in all_agents.items():
            if 'enrollment_key_hash' in agent_data:
                stats['total_keys'] += 1
                
                status = agent_data.get('status', 'unknown')
                if status == 'revoked':
                    stats['revoked'] += 1
                elif agent_data.get('enrollment_used'):
                    stats['enrolled'] += 1
                elif agent_data.get('enrollment_expires', 0) < now:
                    stats['expired'] += 1
                else:
                    stats['pending'] += 1
        
        return jsonify({
            'success': True,
            'statistics': stats
        })
        
    except Exception as e:
        logger.error(f"Error getting enrollment status: {e}", exc_info=True)
        return jsonify({'error': 'Failed to get enrollment status'}), 500
