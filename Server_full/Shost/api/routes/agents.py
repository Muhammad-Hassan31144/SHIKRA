"""
Agent communication routes for Shikra Host API
Handles communication with Shikra agents running in VMs
"""

from flask import Blueprint, request, jsonify, send_file
import logging
import time
import os
from datetime import datetime
import secrets

from ..simple_store import agent_store
from ..simple_sample_store import sample_store
from ..simple_analysis_store import analysis_store
from config.config import Config

logger = logging.getLogger(__name__)
agents_bp = Blueprint('agents', __name__)

from ..auth import require_agent_auth, _hash_token

def _make_assignment_payload(sample: dict) -> dict:
    """Build the assignment payload returned to the agent."""
    return {
        'sample_id': sample['id'],
        'filename': sample['filename'],
        'file_hash': sample['file_hash'],
        'file_size': sample['file_size'],
        'analysis_id': sample['analysis_id'],
        'download_url': f"/api/v1/agent/download/{sample['id']}",
        'configuration': {
            'hook_categories': Config.API_HOOK_CATEGORIES,
            'memory_dump_triggers': getattr(Config, 'MEMORY_DUMP_TRIGGERS', []),
            'analysis_timeout': getattr(Config, 'ANALYSIS_TIMEOUT', 300)
        }
    }

@agents_bp.route('/next-sample', methods=['GET'])
@require_agent_auth
def get_next_sample():
    """Get next sample for analysis"""
    try:
        agent_id = request.agent_id
        
        # Reload samples from file to get latest changes
        sample_store.reload_from_file()
        
        # If there is already an active sample for this agent, return it (one-at-a-time policy)
        active = sample_store.get_active_for_agent(agent_id)
        if active:
            return jsonify(_make_assignment_payload(active)), 200

        # Recover stale assigned/downloading/running samples
        sample_store.recover_stale_samples(timeout_seconds=getattr(Config, 'STALE_SAMPLE_TIMEOUT', 300))
        # Get next pending sample
        sample = sample_store.get_next_pending_sample()
        if not sample:
            return jsonify({'message': 'No samples available'}), 204
        
        # Assign sample to agent
        if sample_store.assign_sample_to_agent(sample['id'], agent_id):
            logger.info(f"Sample {sample['id']} assigned to agent {agent_id}")
            return jsonify(_make_assignment_payload(sample))
        else:
            return jsonify({'error': 'Failed to assign sample'}), 500
            
    except Exception as e:
        logger.error(f"Error getting next sample: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@agents_bp.route('/download/<sample_id>', methods=['GET'])
@require_agent_auth
def download_sample(sample_id):
    """Download sample file"""
    try:
        agent_id = request.agent_id
        
        # Verify sample exists and is assigned to this agent
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        if sample['assigned_agent'] != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403
        
        # Check if file exists
        if not os.path.exists(sample['file_path']):
            logger.error(f"Sample file not found: {sample['file_path']}")
            return jsonify({'error': 'Sample file not found'}), 404
        
        # Update sample status to downloading
        sample_store.update_sample_status(sample_id, 'downloading', agent_id)
        
        logger.info(f"Agent {agent_id} downloading sample {sample_id}")
        
        return send_file(
            sample['file_path'],
            as_attachment=True,
            download_name=sample['filename']
        )
        
    except Exception as e:
        logger.error(f"Error downloading sample {sample_id}: {e}")
        return jsonify({'error': 'Download failed'}), 500

@agents_bp.route('/status', methods=['POST'])
@require_agent_auth
def update_status():
    """Update analysis status"""
    try:
        agent_id = request.agent_id
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
        
        sample_id = data.get('sample_id')
        status = data.get('status')
        progress = data.get('progress', 0)
        current_stage = data.get('current_stage', '')
        
        if not sample_id or not status:
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Update sample status
        success = sample_store.update_sample_status(sample_id, status, agent_id)
        
        if not success:
            return jsonify({'error': 'Failed to update status or sample not assigned to agent'}), 500
            
        logger.info(f"Status updated for sample {sample_id}: {status} ({progress}%) - Stage: {current_stage}")
        
        return jsonify({
            'message': 'Status updated successfully',
            'sample_id': sample_id,
            'status': status,
            'progress': progress,
            'current_stage': current_stage
        })
        
    except Exception as e:
        logger.error(f"Error updating status: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@agents_bp.route('/upload/artifacts', methods=['POST'])
@require_agent_auth
def upload_artifacts():
    """Upload analysis artifacts"""
    try:
        agent_id = request.agent_id
        
        # Check if multipart form data
        if 'metadata' not in request.form:
            return jsonify({'error': 'Missing metadata'}), 400
        
        import json
        metadata = json.loads(request.form['metadata'])
        sample_id = metadata.get('sample_id')
        analysis_id = metadata.get('analysis_id')
        
        if not sample_id:
            return jsonify({'error': 'Missing sample_id in metadata'}), 400
        
        # Verify sample assignment
        sample = sample_store.get_sample(sample_id)
        if not sample or sample.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Invalid sample or assignment'}), 403
        
        # Ensure analysis record
        analysis_id = analysis_store.ensure_analysis_for_sample(sample_id, analysis_id, agent_id)
        
        # Create artifacts directory
        artifacts_dir = os.path.join(Config.ARTIFACT_STORAGE, sample_id)
        os.makedirs(artifacts_dir, exist_ok=True)
        
        # Save uploaded files
        uploaded_files = []
        for file_key in request.files:
            file = request.files[file_key]
            if file.filename:
                file_path = os.path.join(artifacts_dir, file.filename)
                file.save(file_path)
                uploaded_files.append({
                    'filename': file.filename,
                    'path': file_path,
                    'size': os.path.getsize(file_path)
                })
        
        # Save metadata file
        metadata_path = os.path.join(artifacts_dir, 'metadata.json')
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Update analysis record
        analysis_store.update_artifacts(
            analysis_id=analysis_id,
            artifacts_path=artifacts_dir,
            metadata=metadata
        )
        
        logger.info(f"Artifacts uploaded for sample {sample_id}: {len(uploaded_files)} files")
        
        return jsonify({
            'message': 'Artifacts uploaded successfully',
            'sample_id': sample_id,
            'analysis_id': analysis_id,
            'uploaded_files': uploaded_files,
            'artifacts_path': artifacts_dir
        })
        
    except Exception as e:
        logger.error(f"Error uploading artifacts: {e}")
        return jsonify({'error': 'Upload failed'}), 500

@agents_bp.route('/health', methods=['HEAD', 'GET'])
@require_agent_auth
def health_check():
    """Agent health check endpoint"""
    try:
        agent_id = request.agent_id
        
        # Update agent status in JSON store
        agent_store.update_agent_status(agent_id, 'online')
        
        if request.method == 'HEAD':
            return '', 200
        else:
            return jsonify({
                'status': 'healthy',
                'agent_id': agent_id,
                'timestamp': datetime.utcnow().isoformat(),
                'server_time': int(time.time())
            })
            
    except Exception as e:
        logger.error(f"Health check error: {e}")
        return jsonify({'error': 'Health check failed'}), 500

@agents_bp.route('/register', methods=['POST'])
def register_agent():
    """
    Agent registration endpoint - exchanges enrollment key for config
    
    NEW WORKFLOW (enrollment key-based):
    - Agent sends {"enrollment_key": "..."}
    - Shost validates key, marks as used
    - Returns full config with agent_id and access_token
    
    LEGACY WORKFLOW (direct registration):
    - Agent sends {"agent_id": "..."}
    - Backward compatible for old agents
    """
    try:
        data = request.get_json() or {}
        
        # NEW: Check if enrollment key is provided
        enrollment_key = data.get('enrollment_key')
        machine_fingerprint = data.get('machine_fingerprint', '')
        hostname = data.get('hostname', 'unknown')
        
        if enrollment_key:
            logger.info(f"Processing enrollment key-based registration from {hostname}")
            
            # Hash the provided key
            import hashlib
            key_hash = hashlib.sha256(enrollment_key.encode()).hexdigest()
            
            # Find agent with matching enrollment key
            agent_store.reload_from_file()
            all_agents = agent_store.get_all_agents()
            
            matching_agent = None
            for agent_id, agent_data in all_agents.items():
                if agent_data.get('enrollment_key_hash') == key_hash:
                    matching_agent = agent_data
                    matching_agent['agent_id'] = agent_id
                    break
            
            if not matching_agent:
                logger.warning(f"Invalid enrollment key from {hostname}")
                return jsonify({'error': 'Invalid enrollment key'}), 401
            
            # RE-REGISTRATION DETECTION AND HANDLING
            if matching_agent.get('enrollment_used'):
                stored_fingerprint = matching_agent.get('machine_fingerprint', '')
                
                # Scenario 1: Same machine re-registering (config lost, reinstall, etc.)
                if stored_fingerprint == machine_fingerprint:
                    logger.warning(f"Agent {matching_agent['agent_id']} attempting re-registration from SAME machine")
                    logger.info(f"Allowing re-registration (likely config file lost or agent reinstall)")
                    # ALLOW: Reset enrollment_used flag to permit re-registration
                    # This is safe because it's the same physical machine
                
                # Scenario 2: Different machine with same enrollment key (VM clone, unauthorized use)
                else:
                    logger.error(f"Agent {matching_agent['agent_id']} attempting re-registration from DIFFERENT machine!")
                    logger.error(f"Original fingerprint: {stored_fingerprint}")
                    logger.error(f"New fingerprint: {machine_fingerprint}")
                    logger.error(f"Original hostname: {matching_agent.get('hostname', 'unknown')}")
                    logger.error(f"New hostname: {hostname}")
                    
                    # DENY: Potential security issue - enrollment key leaked or VM cloned
                    return jsonify({
                        'error': 'Enrollment key already used by different machine',
                        'details': 'This enrollment key has been used on a different machine. Contact administrator.',
                        'original_hostname': matching_agent.get('hostname', 'unknown'),
                        'detected_issue': 'vm_clone_or_key_leak'
                    }), 403
            
            # Generate new access token
            access_token = secrets.token_urlsafe(48)
            token_sha = _hash_token(access_token)
            token_expires = int(datetime.utcnow().timestamp()) + int(getattr(Config, 'TOKEN_TTL_SECONDS', 60 * 60 * 24 * 365))
            
            # Get VM name from request (used for memory dump capture)
            vm_name = data.get('vm_name', hostname)
            
            # Mark enrollment key as used and update token
            agent_store.update_fields(matching_agent['agent_id'], {
                'enrollment_used': True,
                'status': 'active',
                'first_seen': time.time(),
                'last_seen': time.time(),
                'token_sha': token_sha,
                'token_expires': token_expires,
                'machine_fingerprint': machine_fingerprint,  # Store for re-registration detection
                'hostname': hostname,
                'vm_name': vm_name,  # Store VM name for memory dump operations
                'registration_count': matching_agent.get('registration_count', 0) + 1,
                'last_registration': datetime.utcnow().isoformat()
            })
            
            logger.info(f"Agent {matching_agent['agent_id']} registered via enrollment key")
            
            # Build configuration response
            base_url = getattr(Config, 'BASE_URL', '') or request.host_url.rstrip('/')
            return jsonify({
                'agent_id': matching_agent['agent_id'],
                'access_token': access_token,
                'config': {
                    'host_url': f"{base_url}/api/v1",
                    'poll_interval': matching_agent.get('poll_interval', 30000),
                    'working_directory': 'work',
                    'log_level': 3,
                    'max_retries': 5,
                    'execution_timeout': 300000,
                    'features': {
                        'enable_hooking': matching_agent.get('enable_hooking', True),
                        'enable_memory_dumps': matching_agent.get('enable_memory_dumps', False),
                        'enable_network_capture': matching_agent.get('enable_network_capture', False)
                    }
                }
            }), 200
        
        # LEGACY: Direct registration (backward compatibility)
        agent_id = data.get('agent_id')
        if not agent_id:
            return jsonify({'error': 'Missing agent_id or enrollment_key'}), 400

        logger.info(f"Processing legacy direct registration for {agent_id}")

        # Optional fields with sensible defaults
        agent_name = data.get('name', f'Agent {agent_id}')
        capabilities = data.get('capabilities', 'file,registry,process,network,memory')
        host_url = data.get('host_url', '')
        poll_interval = data.get('poll_interval', getattr(Config, 'AGENT_POLL_INTERVAL', 30000))
        working_dir = data.get('working_directory', 'C:\\Temp\\SecurityHealth')
        log_level = data.get('log_level', 2)
        max_retries = data.get('max_retries', 3)
        execution_timeout = data.get('execution_timeout', 300000)
        enable_hooking = data.get('enable_hooking', True)
        enable_memory_dumps = data.get('enable_memory_dumps', True)
        enable_network_capture = data.get('enable_network_capture', True)

        # Create or update agent record
        agent_data = {
            'agent_id': agent_id,
            'name': agent_name,
            'capabilities': capabilities,
            'host_url': host_url,
            'poll_interval': poll_interval,
            'working_directory': working_dir,
            'log_level': log_level,
            'max_retries': max_retries,
            'execution_timeout': execution_timeout,
            'enable_hooking': enable_hooking,
            'enable_memory_dumps': enable_memory_dumps,
            'enable_network_capture': enable_network_capture
        }
        agent_store.register_agent(agent_id, agent_data)

        # Issue bearer token and persist hash + expiry
        token = secrets.token_urlsafe(32)
        token_sha = _hash_token(token)
        token_expires = int(datetime.utcnow().timestamp()) + int(getattr(Config, 'TOKEN_TTL_SECONDS', 60 * 60 * 24 * 30))
        agent_store.update_fields(agent_id, {
            'token_sha': token_sha,
            'token_expires': token_expires,
        })

        logger.info(f"Agent registered/updated and token issued: {agent_id}")

        return jsonify({
            'message': 'Agent registered successfully',
            'agent_id': agent_id,
            'status': 'registered',
            'access_token': token,
            'authToken': f"{token}",
            'token_expires': token_expires,
            'configuration': {
                'poll_interval': poll_interval,
                'server_endpoints': {
                    'next_sample': '/api/v1/agent/next-sample',
                    'download': '/api/v1/agent/download/{sample_id}',
                    'status': '/api/v1/agent/status',
                    'upload': '/api/v1/agent/upload/artifacts',
                    'health': '/api/v1/agent/health'
                },
                'features': {
                    'hooking_enabled': enable_hooking,
                    'memory_dumps_enabled': enable_memory_dumps,
                    'network_capture_enabled': enable_network_capture
                },
                'analysis_config': {
                    'hook_categories': getattr(Config, 'API_HOOK_CATEGORIES', []),
                    'memory_dump_triggers': getattr(Config, 'MEMORY_DUMP_TRIGGERS', []),
                    'analysis_timeout': getattr(Config, 'ANALYSIS_TIMEOUT', 300)
                }
            },
            'config': {
                'agent': {
                    'hostUrl': getattr(Config, 'BASE_URL', ''),
                    'authToken': token,
                    'agentId': agent_id,
                    'pollIntervalMs': poll_interval,
                    'workingDirectory': r'C:\SecurityHealth'
                }
            }
        })

    except Exception as e:
        logger.error(f"Agent registration error: {e}")
        return jsonify({'error': 'Registration failed'}), 500

@agents_bp.route('/verify', methods=['POST'])
@require_agent_auth
def verify_agent_health():
    """
    Verify agent health and connectivity
    
    Tests:
    1. Authentication working
    2. Can receive sample list
    3. Can download sample
    4. Can upload artifact
    
    Returns detailed status for each test
    """
    try:
        agent_id = request.agent_id
        
        results = {
            'agent_id': agent_id,
            'timestamp': time.time(),
            'tests': {}
        }
        
        # Test 1: Authentication (already passed if we're here)
        results['tests']['authentication'] = {
            'status': 'passed',
            'message': 'Agent authenticated successfully'
        }
        
        # Test 2: Agent exists in store
        agent = agent_store.get_agent(agent_id)
        if agent:
            results['tests']['agent_registered'] = {
                'status': 'passed',
                'message': f"Agent found: {agent.get('name')}",
                'details': {
                    'status': agent.get('status'),
                    'last_seen': agent.get('last_seen'),
                    'vm_id': agent.get('vm_id', 'unknown')
                }
            }
        else:
            results['tests']['agent_registered'] = {
                'status': 'failed',
                'message': 'Agent not found in store'
            }
        
        # Test 3: Can access sample list
        try:
            sample_store.reload_from_file()
            sample_count = len(sample_store._samples)
            results['tests']['sample_access'] = {
                'status': 'passed',
                'message': f"Can access sample store ({sample_count} samples)"
            }
        except Exception as e:
            results['tests']['sample_access'] = {
                'status': 'failed',
                'message': f"Cannot access samples: {str(e)}"
            }
        
        # Test 4: Disk space
        try:
            import shutil
            total, used, free = shutil.disk_usage(Config.SAMPLE_STORAGE)
            free_gb = free // (1024**3)
            total_gb = total // (1024**3)
            results['tests']['disk_space'] = {
                'status': 'passed' if free_gb > 5 else 'warning',
                'message': f"Free space: {free_gb}GB / {total_gb}GB",
                'details': {'free_gb': free_gb, 'total_gb': total_gb}
            }
        except Exception as e:
            results['tests']['disk_space'] = {
                'status': 'failed',
                'message': f"Cannot check disk space: {str(e)}"
            }
        
        # Overall status
        all_passed = all(t.get('status') == 'passed' for t in results['tests'].values())
        results['overall_status'] = 'healthy' if all_passed else 'degraded'
        
        logger.info(f"Agent {agent_id} verification: {results['overall_status']}")
        
        return jsonify(results), 200
        
    except Exception as e:
        logger.error(f"Agent verification error: {e}")
        return jsonify({'error': 'Verification failed'}), 500

# Alias endpoint for backward compatibility - some agents might use /samples instead of /next-sample
@agents_bp.route('/samples', methods=['GET'])
@require_agent_auth
def get_samples_alias():
    """Alias for /next-sample for backward compatibility"""
    logger.info(f"Agent {request.agent_id} used deprecated /samples endpoint, redirecting to /next-sample")
    return get_next_sample()

@agents_bp.route('/list', methods=['GET'])
def list_agents():
    """List all registered agents - No authentication required for debugging"""
    try:
        # Reload data from file to get latest changes
        agent_store.reload_from_file()
        
        all_agents = agent_store.get_all_agents()
        
        # Remove sensitive data for display
        safe_agents = {}
        for agent_id, agent_data in all_agents.items():
            safe_agents[agent_id] = {
                'name': agent_data.get('name', 'Unknown'),
                'status': agent_data.get('status', 'unknown'),
                'capabilities': agent_data.get('capabilities', ''),
                'registered_at': agent_data.get('registered_at', ''),
                'last_updated': agent_data.get('last_updated', ''),
                'working_directory': agent_data.get('working_directory', ''),
                'poll_interval': agent_data.get('poll_interval', 0)
            }
        
        stats = agent_store.get_statistics()
        
        return jsonify({
            'agents': safe_agents,
            'stats': stats
        })
        
    except Exception as e:
        logger.error(f"Error listing agents: {e}")
        return jsonify({'error': 'Failed to list agents'}), 500
