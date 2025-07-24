"""
Sample management routes for Shikra Host API
Handles sample upload, listing, and management
"""

from flask import Blueprint, request, jsonify, send_file
import os
import uuid
import hashlib
import mimetypes
import logging
from datetime import datetime
from werkzeug.utils import secure_filename

from ..simple_sample_store import sample_store
from ..auth import require_agent_auth
from config.config import Config
# Remove database dependency
# from ..models.sample import SampleModel
from ..simple_analysis_store import analysis_store

logger = logging.getLogger(__name__)
samples_bp = Blueprint('samples', __name__)

def calculate_file_hash(file_path):
    """Calculate SHA256 hash of a file"""
    hash_sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_sha256.update(chunk)
    return hash_sha256.hexdigest()

def validate_file_type(filename):
    """Validate if file type is allowed"""
    _, ext = os.path.splitext(filename.lower())
    return ext in Config.ALLOWED_EXTENSIONS

def get_file_type(filename):
    """Get file type based on extension"""
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type:
        return mime_type
    
    # Fallback for common malware types
    _, ext = os.path.splitext(filename.lower())
    type_map = {
        '.exe': 'application/x-executable',
        '.dll': 'application/x-msdownload',
        '.scr': 'application/x-executable',
        '.com': 'application/x-executable',
        '.bat': 'application/x-bat',
        '.ps1': 'application/x-powershell',
        '.vbs': 'application/x-vbscript',
        '.jar': 'application/java-archive',
        '.zip': 'application/zip',
        '.rar': 'application/x-rar-compressed'
    }
    
    return type_map.get(ext, 'application/octet-stream')

@samples_bp.route('/pending', methods=['GET'])
@require_agent_auth
def get_pending_sample():
    """Return current active or assign next pending sample for the authenticated agent.
    Response shape matches the refactored agent expectations.
    """
    try:
        # request.agent_id is set by require_agent_auth
        agent_id = request.agent_id

        # Always reload for freshness
        sample_store.reload_from_file()

        # One-at-a-time policy: return active first
        active = sample_store.get_active_for_agent(agent_id)
        sample = active if active else sample_store.get_next_pending_sample()
        if not sample:
            return ('', 204)

        if not active:
            if not sample_store.assign_sample_to_agent(sample['id'], agent_id):
                return jsonify({'error': 'Failed to assign sample'}), 500

        # Build response
        return jsonify({
            'id': sample['id'],
            'filename': sample['filename'],
            'sha256': sample['file_hash'],
            'sizeBytes': sample['file_size'],
            'downloadUrl': f"/api/v1/agent/download/{sample['id']}"
        })

    except Exception as e:
        logger.error(f"Error in /samples/pending: {e}")
        return jsonify({'error': 'Internal server error'}), 500

@samples_bp.route('/upload', methods=['POST'])
def upload_sample():
    """Upload a new malware sample"""
    try:
        # Check if file is present
        if 'sample' not in request.files:
            return jsonify({'error': 'No sample file provided'}), 400
        
        file = request.files['sample']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Validate file type
        if not validate_file_type(file.filename):
            return jsonify({
                'error': 'File type not allowed',
                'allowed_types': list(Config.ALLOWED_EXTENSIONS)
            }), 400
        
        # Check file size
        file.seek(0, os.SEEK_END)
        file_size = file.tell()
        file.seek(0)
        
        if file_size > Config.MAX_SAMPLE_SIZE:
            return jsonify({
                'error': 'File too large',
                'max_size': Config.MAX_SAMPLE_SIZE,
                'file_size': file_size
            }), 400
        
        # Generate unique sample ID and secure filename
        sample_id = str(uuid.uuid4())
        original_filename = secure_filename(file.filename)
        safe_filename = f"{sample_id}_{original_filename}"
        
        # Ensure storage directory exists
        os.makedirs(Config.SAMPLE_STORAGE, exist_ok=True)
        
        # Save file
        file_path = os.path.join(Config.SAMPLE_STORAGE, safe_filename)
        file.save(file_path)
        
        # Calculate file hash
        file_hash = calculate_file_hash(file_path)
        
        # Check for duplicate (simple check - we could enhance this)
        existing_samples = sample_store.list_samples()
        for existing in existing_samples:
            if existing.get('file_hash') == file_hash:
                # Remove the duplicate file
                os.remove(file_path)
                return jsonify({
                    'message': 'Sample already exists',
                    'sample_id': existing['id'],
                    'status': existing['status']
                }), 200
        
        # Get file type
        file_type = get_file_type(original_filename)
        
        # Store sample metadata in simple storage
        stored_sample_id = sample_store.add_sample(
            filename=original_filename,
            file_path=file_path,
            file_hash=file_hash,
            file_size=file_size
        )
        
        if stored_sample_id:
            logger.info(f"Sample uploaded: {stored_sample_id} ({original_filename})")
            
            return jsonify({
                'message': 'Sample uploaded successfully',
                'sample_id': stored_sample_id,
                'filename': original_filename,
                'file_hash': file_hash,
                'file_size': file_size,
                'file_type': file_type,
                'status': 'pending'
            }), 201
        else:
            # Remove file if storage failed
            os.remove(file_path)
            return jsonify({'error': 'Failed to store sample metadata'}), 500
            
    except Exception as e:
        logger.error(f"Sample upload error: {e}")
        return jsonify({'error': 'Upload failed'}), 500

@samples_bp.route('', methods=['GET'])
@samples_bp.route('/', methods=['GET'])
def list_samples():
    """List all samples with optional filtering"""
    try:
        # Reload data from file to get latest changes
        sample_store.reload_from_file()
        
        # Get query parameters
        status = request.args.get('status')
        limit = int(request.args.get('limit', 50))
        
        # Get samples from simple storage
        samples = sample_store.list_samples(status=status, limit=limit)
        
        # Format response
        sample_list = []
        for sample in samples:
            sample_data = {
                'id': sample['id'],
                'filename': sample['filename'],
                'file_hash': sample['file_hash'],
                'file_size': sample['file_size'],
                'status': sample['status'],
                'assigned_agent': sample.get('assigned_agent'),
                'uploaded_at': sample['uploaded_at'],
                'assigned_at': sample.get('assigned_at'),
                'completed_at': sample.get('completed_at')
            }
            sample_list.append(sample_data)
        
        return jsonify({
            'samples': sample_list,
            'total': len(sample_list),
            'statistics': sample_store.get_statistics()
        })
        
    except Exception as e:
        logger.error(f"Error listing samples: {e}")
    return jsonify({'error': 'Failed to list samples'}), 500

@samples_bp.route('/<sample_id>/results', methods=['POST'])
@require_agent_auth
def upload_results(sample_id):
    """Upload analysis results (multipart form) for a sample assigned to this agent."""
    try:
        agent_id = request.agent_id
        s = sample_store.get_sample(sample_id)
        if not s:
            return jsonify({'error': 'Sample not found'}), 404
        if s.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403

        # Prepare artifacts directory
        artifacts_dir = os.path.join(Config.ARTIFACT_STORAGE, sample_id)
        os.makedirs(artifacts_dir, exist_ok=True)

        # Save all uploaded files
        saved = []
        for key, file in request.files.items():
            if not file.filename:
                continue
            fname = secure_filename(file.filename)
            fpath = os.path.join(artifacts_dir, fname)
            file.save(fpath)
            saved.append({'field': key, 'filename': fname, 'path': fpath, 'size': os.path.getsize(fpath)})

        # Optional metadata JSON in a field named 'metadata'
        meta = {}
        if 'metadata' in request.form:
            try:
                import json as _json
                meta = _json.loads(request.form['metadata'])
            except Exception:
                meta = {'raw_metadata': request.form['metadata']}

        analysis_id = analysis_store.ensure_analysis_for_sample(sample_id, s.get('analysis_id'), agent_id)
        analysis_store.update_artifacts(analysis_id, artifacts_dir, {'files': saved, **meta})

        # Mark sample as completed if desired
        sample_store.update_sample_status(sample_id, 'completed', agent_id)

        return jsonify({'resultId': analysis_id, 'status': 'received', 'files': [x['filename'] for x in saved]})
    except Exception as e:
        logger.error(f"Error in /samples/{sample_id}/results: {e}")
        return jsonify({'error': 'Failed to upload results'}), 500

@samples_bp.route('/<sample_id>/dump-trigger', methods=['POST'])
@require_agent_auth
def dump_trigger(sample_id):
    """Record a memory dump trigger event for the assigned sample."""
    try:
        agent_id = request.agent_id
        s = sample_store.get_sample(sample_id)
        if not s:
            return jsonify({'error': 'Sample not found'}), 404
        if s.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403

        payload = request.get_json() or {}
        analysis_id = analysis_store.ensure_analysis_for_sample(sample_id, s.get('analysis_id'), agent_id)

        # Append trigger to artifacts metadata
        a = analysis_store.get_by_id(analysis_id) or {}
        meta = (a.get('artifacts') or {}).get('metadata') or {}
        meta_triggers = meta.get('triggers', [])
        
        trigger_entry = {
            'timestamp': payload.get('timestamp'),
            'reason': payload.get('reason'),
            'score': payload.get('score'),
            'details': payload.get('details', {}),
        }
        
        # MEMORY DUMP CAPTURE: Get VM name and trigger dump
        from ..simple_store import agent_store
        import subprocess
        
        agent = agent_store.get_agent(agent_id)
        vm_name = agent.get('vm_name') if agent else None
        
        if vm_name:
            timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            dump_filename = f"{sample_id}_{timestamp_str}.raw"
            dump_path = os.path.join(Config.DUMP_STORAGE, dump_filename)
            
            # Ensure dump directory exists
            os.makedirs(Config.DUMP_STORAGE, exist_ok=True)
            
            logger.info(f"Triggering memory dump for VM: {vm_name}")
            
            try:
                # Execute virsh dump command
                result = subprocess.run(
                    ['virsh', 'dump', vm_name, dump_path, '--memory-only', '--live'],
                    capture_output=True,
                    timeout=60,
                    text=True
                )
                
                if result.returncode == 0:
                    dump_size = os.path.getsize(dump_path) if os.path.exists(dump_path) else 0
                    logger.info(f"Memory dump captured successfully: {dump_path} ({dump_size} bytes)")
                    
                    trigger_entry['dump_captured'] = True
                    trigger_entry['dump_path'] = dump_path
                    trigger_entry['dump_size'] = dump_size
                    trigger_entry['dump_filename'] = dump_filename
                else:
                    logger.error(f"Memory dump failed: {result.stderr}")
                    trigger_entry['dump_captured'] = False
                    trigger_entry['dump_error'] = result.stderr
                    
            except subprocess.TimeoutExpired:
                logger.error(f"Memory dump timed out for VM: {vm_name}")
                trigger_entry['dump_captured'] = False
                trigger_entry['dump_error'] = "Timeout after 60 seconds"
            except Exception as e:
                logger.error(f"Memory dump exception: {e}")
                trigger_entry['dump_captured'] = False
                trigger_entry['dump_error'] = str(e)
        else:
            logger.warning(f"VM name not found for agent {agent_id}, cannot capture memory dump")
            trigger_entry['dump_captured'] = False
            trigger_entry['dump_error'] = "VM name not available"
        
        meta_triggers.append(trigger_entry)
        meta['triggers'] = meta_triggers
        analysis_store.update_artifacts(analysis_id, (a.get('artifacts') or {}).get('path') or '', meta)

        logger.info(f"Dump trigger recorded for sample {sample_id} by agent {agent_id}")
        return jsonify({'acknowledged': True, 'analysis_id': analysis_id, 'dump_captured': trigger_entry.get('dump_captured', False)})
    except Exception as e:
        logger.error(f"Error recording dump trigger for {sample_id}: {e}")
        return jsonify({'error': 'Failed to record dump trigger'}), 500

@samples_bp.route('/<sample_id>', methods=['GET'])
def get_sample(sample_id):
    """Get detailed information about a specific sample"""
    try:
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        response_data = {
            'id': sample['id'],
            'filename': sample['filename'],
            'file_hash': sample['file_hash'],
            'file_size': sample['file_size'],
            'status': sample['status'],
            'assigned_agent': sample.get('assigned_agent'),
            'uploaded_at': sample['uploaded_at'],
            'assigned_at': sample.get('assigned_at'),
            'completed_at': sample.get('completed_at'),
            'file_path': sample['file_path']
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error getting sample {sample_id}: {e}")
        return jsonify({'error': 'Failed to get sample'}), 500

@samples_bp.route('/<sample_id>/download', methods=['GET'])
def download_sample(sample_id):
    """Download a sample file (for authorized users)"""
    try:
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        if not os.path.exists(sample['file_path']):
            return jsonify({'error': 'Sample file not found on disk'}), 404
        
        logger.info(f"Sample downloaded: {sample_id}")
        
        return send_file(
            sample['file_path'],
            as_attachment=True,
            download_name=sample['filename']
        )
        
    except Exception as e:
        logger.error(f"Error downloading sample {sample_id}: {e}")
        return jsonify({'error': 'Download failed'}), 500

@samples_bp.route('/<sample_id>', methods=['DELETE'])
def delete_sample(sample_id):
    """Delete a sample and its associated data"""
    try:
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        # Check if sample is currently being analyzed
        if sample['status'] in ['assigned', 'running', 'downloading']:
            return jsonify({
                'error': 'Cannot delete sample currently being analyzed'
            }), 409
        
        # Delete sample file
        if os.path.exists(sample['file_path']):
            os.remove(sample['file_path'])
        
        # Delete from JSON storage
        sample_store._samples.pop(sample_id, None)
        sample_store.save_samples()
        
        logger.info(f"Sample deleted: {sample_id}")
        return jsonify({'message': 'Sample deleted successfully'})
            
    except Exception as e:
        logger.error(f"Error deleting sample {sample_id}: {e}")
        return jsonify({'error': 'Delete failed'}), 500

@samples_bp.route('/<sample_id>/requeue', methods=['POST'])
def requeue_sample(sample_id):
    """Requeue a sample for analysis"""
    try:
        sample = sample_store.get_sample(sample_id)
        if not sample:
            return jsonify({'error': 'Sample not found'}), 404
        
        # Reset sample status using sample_store
        if sample_store.update_sample_status(sample_id, 'pending'):
            # Clear agent assignment
            sample['assigned_agent'] = None
            sample['analysis_id'] = None
            sample['assigned_at'] = None
            sample_store.save_samples()
            
            logger.info(f"Sample requeued: {sample_id}")
            return jsonify({
                'message': 'Sample requeued successfully',
                'sample_id': sample_id,
                'status': 'pending'
            })
        else:
            return jsonify({'error': 'Failed to requeue sample'}), 500
            
    except Exception as e:
        logger.error(f"Error requeuing sample {sample_id}: {e}")
        return jsonify({'error': 'Requeue failed'}), 500

@samples_bp.route('/stats', methods=['GET'])
def get_sample_stats():
    """Get sample statistics"""
    try:
        stats = sample_store.get_statistics()
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting sample stats: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500
