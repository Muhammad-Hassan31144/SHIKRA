"""
Analysis management routes for Shikra Host API
"""

from flask import Blueprint, request, jsonify
import logging

from ..simple_analysis_store import analysis_store
from ..auth import require_agent_auth
from ..simple_sample_store import sample_store
from ..simple_sample_store import sample_store

logger = logging.getLogger(__name__)
analysis_bp = Blueprint('analysis', __name__)

@analysis_bp.route('', methods=['GET'])
@analysis_bp.route('/', methods=['GET'])
def list_analyses():
    """List analysis results (JSON store)"""
    try:
        status = request.args.get('status')
        limit = int(request.args.get('limit', 50))
        offset = int(request.args.get('offset', 0))
        analyses = analysis_store.get_all(limit=limit, offset=offset, status=status)
        return jsonify({
            'analyses': analyses,
            'total': len(analyses),
            'limit': limit,
            'offset': offset
        })
    except Exception as e:
        logger.error(f"Error listing analyses: {e}")
        return jsonify({'error': 'Failed to list analyses'}), 500

@analysis_bp.route('/<string:analysis_id>', methods=['GET'])
def get_analysis(analysis_id):
    """Get specific analysis details (JSON store)"""
    try:
        analysis = analysis_store.get_by_id(analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        return jsonify(analysis)
    except Exception as e:
        logger.error(f"Error getting analysis {analysis_id}: {e}")
        return jsonify({'error': 'Failed to get analysis'}), 500

@analysis_bp.route('/active', methods=['GET'])
def get_active_analyses():
    """Get currently active analyses (JSON store)"""
    try:
        analyses = analysis_store.get_active_analyses()
        return jsonify({
            'active_analyses': analyses,
            'count': len(analyses)
        })
    except Exception as e:
        logger.error(f"Error getting active analyses: {e}")
        return jsonify({'error': 'Failed to get active analyses'}), 500

@analysis_bp.route('/stats', methods=['GET'])
def get_analysis_stats():
    """Get analysis statistics (JSON store)"""
    try:
        stats = analysis_store.get_statistics()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Error getting analysis stats: {e}")
        return jsonify({'error': 'Failed to get statistics'}), 500

@analysis_bp.route('/<string:analysis_id>/trigger-dump', methods=['POST'])
def trigger_memory_dump(analysis_id):
    """Trigger memory dump for active analysis (placeholder)"""
    try:
        analysis = analysis_store.get_by_id(analysis_id)
        if not analysis:
            return jsonify({'error': 'Analysis not found'}), 404
        if analysis.get('status') not in ['running', 'analyzing']:
            return jsonify({'error': 'Analysis not in a dump-eligible state'}), 400
        logger.info(f"Memory dump trigger requested for analysis {analysis_id}")
        return jsonify({
            'message': 'Memory dump trigger recorded',
            'analysis_id': analysis_id,
            'sample_id': analysis.get('sample_id')
        })
    except Exception as e:
        logger.error(f"Error triggering memory dump for analysis {analysis_id}: {e}")
        return jsonify({'error': 'Failed to trigger memory dump'}), 500

# New: sample-centric trigger endpoint to match refactored agent
@analysis_bp.route('/sample/<string:sample_id>/dump-trigger', methods=['POST'])
@require_agent_auth
def trigger_dump_for_sample(sample_id: str):
    try:
        agent_id = request.agent_id
        s = sample_store.get_sample(sample_id)
        if not s:
            return jsonify({'error': 'Sample not found'}), 404
        if s.get('assigned_agent') != agent_id:
            return jsonify({'error': 'Sample not assigned to this agent'}), 403

        payload = request.get_json() or {}
        analysis_id = analysis_store.ensure_analysis_for_sample(sample_id, s.get('analysis_id'), agent_id)
        # Record as artifacts metadata extension for now
        triggers = payload
        a = analysis_store.get_by_id(analysis_id) or {}
        meta = (a.get('artifacts') or {}).get('metadata') or {}
        meta_triggers = meta.get('triggers', [])
        meta_triggers.append({
            'timestamp': payload.get('timestamp'),
            'reason': payload.get('reason'),
            'score': payload.get('score'),
            'details': payload.get('details', {}),
        })
        meta['triggers'] = meta_triggers
        analysis_store.update_artifacts(analysis_id, (a.get('artifacts') or {}).get('path') or '', meta)

        logger.info(f"Recorded dump trigger for sample {sample_id} by agent {agent_id}")
        return jsonify({'acknowledged': True, 'analysis_id': analysis_id})
    except Exception as e:
        logger.error(f"Error in sample dump-trigger for {sample_id}: {e}")
        return jsonify({'error': 'Failed to record dump trigger'}), 500
