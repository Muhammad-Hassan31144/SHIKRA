"""
Simple JSON-based analysis storage for Shikra Host
Replaces database-backed AnalysisModel with a file-based store
"""

import json
import os
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional


class SimpleAnalysisStore:
    def __init__(self, storage_path: str = "data/analysis.json"):
        if not os.path.isabs(storage_path):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            storage_path = os.path.join(base_dir, storage_path)
        self.storage_path = storage_path
        os.makedirs(os.path.dirname(storage_path), exist_ok=True)
        self._analyses = self._load()

    def _load(self) -> Dict[str, Any]:
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def _save(self) -> None:
        with open(self.storage_path, 'w') as f:
            json.dump(self._analyses, f, indent=2, default=str)

    def reload_from_file(self) -> bool:
        self._analyses = self._load()
        return True

    def ensure_analysis_for_sample(self, sample_id: str, analysis_id: Optional[str], agent_id: Optional[str] = None) -> str:
        """Ensure an analysis record exists for a sample; return analysis_id."""
        if analysis_id and analysis_id in self._analyses:
            return analysis_id
        # create new or populate given id
        if not analysis_id:
            analysis_id = str(uuid.uuid4())
        self._analyses[analysis_id] = {
            'id': analysis_id,
            'sample_id': sample_id,
            'agent_id': agent_id,
            'status': 'assigned',
            'progress': 0,
            'current_stage': '',
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'artifacts': None
        }
        self._save()
        return analysis_id

    def update_status(self, analysis_id: str, status: str, progress: int = 0, current_stage: str = '') -> bool:
        a = self._analyses.get(analysis_id)
        if not a:
            return False
        a['status'] = status
        a['progress'] = progress
        a['current_stage'] = current_stage
        if status in ['completed', 'failed', 'error']:
            a['completed_at'] = datetime.utcnow().isoformat()
        a['updated_at'] = datetime.utcnow().isoformat()
        self._save()
        return True

    def update_artifacts(self, analysis_id: str, artifacts_path: str, metadata: Dict[str, Any]) -> bool:
        a = self._analyses.get(analysis_id)
        if not a:
            return False
        a['artifacts'] = {
            'path': artifacts_path,
            'metadata': metadata,
            'updated_at': datetime.utcnow().isoformat(),
        }
        a['updated_at'] = datetime.utcnow().isoformat()
        self._save()
        return True

    def get_by_id(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        return self._analyses.get(analysis_id)

    def get_all(self, limit: int = 50, offset: int = 0, status: Optional[str] = None) -> List[Dict[str, Any]]:
        items = list(self._analyses.values())
        if status:
            items = [a for a in items if a.get('status') == status]
        # newest first
        items.sort(key=lambda x: x.get('updated_at', ''), reverse=True)
        return items[offset:offset + limit]

    def get_active_analyses(self) -> List[Dict[str, Any]]:
        return [a for a in self._analyses.values() if a.get('status') in ['assigned', 'running', 'analyzing']]

    def get_statistics(self) -> Dict[str, int]:
        stats = {
            'total': len(self._analyses),
            'assigned': 0,
            'running': 0,
            'analyzing': 0,
            'completed': 0,
            'failed': 0,
            'error': 0,
        }
        for a in self._analyses.values():
            s = a.get('status', 'unknown')
            if s in stats:
                stats[s] += 1
        return stats

    def add_memory_dump_trigger(self, sample_id: str, trigger_type: str, score: int, reason: str, dump_path: str) -> bool:
        """Record a memory dump trigger event"""
        # Find or create analysis for this sample
        analysis_id = None
        for aid, analysis in self._analyses.items():
            if analysis.get('sample_id') == sample_id:
                analysis_id = aid
                break
        
        if not analysis_id:
            analysis_id = self.ensure_analysis_for_sample(sample_id, None, None)
        
        a = self._analyses.get(analysis_id)
        if not a:
            return False
        
        if 'memory_dumps' not in a:
            a['memory_dumps'] = []
        
        trigger_event = {
            'timestamp': datetime.utcnow().isoformat(),
            'trigger_type': trigger_type,
            'score': score,
            'reason': reason,
            'dump_path': dump_path
        }
        
        a['memory_dumps'].append(trigger_event)
        a['updated_at'] = datetime.utcnow().isoformat()
        self._save()
        return True


# Global instance
analysis_store = SimpleAnalysisStore()
