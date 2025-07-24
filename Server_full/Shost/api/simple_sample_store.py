"""
Simple JSON-based sample storage for Shikra Host
Replaces database with file-based storage for simplicity
"""

import json
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

class SimpleSampleStore:
    def __init__(self, storage_path: str = "data/samples.json"):
        if not os.path.isabs(storage_path):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            storage_path = os.path.join(base_dir, storage_path)
        self.storage_path = storage_path
        self.ensure_storage_directory()
        self._samples = self.load_samples()
    
    def ensure_storage_directory(self):
        """Ensure the storage directory exists"""
        os.makedirs(os.path.dirname(self.storage_path), exist_ok=True)
    
    def load_samples(self) -> Dict[str, Any]:
        """Load samples from JSON file"""
        if os.path.exists(self.storage_path):
            try:
                with open(self.storage_path, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def save_samples(self):
        """Save samples to JSON file"""
        try:
            with open(self.storage_path, 'w') as f:
                json.dump(self._samples, f, indent=2, default=str)
        except IOError as e:
            raise Exception(f"Failed to save samples: {e}")
    
    def reload_from_file(self):
        """Reload samples from JSON file (for manual edits)"""
        self._samples = self.load_samples()
        return True
    
    def add_sample(self, filename: str, file_path: str, file_hash: str, file_size: int) -> str:
        """Add a new sample"""
        sample_id = str(uuid.uuid4())
        
        sample_data = {
            'id': sample_id,
            'filename': filename,
            'file_path': file_path,
            'file_hash': file_hash,
            'file_size': file_size,
            'status': 'pending',
            'assigned_agent': None,
            'analysis_id': None,
            'uploaded_at': datetime.utcnow().isoformat(),
            'assigned_at': None,
            'completed_at': None,
            'priority': 5,  # Default priority
            'retries': 0,
            'max_retries': 3
        }
        
        self._samples[sample_id] = sample_data
        self.save_samples()
        
        return sample_id
    
    def get_sample(self, sample_id: str) -> Optional[Dict[str, Any]]:
        """Get sample by ID"""
        return self._samples.get(sample_id)
    
    def list_samples(self, status: str = None, limit: int = 100) -> List[Dict[str, Any]]:
        """List samples, optionally filtered by status"""
        samples = list(self._samples.values())
        
        if status:
            samples = [s for s in samples if s.get('status') == status]
        
        # Sort by uploaded_at (newest first)
        samples.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)
        
        return samples[:limit]
    
    def get_next_pending_sample(self) -> Optional[Dict[str, Any]]:
        """Get the next pending sample for assignment"""
        pending_samples = [
            s for s in self._samples.values() 
            if s.get('status') == 'pending' and s.get('retries', 0) < s.get('max_retries', 3)
        ]
        
        if not pending_samples:
            return None
        
        # Sort by priority (lower number = higher priority) then by upload time
        pending_samples.sort(key=lambda x: (x.get('priority', 5), x.get('uploaded_at', '')))
        
        return pending_samples[0]

    def get_active_for_agent(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Return a currently active (assigned/downloading/running) sample for this agent, if any."""
        for s in self._samples.values():
            if s.get('assigned_agent') == agent_id and s.get('status') in ('assigned', 'downloading', 'running'):
                return s
        return None

    def recover_stale_samples(self, timeout_seconds: int = 300) -> int:
        """Reset stale in-progress samples back to pending so they can be reassigned.

        A sample is considered stale if its status is in {assigned, downloading, running}
        and its last update timestamp is older than timeout_seconds.

        Returns the number of samples recovered.
        """
        now = datetime.utcnow()
        recovered = 0
        for s in list(self._samples.values()):
            status = s.get('status')
            if status not in ['assigned', 'downloading', 'running']:
                continue
            ts_str = s.get('updated_at') or s.get('assigned_at') or s.get('uploaded_at')
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str)
            except Exception:
                continue
            age = (now - ts).total_seconds()
            if age > timeout_seconds:
                # Increment retry and reset to pending (clears assignment if under limit)
                self.increment_retry_count(s['id'])
                recovered += 1
        return recovered
    
    def assign_sample_to_agent(self, sample_id: str, agent_id: str) -> bool:
        """Assign sample to an agent"""
        if sample_id not in self._samples:
            return False
        
        sample = self._samples[sample_id]
        if sample.get('status') != 'pending':
            return False
        
        # Generate analysis ID
        analysis_id = str(uuid.uuid4())
        
        sample.update({
            'status': 'assigned',
            'assigned_agent': agent_id,
            'analysis_id': analysis_id,
            'assigned_at': datetime.utcnow().isoformat()
        })
        
        self.save_samples()
        return True
    
    def update_sample_status(self, sample_id: str, status: str, agent_id: str = None) -> bool:
        """Update sample status"""
        if sample_id not in self._samples:
            return False
        
        sample = self._samples[sample_id]
        
        # Validate agent ownership for status updates
        if agent_id and sample.get('assigned_agent') != agent_id:
            return False
        
        sample['status'] = status
        sample['updated_at'] = datetime.utcnow().isoformat()
        
        if status in ['completed', 'failed', 'error']:
            sample['completed_at'] = datetime.utcnow().isoformat()
        elif status == 'running':
            sample['started_at'] = datetime.utcnow().isoformat()
        
        self.save_samples()
        return True
    
    def increment_retry_count(self, sample_id: str) -> bool:
        """Increment retry count for failed sample"""
        if sample_id not in self._samples:
            return False
        
        sample = self._samples[sample_id]
        sample['retries'] = sample.get('retries', 0) + 1
        
        # Reset to pending if under retry limit
        if sample['retries'] < sample.get('max_retries', 3):
            sample.update({
                'status': 'pending',
                'assigned_agent': None,
                'analysis_id': None,
                'assigned_at': None
            })
        else:
            sample['status'] = 'failed_max_retries'
        
        self.save_samples()
        return True
    
    def get_samples_for_agent(self, agent_id: str) -> List[Dict[str, Any]]:
        """Get all samples assigned to a specific agent"""
        return [
            s for s in self._samples.values() 
            if s.get('assigned_agent') == agent_id
        ]
    
    def get_statistics(self) -> Dict[str, int]:
        """Get sample statistics"""
        stats = {
            'total_samples': len(self._samples),
            'pending_samples': 0,
            'assigned_samples': 0,
            'running_samples': 0,
            'completed_samples': 0,
            'failed_samples': 0
        }
        
        for sample in self._samples.values():
            status = sample.get('status', 'unknown')
            if status == 'pending':
                stats['pending_samples'] += 1
            elif status == 'assigned':
                stats['assigned_samples'] += 1
            elif status == 'running':
                stats['running_samples'] += 1
            elif status == 'completed':
                stats['completed_samples'] += 1
            elif status in ['failed', 'error', 'failed_max_retries']:
                stats['failed_samples'] += 1
        
        return stats

# Global instance
sample_store = SimpleSampleStore()
