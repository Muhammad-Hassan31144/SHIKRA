"""
Simple JSON-based agent storage - No database required!
Much simpler and easier to debug than SQLite
"""

import json
import os
import logging
from datetime import datetime
from threading import Lock
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

class SimpleAgentStore:
    """Simple JSON file-based agent storage"""
    
    def __init__(self, storage_file="data/agents.json"):
        # Resolve storage path relative to this package if not absolute
        if not os.path.isabs(storage_file):
            base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
            storage_file = os.path.join(base_dir, storage_file)
        self.storage_file = storage_file
        self.lock = Lock()  # Thread safety for concurrent access
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(storage_file), exist_ok=True)
        
        # Load existing agents or initialize empty
        self._agents = self._load_data()
        
        # Initialize empty storage if file doesn't exist
        if not os.path.exists(storage_file):
            self._save_data({})
    
    def _load_data(self):
        """Load agents data from JSON file"""
        try:
            with open(self.storage_file, 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            logger.warning(f"Could not load agents data: {e}, using empty data")
            return {}
    
    def _save_data(self, data):
        """Save agents data to JSON file"""
        try:
            with open(self.storage_file, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except Exception as e:
            logger.error(f"Failed to save agents data: {e}")
            return False
    
    def reload_from_file(self):
        """Reload agents from JSON file (for manual edits)"""
        with self.lock:
            self._agents = self._load_data()
            return True
    
    def register_agent(self, agent_id, agent_data):
        """Register a new agent or update existing one"""
        with self.lock:
            # Add metadata
            now = datetime.now().isoformat()
            agent_data.update({
                'registered_at': now,
                'last_updated': now,
                'status': 'registered'
            })
            
            self._agents[agent_id] = agent_data
            
            if self._save_data(self._agents):
                logger.info(f"Agent registered: {agent_id}")
                return True
            else:
                logger.error(f"Failed to register agent: {agent_id}")
                return False
    
    def get_agent(self, agent_id):
        """Get agent by ID"""
        return self._agents.get(agent_id)

    def put_agent(self, agent_id: str, agent_data: Dict[str, Any]) -> bool:
        """Create or replace an agent record."""
        with self.lock:
            self._agents[agent_id] = agent_data
            return self._save_data(self._agents)

    def update_fields(self, agent_id: str, updates: Dict[str, Any]) -> bool:
        """Update specific fields on an agent record."""
        with self.lock:
            if agent_id not in self._agents:
                return False
            self._agents[agent_id].update(updates)
            self._agents[agent_id]['last_updated'] = datetime.utcnow().isoformat()
            return self._save_data(self._agents)
    
    def get_all_agents(self):
        """Get all registered agents"""
        return dict(self._agents)
    
    def update_agent_status(self, agent_id, status):
        """Update agent status"""
        with self.lock:
            if agent_id in self._agents:
                self._agents[agent_id]['status'] = status
                self._agents[agent_id]['last_updated'] = datetime.now().isoformat()
                
                if self._save_data(self._agents):
                    logger.info(f"Agent status updated: {agent_id} -> {status}")
                    return True
                else:
                    logger.error(f"Failed to update agent status: {agent_id}")
                    return False
            else:
                logger.warning(f"Agent not found for status update: {agent_id}")
                return False
    
    def verify_agent_credentials(self, agent_id, agent_secret):
        """Verify agent credentials"""
        agent = self.get_agent(agent_id)
        if agent and agent.get('agent_secret') == agent_secret:
            # Update last seen
            self.update_agent_status(agent_id, 'active')
            return True
        return False
    
    def remove_agent(self, agent_id):
        """Remove an agent"""
        with self.lock:
            agents = self._load_data()
            
            if agent_id in agents:
                del agents[agent_id]
                
                if self._save_data(agents):
                    logger.info(f"Agent removed: {agent_id}")
                    return True
                else:
                    logger.error(f"Failed to remove agent: {agent_id}")
                    return False
            else:
                logger.warning(f"Agent not found for removal: {agent_id}")
                return False
    
    def update_agent_last_seen(self, agent_id: str) -> bool:
        """Update agent's last seen timestamp"""
        with self.lock:
            if agent_id not in self._agents:
                return False
            
            self._agents[agent_id]['last_updated'] = datetime.utcnow().isoformat()
            return self._save_data(self._agents)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get agent statistics"""
        stats = {
            'total_agents': len(self._agents),
            'registered_agents': len(self._agents),
            'active_agents': 0,  # Could implement based on last_updated time
            'storage_file': self.storage_file,
            'last_updated': datetime.utcnow().isoformat()
        }
        
        return stats

# Global instance
agent_store = SimpleAgentStore()
