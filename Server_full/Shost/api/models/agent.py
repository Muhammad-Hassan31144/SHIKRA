"""
Database model for agent management
"""

import sqlite3
import logging
from datetime import datetime
from database.init_db import get_database_connection

logger = logging.getLogger(__name__)

class AgentModel:
    """Database model for Shikra agents"""
    
    @staticmethod
    def create(agent_id, name, secret_key, capabilities='', vm_id=None):
        """Create a new agent record"""
        try:
            with get_database_connection() as conn:
                conn.execute('''
                    INSERT INTO agents (id, name, secret_key, capabilities, vm_id, status)
                    VALUES (?, ?, ?, ?, ?, 'offline')
                ''', (agent_id, name, secret_key, capabilities, vm_id))
                
                conn.commit()
                logger.info(f"Agent created: {agent_id}")
                return True
                
        except sqlite3.IntegrityError:
            logger.warning(f"Agent already exists: {agent_id}")
            return False
        except Exception as e:
            logger.error(f"Failed to create agent {agent_id}: {e}")
            return False
    
    @staticmethod
    def get_by_id(agent_id):
        """Get agent by ID"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM agents WHERE id = ?
                ''', (agent_id,))
                
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get agent {agent_id}: {e}")
            return None
    
    @staticmethod
    def get_all(status=None):
        """Get all agents with optional status filter"""
        try:
            with get_database_connection() as conn:
                if status:
                    cursor = conn.execute('''
                        SELECT * FROM agents WHERE status = ? ORDER BY created_at DESC
                    ''', (status,))
                else:
                    cursor = conn.execute('''
                        SELECT * FROM agents ORDER BY created_at DESC
                    ''')
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get agents: {e}")
            return []
    
    @staticmethod
    def update_status(agent_id, status):
        """Update agent status"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE agents 
                    SET status = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (status, agent_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to update agent status {agent_id}: {e}")
            return False
    
    @staticmethod
    def update_last_seen(agent_id):
        """Update agent last seen timestamp"""
        try:
            with get_database_connection() as conn:
                conn.execute('''
                    UPDATE agents 
                    SET last_seen = CURRENT_TIMESTAMP, status = 'online' 
                    WHERE id = ?
                ''', (agent_id,))
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update last seen for agent {agent_id}: {e}")
            return False
    
    @staticmethod
    def assign_vm(agent_id, vm_id):
        """Assign VM to agent"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE agents 
                    SET vm_id = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (vm_id, agent_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to assign VM to agent {agent_id}: {e}")
            return False
    
    @staticmethod
    def update_ip_address(agent_id, ip_address):
        """Update agent IP address"""
        try:
            with get_database_connection() as conn:
                conn.execute('''
                    UPDATE agents 
                    SET ip_address = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (ip_address, agent_id))
                
                conn.commit()
                return True
                
        except Exception as e:
            logger.error(f"Failed to update IP for agent {agent_id}: {e}")
            return False
    
    @staticmethod
    def delete(agent_id):
        """Delete agent record"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    DELETE FROM agents WHERE id = ?
                ''', (agent_id,))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to delete agent {agent_id}: {e}")
            return False
    
    @staticmethod
    def get_online_agents():
        """Get all online agents"""
        return AgentModel.get_all(status='online')
    
    @staticmethod
    def get_statistics():
        """Get agent statistics"""
        try:
            with get_database_connection() as conn:
                # Total agents
                cursor = conn.execute('SELECT COUNT(*) FROM agents')
                total = cursor.fetchone()[0]
                
                # By status
                cursor = conn.execute('''
                    SELECT status, COUNT(*) 
                    FROM agents 
                    GROUP BY status
                ''')
                by_status = dict(cursor.fetchall())
                
                # Recently active (last 24 hours)
                cursor = conn.execute('''
                    SELECT COUNT(*) 
                    FROM agents 
                    WHERE last_seen > datetime('now', '-24 hours')
                ''')
                recent_active = cursor.fetchone()[0]
                
                return {
                    'total': total,
                    'by_status': by_status,
                    'recent_active': recent_active
                }
                
        except Exception as e:
            logger.error(f"Failed to get agent statistics: {e}")
            return {}
