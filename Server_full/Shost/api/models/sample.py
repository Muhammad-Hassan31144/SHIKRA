"""
Database model for sample management
"""

import sqlite3
import logging
from datetime import datetime
from database.init_db import get_database_connection

logger = logging.getLogger(__name__)

class SampleModel:
    """Database model for malware samples"""
    
    @staticmethod
    def create(sample_id, filename, original_filename, file_hash, file_size, file_path, file_type=None):
        """Create a new sample record"""
        try:
            with get_database_connection() as conn:
                conn.execute('''
                    INSERT INTO samples 
                    (id, filename, original_filename, file_hash, file_size, file_path, file_type, status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
                ''', (sample_id, filename, original_filename, file_hash, file_size, file_path, file_type))
                
                conn.commit()
                logger.info(f"Sample created: {sample_id}")
                return True
                
        except sqlite3.IntegrityError as e:
            logger.warning(f"Sample creation failed (duplicate?): {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to create sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def get_by_id(sample_id):
        """Get sample by ID"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM samples WHERE id = ?
                ''', (sample_id,))
                
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get sample {sample_id}: {e}")
            return None
    
    @staticmethod
    def get_by_hash(file_hash):
        """Get sample by file hash"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM samples WHERE file_hash = ?
                ''', (file_hash,))
                
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get sample by hash {file_hash}: {e}")
            return None
    
    @staticmethod
    def get_all(status=None, limit=50, offset=0):
        """Get all samples with optional filtering"""
        try:
            with get_database_connection() as conn:
                if status:
                    cursor = conn.execute('''
                        SELECT * FROM samples 
                        WHERE status = ? 
                        ORDER BY uploaded_at DESC 
                        LIMIT ? OFFSET ?
                    ''', (status, limit, offset))
                else:
                    cursor = conn.execute('''
                        SELECT * FROM samples 
                        ORDER BY uploaded_at DESC 
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get samples: {e}")
            return []
    
    @staticmethod
    def get_next_pending():
        """Get next pending sample for analysis"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM samples 
                    WHERE status = 'pending' 
                    ORDER BY uploaded_at ASC 
                    LIMIT 1
                ''')
                
                row = cursor.fetchone()
                if row:
                    return dict(row)
                return None
                
        except Exception as e:
            logger.error(f"Failed to get next pending sample: {e}")
            return None
    
    @staticmethod
    def update_status(sample_id, status):
        """Update sample status"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE samples 
                    SET status = ? 
                    WHERE id = ?
                ''', (status, sample_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to update sample status {sample_id}: {e}")
            return False
    
    @staticmethod
    def assign_to_agent(sample_id, agent_id):
        """Assign sample to agent"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE samples 
                    SET assigned_agent = ?, 
                        status = CASE WHEN ? IS NOT NULL THEN 'assigned' ELSE 'pending' END,
                        analysis_started_at = CASE WHEN ? IS NOT NULL THEN CURRENT_TIMESTAMP ELSE NULL END
                    WHERE id = ?
                ''', (agent_id, agent_id, agent_id, sample_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to assign sample {sample_id} to agent {agent_id}: {e}")
            return False
    
    @staticmethod
    def mark_completed(sample_id):
        """Mark sample analysis as completed"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE samples 
                    SET status = 'completed', analysis_completed_at = CURRENT_TIMESTAMP 
                    WHERE id = ?
                ''', (sample_id,))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to mark sample completed {sample_id}: {e}")
            return False
    
    @staticmethod
    def delete(sample_id):
        """Delete sample record"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    DELETE FROM samples WHERE id = ?
                ''', (sample_id,))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to delete sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def get_by_agent(agent_id):
        """Get samples assigned to specific agent"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM samples 
                    WHERE assigned_agent = ? 
                    ORDER BY analysis_started_at DESC
                ''', (agent_id,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except Exception as e:
            logger.error(f"Failed to get samples for agent {agent_id}: {e}")
            return []
    
    @staticmethod
    def get_statistics():
        """Get sample statistics"""
        try:
            with get_database_connection() as conn:
                # Total samples
                cursor = conn.execute('SELECT COUNT(*) FROM samples')
                total = cursor.fetchone()[0]
                
                # By status
                cursor = conn.execute('''
                    SELECT status, COUNT(*) 
                    FROM samples 
                    GROUP BY status
                ''')
                by_status = dict(cursor.fetchall())
                
                # By file type
                cursor = conn.execute('''
                    SELECT file_type, COUNT(*) 
                    FROM samples 
                    WHERE file_type IS NOT NULL
                    GROUP BY file_type
                ''')
                by_type = dict(cursor.fetchall())
                
                # Recent uploads (last 24 hours)
                cursor = conn.execute('''
                    SELECT COUNT(*) 
                    FROM samples 
                    WHERE uploaded_at > datetime('now', '-24 hours')
                ''')
                recent_uploads = cursor.fetchone()[0]
                
                # Total file size
                cursor = conn.execute('SELECT SUM(file_size) FROM samples')
                total_size = cursor.fetchone()[0] or 0
                
                return {
                    'total': total,
                    'by_status': by_status,
                    'by_type': by_type,
                    'recent_uploads': recent_uploads,
                    'total_size': total_size
                }
                
        except Exception as e:
            logger.error(f"Failed to get sample statistics: {e}")
            return {}
    
    @staticmethod
    def update_metadata(sample_id, metadata):
        """Update sample metadata"""
        try:
            import json
            metadata_str = json.dumps(metadata) if metadata else None
            
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE samples 
                    SET metadata = ? 
                    WHERE id = ?
                ''', (metadata_str, sample_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to update metadata for sample {sample_id}: {e}")
            return False
