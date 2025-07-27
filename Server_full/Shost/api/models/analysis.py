"""
Database model for analysis management
"""

import sqlite3
import logging
import json
from datetime import datetime
from database.init_db import get_database_connection

logger = logging.getLogger(__name__)

class AnalysisModel:
    """Database model for analysis results and progress"""
    
    @staticmethod
    def create(sample_id, agent_id, status='created'):
        """Create a new analysis record"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    INSERT INTO analysis_results 
                    (sample_id, agent_id, status, progress, current_stage)
                    VALUES (?, ?, ?, 0, 'initialized')
                ''', (sample_id, agent_id, status))
                
                analysis_id = cursor.lastrowid
                conn.commit()
                
                logger.info(f"Analysis created: {analysis_id} for sample {sample_id}")
                return analysis_id
                
        except Exception as e:
            logger.error(f"Failed to create analysis for sample {sample_id}: {e}")
            return None
    
    @staticmethod
    def get_by_id(analysis_id):
        """Get analysis by ID"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM analysis_results WHERE id = ?
                ''', (analysis_id,))
                
                row = cursor.fetchone()
                if row:
                    result = dict(row)
                    # Parse JSON fields
                    if result.get('hook_statistics'):
                        try:
                            result['hook_statistics'] = json.loads(result['hook_statistics'])
                        except json.JSONDecodeError:
                            pass
                    return result
                return None
                
        except Exception as e:
            logger.error(f"Failed to get analysis {analysis_id}: {e}")
            return None
    
    @staticmethod
    def get_by_sample_id(sample_id):
        """Get analysis by sample ID"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT * FROM analysis_results 
                    WHERE sample_id = ? 
                    ORDER BY created_at DESC
                    LIMIT 1
                ''', (sample_id,))
                
                row = cursor.fetchone()
                if row:
                    result = dict(row)
                    # Parse JSON fields
                    if result.get('hook_statistics'):
                        try:
                            result['hook_statistics'] = json.loads(result['hook_statistics'])
                        except json.JSONDecodeError:
                            pass
                    return result
                return None
                
        except Exception as e:
            logger.error(f"Failed to get analysis for sample {sample_id}: {e}")
            return None
    
    @staticmethod
    def get_all(limit=50, offset=0, status=None):
        """Get all analysis records"""
        try:
            with get_database_connection() as conn:
                if status:
                    cursor = conn.execute('''
                        SELECT a.*, s.filename, s.original_filename, ag.name as agent_name
                        FROM analysis_results a
                        JOIN samples s ON a.sample_id = s.id
                        JOIN agents ag ON a.agent_id = ag.id
                        WHERE a.status = ?
                        ORDER BY a.created_at DESC
                        LIMIT ? OFFSET ?
                    ''', (status, limit, offset))
                else:
                    cursor = conn.execute('''
                        SELECT a.*, s.filename, s.original_filename, ag.name as agent_name
                        FROM analysis_results a
                        JOIN samples s ON a.sample_id = s.id
                        JOIN agents ag ON a.agent_id = ag.id
                        ORDER BY a.created_at DESC
                        LIMIT ? OFFSET ?
                    ''', (limit, offset))
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    # Parse JSON fields
                    if result.get('hook_statistics'):
                        try:
                            result['hook_statistics'] = json.loads(result['hook_statistics'])
                        except json.JSONDecodeError:
                            pass
                    results.append(result)
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to get analysis records: {e}")
            return []
    
    @staticmethod
    def update_status(sample_id, agent_id, status, progress=None, current_stage=None):
        """Update analysis status"""
        try:
            with get_database_connection() as conn:
                # Build update query dynamically
                fields = ['status = ?', 'updated_at = CURRENT_TIMESTAMP']
                values = [status]
                
                if progress is not None:
                    fields.append('progress = ?')
                    values.append(progress)
                
                if current_stage is not None:
                    fields.append('current_stage = ?')
                    values.append(current_stage)
                
                # Add WHERE clause values
                values.extend([sample_id, agent_id])
                
                query = f'''
                    UPDATE analysis_results 
                    SET {', '.join(fields)}
                    WHERE sample_id = ? AND agent_id = ?
                '''
                
                cursor = conn.execute(query, values)
                conn.commit()
                
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to update analysis status for sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def update_artifacts(sample_id, agent_id, artifacts_path=None, metadata=None):
        """Update analysis artifacts and metadata"""
        try:
            with get_database_connection() as conn:
                # Build update query
                fields = ['updated_at = CURRENT_TIMESTAMP']
                values = []
                
                if artifacts_path:
                    fields.append('artifacts_path = ?')
                    values.append(artifacts_path)
                
                if metadata:
                    fields.append('behavior_summary = ?')
                    values.append(json.dumps(metadata) if isinstance(metadata, dict) else str(metadata))
                
                # Add WHERE clause values
                values.extend([sample_id, agent_id])
                
                query = f'''
                    UPDATE analysis_results 
                    SET {', '.join(fields)}
                    WHERE sample_id = ? AND agent_id = ?
                '''
                
                cursor = conn.execute(query, values)
                conn.commit()
                
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to update artifacts for sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def update_memory_dump(sample_id, agent_id, dump_path):
        """Update memory dump path"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE analysis_results 
                    SET memory_dump_path = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE sample_id = ? AND agent_id = ?
                ''', (dump_path, sample_id, agent_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to update memory dump for sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def update_hook_statistics(sample_id, agent_id, statistics):
        """Update hook engine statistics"""
        try:
            stats_json = json.dumps(statistics) if isinstance(statistics, dict) else str(statistics)
            
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE analysis_results 
                    SET hook_statistics = ?, updated_at = CURRENT_TIMESTAMP 
                    WHERE sample_id = ? AND agent_id = ?
                ''', (stats_json, sample_id, agent_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to update hook statistics for sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def set_error(sample_id, agent_id, error_message):
        """Set analysis error status"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    UPDATE analysis_results 
                    SET status = 'error', 
                        error_message = ?, 
                        updated_at = CURRENT_TIMESTAMP 
                    WHERE sample_id = ? AND agent_id = ?
                ''', (error_message, sample_id, agent_id))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to set error for sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def delete_by_sample_id(sample_id):
        """Delete analysis records for a sample"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    DELETE FROM analysis_results WHERE sample_id = ?
                ''', (sample_id,))
                
                conn.commit()
                return cursor.rowcount > 0
                
        except Exception as e:
            logger.error(f"Failed to delete analysis records for sample {sample_id}: {e}")
            return False
    
    @staticmethod
    def get_active_analyses():
        """Get currently active analyses"""
        try:
            with get_database_connection() as conn:
                cursor = conn.execute('''
                    SELECT a.*, s.filename, s.original_filename, ag.name as agent_name
                    FROM analysis_results a
                    JOIN samples s ON a.sample_id = s.id
                    JOIN agents ag ON a.agent_id = ag.id
                    WHERE a.status IN ('assigned', 'downloading', 'running', 'analyzing')
                    ORDER BY a.created_at DESC
                ''')
                
                results = []
                for row in cursor.fetchall():
                    result = dict(row)
                    # Parse JSON fields
                    if result.get('hook_statistics'):
                        try:
                            result['hook_statistics'] = json.loads(result['hook_statistics'])
                        except json.JSONDecodeError:
                            pass
                    results.append(result)
                
                return results
                
        except Exception as e:
            logger.error(f"Failed to get active analyses: {e}")
            return []
    
    @staticmethod
    def get_statistics():
        """Get analysis statistics"""
        try:
            with get_database_connection() as conn:
                # Total analyses
                cursor = conn.execute('SELECT COUNT(*) FROM analysis_results')
                total = cursor.fetchone()[0]
                
                # By status
                cursor = conn.execute('''
                    SELECT status, COUNT(*) 
                    FROM analysis_results 
                    GROUP BY status
                ''')
                by_status = dict(cursor.fetchall())
                
                # Completed in last 24 hours
                cursor = conn.execute('''
                    SELECT COUNT(*) 
                    FROM analysis_results 
                    WHERE status = 'completed' 
                    AND updated_at > datetime('now', '-24 hours')
                ''')
                recent_completed = cursor.fetchone()[0]
                
                # Average completion time (for completed analyses)
                cursor = conn.execute('''
                    SELECT AVG(
                        (julianday(updated_at) - julianday(created_at)) * 24 * 60
                    ) as avg_minutes
                    FROM analysis_results 
                    WHERE status = 'completed'
                ''')
                avg_time_row = cursor.fetchone()
                avg_completion_time = avg_time_row[0] if avg_time_row[0] else 0
                
                return {
                    'total': total,
                    'by_status': by_status,
                    'recent_completed': recent_completed,
                    'avg_completion_time_minutes': round(avg_completion_time, 2) if avg_completion_time else 0
                }
                
        except Exception as e:
            logger.error(f"Failed to get analysis statistics: {e}")
            return {}
