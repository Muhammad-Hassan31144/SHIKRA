"""
Database initialization and schema setup for Shikra Host
Simple SQLite database for MVP implementation
"""

import os
import sys
import sqlite3
import logging
from datetime import datetime

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config.config import Config

logger = logging.getLogger(__name__)

def get_database_connection():
    """Get database connection with proper configuration"""
    db_path = Config.DATABASE_PATH
    
    # Ensure directory exists
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row  # Enable column access by name
    conn.execute("PRAGMA foreign_keys = ON")  # Enable foreign key constraints
    
    return conn

def create_tables(conn):
    """Create database tables"""
    
    # Agents table - stores agent information and credentials
    conn.execute('''
        CREATE TABLE IF NOT EXISTS agents (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            secret_key TEXT NOT NULL,
            vm_id TEXT,
            status TEXT DEFAULT 'offline',
            last_seen TIMESTAMP,
            capabilities TEXT,
            ip_address TEXT,
            version TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Samples table - stores malware sample information
    conn.execute('''
        CREATE TABLE IF NOT EXISTS samples (
            id TEXT PRIMARY KEY,
            filename TEXT NOT NULL,
            original_filename TEXT NOT NULL,
            file_hash TEXT UNIQUE NOT NULL,
            file_size INTEGER NOT NULL,
            file_path TEXT NOT NULL,
            file_type TEXT,
            status TEXT DEFAULT 'pending',
            assigned_agent TEXT,
            priority INTEGER DEFAULT 5,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            analysis_started_at TIMESTAMP,
            analysis_completed_at TIMESTAMP,
            metadata TEXT,
            FOREIGN KEY (assigned_agent) REFERENCES agents (id)
        )
    ''')
    
    # Analysis results table - stores analysis progress and results
    conn.execute('''
        CREATE TABLE IF NOT EXISTS analysis_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sample_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            status TEXT NOT NULL,
            progress INTEGER DEFAULT 0,
            current_stage TEXT,
            artifacts_path TEXT,
            memory_dump_path TEXT,
            api_calls_log TEXT,
            behavior_summary TEXT,
            error_message TEXT,
            hook_statistics TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sample_id) REFERENCES samples (id),
            FOREIGN KEY (agent_id) REFERENCES agents (id)
        )
    ''')
    
    # VM instances table - tracks VM status and configuration
    conn.execute('''
        CREATE TABLE IF NOT EXISTS vm_instances (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT DEFAULT 'stopped',
            image_path TEXT NOT NULL,
            snapshot_name TEXT,
            vnc_port INTEGER,
            ssh_port INTEGER,
            ip_address TEXT,
            assigned_agent TEXT,
            current_sample TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            started_at TIMESTAMP,
            stopped_at TIMESTAMP,
            FOREIGN KEY (assigned_agent) REFERENCES agents (id),
            FOREIGN KEY (current_sample) REFERENCES samples (id)
        )
    ''')
    
    # Hook events table - stores API hook events (optional for detailed logging)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS hook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            timestamp TIMESTAMP NOT NULL,
            process_id INTEGER,
            thread_id INTEGER,
            api_name TEXT NOT NULL,
            module_name TEXT,
            parameters TEXT,
            return_value TEXT,
            call_duration INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (analysis_id) REFERENCES analysis_results (id)
        )
    ''')
    
    # System logs table - stores system events and errors
    conn.execute('''
        CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT NOT NULL,
            component TEXT NOT NULL,
            message TEXT NOT NULL,
            details TEXT,
            vm_id TEXT,
            agent_id TEXT,
            sample_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (vm_id) REFERENCES vm_instances (id),
            FOREIGN KEY (agent_id) REFERENCES agents (id),
            FOREIGN KEY (sample_id) REFERENCES samples (id)
        )
    ''')

def create_indexes(conn):
    """Create database indexes for better performance"""
    
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_agents_status ON agents(status)",
        "CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen)",
        "CREATE INDEX IF NOT EXISTS idx_samples_status ON samples(status)",
        "CREATE INDEX IF NOT EXISTS idx_samples_hash ON samples(file_hash)",
        "CREATE INDEX IF NOT EXISTS idx_samples_uploaded ON samples(uploaded_at)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_status ON analysis_results(status)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_sample ON analysis_results(sample_id)",
        "CREATE INDEX IF NOT EXISTS idx_analysis_agent ON analysis_results(agent_id)",
        "CREATE INDEX IF NOT EXISTS idx_vm_status ON vm_instances(status)",
        "CREATE INDEX IF NOT EXISTS idx_hook_events_analysis ON hook_events(analysis_id)",
        "CREATE INDEX IF NOT EXISTS idx_hook_events_timestamp ON hook_events(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_system_logs_level ON system_logs(level)",
        "CREATE INDEX IF NOT EXISTS idx_system_logs_component ON system_logs(component)",
        "CREATE INDEX IF NOT EXISTS idx_system_logs_created ON system_logs(created_at)"
    ]
    
    for index_sql in indexes:
        conn.execute(index_sql)

def insert_default_data(conn):
    """Insert default data for testing and development"""
    
    # Check if we already have data
    cursor = conn.execute("SELECT COUNT(*) FROM agents")
    if cursor.fetchone()[0] > 0:
        logger.info("Default data already exists, skipping initialization")
        return
    
    # Insert default agent with pattern matching actual agent IDs
    default_agent_id = "shikra-agent-001"
    conn.execute('''
        INSERT INTO agents (id, name, secret_key, capabilities, status)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        default_agent_id,
        "Default Shikra Agent",
        Config.AGENT_SECRET_KEY,
        "file,registry,process,network,memory",
        "offline"
    ))
    
    # Also create a pattern agent for dynamic agent IDs from Windows VMs
    dynamic_agent_id = f"agent-{os.getenv('HOSTNAME', 'WINDOWS')}-001"
    try:
        conn.execute('''
            INSERT INTO agents (id, name, secret_key, capabilities, status)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            dynamic_agent_id,
            "Dynamic Windows Agent",
            Config.AGENT_SECRET_KEY,
            "file,registry,process,network,memory",
            "offline"
        ))
    except:
        pass  # May already exist
    
    # Insert sample VM instance
    default_vm_id = "vm-windows-analysis-001"
    conn.execute('''
        INSERT INTO vm_instances (id, name, image_path, snapshot_name, vnc_port, ssh_port, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (
        default_vm_id,
        "Windows Analysis VM",
        Config.VM_IMAGE_PATH,
        Config.VM_SNAPSHOT_NAME,
        Config.VM_VNC_PORT,
        Config.VM_SSH_PORT,
        "stopped"
    ))
    
    logger.info(f"Default agent created: {default_agent_id}")
    logger.info(f"Default VM instance created: {default_vm_id}")

def initialize_database():
    """Initialize the database with tables and default data"""
    try:
        logger.info("Initializing database...")
        
        with get_database_connection() as conn:
            # Create tables
            create_tables(conn)
            logger.info("Database tables created")
            
            # Create indexes
            create_indexes(conn)
            logger.info("Database indexes created")
            
            # Insert default data
            insert_default_data(conn)
            logger.info("Default data inserted")
            
            conn.commit()
        
        logger.info(f"Database initialized successfully at: {Config.DATABASE_PATH}")
        return True
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return False

def reset_database():
    """Reset database by dropping all tables and recreating"""
    try:
        logger.warning("Resetting database - all data will be lost!")
        
        with get_database_connection() as conn:
            # Get all table names
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            
            # Drop all tables
            for table in tables:
                conn.execute(f"DROP TABLE IF EXISTS {table}")
            
            conn.commit()
        
        # Recreate database
        return initialize_database()
        
    except Exception as e:
        logger.error(f"Database reset failed: {e}")
        return False

def get_database_stats():
    """Get database statistics for monitoring"""
    try:
        with get_database_connection() as conn:
            stats = {}
            
            # Count records in each table
            tables = ['agents', 'samples', 'analysis_results', 'vm_instances', 'hook_events', 'system_logs']
            for table in tables:
                cursor = conn.execute(f"SELECT COUNT(*) FROM {table}")
                stats[table] = cursor.fetchone()[0]
            
            # Get database file size
            if os.path.exists(Config.DATABASE_PATH):
                stats['database_size'] = os.path.getsize(Config.DATABASE_PATH)
            
            return stats
            
    except Exception as e:
        logger.error(f"Failed to get database stats: {e}")
        return {}

if __name__ == "__main__":
    # Allow running this script directly for database management
    import sys
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "reset":
            if reset_database():
                print("Database reset successfully")
            else:
                print("Database reset failed")
                sys.exit(1)
        elif sys.argv[1] == "stats":
            stats = get_database_stats()
            print("Database Statistics:")
            for table, count in stats.items():
                if table == 'database_size':
                    print(f"  Database size: {count} bytes")
                else:
                    print(f"  {table}: {count} records")
    else:
        if initialize_database():
            print("Database initialized successfully")
        else:
            print("Database initialization failed")
            sys.exit(1)
