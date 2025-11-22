"""
Configuration settings for Shikra Host (Shost)
Simple MVP configuration with environment variable support
"""

import os
from datetime import timedelta

class Config:
    """Main configuration class"""
    
    # ================================
    # API Server Configuration
    # ================================
    API_HOST = os.getenv('SHOST_API_HOST', '0.0.0.0')
    API_PORT = int(os.getenv('SHOST_API_PORT', '8080'))
    SECRET_KEY = os.getenv('SHOST_SECRET_KEY', 'shikra-dev-secret-key-change-in-production')
    DEBUG = os.getenv('SHOST_DEBUG', 'False').lower() == 'true'
    
    # ================================
    # Database Configuration
    # ================================
    DATABASE_PATH = os.getenv('SHOST_DATABASE_PATH', '/tmp/shost/shost.db')
    
    # ================================
    # Storage Configuration
    # ================================
    SAMPLE_STORAGE = os.getenv('SHOST_SAMPLE_STORAGE', 'data/samples')
    ARTIFACT_STORAGE = os.getenv('SHOST_ARTIFACT_STORAGE', 'data/artifacts')
    DUMP_STORAGE = os.getenv('SHOST_DUMP_STORAGE', 'data/dumps')
    MAX_SAMPLE_SIZE = int(os.getenv('SHOST_MAX_SAMPLE_SIZE', '100')) * 1024 * 1024  # 100MB default
    
    # ================================
    # VM Configuration (QEMU-KVM)
    # ================================
    VM_IMAGE_PATH = os.getenv('SHOST_VM_IMAGE_PATH', '/var/lib/libvirt/images/win10.clean_baseline_20250824_133607')
    VM_SNAPSHOT_NAME = os.getenv('SHOST_VM_SNAPSHOT', 'clean_baseline_20250824_133607')
    VM_RAM = int(os.getenv('SHOST_VM_RAM', '4096'))  # MB
    VM_CORES = int(os.getenv('SHOST_VM_CORES', '2'))
    VM_VNC_PORT = int(os.getenv('SHOST_VM_VNC_PORT', '5900'))
    VM_SSH_PORT = int(os.getenv('SHOST_VM_SSH_PORT', '2222'))
    VM_NETWORK_BRIDGE = os.getenv('SHOST_VM_BRIDGE', 'virbr0')
    VM_TIMEOUT = int(os.getenv('SHOST_VM_TIMEOUT', '300'))  # seconds
    
    # ================================
    # Agent Configuration
    # ================================
    AGENT_PATH = os.getenv('SHOST_AGENT_PATH', '../build/windows-release/bin/ShikraAgent.exe')
    HOOKENGINE_PATH = os.getenv('SHOST_HOOKENGINE_PATH', '../build/windows-release/bin/HookEngine.dll')
    AGENT_SECRET_KEY = os.getenv('SHOST_AGENT_SECRET', 'shikra-agent-hmac-secret-key')
    AGENT_DEPLOY_PATH = os.getenv('SHOST_AGENT_DEPLOY_PATH', 'C:\\\\Temp\\\\ShikraAgent')
    AGENT_POLL_INTERVAL = int(os.getenv('SHOST_AGENT_POLL_INTERVAL', '10'))  # seconds
    
    # ================================
    # Analysis Configuration
    # ================================
    ANALYSIS_TIMEOUT = int(os.getenv('SHOST_ANALYSIS_TIMEOUT', '600'))  # 10 minutes default
    MEMORY_DUMP_TRIGGERS = os.getenv('SHOST_DUMP_TRIGGERS', 'process_creation,file_write,network_connect').split(',')
    API_HOOK_CATEGORIES = os.getenv('SHOST_HOOK_CATEGORIES', 'file,registry,process,network,memory').split(',')
    
    # ================================
    # Security Configuration
    # ================================
    ALLOWED_EXTENSIONS = {'.exe', '.dll', '.scr', '.com', '.bat', '.ps1', '.vbs', '.jar', '.zip', '.rar'}
    UPLOAD_RATE_LIMIT = os.getenv('SHOST_UPLOAD_RATE_LIMIT', '10 per minute')
    API_RATE_LIMIT = os.getenv('SHOST_API_RATE_LIMIT', '100 per minute')
    
    # ================================
    # Logging Configuration
    # ================================
    LOG_LEVEL = os.getenv('SHOST_LOG_LEVEL', 'INFO')
    LOG_MAX_SIZE = int(os.getenv('SHOST_LOG_MAX_SIZE', '10')) * 1024 * 1024  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv('SHOST_LOG_BACKUP_COUNT', '5'))
    
    # ================================
    # Dashboard Configuration
    # ================================
    DASHBOARD_REFRESH_INTERVAL = int(os.getenv('SHOST_DASHBOARD_REFRESH', '5'))  # seconds
    SHOW_LIVE_LOGS = os.getenv('SHOST_SHOW_LIVE_LOGS', 'True').lower() == 'true'
    
    # ================================
    # Queue Recovery / Timeouts
    # ================================
    STALE_SAMPLE_TIMEOUT = int(os.getenv('SHOST_STALE_SAMPLE_TIMEOUT', '300'))  # seconds
    
    @classmethod
    def validate_config(cls):
        """Validate configuration settings"""
        errors = []
        
        # Check required paths exist
        if not os.path.exists(os.path.dirname(cls.DATABASE_PATH)):
            try:
                os.makedirs(os.path.dirname(cls.DATABASE_PATH), exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create database directory: {e}")
        
        # Validate VM configuration
        if not cls.VM_IMAGE_PATH or not os.path.exists(cls.VM_IMAGE_PATH):
            errors.append(f"VM image not found: {cls.VM_IMAGE_PATH}")
        
        # Validate storage paths
        for path in [cls.SAMPLE_STORAGE, cls.ARTIFACT_STORAGE, cls.DUMP_STORAGE]:
            try:
                os.makedirs(path, exist_ok=True)
            except Exception as e:
                errors.append(f"Cannot create storage directory {path}: {e}")
        
        # Validate numeric ranges
        if cls.VM_RAM < 1024:
            errors.append("VM_RAM should be at least 1024 MB")
        
        if cls.VM_CORES < 1:
            errors.append("VM_CORES should be at least 1")
        
        if cls.ANALYSIS_TIMEOUT < 60:
            errors.append("ANALYSIS_TIMEOUT should be at least 60 seconds")
        
        return errors

class DevelopmentConfig(Config):
    """Development environment configuration"""
    DEBUG = True
    API_HOST = '127.0.0.1'
    DATABASE_PATH = './dev_shost.db'
    SAMPLE_STORAGE = './dev_samples'
    ARTIFACT_STORAGE = './dev_artifacts'
    DUMP_STORAGE = './dev_dumps'

class ProductionConfig(Config):
    """Production environment configuration"""
    DEBUG = False
    # Use environment variables for all sensitive settings
    
class TestingConfig(Config):
    """Testing environment configuration"""
    TESTING = True
    DATABASE_PATH = ':memory:'  # In-memory SQLite for testing
    SAMPLE_STORAGE = '/tmp/test_samples'
    ARTIFACT_STORAGE = '/tmp/test_artifacts'
    DUMP_STORAGE = '/tmp/test_dumps'

# Configuration selection based on environment
config_map = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

def get_config():
    """Get configuration based on environment"""
    env = os.getenv('SHOST_ENV', 'default')
    return config_map.get(env, DevelopmentConfig)
