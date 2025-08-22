"""
Shikra Host (Shost) - Main Application Entry Point
Simple MVP for malware analysis orchestration with QEMU-KVM VMs
"""

import os
import sys
import logging
from datetime import datetime
from flask import Flask

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.config import Config
from api.app import create_app
from database.init_db import initialize_database
from vm_manager.qemu_manager import QEMUManager

def setup_logging():
    """Configure logging for the application"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(f'{log_dir}/shost.log'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    
    return logging.getLogger(__name__)

def check_prerequisites():
    """Check if all prerequisites are met"""
    logger = logging.getLogger(__name__)
    
    # Check QEMU-KVM availability
    if os.system("which qemu-system-x86_64 > /dev/null 2>&1") != 0:
        logger.error("QEMU-KVM not found. Please install qemu-kvm package.")
        return False
    
    # Check if VM image exists
    if not os.path.exists(Config.VM_IMAGE_PATH):
        logger.error(f"VM image not found at: {Config.VM_IMAGE_PATH}")
        logger.error("Please configure VM_IMAGE_PATH in config.py")
        return False
    
    # Check storage directories
    for path in [Config.SAMPLE_STORAGE, Config.ARTIFACT_STORAGE]:
        os.makedirs(path, exist_ok=True)
        if not os.access(path, os.W_OK):
            logger.error(f"No write access to storage directory: {path}")
            return False
    
    # Check agent files
    if not os.path.exists(Config.AGENT_PATH):
        logger.warning(f"Agent executable not found at: {Config.AGENT_PATH}")
        logger.warning("Agent deployment will fail until this is corrected")
    
    if not os.path.exists(Config.HOOKENGINE_PATH):
        logger.warning(f"Hook engine DLL not found at: {Config.HOOKENGINE_PATH}")
        logger.warning("Agent deployment will fail until this is corrected")
    
    return True

def initialize_components():
    """Initialize all system components"""
    logger = logging.getLogger(__name__)
    
    logger.info("Initializing Shikra Host (Shost) components...")
    
    # Initialize database
    logger.info("Setting up database...")
    if not initialize_database():
        logger.error("Failed to initialize database")
        return False
    
    # Initialize VM manager
    logger.info("Initializing VM manager...")
    vm_manager = QEMUManager()
    
    # Test VM manager functionality
    if not vm_manager.check_vm_availability():
        logger.error("VM manager initialization failed")
        return False
    
    logger.info("All components initialized successfully")
    return True

def main():
    """Main entry point"""
    print(f"""
╔══════════════════════════════════════════════════════════════╗
║                    SHIKRA HOST (SHOST)                      ║
║                 Malware Analysis Orchestration              ║
║                                                              ║
║  🔬 Automated malware analysis with QEMU-KVM VMs           ║
║  🚀 Simple MVP for complete analysis workflow               ║
║  📊 Real-time monitoring and control                        ║
╚══════════════════════════════════════════════════════════════╝

Starting at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
""")
    
    # Setup logging
    logger = setup_logging()
    logger.info("Starting Shikra Host (Shost)")
    
    # Check prerequisites
    logger.info("Checking prerequisites...")
    if not check_prerequisites():
        logger.error("Prerequisites check failed. Please fix the issues above.")
        sys.exit(1)
    
    # Initialize components
    if not initialize_components():
        logger.error("Component initialization failed")
        sys.exit(1)
    
    # Create Flask app
    app = create_app()
    
    # Print startup information
    logger.info(f"API Server: http://{Config.API_HOST}:{Config.API_PORT}")
    logger.info(f"Dashboard: http://{Config.API_HOST}:{Config.API_PORT}/dashboard")
    logger.info(f"Database: {Config.DATABASE_PATH}")
    logger.info(f"Sample Storage: {Config.SAMPLE_STORAGE}")
    logger.info(f"Artifact Storage: {Config.ARTIFACT_STORAGE}")
    
    print(f"""
🌐 Server URLs:
   • API Server:  http://{Config.API_HOST}:{Config.API_PORT}
   • Dashboard:   http://{Config.API_HOST}:{Config.API_PORT}/dashboard
   • API Docs:    http://{Config.API_HOST}:{Config.API_PORT}/api/docs

🗂️  Storage Locations:
   • Database:    {Config.DATABASE_PATH}
   • Samples:     {Config.SAMPLE_STORAGE}
   • Artifacts:   {Config.ARTIFACT_STORAGE}
   • Logs:        logs/

🎮 Quick Start:
   1. Upload a sample via dashboard or API
   2. Start analysis from the dashboard
   3. Monitor real-time progress
   4. View results and artifacts

Press Ctrl+C to stop the server
""")
    
    try:
        # Start the Flask application
        app.run(
            host=Config.API_HOST,
            port=Config.API_PORT,
            debug=Config.DEBUG,
            threaded=True
        )
    except KeyboardInterrupt:
        logger.info("Received shutdown signal")
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)
    finally:
        logger.info("Shutting down Shikra Host")
        # TODO: Add cleanup for running VMs
        print("\n🛑 Shikra Host stopped")

if __name__ == "__main__":
    main()
