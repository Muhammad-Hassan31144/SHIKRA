"""
QEMU-KVM Virtual Machine Manager for Shikra Host
Handles VM lifecycle, deployment, and management
"""

import os
import subprocess
import logging
import time
import json
import uuid
from datetime import datetime
import xml.etree.ElementTree as ET

from config.config import Config

logger = logging.getLogger(__name__)

class QEMUManager:
    """QEMU-KVM virtual machine manager"""
    
    def __init__(self):
        self.vms = {}  # Track running VMs
        self.base_vnc_port = Config.VM_VNC_PORT
        self.base_ssh_port = Config.VM_SSH_PORT
    
    def check_vm_availability(self):
        """Check if QEMU-KVM is available and properly configured"""
        try:
            # Check if qemu-system-x86_64 is available
            result = subprocess.run(['which', 'qemu-system-x86_64'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                logger.error("qemu-system-x86_64 not found")
                return False
            
            # Check if KVM is available
            if not os.path.exists('/dev/kvm'):
                logger.warning("KVM acceleration not available")
            
            # Check if base VM image exists
            if not os.path.exists(Config.VM_IMAGE_PATH):
                logger.error(f"Base VM image not found: {Config.VM_IMAGE_PATH}")
                return False
            
            logger.info("QEMU-KVM availability check passed")
            return True
            
        except Exception as e:
            logger.error(f"VM availability check failed: {e}")
            return False
    
    def create_vm_instance(self, vm_id=None, vm_name=None):
        """Create a new VM instance from base image"""
        try:
            if not vm_id:
                vm_id = f"shikra-vm-{uuid.uuid4().hex[:8]}"
            
            if not vm_name:
                vm_name = f"Shikra Analysis VM {vm_id}"
            
            # Create working directory for this VM
            vm_dir = f"/tmp/shost/vms/{vm_id}"
            os.makedirs(vm_dir, exist_ok=True)
            
            # Create a copy-on-write disk image
            vm_disk = os.path.join(vm_dir, f"{vm_id}.qcow2")
            qemu_img_cmd = [
                'qemu-img', 'create',
                '-f', 'qcow2',
                '-F', 'qcow2',
                '-b', Config.VM_IMAGE_PATH,
                vm_disk
            ]
            
            result = subprocess.run(qemu_img_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to create VM disk: {result.stderr}")
                return None
            
            # Assign ports
            vnc_port = self.base_vnc_port + len(self.vms)
            ssh_port = self.base_ssh_port + len(self.vms)
            
            vm_config = {
                'id': vm_id,
                'name': vm_name,
                'disk_path': vm_disk,
                'vnc_port': vnc_port,
                'ssh_port': ssh_port,
                'status': 'created',
                'created_at': datetime.utcnow().isoformat(),
                'process': None
            }
            
            self.vms[vm_id] = vm_config
            
            logger.info(f"VM instance created: {vm_id}")
            return vm_config
            
        except Exception as e:
            logger.error(f"Failed to create VM instance: {e}")
            return None
    
    def start_vm(self, vm_id):
        """Start a VM instance"""
        try:
            if vm_id not in self.vms:
                logger.error(f"VM {vm_id} not found")
                return False
            
            vm_config = self.vms[vm_id]
            
            if vm_config['status'] == 'running':
                logger.warning(f"VM {vm_id} is already running")
                return True
            
            # Build QEMU command
            qemu_cmd = [
                'qemu-system-x86_64',
                '-enable-kvm',
                '-m', str(Config.VM_RAM),
                '-smp', str(Config.VM_CORES),
                '-drive', f"file={vm_config['disk_path']},format=qcow2",
                '-netdev', f"bridge,id=net0,br={Config.VM_NETWORK_BRIDGE}",
                '-device', 'e1000,netdev=net0',
                '-vnc', f":{vm_config['vnc_port'] - 5900}",
                '-daemonize',
                '-pidfile', f"/tmp/shost/vms/{vm_id}/qemu.pid",
                '-monitor', f"unix:/tmp/shost/vms/{vm_id}/monitor.sock,server,nowait",
                '-serial', f"unix:/tmp/shost/vms/{vm_id}/serial.sock,server,nowait"
            ]
            
            # Add snapshot if specified
            if Config.VM_SNAPSHOT_NAME:
                qemu_cmd.extend(['-loadvm', Config.VM_SNAPSHOT_NAME])
            
            logger.info(f"Starting VM {vm_id} with command: {' '.join(qemu_cmd)}")
            
            # Start the VM
            result = subprocess.run(qemu_cmd, capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Failed to start VM {vm_id}: {result.stderr}")
                return False
            
            # Wait a moment for VM to start
            time.sleep(2)
            
            # Check if VM is actually running
            pid_file = f"/tmp/shost/vms/{vm_id}/qemu.pid"
            if os.path.exists(pid_file):
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                
                # Check if process is running
                try:
                    os.kill(pid, 0)  # Send signal 0 to check if process exists
                    vm_config['status'] = 'running'
                    vm_config['started_at'] = datetime.utcnow().isoformat()
                    vm_config['process_pid'] = pid
                    
                    logger.info(f"VM {vm_id} started successfully (PID: {pid})")
                    return True
                except OSError:
                    logger.error(f"VM {vm_id} process not found after start")
                    return False
            else:
                logger.error(f"VM {vm_id} PID file not created")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start VM {vm_id}: {e}")
            return False
    
    def stop_vm(self, vm_id, force=False):
        """Stop a VM instance"""
        try:
            if vm_id not in self.vms:
                logger.error(f"VM {vm_id} not found")
                return False
            
            vm_config = self.vms[vm_id]
            
            if vm_config['status'] != 'running':
                logger.warning(f"VM {vm_id} is not running")
                return True
            
            pid_file = f"/tmp/shost/vms/{vm_id}/qemu.pid"
            
            if os.path.exists(pid_file):
                with open(pid_file, 'r') as f:
                    pid = int(f.read().strip())
                
                try:
                    if force:
                        # Force kill
                        os.kill(pid, 9)  # SIGKILL
                        logger.info(f"VM {vm_id} force killed")
                    else:
                        # Graceful shutdown via monitor
                        monitor_cmd = f"echo 'system_powerdown' | socat - UNIX-CONNECT:/tmp/shost/vms/{vm_id}/monitor.sock"
                        subprocess.run(monitor_cmd, shell=True, timeout=10)
                        
                        # Wait for graceful shutdown
                        for _ in range(30):  # Wait up to 30 seconds
                            try:
                                os.kill(pid, 0)
                                time.sleep(1)
                            except OSError:
                                break
                        else:
                            # Force kill if graceful shutdown failed
                            logger.warning(f"VM {vm_id} graceful shutdown timeout, force killing")
                            os.kill(pid, 9)
                    
                    vm_config['status'] = 'stopped'
                    vm_config['stopped_at'] = datetime.utcnow().isoformat()
                    vm_config['process_pid'] = None
                    
                    # Clean up PID file
                    if os.path.exists(pid_file):
                        os.remove(pid_file)
                    
                    logger.info(f"VM {vm_id} stopped successfully")
                    return True
                    
                except OSError:
                    logger.warning(f"VM {vm_id} process already dead")
                    vm_config['status'] = 'stopped'
                    return True
            else:
                logger.warning(f"VM {vm_id} PID file not found")
                vm_config['status'] = 'stopped'
                return True
                
        except Exception as e:
            logger.error(f"Failed to stop VM {vm_id}: {e}")
            return False
    
    def reset_vm(self, vm_id):
        """Reset VM to clean snapshot state"""
        try:
            if vm_id not in self.vms:
                logger.error(f"VM {vm_id} not found")
                return False
            
            # Stop the VM first
            if not self.stop_vm(vm_id):
                logger.error(f"Failed to stop VM {vm_id} for reset")
                return False
            
            # Wait a moment
            time.sleep(2)
            
            # Start with snapshot
            if self.start_vm(vm_id):
                logger.info(f"VM {vm_id} reset successfully")
                return True
            else:
                logger.error(f"Failed to restart VM {vm_id} after reset")
                return False
                
        except Exception as e:
            logger.error(f"Failed to reset VM {vm_id}: {e}")
            return False
    
    def get_vm_status(self, vm_id):
        """Get status of a specific VM"""
        if vm_id not in self.vms:
            return None
        
        vm_config = self.vms[vm_id].copy()
        
        # Update status by checking process
        if vm_config.get('process_pid'):
            try:
                os.kill(vm_config['process_pid'], 0)
                vm_config['status'] = 'running'
            except OSError:
                vm_config['status'] = 'stopped'
                vm_config['process_pid'] = None
        
        return vm_config
    
    def list_vms(self):
        """List all VM instances"""
        vm_list = []
        for vm_id, vm_config in self.vms.items():
            status = self.get_vm_status(vm_id)
            if status:
                vm_list.append(status)
        
        return vm_list
    
    def cleanup_vm(self, vm_id):
        """Clean up VM resources and files"""
        try:
            if vm_id in self.vms:
                # Stop VM if running
                self.stop_vm(vm_id, force=True)
                
                vm_config = self.vms[vm_id]
                
                # Remove disk file
                if os.path.exists(vm_config['disk_path']):
                    os.remove(vm_config['disk_path'])
                
                # Remove VM directory
                vm_dir = f"/tmp/shost/vms/{vm_id}"
                if os.path.exists(vm_dir):
                    import shutil
                    shutil.rmtree(vm_dir)
                
                # Remove from tracking
                del self.vms[vm_id]
                
                logger.info(f"VM {vm_id} cleaned up successfully")
                return True
            else:
                logger.warning(f"VM {vm_id} not found for cleanup")
                return False
                
        except Exception as e:
            logger.error(f"Failed to cleanup VM {vm_id}: {e}")
            return False
    
    def get_vm_vnc_url(self, vm_id):
        """Get VNC URL for VM"""
        if vm_id not in self.vms:
            return None
        
        vm_config = self.vms[vm_id]
        if vm_config['status'] == 'running':
            return f"vnc://localhost:{vm_config['vnc_port']}"
        
        return None
    
    def execute_command_in_vm(self, vm_id, command):
        """Execute command in VM via monitor (limited functionality)"""
        try:
            if vm_id not in self.vms:
                return None
            
            vm_config = self.vms[vm_id]
            if vm_config['status'] != 'running':
                return None
            
            # This is a placeholder - in a real implementation, you would
            # need SSH or guest agent for command execution
            logger.warning("Command execution in VM not fully implemented")
            
            return {
                'command': command,
                'status': 'not_implemented',
                'message': 'Command execution requires SSH or guest agent setup'
            }
            
        except Exception as e:
            logger.error(f"Failed to execute command in VM {vm_id}: {e}")
            return None
