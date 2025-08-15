"""
VM Snapshot Management with virsh/libvirt
Handles snapshot creation, restoration, and listing for QEMU-KVM VMs
"""

import subprocess
import logging
import json
import os
from datetime import datetime
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

class SnapshotManager:
    """Manages VM snapshots using virsh commands"""
    
    def __init__(self):
        """Initialize snapshot manager"""
        self.virsh_cmd = "virsh"
        self._verify_virsh_available()
    
    def _verify_virsh_available(self):
        """Check if virsh is available"""
        try:
            subprocess.run([self.virsh_cmd, "--version"], 
                         capture_output=True, check=True, timeout=5)
            logger.info("virsh is available and ready")
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired) as e:
            logger.error(f"virsh not available: {e}")
            raise RuntimeError("virsh command not found or not working. Is libvirt installed?")
    
    def create_snapshot(self, vm_name: str, snapshot_name: str = None, 
                       description: str = None) -> Dict[str, any]:
        """
        Create a VM snapshot
        
        Args:
            vm_name: Name of the VM (e.g., 'win10-analysis')
            snapshot_name: Optional snapshot name (auto-generated if None)
            description: Optional description
            
        Returns:
            Dictionary with snapshot info
            
        Raises:
            RuntimeError: If snapshot creation fails
        """
        # Auto-generate snapshot name if not provided
        if not snapshot_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            snapshot_name = f"clean_state_{timestamp}"
        
        if not description:
            description = f"Snapshot created at {datetime.now().isoformat()}"
        
        logger.info(f"Creating snapshot '{snapshot_name}' for VM '{vm_name}'")
        
        try:
            # Create snapshot using virsh snapshot-create-as
            cmd = [
                self.virsh_cmd,
                "snapshot-create-as",
                vm_name,
                snapshot_name,
                description,
                "--atomic"  # Atomic operation for safety
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  check=True, timeout=60)
            
            logger.info(f"Snapshot created successfully: {snapshot_name}")
            
            return {
                "success": True,
                "vm_name": vm_name,
                "snapshot_name": snapshot_name,
                "description": description,
                "created_at": datetime.now().isoformat(),
                "message": result.stdout.strip()
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to create snapshot: {e.stderr}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = f"Snapshot creation timed out for VM '{vm_name}'"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
    
    def restore_snapshot(self, vm_name: str, snapshot_name: str = None) -> Dict[str, any]:
        """
        Restore VM to a snapshot
        
        Args:
            vm_name: Name of the VM
            snapshot_name: Name of snapshot to restore (uses current/latest if None)
            
        Returns:
            Dictionary with restore info
            
        Raises:
            RuntimeError: If restore fails
        """
        logger.info(f"Restoring VM '{vm_name}' to snapshot '{snapshot_name or 'current'}'")
        
        try:
            # Restore snapshot
            cmd = [self.virsh_cmd, "snapshot-revert", vm_name]
            
            if snapshot_name:
                cmd.append(snapshot_name)
            else:
                cmd.append("--current")  # Use current snapshot
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  check=True, timeout=60)
            
            logger.info(f"Snapshot restored successfully")
            
            return {
                "success": True,
                "vm_name": vm_name,
                "snapshot_name": snapshot_name or "current",
                "restored_at": datetime.now().isoformat(),
                "message": result.stdout.strip()
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to restore snapshot: {e.stderr}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
        except subprocess.TimeoutExpired:
            error_msg = f"Snapshot restore timed out for VM '{vm_name}'"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
    
    def list_snapshots(self, vm_name: str) -> List[Dict[str, any]]:
        """
        List all snapshots for a VM
        
        Args:
            vm_name: Name of the VM
            
        Returns:
            List of snapshot dictionaries
        """
        logger.debug(f"Listing snapshots for VM '{vm_name}'")
        
        try:
            # List snapshots
            cmd = [self.virsh_cmd, "snapshot-list", vm_name, "--name"]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  check=True, timeout=30)
            
            snapshot_names = [name.strip() for name in result.stdout.split('\n') if name.strip()]
            
            # Get details for each snapshot
            snapshots = []
            for name in snapshot_names:
                try:
                    detail_cmd = [self.virsh_cmd, "snapshot-info", vm_name, name]
                    detail_result = subprocess.run(detail_cmd, capture_output=True, text=True,
                                                  check=True, timeout=10)
                    
                    # Parse snapshot info (simple parsing)
                    info = {"name": name}
                    for line in detail_result.stdout.split('\n'):
                        if ':' in line:
                            key, value = line.split(':', 1)
                            info[key.strip().lower().replace(' ', '_')] = value.strip()
                    
                    snapshots.append(info)
                except Exception as e:
                    logger.warning(f"Could not get details for snapshot '{name}': {e}")
                    snapshots.append({"name": name, "error": str(e)})
            
            logger.info(f"Found {len(snapshots)} snapshot(s) for VM '{vm_name}'")
            return snapshots
            
        except subprocess.CalledProcessError as e:
            if "domain not found" in e.stderr.lower() or "no domain" in e.stderr.lower():
                logger.warning(f"VM '{vm_name}' not found")
                return []
            else:
                logger.error(f"Failed to list snapshots: {e.stderr}")
                return []
        except Exception as e:
            logger.error(f"Error listing snapshots: {e}")
            return []
    
    def delete_snapshot(self, vm_name: str, snapshot_name: str) -> Dict[str, any]:
        """
        Delete a VM snapshot
        
        Args:
            vm_name: Name of the VM
            snapshot_name: Name of snapshot to delete
            
        Returns:
            Dictionary with deletion info
        """
        logger.info(f"Deleting snapshot '{snapshot_name}' from VM '{vm_name}'")
        
        try:
            cmd = [self.virsh_cmd, "snapshot-delete", vm_name, snapshot_name]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  check=True, timeout=30)
            
            logger.info(f"Snapshot deleted successfully")
            
            return {
                "success": True,
                "vm_name": vm_name,
                "snapshot_name": snapshot_name,
                "deleted_at": datetime.now().isoformat(),
                "message": result.stdout.strip()
            }
            
        except subprocess.CalledProcessError as e:
            error_msg = f"Failed to delete snapshot: {e.stderr}"
            logger.error(error_msg)
            raise RuntimeError(error_msg)
    
    def get_current_snapshot(self, vm_name: str) -> Optional[str]:
        """
        Get the name of the current snapshot
        
        Args:
            vm_name: Name of the VM
            
        Returns:
            Name of current snapshot or None
        """
        try:
            cmd = [self.virsh_cmd, "snapshot-current", vm_name, "--name"]
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  check=True, timeout=10)
            
            current = result.stdout.strip()
            return current if current else None
            
        except subprocess.CalledProcessError:
            # No current snapshot
            return None
        except Exception as e:
            logger.error(f"Error getting current snapshot: {e}")
            return None
    
    def has_snapshot(self, vm_name: str, snapshot_name: str = None) -> bool:
        """
        Check if VM has a snapshot (optionally by name)
        
        Args:
            vm_name: Name of the VM
            snapshot_name: Optional specific snapshot name to check
            
        Returns:
            True if snapshot exists, False otherwise
        """
        snapshots = self.list_snapshots(vm_name)
        
        if snapshot_name:
            return any(s.get('name') == snapshot_name for s in snapshots)
        else:
            return len(snapshots) > 0
    
    def get_snapshot_status(self, vm_name: str) -> Dict[str, any]:
        """
        Get comprehensive snapshot status for a VM
        
        Args:
            vm_name: Name of the VM
            
        Returns:
            Dictionary with snapshot status information
        """
        snapshots = self.list_snapshots(vm_name)
        current = self.get_current_snapshot(vm_name)
        
        return {
            "vm_name": vm_name,
            "has_snapshots": len(snapshots) > 0,
            "snapshot_count": len(snapshots),
            "current_snapshot": current,
            "snapshots": snapshots,
            "ready_for_analysis": len(snapshots) > 0
        }


# Global singleton instance
_snapshot_manager = None

def get_snapshot_manager() -> SnapshotManager:
    """Get or create the global snapshot manager instance"""
    global _snapshot_manager
    if _snapshot_manager is None:
        _snapshot_manager = SnapshotManager()
    return _snapshot_manager
