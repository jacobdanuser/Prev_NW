"""
Universal Metadata Reset System

Comprehensive utilities to reset all types of metadata across:
- Metaphysical system state (energy pools, consciousness, ability usage)
- Git repository metadata
- File system metadata
- Generic object metadata
"""

import os
import json
from datetime import datetime
from pathlib import Path
from dataclasses import asdict, replace
from typing import Any, Dict, List, Optional
from enum import Enum

from metaphysical_restrictions import (
    MetaphysicalPractitioner, MetaphysicalCapability,
    CapabilityType, RestrictionType
)


# ============================================================================
# PART 1: METAPHYSICAL SYSTEM RESET
# ============================================================================

class MetaphysicalResetType(Enum):
    """Types of metaphysical resets available."""
    FULL_RESET = "full_reset"
    ENERGY_RESET = "energy_reset"
    CONSCIOUSNESS_RESET = "consciousness_reset"
    USAGE_RESET = "usage_reset"
    RESTRICTION_RESET = "restriction_reset"
    STATE_SNAPSHOT = "state_snapshot"


class MetaphysicalResetManager:
    """Manage reset operations for metaphysical system state."""
    
    def __init__(self):
        self.reset_history = []
        self.state_snapshots = {}
    
    def snapshot_state(self, practitioner: MetaphysicalPractitioner, 
                      snapshot_name: Optional[str] = None) -> Dict:
        """Create a snapshot of practitioner state for later restoration."""
        name = snapshot_name or f"snapshot_{datetime.now().isoformat()}"
        
        snapshot = {
            "timestamp": datetime.now().isoformat(),
            "practitioner_name": practitioner.name,
            "consciousness_level": practitioner.consciousness_level,
            "energy_pool": practitioner.energy_pool,
            "max_energy": practitioner.max_energy,
            "capabilities": []
        }
        
        for cap in practitioner.capabilities:
            cap_data = {
                "name": cap.name,
                "capability_type": cap.capability_type.value,
                "base_power_level": cap.base_power_level,
                "is_usable": cap.is_usable,
                "use_count": cap.use_count,
                "restrictions_count": len(cap.restrictions)
            }
            snapshot["capabilities"].append(cap_data)
        
        self.state_snapshots[name] = snapshot
        self.reset_history.append({
            "action": "snapshot",
            "name": name,
            "timestamp": datetime.now().isoformat()
        })
        
        return snapshot
    
    def restore_snapshot(self, practitioner: MetaphysicalPractitioner, 
                        snapshot_name: str) -> bool:
        """Restore practitioner to a previous snapshot."""
        if snapshot_name not in self.state_snapshots:
            return False
        
        snapshot = self.state_snapshots[snapshot_name]
        
        # Restore basic state
        practitioner.consciousness_level = snapshot["consciousness_level"]
        practitioner.energy_pool = snapshot["energy_pool"]
        practitioner.max_energy = snapshot["max_energy"]
        
        # Reset capability usage counts
        for i, cap in enumerate(practitioner.capabilities):
            if i < len(snapshot["capabilities"]):
                cap_data = snapshot["capabilities"][i]
                cap.use_count = cap_data["use_count"]
                cap.is_usable = cap_data["is_usable"]
        
        self.reset_history.append({
            "action": "restore",
            "snapshot": snapshot_name,
            "timestamp": datetime.now().isoformat()
        })
        
        return True
    
    def reset_energy(self, practitioner: MetaphysicalPractitioner) -> Dict:
        """Reset energy pool to maximum."""
        old_energy = practitioner.energy_pool
        practitioner.energy_pool = practitioner.max_energy
        
        reset_info = {
            "type": "energy_reset",
            "old_value": old_energy,
            "new_value": practitioner.energy_pool,
            "timestamp": datetime.now().isoformat()
        }
        
        self.reset_history.append(reset_info)
        return reset_info
    
    def reset_consciousness(self, practitioner: MetaphysicalPractitioner, 
                           level: float = 1.0) -> Dict:
        """Reset consciousness level."""
        old_consciousness = practitioner.consciousness_level
        practitioner.consciousness_level = max(0.0, min(1.0, level))
        
        reset_info = {
            "type": "consciousness_reset",
            "old_value": old_consciousness,
            "new_value": practitioner.consciousness_level,
            "timestamp": datetime.now().isoformat()
        }
        
        self.reset_history.append(reset_info)
        return reset_info
    
    def reset_usage_counts(self, practitioner: MetaphysicalPractitioner) -> Dict:
        """Reset all ability usage counts to zero."""
        reset_info = {
            "type": "usage_reset",
            "abilities_reset": [],
            "timestamp": datetime.now().isoformat()
        }
        
        for capability in practitioner.capabilities:
            old_count = capability.use_count
            capability.use_count = 0
            capability.last_used_timestamp = None
            
            reset_info["abilities_reset"].append({
                "ability": capability.name,
                "old_count": old_count,
                "new_count": 0
            })
        
        self.reset_history.append(reset_info)
        return reset_info
    
    def reset_restrictions(self, practitioner: MetaphysicalPractitioner) -> Dict:
        """Clear all restrictions from all capabilities."""
        reset_info = {
            "type": "restriction_reset",
            "abilities_modified": [],
            "timestamp": datetime.now().isoformat()
        }
        
        for capability in practitioner.capabilities:
            old_restrictions = len(capability.restrictions)
            capability.restrictions = []
            
            reset_info["abilities_modified"].append({
                "ability": capability.name,
                "old_restriction_count": old_restrictions,
                "new_restriction_count": 0
            })
        
        self.reset_history.append(reset_info)
        return reset_info
    
    def full_reset(self, practitioner: MetaphysicalPractitioner) -> Dict:
        """Complete reset of all metaphysical state."""
        reset_info = {
            "type": "full_reset",
            "timestamp": datetime.now().isoformat(),
            "resets_applied": []
        }
        
        # Apply all resets
        reset_info["resets_applied"].append(self.reset_energy(practitioner))
        reset_info["resets_applied"].append(
            self.reset_consciousness(practitioner, level=1.0)
        )
        reset_info["resets_applied"].append(self.reset_usage_counts(practitioner))
        reset_info["resets_applied"].append(self.reset_restrictions(practitioner))
        
        self.reset_history.append(reset_info)
        return reset_info
    
    def get_reset_history(self, limit: Optional[int] = None) -> List[Dict]:
        """Get history of reset operations."""
        history = self.reset_history
        if limit:
            history = history[-limit:]
        return history
    
    def export_history(self, filepath: str) -> bool:
        """Export reset history to JSON file."""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.reset_history, f, indent=2)
            return True
        except Exception:
            return False


# ============================================================================
# PART 2: GIT REPOSITORY METADATA RESET
# ============================================================================

class GitMetadataReset:
    """Utilities for resetting git repository metadata."""
    
    @staticmethod
    def reset_uncommitted_changes(repo_path: str = ".") -> Dict:
        """Reset all uncommitted changes (like git checkout -- .)."""
        import subprocess
        
        try:
            result = subprocess.run(
                ["git", "checkout", "--", "."],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            
            return {
                "success": result.returncode == 0,
                "action": "reset_uncommitted_changes",
                "message": result.stdout or result.stderr,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "action": "reset_uncommitted_changes",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def reset_to_head(repo_path: str = ".") -> Dict:
        """Reset repository to HEAD (like git reset --hard HEAD)."""
        import subprocess
        
        try:
            result = subprocess.run(
                ["git", "reset", "--hard", "HEAD"],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            
            return {
                "success": result.returncode == 0,
                "action": "reset_to_head",
                "message": result.stdout or result.stderr,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "action": "reset_to_head",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def reset_author_metadata(repo_path: str = ".", 
                             new_author: str = "Anonymous",
                             new_email: str = "anon@example.com") -> Dict:
        """Reset git author metadata for new commits."""
        import subprocess
        
        try:
            subprocess.run(
                ["git", "config", "user.name", new_author],
                cwd=repo_path,
                capture_output=True
            )
            subprocess.run(
                ["git", "config", "user.email", new_email],
                cwd=repo_path,
                capture_output=True
            )
            
            return {
                "success": True,
                "action": "reset_author_metadata",
                "author": new_author,
                "email": new_email,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "action": "reset_author_metadata",
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def clean_git_metadata(repo_path: str = ".") -> Dict:
        """Clean git cache and reset metadata."""
        import subprocess
        
        results = {
            "action": "clean_git_metadata",
            "operations": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Remove from git cache
        try:
            result = subprocess.run(
                ["git", "rm", "-r", "--cached", "."],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            results["operations"].append({
                "operation": "cache_clean",
                "success": result.returncode == 0
            })
        except Exception as e:
            results["operations"].append({
                "operation": "cache_clean",
                "success": False,
                "error": str(e)
            })
        
        # Re-add files
        try:
            result = subprocess.run(
                ["git", "add", "."],
                cwd=repo_path,
                capture_output=True,
                text=True
            )
            results["operations"].append({
                "operation": "re_add_files",
                "success": result.returncode == 0
            })
        except Exception as e:
            results["operations"].append({
                "operation": "re_add_files",
                "success": False,
                "error": str(e)
            })
        
        return results


# ============================================================================
# PART 3: FILE METADATA RESET
# ============================================================================

class FileMetadataReset:
    """Utilities for resetting file system metadata."""
    
    @staticmethod
    def reset_file_timestamps(filepath: str, 
                             access_time: Optional[float] = None,
                             modify_time: Optional[float] = None) -> Dict:
        """Reset file access and modification times."""
        try:
            now = datetime.now().timestamp()
            atime = access_time or now
            mtime = modify_time or now
            
            os.utime(filepath, (atime, mtime))
            
            return {
                "success": True,
                "action": "reset_file_timestamps",
                "filepath": filepath,
                "access_time": datetime.fromtimestamp(atime).isoformat(),
                "modify_time": datetime.fromtimestamp(mtime).isoformat(),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "action": "reset_file_timestamps",
                "filepath": filepath,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def reset_directory_timestamps(dirpath: str) -> Dict:
        """Reset timestamps for all files in a directory."""
        results = {
            "action": "reset_directory_timestamps",
            "dirpath": dirpath,
            "files_processed": 0,
            "files_failed": 0,
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            for filepath in Path(dirpath).rglob('*'):
                if filepath.is_file():
                    try:
                        FileMetadataReset.reset_file_timestamps(str(filepath))
                        results["files_processed"] += 1
                    except Exception:
                        results["files_failed"] += 1
        except Exception as e:
            results["error"] = str(e)
        
        return results
    
    @staticmethod
    def reset_file_permissions(filepath: str, mode: int = 0o644) -> Dict:
        """Reset file permissions."""
        try:
            os.chmod(filepath, mode)
            
            return {
                "success": True,
                "action": "reset_file_permissions",
                "filepath": filepath,
                "permissions": oct(mode),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "action": "reset_file_permissions",
                "filepath": filepath,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def reset_file_content_metadata(filepath: str) -> Dict:
        """Reset file metadata by touching the file (updates mtime)."""
        try:
            Path(filepath).touch()
            
            return {
                "success": True,
                "action": "reset_file_content_metadata",
                "filepath": filepath,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "success": False,
                "action": "reset_file_content_metadata",
                "filepath": filepath,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
    
    @staticmethod
    def clear_python_cache(dirpath: str = ".") -> Dict:
        """Remove Python cache files (__pycache__, .pyc, .pyo)."""
        results = {
            "action": "clear_python_cache",
            "dirpath": dirpath,
            "directories_removed": [],
            "files_removed": [],
            "timestamp": datetime.now().isoformat()
        }
        
        try:
            # Remove __pycache__ directories
            for pycache in Path(dirpath).rglob('__pycache__'):
                try:
                    import shutil
                    shutil.rmtree(pycache)
                    results["directories_removed"].append(str(pycache))
                except Exception as e:
                    results.setdefault("errors", []).append(str(e))
            
            # Remove .pyc and .pyo files
            for pattern in ['**/*.pyc', '**/*.pyo']:
                for filepath in Path(dirpath).glob(pattern):
                    try:
                        filepath.unlink()
                        results["files_removed"].append(str(filepath))
                    except Exception as e:
                        results.setdefault("errors", []).append(str(e))
        except Exception as e:
            results["error"] = str(e)
        
        return results


# ============================================================================
# PART 4: GENERIC METADATA RESET FRAMEWORK
# ============================================================================

class MetadataResetFramework:
    """Generic framework for resetting any object metadata."""
    
    def __init__(self):
        self.registered_types = {}
        self.reset_log = []
    
    def register_type(self, type_name: str, reset_handler: callable) -> None:
        """Register a custom type with its reset handler."""
        self.registered_types[type_name] = reset_handler
    
    def reset_object(self, obj: Any, reset_type: str = "full") -> Dict:
        """Reset an object's metadata using registered handler."""
        obj_type = type(obj).__name__
        
        if obj_type not in self.registered_types:
            return {
                "success": False,
                "error": f"No reset handler registered for type {obj_type}",
                "timestamp": datetime.now().isoformat()
            }
        
        try:
            handler = self.registered_types[obj_type]
            result = handler(obj, reset_type)
            
            self.reset_log.append({
                "object_type": obj_type,
                "reset_type": reset_type,
                "success": result.get("success", True),
                "timestamp": datetime.now().isoformat()
            })
            
            return result
        except Exception as e:
            error_result = {
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }
            
            self.reset_log.append({
                "object_type": obj_type,
                "reset_type": reset_type,
                "success": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            })
            
            return error_result
    
    def reset_dict_metadata(self, data: Dict) -> Dict:
        """Reset all metadata in a dictionary."""
        result = {
            "action": "reset_dict_metadata",
            "original_size": len(data),
            "metadata_fields_removed": [],
            "timestamp": datetime.now().isoformat()
        }
        
        metadata_patterns = [
            "_metadata", "_meta", "__meta__", "metadata",
            "_timestamp", "_created", "_modified", "_updated",
            "_id", "__id__", "_hash", "__hash__"
        ]
        
        keys_to_remove = [
            k for k in data.keys()
            if any(pattern in k.lower() for pattern in metadata_patterns)
        ]
        
        for key in keys_to_remove:
            del data[key]
            result["metadata_fields_removed"].append(key)
        
        return result
    
    def reset_all_metadata(self, obj: Any) -> Dict:
        """Attempt to reset all metadata from an object."""
        result = {
            "action": "reset_all_metadata",
            "object_type": type(obj).__name__,
            "operations": [],
            "timestamp": datetime.now().isoformat()
        }
        
        # Reset common metadata attributes
        metadata_attrs = [
            '_metadata', '_meta', '__meta__', 'metadata',
            '_timestamp', '_created', '_modified', '_updated',
            '_id', '__id__', '_hash'
        ]
        
        for attr in metadata_attrs:
            if hasattr(obj, attr):
                try:
                    setattr(obj, attr, None)
                    result["operations"].append({
                        "attribute": attr,
                        "action": "cleared",
                        "success": True
                    })
                except Exception as e:
                    result["operations"].append({
                        "attribute": attr,
                        "action": "clear_failed",
                        "error": str(e)
                    })
        
        return result


# ============================================================================
# COMPREHENSIVE RESET MANAGER
# ============================================================================

class UniversalMetadataResetManager:
    """Master reset manager coordinating all metadata reset operations."""
    
    def __init__(self):
        self.metaphysical_manager = MetaphysicalResetManager()
        self.framework = MetadataResetFramework()
        self.overall_log = []
    
    def reset_all(self, practitioner: MetaphysicalPractitioner, 
                 repo_path: Optional[str] = None,
                 file_paths: Optional[List[str]] = None) -> Dict:
        """Execute comprehensive reset of all metadata types."""
        full_reset = {
            "action": "universal_metadata_reset",
            "timestamp": datetime.now().isoformat(),
            "operations": {}
        }
        
        # Reset metaphysical system
        full_reset["operations"]["metaphysical"] = \
            self.metaphysical_manager.full_reset(practitioner)
        
        # Reset git metadata (if repo path provided)
        if repo_path:
            full_reset["operations"]["git"] = {
                "uncommitted": GitMetadataReset.reset_uncommitted_changes(repo_path),
                "author": GitMetadataReset.reset_author_metadata(repo_path)
            }
        
        # Reset file metadata (if file paths provided)
        if file_paths:
            full_reset["operations"]["files"] = {}
            for filepath in file_paths:
                full_reset["operations"]["files"][filepath] = {
                    "timestamps": FileMetadataReset.reset_file_timestamps(filepath),
                    "permissions": FileMetadataReset.reset_file_permissions(filepath)
                }
        
        # Clear Python cache
        full_reset["operations"]["cache"] = FileMetadataReset.clear_python_cache()
        
        self.overall_log.append(full_reset)
        return full_reset
    
    def get_overall_log(self) -> List[Dict]:
        """Get log of all reset operations."""
        return self.overall_log


# ============================================================================
# DEMONSTRATION
# ============================================================================

def demonstrate_metadata_reset():
    """Show all metadata reset capabilities."""
    from metaphysical_restrictions import create_balanced_magic_system
    
    print("\n" + "="*70)
    print("UNIVERSAL METADATA RESET SYSTEM DEMONSTRATION")
    print("="*70)
    
    # 1. Metaphysical System Reset
    print("\n--- 1. METAPHYSICAL SYSTEM RESET ---")
    mage = create_balanced_magic_system()
    manager = MetaphysicalResetManager()
    
    # Use an ability
    mage.use_capability(mage.capabilities[0])
    print(f"After using ability: Energy = {mage.energy_pool}")
    print(f"Ability use count = {mage.capabilities[0].use_count}")
    
    # Take a snapshot
    snapshot = manager.snapshot_state(mage, "before_trauma")
    print(f"✓ Snapshot created: {snapshot['timestamp']}")
    
    # Simulate damage
    mage.consciousness_level = 0.3
    print(f"\nAfter trauma: Consciousness = {mage.consciousness_level:.1%}")
    
    # Reset energy
    reset_energy = manager.reset_energy(mage)
    print(f"✓ Energy reset: {reset_energy['old_value']:.1f} → {reset_energy['new_value']:.1f}")
    
    # Reset consciousness
    reset_cons = manager.reset_consciousness(mage, 1.0)
    print(f"✓ Consciousness reset: {reset_cons['old_value']:.1%} → {reset_cons['new_value']:.1%}")
    
    # Reset usage counts
    reset_usage = manager.reset_usage_counts(mage)
    print(f"✓ Usage counts reset for {len(reset_usage['abilities_reset'])} abilities")
    
    # 2. Generic Metadata Reset
    print("\n--- 2. GENERIC METADATA RESET ---")
    test_dict = {
        "name": "Test",
        "_metadata": {"created": "2026-02-18"},
        "_timestamp": 1234567890,
        "data": [1, 2, 3],
        "_id": "xyz123"
    }
    
    framework = MetadataResetFramework()
    reset_dict = framework.reset_dict_metadata(test_dict)
    print(f"✓ Removed {len(reset_dict['metadata_fields_removed'])} metadata fields")
    print(f"  Fields removed: {reset_dict['metadata_fields_removed']}")
    print(f"  Dict now: {test_dict}")
    
    # 3. File Metadata Reset
    print("\n--- 3. FILE METADATA RESET ---")
    reset_cache = FileMetadataReset.clear_python_cache()
    print(f"✓ Cache cleanup:")
    print(f"  Directories removed: {len(reset_cache['directories_removed'])}")
    print(f"  Files removed: {len(reset_cache['files_removed'])}")
    
    # 4. Reset History
    print("\n--- 4. RESET HISTORY ---")
    history = manager.get_reset_history(limit=3)
    print(f"✓ Last {len(history)} reset operations:")
    for op in history:
        action = op.get('action') or op.get('type', 'unknown_action')
        print(f"  - {action} at {op['timestamp']}")
    
    # 5. Full Reset (all metadata types)
    print("\n--- 5. FULL UNIVERSAL RESET ---")
    universal_manager = UniversalMetadataResetManager()
    full_reset = universal_manager.reset_all(mage)
    print(f"✓ Universal reset completed")
    print(f"  Metaphysical: {full_reset['operations']['metaphysical']['type']}")
    print(f"  Cache: {full_reset['operations']['cache']['action']}")
    print(f"  Total operations: {len(full_reset['operations'])}")


if __name__ == "__main__":
    demonstrate_metadata_reset()
