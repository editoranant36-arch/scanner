import os
import sys
import shutil
import subprocess
from typing import Dict, Any, Optional, List
from core.models import UserAction, FolderItem, DecisionStatus
from core.data_layer import DataAndHistoryLayer
from core.correlation_engine import PROTECTED_SYSTEM_PATHS, PROTECTED_FOLDER_NAMES

class ActionLayer:
    """
    Layer 5: Action Layer
    Handles user decisions and safe execution.
    - Delete: Move to Quarantine / (Optional) Permanent Delete
    - Keep / Allow: Add to Allowlist (skip in future scans)
    - View Folder: Open in Explorer / File Manager & show details
    - Ignore: Skip this scan (no disk changes)
    Strictly enforces Safety Rules.
    """

    def __init__(self, data_layer: Optional[DataAndHistoryLayer] = None):
        self.data_layer = data_layer or DataAndHistoryLayer()

    def execute_action(self,
                       path: str,
                       action: str,
                       app_name: str = "",
                       permanent_delete: bool = False) -> Dict[str, Any]:
        """
        Executes an action chosen by the user or UI.
        Actions: 'delete', 'keep_allow', 'view_folder', 'ignore'
        """
        action_norm = action.lower().strip()
        settings = self.data_layer.get_settings()

        # Enforce Safety Rule 1: Never delete system / Windows folders
        if action_norm in ["delete", "permanent_delete", "delete_permanent"]:
            is_sys, reason = self._is_system_path(path)
            if is_sys and settings.get("safety_never_delete_system", True):
                return {
                    "success": False,
                    "action": "delete",
                    "error": f"SAFETY BLOCKED: Folder is protected system path ({reason}). Deletion is prohibited.",
                    "path": path
                }

            if permanent_delete or action_norm in ["permanent_delete", "delete_permanent"]:
                return self._permanent_delete(path, app_name)
            else:
                return self._quarantine_delete(path, app_name)


        elif action_norm in ["keep", "keep_allow", "allow"]:
            self.data_layer.add_to_allowlist(path)
            return {
                "success": True,
                "action": "keep_allow",
                "message": f"Added '{path}' to allowlist. It will be skipped in future scans.",
                "path": path
            }

        elif action_norm in ["view", "view_folder"]:
            details = self._inspect_folder(path)
            self._try_open_in_file_manager(path)
            return {
                "success": True,
                "action": "view_folder",
                "details": details,
                "path": path
            }

        elif action_norm == "ignore":
            return {
                "success": True,
                "action": "ignore",
                "message": f"Skipped '{path}' for this scan session.",
                "path": path
            }

        else:
            return {
                "success": False,
                "action": action,
                "error": f"Unknown action: {action}",
                "path": path
            }

    def _quarantine_delete(self, path: str, app_name: str) -> Dict[str, Any]:
        """Safely moves the folder to the quarantine repository."""
        item = self.data_layer.quarantine_folder(path, app_name or "Unknown Application")
        return {
            "success": True,
            "action": "delete",
            "mode": "quarantine",
            "message": f"Folder safely moved to Quarantine (Item ID: {item.id if item else 'N/A'}).",
            "path": path,
            "quarantine_id": item.id if item else None
        }

    def _permanent_delete(self, path: str, app_name: str) -> Dict[str, Any]:
        """Permanently deletes the folder from disk."""
        try:
            expanded = os.path.expanduser(path)
            deleted_items = []
            
            if os.path.exists(expanded):
                if os.path.isdir(expanded):
                    shutil.rmtree(expanded)
                else:
                    os.remove(expanded)
                deleted_items.append(expanded)

            # Also clean up any demo sandbox folder if one was generated
            clean_path = path.replace("\\", "/").rstrip("/")
            parts = [p for p in clean_path.split("/") if p and ":" not in p]
            safe_name = "_".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else "")
            if safe_name:
                sandbox_dir = os.path.expanduser(f"~/.config/app_leftover_scanner/demo_sandbox/{safe_name}")
                if os.path.exists(sandbox_dir):
                    shutil.rmtree(sandbox_dir)
                    deleted_items.append(sandbox_dir)

            return {
                "success": True,
                "action": "delete",
                "mode": "permanent",
                "message": f"Folder '{path}' was permanently deleted and removed from the system.",
                "path": path,
                "deleted_locations": deleted_items
            }
        except Exception as e:
            return {
                "success": False,
                "action": "delete",
                "error": f"Failed to permanently delete from system: {str(e)}",
                "path": path
            }


    def _is_system_path(self, path: str) -> Tuple[bool, str]:
        """Checks if the path is protected system path."""
        norm = path.lower().replace("/", "\\")
        base = os.path.basename(path).lower()

        if base in PROTECTED_FOLDER_NAMES:
            return True, f"Matched protected folder name '{base}'"

        for sp in PROTECTED_SYSTEM_PATHS:
            sp_norm = sp.lower().replace("/", "\\")
            if norm == sp_norm or norm.startswith(sp_norm + "\\"):
                return True, f"Inside protected path '{sp}'"

        return False, ""

    def _inspect_folder(self, path: str) -> Dict[str, Any]:
        """Inspects folder files, count, size, and sample contents."""
        info = {
            "path": path,
            "exists": os.path.exists(path),
            "file_count": 0,
            "folder_count": 0,
            "sample_files": []
        }
        if os.path.exists(path) and os.path.isdir(path):
            try:
                for root, dirs, files in os.walk(path):
                    info["folder_count"] += len(dirs)
                    info["file_count"] += len(files)
                    if len(info["sample_files"]) < 10:
                        for f in files[:10 - len(info["sample_files"])]:
                            info["sample_files"].append(os.path.join(root, f))
            except Exception:
                pass
        return info

    def open_in_file_manager(self, path: str) -> Dict[str, Any]:
        """Opens the specified folder in the OS file manager (Explorer/Thunar/Nautilus/Finder)."""
        expanded = os.path.expanduser(path)

        target_path = expanded
        is_demo_created = False

        if not os.path.exists(expanded):
            # If path does not exist (e.g. Windows demo path on Linux), create a realistic sandbox folder so file manager can open it!
            clean_path = path.replace("\\", "/").rstrip("/")
            parts = [p for p in clean_path.split("/") if p and ":" not in p]
            safe_name = "_".join(parts[-2:]) if len(parts) >= 2 else (parts[-1] if parts else "Leftover_Demo")
            sandbox_dir = os.path.expanduser(f"~/.config/app_leftover_scanner/demo_sandbox/{safe_name}")
            os.makedirs(sandbox_dir, exist_ok=True)

            # Create sample leftover files to demonstrate residual data
            with open(os.path.join(sandbox_dir, "leftover_app_data.log"), "w") as f:
                f.write(f"Sample leftover residual data for: {path}\nSimulated leftover size: 438 MB\n")
            with open(os.path.join(sandbox_dir, "cache.db"), "w") as f:
                f.write("SAMPLE_DATABASE_CACHE_BINARY_DATA\n")
            sub_cache = os.path.join(sandbox_dir, "CrashReports")
            os.makedirs(sub_cache, exist_ok=True)
            with open(os.path.join(sub_cache, "crash_dump_0.dmp"), "w") as f:
                f.write("DUMP\n")

            target_path = sandbox_dir
            is_demo_created = True

        opened = False
        try:
            if sys.platform.startswith("win"):
                # Windows
                os.startfile(target_path)
                opened = True
            elif sys.platform.startswith("darwin"):
                # macOS
                subprocess.Popen(["open", target_path])
                opened = True
            else:
                # Linux: try thunar, xdg-open, nautilus
                env = os.environ.copy()
                if "DISPLAY" not in env:
                    env["DISPLAY"] = ":0.0"

                for tool in ["thunar", "xdg-open", "nautilus", "dolphin", "pcmanfm"]:
                    if shutil.which(tool):
                        subprocess.Popen([tool, target_path], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        opened = True
                        break
        except Exception as e:
            return {"success": False, "error": str(e), "path": target_path}

        return {
            "success": opened,
            "target_path": target_path,
            "is_demo_sandbox": is_demo_created,
            "message": f"Opened '{target_path}' in file manager"
        }

    def _try_open_in_file_manager(self, path: str) -> bool:
        res = self.open_in_file_manager(path)
        return res.get("success", False)

