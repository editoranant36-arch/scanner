import os
import json
import shutil
import time
from typing import List, Dict, Optional, Any
from core.models import QuarantineItem, ScanSummary, FolderItem

DATA_DIR = os.path.expanduser("~/.config/app_leftover_scanner")
ALLOWLIST_FILE = os.path.join(DATA_DIR, "allowlist.json")
QUARANTINE_DIR = os.path.join(DATA_DIR, "quarantine")
QUARANTINE_MANIFEST = os.path.join(DATA_DIR, "quarantine_manifest.json")
HISTORY_FILE = os.path.join(DATA_DIR, "scan_history.json")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")

DEFAULT_SETTINGS = {
    "safety_never_delete_system": True,
    "safety_check_running_processes": True,
    "safety_verify_signatures_registry": True,
    "safety_quarantine_instead_of_delete": True,
    "safety_always_ask_non_system": True,
    "allow_permanent_delete": True,
    "demo_mode": False,
    "custom_scan_paths": []
}


class DataAndHistoryLayer:
    """
    Layer 6: Data & History Layer
    Stores user choices, quarantine and scan history.
    - Allowlist (folders to keep)
    - Quarantine (deleted items, restorable)
    - Scan History (logs and reports)
    - Settings (preferences)
    """

    def __init__(self, base_dir: Optional[str] = None):
        self.data_dir = base_dir or DATA_DIR
        self.quarantine_dir = os.path.join(self.data_dir, "quarantine")
        self.allowlist_file = os.path.join(self.data_dir, "allowlist.json")
        self.quarantine_manifest = os.path.join(self.data_dir, "quarantine_manifest.json")
        self.history_file = os.path.join(self.data_dir, "scan_history.json")
        self.settings_file = os.path.join(self.data_dir, "settings.json")
        self._ensure_dirs()

    def _ensure_dirs(self):
        os.makedirs(self.data_dir, exist_ok=True)
        os.makedirs(self.quarantine_dir, exist_ok=True)
        if not os.path.exists(self.allowlist_file):
            self.save_allowlist([])
        if not os.path.exists(self.quarantine_manifest):
            self._save_json(self.quarantine_manifest, [])
        if not os.path.exists(self.history_file):
            self._save_json(self.history_file, [])
        if not os.path.exists(self.settings_file):
            self._save_json(self.settings_file, DEFAULT_SETTINGS)

    def _load_json(self, path: str, default: Any) -> Any:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    return json.load(f)
        except Exception:
            pass
        return default

    def _save_json(self, path: str, data: Any):
        temp_path = f"{path}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(temp_path, path)

    # Allowlist methods
    def get_allowlist(self) -> List[str]:
        return self._load_json(self.allowlist_file, [])

    def save_allowlist(self, allowlist: List[str]):
        normalized = sorted(list(set(os.path.normpath(p) for p in allowlist if p.strip())))
        self._save_json(self.allowlist_file, normalized)

    def add_to_allowlist(self, path: str):
        current = self.get_allowlist()
        norm = os.path.normpath(path)
        if norm not in current:
            current.append(norm)
            self.save_allowlist(current)

    def remove_from_allowlist(self, path: str):
        current = self.get_allowlist()
        norm = os.path.normpath(path)
        if norm in current:
            current.remove(norm)
            self.save_allowlist(current)

    def is_allowlisted(self, path: str) -> bool:
        norm = os.path.normpath(path)
        for allowed in self.get_allowlist():
            if norm == allowed or norm.startswith(allowed + os.sep):
                return True
        return False

    # Quarantine methods
    def get_quarantine_items(self) -> List[Dict[str, Any]]:
        return self._load_json(self.quarantine_manifest, [])

    def quarantine_folder(self, folder_path: str, app_name: str, reason: str = "") -> Optional[QuarantineItem]:
        item_id = f"quarantine_{int(time.time()*1000)}"
        target_dir = os.path.join(self.quarantine_dir, item_id)
        
        # Calculate size before moving if exists
        size_bytes = 0
        if os.path.exists(folder_path):
            for root, dirs, files in os.walk(folder_path):
                for f in files:
                    fp = os.path.join(root, f)
                    if not os.path.islink(fp):
                        try:
                            size_bytes += os.path.getsize(fp)
                        except Exception:
                            pass
            try:
                shutil.move(folder_path, target_dir)
            except Exception as e:
                # If cannot move (e.g. cross-device or permission or simulated path), handle gracefully
                os.makedirs(target_dir, exist_ok=True)
                with open(os.path.join(target_dir, "meta.txt"), "w") as mf:
                    mf.write(f"Quarantined {folder_path} - error moving: {str(e)}")
        else:
            # Demo/simulated item
            os.makedirs(target_dir, exist_ok=True)
            with open(os.path.join(target_dir, "simulated.txt"), "w") as mf:
                mf.write(f"Simulated quarantine for {folder_path}")

        item = QuarantineItem(
            id=item_id,
            original_path=folder_path,
            quarantine_path=target_dir,
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
            size_bytes=size_bytes,
            size_formatted=self._format_size(size_bytes),
            associated_app=app_name,
            reason=reason or "Uninstalled application leftover"
        )
        
        items = self.get_quarantine_items()
        items.insert(0, item.__dict__)
        self._save_json(self.quarantine_manifest, items)
        return item

    def restore_quarantine_item(self, item_id: str) -> bool:
        items = self.get_quarantine_items()
        item_to_restore = next((i for i in items if i["id"] == item_id), None)
        if not item_to_restore:
            return False

        orig_path = item_to_restore["original_path"]
        quar_path = item_to_restore["quarantine_path"]

        try:
            if os.path.exists(quar_path):
                parent = os.path.dirname(orig_path)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                shutil.move(quar_path, orig_path)
            items = [i for i in items if i["id"] != item_id]
            self._save_json(self.quarantine_manifest, items)
            return True
        except Exception:
            return False

    def delete_quarantine_item_permanently(self, item_id: str) -> bool:
        items = self.get_quarantine_items()
        item_to_delete = next((i for i in items if i["id"] == item_id), None)
        if not item_to_delete:
            return False

        quar_path = item_to_delete["quarantine_path"]
        try:
            if os.path.exists(quar_path):
                shutil.rmtree(quar_path)
            items = [i for i in items if i["id"] != item_id]
            self._save_json(self.quarantine_manifest, items)
            return True
        except Exception:
            return False

    # History methods
    def get_history(self) -> List[Dict[str, Any]]:
        return self._load_json(self.history_file, [])

    def record_scan_history(self, summary: ScanSummary):
        history = self.get_history()
        record = {
            "timestamp": summary.timestamp,
            "duration_seconds": summary.duration_seconds,
            "total_folders_scanned": summary.total_folders_scanned,
            "installed_apps_count": summary.installed_apps_count,
            "leftovers_detected": summary.leftovers_detected,
            "system_protected_count": summary.system_protected_count,
            "active_apps_count": summary.active_apps_count,
            "uncertain_count": summary.uncertain_count,
            "total_space_recoverable": self._format_size(summary.total_space_recoverable_bytes),
            "leftover_paths": [item.path for item in summary.items if item.decision.value == "Application Deleted"]
        }
        history.insert(0, record)
        # Keep last 50 scans
        history = history[:50]
        self._save_json(self.history_file, history)

    # Settings methods
    def get_settings(self) -> Dict[str, Any]:
        settings = DEFAULT_SETTINGS.copy()
        user_settings = self._load_json(self.settings_file, {})
        settings.update(user_settings)
        return settings

    def update_settings(self, new_settings: Dict[str, Any]):
        current = self.get_settings()
        current.update(new_settings)
        self._save_json(self.settings_file, current)

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}" if unit != 'B' else f"{int(size)} B"
            size /= 1024.0
        return f"{size:.1f} PB"
