import time
from typing import List, Dict, Optional, Any
from core.models import FolderItem, InstalledApp, ScanSummary, DecisionStatus
from core.scan_engine import ScanEngine
from core.correlation_engine import CorrelationEngine
from core.decision_engine import DecisionEngine
from core.action_layer import ActionLayer
from core.data_layer import DataAndHistoryLayer

class ScannerOrchestrator:
    """
    Coordinates the entire Application Leftover Folder Scanner workflow:
    1. Scan installed applications and system folders (ScanEngine)
    2. Correlate and analyze using registry, processes, services and checks (CorrelationEngine)
    3. Classify into status categories (DecisionEngine)
    4. Provide user actions (ActionLayer)
    5. Maintain allowlist, quarantine, history, and settings (DataAndHistoryLayer)
    """

    def __init__(self, data_layer: Optional[DataAndHistoryLayer] = None, demo_mode: bool = False):
        self.data_layer = data_layer or DataAndHistoryLayer()
        self.demo_mode = demo_mode
        self.scan_engine = ScanEngine(demo_mode=self.demo_mode)
        self.correlation_engine = CorrelationEngine(demo_mode=self.demo_mode)
        self.decision_engine = DecisionEngine(data_layer=self.data_layer)
        self.action_layer = ActionLayer(data_layer=self.data_layer)
        self.last_scan_summary: Optional[ScanSummary] = None

    def set_demo_mode(self, enabled: bool):
        self.demo_mode = enabled
        self.scan_engine.demo_mode = enabled
        self.correlation_engine.demo_mode = enabled

    def run_full_scan(self, custom_paths: Optional[List[str]] = None) -> ScanSummary:
        """Executes full scan across the 4-phase analysis flow."""
        start_time = time.time()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")

        # Step 1: Detect installed applications
        installed_apps = self.scan_engine.detect_installed_apps()

        # Step 2: Scan file system candidate roots
        candidate_folders = self.scan_engine.scan_file_system(custom_paths=custom_paths)

        # Step 3: Scan registry, services, and system associations
        sys_info = self.scan_engine.scan_registry_and_system()

        # Step 4: Correlate each folder with applications and system checks
        analyzed_folders: List[FolderItem] = []
        for folder in candidate_folders:
            analyzed = self.correlation_engine.analyze_folder(folder, installed_apps, sys_info)
            analyzed_folders.append(analyzed)

        # Step 5: Classify items via Decision Engine
        classified_folders = self.decision_engine.batch_classify(analyzed_folders)

        # Step 6: Compute statistics and summary
        duration = round(time.time() - start_time, 2)
        metrics = self.decision_engine.get_summary_counts(classified_folders)

        summary = ScanSummary(
            timestamp=timestamp,
            total_folders_scanned=len(classified_folders),
            installed_apps_count=len(installed_apps),
            leftovers_detected=metrics["leftovers"],
            system_protected_count=metrics["system_protected"],
            active_apps_count=metrics["active_apps"],
            uncertain_count=metrics["uncertain"],
            total_space_recoverable_bytes=metrics["recoverable_bytes"],
            duration_seconds=duration,
            items=classified_folders
        )

        self.last_scan_summary = summary
        self.data_layer.record_scan_history(summary)
        return summary

    def execute_item_action(self,
                            path: str,
                            action: str,
                            app_name: str = "",
                            permanent_delete: bool = False) -> Dict[str, Any]:
        """Executes action (delete, keep_allow, view_folder, ignore) on a specific item."""
        result = self.action_layer.execute_action(
            path=path,
            action=action,
            app_name=app_name,
            permanent_delete=permanent_delete
        )
        
        # Update last scan summary state if item is present
        if self.last_scan_summary:
            for item in self.last_scan_summary.items:
                if item.path == path:
                    item.action_taken = action
                    if action == "delete":
                        item.user_status = "quarantined" if not permanent_delete else "deleted"
                    elif action in ["keep", "keep_allow"]:
                        item.user_status = "allowed"
                    elif action == "ignore":
                        item.user_status = "ignored"
                    break

        return result

    # Allowlist proxies
    def get_allowlist(self) -> List[str]:
        return self.data_layer.get_allowlist()

    def add_allowlist(self, path: str):
        self.data_layer.add_to_allowlist(path)

    def remove_allowlist(self, path: str):
        self.data_layer.remove_from_allowlist(path)

    # Quarantine proxies
    def get_quarantine(self) -> List[Dict[str, Any]]:
        return self.data_layer.get_quarantine_items()

    def restore_quarantine(self, item_id: str) -> bool:
        return self.data_layer.restore_quarantine_item(item_id)

    def delete_quarantine_permanent(self, item_id: str) -> bool:
        return self.data_layer.delete_quarantine_item_permanently(item_id)

    # History & Settings proxies
    def get_history(self) -> List[Dict[str, Any]]:
        return self.data_layer.get_history()

    def get_settings(self) -> Dict[str, Any]:
        return self.data_layer.get_settings()

    def update_settings(self, settings: Dict[str, Any]):
        self.data_layer.update_settings(settings)

    def open_folder_in_os(self, path: str) -> Dict[str, Any]:
        return self.action_layer.open_in_file_manager(path)

