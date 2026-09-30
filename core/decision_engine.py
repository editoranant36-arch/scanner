import os
from typing import List, Dict, Optional, Tuple, Any
from core.models import FolderItem, DecisionStatus, UserAction
from core.data_layer import DataAndHistoryLayer

class DecisionEngine:
    """
    Layer 4: Decision Engine
    Classifies each item and decides the next action based on correlation data and safety rules.
    - Application Exists -> Keep (No action)
    - Application Deleted -> Leftover Folder Found (Triggers user action)
    - System Protected -> Keep (No Deletion)
    - Unknown / Uncertain -> Ask User / Ignore
    """

    def __init__(self, data_layer: Optional[DataAndHistoryLayer] = None):
        self.data_layer = data_layer or DataAndHistoryLayer()

    def classify_folder(self, folder: FolderItem) -> FolderItem:
        """Classifies a folder into one of the 4 defined decision statuses."""
        settings = self.data_layer.get_settings()
        
        # 1. Check Allowlist: if user previously allowed this folder, it is kept
        if self.data_layer.is_allowlisted(folder.path):
            folder.decision = DecisionStatus.APPLICATION_EXISTS
            folder.decision_reason = "Folder is in user allowlist. Skipped from leftover list."
            return folder

        # 2. System Protected: Critical system/OS folders can NEVER be deleted
        if folder.is_protected:
            folder.decision = DecisionStatus.SYSTEM_PROTECTED
            if not folder.decision_reason:
                folder.decision_reason = "Protected system directory. Deletion strictly prohibited."
            return folder

        # 3. Check Running Processes / Services lock
        if settings.get("safety_check_running_processes", True) and folder.running_process_names:
            folder.decision = DecisionStatus.APPLICATION_EXISTS
            folder.decision_reason = f"Active processes detected ({', '.join(folder.running_process_names)}). Protected from deletion."
            return folder

        # 4. Installed Application Exists check
        # If correlated to an active installed app
        if folder.decision_reason and "currently installed" in folder.decision_reason:
            folder.decision = DecisionStatus.APPLICATION_EXISTS
            return folder

        # 5. Application Deleted (Leftover Folder)
        if folder.associated_app_name:
            folder.decision = DecisionStatus.APPLICATION_DELETED
            if not folder.decision_reason:
                folder.decision_reason = f"Application '{folder.associated_app_name}' is not installed. Leftover folder identified."
            return folder

        # 6. Unknown / Uncertain
        folder.decision = DecisionStatus.UNKNOWN_UNCERTAIN
        if not folder.decision_reason:
            folder.decision_reason = "Unable to correlate folder with known application or system component."
        return folder

    def batch_classify(self, folders: List[FolderItem]) -> List[FolderItem]:
        """Classifies a list of folder items."""
        classified = []
        for f in folders:
            classified.append(self.classify_folder(f))
        return classified

    def get_summary_counts(self, folders: List[FolderItem]) -> Dict[str, Any]:
        """Calculates aggregate metrics for the scanned folders."""
        counts = {
            "total": len(folders),
            "leftovers": 0,
            "active_apps": 0,
            "system_protected": 0,
            "uncertain": 0,
            "recoverable_bytes": 0
        }
        for f in folders:
            if f.decision == DecisionStatus.APPLICATION_DELETED:
                counts["leftovers"] += 1
                counts["recoverable_bytes"] += f.size_bytes
            elif f.decision == DecisionStatus.APPLICATION_EXISTS:
                counts["active_apps"] += 1
            elif f.decision == DecisionStatus.SYSTEM_PROTECTED:
                counts["system_protected"] += 1
            elif f.decision == DecisionStatus.UNKNOWN_UNCERTAIN:
                counts["uncertain"] += 1

        return counts
