import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Any

class DecisionStatus(Enum):
    APPLICATION_EXISTS = "Application Exists"
    APPLICATION_DELETED = "Application Deleted"
    SYSTEM_PROTECTED = "System Protected"
    UNKNOWN_UNCERTAIN = "Unknown / Uncertain"

class UserAction(Enum):
    DELETE = "Delete"
    KEEP_ALLOW = "Keep / Allow"
    VIEW_FOLDER = "View Folder"
    IGNORE = "Ignore"

@dataclass
class InstalledApp:
    name: str
    display_name: str
    version: str = "Unknown"
    publisher: str = "Unknown"
    install_location: Optional[str] = None
    uninstall_string: Optional[str] = None
    registry_key: Optional[str] = None
    is_system_app: bool = False

@dataclass
class FolderItem:
    path: str
    name: str
    size_bytes: int = 0
    size_formatted: str = "0 B"
    associated_app_name: Optional[str] = None
    decision: DecisionStatus = DecisionStatus.UNKNOWN_UNCERTAIN
    decision_reason: str = ""
    is_protected: bool = False
    running_process_names: List[str] = field(default_factory=list)
    has_services: bool = False
    has_registry_references: bool = False
    has_digital_signatures: bool = False
    last_modified: float = 0.0
    action_taken: Optional[str] = None
    user_status: Optional[str] = None  # "deleted", "quarantined", "allowed", "ignored"

    def format_size(self) -> str:
        size = self.size_bytes
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}" if unit != 'B' else f"{int(size)} B"
            size /= 1024.0
        return f"{size:.1f} PB"

@dataclass
class ScanSummary:
    timestamp: str
    total_folders_scanned: int = 0
    installed_apps_count: int = 0
    leftovers_detected: int = 0
    system_protected_count: int = 0
    active_apps_count: int = 0
    uncertain_count: int = 0
    total_space_recoverable_bytes: int = 0
    duration_seconds: float = 0.0
    items: List[FolderItem] = field(default_factory=list)

@dataclass
class QuarantineItem:
    id: str
    original_path: str
    quarantine_path: str
    timestamp: str
    size_bytes: int
    size_formatted: str
    associated_app: str
    reason: str
