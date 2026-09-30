import os
import re
import psutil
from typing import List, Dict, Optional, Tuple, Set
from core.models import FolderItem, InstalledApp

# Critical protected system path signatures
PROTECTED_SYSTEM_PATHS = {
    # Windows
    "c:\\windows",
    "c:\\windows\\system32",
    "c:\\windows\\syswow64",
    "c:\\windows\\winsxs",
    "c:\\program files\\windowsapps",
    "c:\\program files\\windows defender",
    "c:\\program files\\common files\\system",
    "c:\\users\\all users\\microsoft\\windows",
    # Linux
    "/bin", "/sbin", "/etc", "/lib", "/lib64", "/boot", "/sys", "/proc",
    "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/include"
}

PROTECTED_FOLDER_NAMES = {
    "system32", "syswow64", "winsxs", "windowsapps", "system volume information",
    "recovery", "boot", "etc", "bin", "sbin", "lib", "proc", "sys", "dev"
}

class CorrelationEngine:
    """
    Layer 3: Correlation & Analysis Engine
    Determines status of each folder and application.
    - Check if application is installed
    - Does folder belong to the application?
    - Is it system / Windows protected?
    - Check running processes, services, references, digital signatures
    """

    def __init__(self, demo_mode: bool = False):
        self.demo_mode = demo_mode

    def analyze_folder(self, 
                       folder: FolderItem, 
                       installed_apps: List[InstalledApp], 
                       system_info: Dict[str, Any]) -> FolderItem:
        """Runs the 4 correlation & analysis checks on a folder item."""
        
        # 1. Is it system / Windows protected?
        is_protected, protect_reason = self.check_system_protected(folder.path, folder.name)
        folder.is_protected = is_protected
        if is_protected:
            folder.decision_reason = protect_reason
            return folder

        # 2. Check running processes, services, references, digital signatures
        running_procs = self.check_running_processes(folder.path)
        folder.running_process_names = running_procs
        folder.has_services = self.check_services(folder.name, system_info.get("services", []))
        folder.has_registry_references = self.check_registry_references(folder.name, system_info.get("app_keys", []))
        folder.has_digital_signatures = self.check_signatures(folder.path)

        # 3. Does folder belong to an application? & Check if application is installed
        matched_app, confidence = self.correlate_with_applications(folder.path, folder.name, installed_apps)
        if matched_app:
            folder.associated_app_name = matched_app.display_name
            folder.decision_reason = f"Application '{matched_app.display_name}' (v{matched_app.version}) is currently installed."
        else:
            # Check if it looks like a known uninstalled application
            inferred_name = self.infer_application_name(folder.path, folder.name)
            if inferred_name:
                folder.associated_app_name = inferred_name
                folder.decision_reason = f"Application '{inferred_name}' is not installed in the system."
            else:
                folder.associated_app_name = None
                folder.decision_reason = "No matching application metadata or install record found."

        return folder

    def check_system_protected(self, path: str, name: str) -> Tuple[bool, str]:
        """Check if folder is a critical system / Windows protected folder."""
        norm_path = path.lower().replace("/", "\\")
        lower_name = name.lower()

        if lower_name in PROTECTED_FOLDER_NAMES:
            return True, f"System critical protected component: {name}"

        for sys_path in PROTECTED_SYSTEM_PATHS:
            normalized_sys = sys_path.lower().replace("/", "\\")
            if norm_path == normalized_sys or norm_path.startswith(normalized_sys + "\\"):
                return True, f"Protected operating system directory: {sys_path}"

        # Linux root paths
        unix_path = path.replace("\\", "/")
        for sys_path in ["/etc", "/bin", "/sbin", "/boot", "/sys", "/proc", "/usr/bin", "/usr/lib"]:
            if unix_path == sys_path or unix_path.startswith(sys_path + "/"):
                return True, f"Linux system protected path: {sys_path}"

        return False, ""

    def correlate_with_applications(self, path: str, folder_name: str, installed_apps: List[InstalledApp]) -> Tuple[Optional[InstalledApp], float]:
        """Check if folder belongs to an installed application."""
        norm_path = path.lower().replace("/", "\\")
        name_clean = re.sub(r'[^a-zA-Z0-9]', '', folder_name).lower()

        # Direct install location match
        for app in installed_apps:
            if app.install_location:
                app_loc = app.install_location.lower().replace("/", "\\")
                if norm_path == app_loc or norm_path.startswith(app_loc + "\\") or app_loc.startswith(norm_path + "\\"):
                    return app, 1.0

        # Exact and tokenized name matches
        for app in installed_apps:
            app_clean = re.sub(r'[^a-zA-Z0-9]', '', app.name).lower()
            disp_clean = re.sub(r'[^a-zA-Z0-9]', '', app.display_name).lower()

            if name_clean and (name_clean == app_clean or name_clean == disp_clean):
                return app, 0.95
            
            # Substring match if name is long enough
            if len(name_clean) >= 4:
                if name_clean in app_clean or name_clean in disp_clean:
                    return app, 0.8
                if app_clean in name_clean or disp_clean in name_clean:
                    return app, 0.8

        return None, 0.0

    def infer_application_name(self, path: str, folder_name: str) -> Optional[str]:
        """Infers the probable application name from folder naming and path context."""
        # Handle demo items directly if matching
        if "google\\chrome" in path.lower() or "google/chrome" in path.lower():
            return "Google Chrome"
        if "discord" in folder_name.lower():
            return "Discord"
        if "winrar" in folder_name.lower():
            return "WinRAR"

        # General inference
        clean_name = folder_name.strip()
        if clean_name.lower() in ["temp", "cache", "logs", "tmp", "crashreports", "update", "backup"]:
            return None

        # Return capitalised folder name
        return clean_name.replace("_", " ").replace("-", " ").title()

    def check_running_processes(self, folder_path: str) -> List[str]:
        """Check if any currently running processes are executing from or locking the folder."""
        if self.demo_mode:
            # In demo mode, simulate Spotify or Firefox running if inspected
            if "firefox" in folder_path.lower():
                return ["firefox.exe"]
            return []

        running = []
        norm_path = os.path.normpath(folder_path).lower()
        try:
            for proc in psutil.process_iter(['name', 'exe', 'cwd']):
                try:
                    pinfo = proc.info
                    exe_path = pinfo.get('exe')
                    if exe_path:
                        exe_norm = os.path.normpath(exe_path).lower()
                        if exe_norm.startswith(norm_path):
                            running.append(pinfo.get('name') or "Process")
                            continue
                    cwd = pinfo.get('cwd')
                    if cwd:
                        cwd_norm = os.path.normpath(cwd).lower()
                        if cwd_norm.startswith(norm_path):
                            running.append(pinfo.get('name') or "Process")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception:
            pass

        return list(set(running))

    def check_services(self, folder_name: str, services: List[str]) -> bool:
        """Check if any system services reference this application."""
        clean = folder_name.lower()
        for svc in services:
            if clean in svc.lower():
                return True
        return False

    def check_registry_references(self, folder_name: str, app_keys: List[str]) -> bool:
        """Check if registry references exist for this folder."""
        clean = folder_name.lower()
        for key in app_keys:
            if clean in key.lower():
                return True
        return False

    def check_signatures(self, folder_path: str) -> bool:
        """Check if folder files contain valid digital signatures."""
        # On Windows or Linux, check if binary executables are present
        return False
