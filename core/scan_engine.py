import os
import sys
import glob
import subprocess
import configparser
from typing import List, Dict, Set, Optional, Tuple
from core.models import InstalledApp, FolderItem

class ScanEngine:
    """
    Layer 2: Scan Engine
    Coordinates all scanning modules and collects data.
    - Installed Apps Detection (programs list, uninstall entries, metadata)
    - File System Scanner (Program Files, ProgramData, AppData / ~/.config, ~/.local/share)
    - Registry / System Scanner (App keys, services, file associations, version info)
    """

    def __init__(self, demo_mode: bool = False):
        self.demo_mode = demo_mode
        self.is_windows = sys.platform.startswith("win")

    def detect_installed_apps(self) -> List[InstalledApp]:
        """Detect installed applications on the system or return simulated Windows apps if in demo mode."""
        if self.demo_mode:
            return self._get_demo_installed_apps()

        if self.is_windows:
            return self._detect_windows_installed_apps()
        else:
            return self._detect_linux_installed_apps()

    def scan_file_system(self, custom_paths: Optional[List[str]] = None) -> List[FolderItem]:
        """Scan file system application directories for candidate folders."""
        if self.demo_mode:
            return self._get_demo_folders()

        target_roots = []
        if custom_paths:
            target_roots.extend(custom_paths)
        elif self.is_windows:
            target_roots.extend(self._get_windows_scan_roots())
        else:
            target_roots.extend(self._get_linux_scan_roots())

        folder_items = []
        seen_paths = set()

        for root in target_roots:
            if not os.path.exists(root) or not os.path.isdir(root):
                continue
            try:
                with os.scandir(root) as entries:
                    for entry in entries:
                        if entry.is_dir(follow_symlinks=False):
                            norm_path = os.path.normpath(entry.path)
                            if norm_path in seen_paths:
                                continue
                            seen_paths.add(norm_path)
                            
                            size = self._calc_folder_size(norm_path)
                            try:
                                mtime = entry.stat().st_mtime
                            except Exception:
                                mtime = 0.0

                            item = FolderItem(
                                path=norm_path,
                                name=entry.name,
                                size_bytes=size,
                                size_formatted=self._format_size(size),
                                last_modified=mtime
                            )
                            folder_items.append(item)
            except Exception:
                continue

        return folder_items

    def scan_registry_and_system(self) -> Dict[str, Any]:
        """Scans registry, system services, and file associations."""
        if self.demo_mode:
            return {
                "services": ["GoogleUpdateTaskMachineUA", "DiscordUpdater", "WinDefend"],
                "app_keys": ["Software\\Microsoft\\Edge", "Software\\Valve\\Steam"],
                "file_associations": {".pdf": "Edge", ".docx": "Word"}
            }

        services = []
        app_keys = []
        file_assoc = {}

        if self.is_windows:
            try:
                import winreg
                for root_key in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
                    try:
                        with winreg.OpenKey(root_key, r"Software") as key:
                            count = winreg.QueryInfoKey(key)[0]
                            for i in range(count):
                                try:
                                    sub = winreg.EnumKey(key, i)
                                    app_keys.append(sub)
                                except Exception:
                                    break
                    except Exception:
                        pass
            except ImportError:
                pass
        else:
            # Linux: inspect systemd units and desktop file associations
            try:
                res = subprocess.run(["systemctl", "list-unit-files", "--type=service", "--no-pager"], 
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
                if res.returncode == 0:
                    for line in res.stdout.splitlines():
                        parts = line.strip().split()
                        if parts:
                            services.append(parts[0].replace(".service", ""))
            except Exception:
                pass

            # Inspect mimeapps
            mime_path = os.path.expanduser("~/.config/mimeapps.list")
            if os.path.exists(mime_path):
                try:
                    cp = configparser.ConfigParser()
                    cp.read(mime_path)
                    if "Default Applications" in cp:
                        for ext, app in cp["Default Applications"].items():
                            file_assoc[ext] = app
                except Exception:
                    pass

        return {
            "services": services,
            "app_keys": app_keys,
            "file_associations": file_assoc
        }

    # Internal Windows app detection
    def _detect_windows_installed_apps(self) -> List[InstalledApp]:
        apps = []
        try:
            import winreg
            uninstall_paths = [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
            ]
            for hkey, subkey_path in uninstall_paths:
                try:
                    with winreg.OpenKey(hkey, subkey_path) as root:
                        for i in range(winreg.QueryInfoKey(root)[0]):
                            try:
                                key_name = winreg.EnumKey(root, i)
                                with winreg.OpenKey(root, key_name) as app_key:
                                    def qv(v):
                                        try:
                                            return winreg.QueryValueEx(app_key, v)[0]
                                        except Exception:
                                            return None
                                    disp = qv("DisplayName")
                                    if disp:
                                        apps.append(InstalledApp(
                                            name=disp,
                                            display_name=disp,
                                            version=qv("DisplayVersion") or "1.0",
                                            publisher=qv("Publisher") or "Unknown",
                                            install_location=qv("InstallLocation"),
                                            uninstall_string=qv("UninstallString"),
                                            registry_key=f"{subkey_path}\\{key_name}"
                                        ))
                            except Exception:
                                continue
                except Exception:
                    continue
        except ImportError:
            pass
        return apps

    # Internal Linux app detection
    def _detect_linux_installed_apps(self) -> List[InstalledApp]:
        apps = []
        seen_names = set()

        # 1. Desktop entries from standard locations
        desktop_dirs = [
            "/usr/share/applications",
            "/usr/local/share/applications",
            os.path.expanduser("~/.local/share/applications"),
            "/var/lib/flatpak/exports/share/applications",
            "/var/lib/snapd/desktop/applications"
        ]

        for d in desktop_dirs:
            if not os.path.exists(d):
                continue
            for entry_file in glob.glob(os.path.join(d, "*.desktop")):
                try:
                    cp = configparser.ConfigParser(interpolation=None)
                    cp.read(entry_file, encoding='utf-8')
                    if "Desktop Entry" in cp:
                        sec = cp["Desktop Entry"]
                        disp = sec.get("Name", "")
                        exec_cmd = sec.get("Exec", "")
                        if disp and disp.lower() not in seen_names:
                            seen_names.add(disp.lower())
                            apps.append(InstalledApp(
                                name=disp,
                                display_name=disp,
                                version=sec.get("Version", "1.0"),
                                publisher=sec.get("Categories", "Utility").split(";")[0],
                                install_location=entry_file,
                                is_system_app=entry_file.startswith("/usr")
                            ))
                except Exception:
                    continue

        # 2. Add packages from dpkg/apt if available
        try:
            res = subprocess.run(["dpkg-query", "-W", "-f=${Package}|${Version}|${Maintainer}\n"],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=4)
            if res.returncode == 0:
                for line in res.stdout.splitlines()[:500]: # top packages
                    parts = line.split("|")
                    if parts and parts[0]:
                        pkg_name = parts[0]
                        if pkg_name.lower() not in seen_names:
                            seen_names.add(pkg_name.lower())
                            apps.append(InstalledApp(
                                name=pkg_name,
                                display_name=pkg_name,
                                version=parts[1] if len(parts) > 1 else "Unknown",
                                publisher=parts[2] if len(parts) > 2 else "Ubuntu/Debian",
                                is_system_app=True
                            ))
        except Exception:
            pass

        return apps

    def _get_windows_scan_roots(self) -> List[str]:
        roots = []
        for env_var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA"]:
            val = os.environ.get(env_var)
            if val and os.path.exists(val):
                roots.append(val)
        return roots

    def _get_linux_scan_roots(self) -> List[str]:
        return [
            os.path.expanduser("~/.config"),
            os.path.expanduser("~/.local/share"),
            os.path.expanduser("~/.cache"),
            "/opt"
        ]

    def _calc_folder_size(self, path: str, max_files: int = 1500) -> int:
        total = 0
        count = 0
        try:
            for root, dirs, files in os.walk(path):
                for f in files:
                    fp = os.path.join(root, f)
                    if not os.path.islink(fp):
                        try:
                            total += os.path.getsize(fp)
                        except Exception:
                            pass
                    count += 1
                    if count >= max_files:
                        return total
        except Exception:
            pass
        return total

    def _format_size(self, size_bytes: int) -> str:
        size = float(size_bytes)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}" if unit != 'B' else f"{int(size)} B"
            size /= 1024.0
        return f"{size:.1f} PB"

    # Built-in demo datasets matching the image diagram
    def _get_demo_installed_apps(self) -> List[InstalledApp]:
        return [
            InstalledApp(name="Mozilla Firefox", display_name="Mozilla Firefox", version="125.0", publisher="Mozilla Corporation", install_location=r"C:\Program Files\Mozilla Firefox"),
            InstalledApp(name="Visual Studio Code", display_name="Microsoft Visual Studio Code", version="1.88.1", publisher="Microsoft Corporation", install_location=r"C:\Users\User\AppData\Local\Programs\Microsoft VS Code"),
            InstalledApp(name="Steam", display_name="Steam", version="2.10.91", publisher="Valve Corporation", install_location=r"C:\Program Files (x86)\Steam"),
            InstalledApp(name="Spotify", display_name="Spotify Music", version="1.2.34", publisher="Spotify AB", install_location=r"C:\Users\User\AppData\Roaming\Spotify"),
            InstalledApp(name="Microsoft Edge", display_name="Microsoft Edge", version="124.0", publisher="Microsoft Corporation", install_location=r"C:\Program Files (x86)\Microsoft\Edge"),
            InstalledApp(name="7-Zip", display_name="7-Zip 23.01", version="23.01", publisher="Igor Pavlov", install_location=r"C:\Program Files\7-Zip")
        ]

    def _get_demo_folders(self) -> List[FolderItem]:
        # Contains exact examples from the diagram, including Google Chrome (uninstalled leftover, 438 MB)!
        demo_items = [
            FolderItem(
                path=r"C:\Users\User\AppData\Local\Google\Chrome",
                name="Chrome",
                size_bytes=459276288, # 438 MB
                size_formatted="438.0 MB",
                associated_app_name="Google Chrome",
                last_modified=1711789200
            ),
            FolderItem(
                path=r"C:\ProgramData\Discord",
                name="Discord",
                size_bytes=134217728, # 128 MB
                size_formatted="128.0 MB",
                associated_app_name="Discord",
                last_modified=1710500000
            ),
            FolderItem(
                path=r"C:\Program Files (x86)\WinRAR",
                name="WinRAR",
                size_bytes=35651584, # 34 MB
                size_formatted="34.0 MB",
                associated_app_name="WinRAR",
                last_modified=1708100000
            ),
            FolderItem(
                path=r"C:\Program Files\Mozilla Firefox",
                name="Mozilla Firefox",
                size_bytes=241172480, # 230 MB
                size_formatted="230.0 MB",
                associated_app_name="Mozilla Firefox",
                last_modified=1712000000
            ),
            FolderItem(
                path=r"C:\Windows\System32",
                name="System32",
                size_bytes=4294967296, # 4 GB
                size_formatted="4.0 GB",
                associated_app_name="Windows Operating System",
                last_modified=1700000000
            ),
            FolderItem(
                path=r"C:\Program Files\WindowsApps",
                name="WindowsApps",
                size_bytes=2147483648, # 2 GB
                size_formatted="2.0 GB",
                associated_app_name="Microsoft Windows Protected",
                last_modified=1701000000
            ),
            FolderItem(
                path=r"C:\Users\User\AppData\Local\TempCache_OldInstaller",
                name="TempCache_OldInstaller",
                size_bytes=15728640, # 15 MB
                size_formatted="15.0 MB",
                associated_app_name=None,
                last_modified=1704000000
            ),
            FolderItem(
                path=r"C:\Users\User\AppData\Roaming\Spotify",
                name="Spotify",
                size_bytes=188743680, # 180 MB
                size_formatted="180.0 MB",
                associated_app_name="Spotify",
                last_modified=1712100000
            )
        ]
        return demo_items
