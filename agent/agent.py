#!/usr/bin/env python3
"""
Cross-Platform Leftover Folder Scanner Agent
Zero external dependencies (uses standard Python 3 libraries only: urllib, json, os, sys, platform).
Runs on any remote system and reports scan findings back to the central dashboard.
"""

import os
import sys
import json
import time
import socket
import platform
import urllib.request
import urllib.parse

DEFAULT_SERVER_URL = "http://192.168.0.139:8090"

def get_installed_apps_linux():
    apps = set()
    desktop_dirs = [
        "/usr/share/applications",
        "/usr/local/share/applications",
        os.path.expanduser("~/.local/share/applications")
    ]
    for d in desktop_dirs:
        if os.path.exists(d):
            try:
                for f in os.listdir(d):
                    if f.endswith(".desktop"):
                        name = f.replace(".desktop", "").replace("-", " ").replace("_", " ").lower()
                        apps.add(name)
            except Exception:
                pass
    return list(apps)

def get_installed_apps_windows():
    apps = {}
    try:
        import winreg
        keys = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Uninstall")
        ]
        for root, sub in keys:
            try:
                with winreg.OpenKey(root, sub) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as app_key:
                                try:
                                    disp = winreg.QueryValueEx(app_key, "DisplayName")[0]
                                    if disp:
                                        clean = "".join(c for c in disp if c.isalnum()).lower()
                                        apps[clean] = disp
                                except Exception:
                                    pass
                        except Exception:
                            continue
            except Exception:
                pass
    except Exception:
        pass
    return apps

def calc_folder_size(path, max_files=1000):
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

def format_size(size_bytes):
    s = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if s < 1024.0:
            return f"{s:.1f} {unit}" if unit != 'B' else f"{int(s)} B"
        s /= 1024.0
    return f"{s:.1f} PB"

def scan_system():
    is_win = platform.system() == "Windows"
    start_time = time.time()
    hostname = socket.gethostname()

    print(f"Scanning target system: {hostname} ({platform.system()} {platform.release()})...")

    # Target roots
    target_roots = []
    if is_win:
        for ev in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData", "LOCALAPPDATA", "APPDATA"]:
            v = os.environ.get(ev)
            if v and os.path.exists(v):
                target_roots.append(v)
        installed = get_installed_apps_windows()
    else:
        target_roots = [
            os.path.expanduser("~/.config"),
            os.path.expanduser("~/.local/share"),
            "/opt"
        ]
        installed = get_installed_apps_linux()

    protected_names = {"system32", "syswow64", "winsxs", "windowsapps", "bin", "etc", "lib", "boot"}

    items = []
    leftovers_count = 0
    recoverable_bytes = 0
    protected_count = 0
    active_count = 0

    seen = set()
    for root in target_roots:
        if not os.path.exists(root):
            continue
        try:
            for entry in os.listdir(root):
                full_path = os.path.join(root, entry)
                if not os.path.isdir(full_path) or full_path in seen:
                    continue
                seen.add(full_path)

                clean_name = "".join(c for c in entry if c.isalnum()).lower()
                size = calc_folder_size(full_path)

                is_protected = False
                decision = "Unknown / Uncertain"
                reason = ""
                associated_app = entry

                if entry.lower() in protected_names or "system" in entry.lower():
                    is_protected = True
                    decision = "System Protected"
                    reason = "Critical system operating folder."
                    protected_count += 1
                elif is_win:
                    if clean_name in installed:
                        decision = "Application Exists"
                        associated_app = installed[clean_name]
                        reason = f"Application '{associated_app}' is currently installed."
                        active_count += 1
                    else:
                        decision = "Application Deleted"
                        reason = "Application is not installed in the Windows registry."
                        leftovers_count += 1
                        recoverable_bytes += size
                else:
                    if clean_name in installed:
                        decision = "Application Exists"
                        reason = f"Application package '{entry}' is installed."
                        active_count += 1
                    else:
                        decision = "Application Deleted"
                        reason = "Application is not installed."
                        leftovers_count += 1
                        recoverable_bytes += size

                items.append({
                    "path": full_path,
                    "name": entry,
                    "size_bytes": size,
                    "size_formatted": format_size(size),
                    "associated_app_name": associated_app,
                    "decision": decision,
                    "decision_reason": reason,
                    "is_protected": is_protected,
                    "running_processes": []
                })
        except Exception:
            pass

    duration = round(time.time() - start_time, 2)
    print(f"Scan completed in {duration}s:")
    print(f"  Leftover folders: {leftovers_count} ({format_size(recoverable_bytes)})")
    print(f"  Active apps: {active_count}")
    print(f"  Protected folders: {protected_count}")

    # Detect local IP
    ip_addr = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_addr = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    node_id = f"{platform.system().lower()}_{hostname.replace(' ', '_').lower()}"
    payload = {
        "node_id": node_id,
        "hostname": hostname,
        "os_type": f"{platform.system()} {platform.release()}",
        "ip_address": ip_addr,
        "scan_data": {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "duration_seconds": duration,
            "total_folders_scanned": len(items),
            "installed_apps_count": len(installed),
            "leftovers_detected": leftovers_count,
            "system_protected_count": protected_count,
            "active_apps_count": active_count,
            "uncertain_count": 0,
            "total_space_recoverable_bytes": recoverable_bytes,
            "total_space_recoverable_formatted": format_size(recoverable_bytes),
            "items": items
        }
    }
    return payload

def report_to_server(payload, server_url):
    url = f"{server_url.rstrip('/')}/api/nodes/report"
    print(f"Uploading scan report to central dashboard at {url}...")
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            print(f"SUCCESS: System registered! {data.get('message', '')}")
            print(f"View and manage this machine live at: {server_url}")
    except Exception as e:
        print(f"ERROR connecting to dashboard: {e}")

if __name__ == "__main__":
    server = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_SERVER_URL
    scan_result = scan_system()
    report_to_server(scan_result, server)
