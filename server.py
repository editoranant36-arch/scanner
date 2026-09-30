import os
import sys
import json
import time
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
from pydantic import BaseModel

from core.orchestrator import ScannerOrchestrator
from core.models import DecisionStatus

app = FastAPI(title="Application Leftover Folder Scanner API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator instance
orchestrator = ScannerOrchestrator(demo_mode=True)

class ActionRequest(BaseModel):
    path: str
    action: str
    app_name: Optional[str] = ""
    permanent_delete: Optional[bool] = False

class AllowlistRequest(BaseModel):
    path: str
    operation: str = "add"  # "add" or "remove"

class QuarantineRestoreRequest(BaseModel):
    item_id: str

class SettingsUpdateRequest(BaseModel):
    settings: Dict[str, Any]

@app.get("/api/status")
def get_status():
    return {
        "status": "online",
        "demo_mode": orchestrator.demo_mode,
        "is_windows": orchestrator.scan_engine.is_windows,
        "platform": sys.platform,
        "quarantine_count": len(orchestrator.get_quarantine()),
        "allowlist_count": len(orchestrator.get_allowlist()),
        "has_last_scan": orchestrator.last_scan_summary is not None
    }

@app.get("/api/scan")
def run_scan(demo: Optional[bool] = None, custom_paths: Optional[str] = None):
    if demo is not None:
        orchestrator.set_demo_mode(demo)
    
    paths_list = None
    if custom_paths:
        paths_list = [p.strip() for p in custom_paths.split(",") if p.strip()]

    summary = orchestrator.run_full_scan(custom_paths=paths_list)

    items_payload = []
    for it in summary.items:
        items_payload.append({
            "path": it.path,
            "name": it.name,
            "size_bytes": it.size_bytes,
            "size_formatted": it.size_formatted,
            "associated_app_name": it.associated_app_name,
            "decision": it.decision.value,
            "decision_reason": it.decision_reason,
            "is_protected": it.is_protected,
            "running_processes": it.running_process_names,
            "has_services": it.has_services,
            "has_registry_references": it.has_registry_references,
            "action_taken": it.action_taken,
            "user_status": it.user_status,
            "last_modified": it.last_modified
        })

    return {
        "timestamp": summary.timestamp,
        "duration_seconds": summary.duration_seconds,
        "total_folders_scanned": summary.total_folders_scanned,
        "installed_apps_count": summary.installed_apps_count,
        "leftovers_detected": summary.leftovers_detected,
        "system_protected_count": summary.system_protected_count,
        "active_apps_count": summary.active_apps_count,
        "uncertain_count": summary.uncertain_count,
        "total_space_recoverable_bytes": summary.total_space_recoverable_bytes,
        "total_space_recoverable_formatted": orchestrator.data_layer._format_size(summary.total_space_recoverable_bytes),
        "items": items_payload
    }

@app.post("/api/action")
def execute_action(req: ActionRequest):
    res = orchestrator.execute_item_action(
        path=req.path,
        action=req.action,
        app_name=req.app_name or "",
        permanent_delete=req.permanent_delete or False
    )
    return res

@app.get("/api/quarantine")
def list_quarantine():
    return orchestrator.get_quarantine()

@app.post("/api/quarantine/restore")
def restore_quarantine(req: QuarantineRestoreRequest):
    ok = orchestrator.restore_quarantine(req.item_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to restore item from quarantine")
    return {"success": True, "message": "Folder restored successfully to original path."}

@app.delete("/api/quarantine/{item_id}")
def purge_quarantine(item_id: str):
    ok = orchestrator.delete_quarantine_permanent(item_id)
    if not ok:
        raise HTTPException(status_code=400, detail="Failed to permanently delete quarantine item")
    return {"success": True, "message": "Quarantine item permanently removed from disk."}

@app.get("/api/allowlist")
def get_allowlist():
    return orchestrator.get_allowlist()

@app.post("/api/allowlist")
def update_allowlist(req: AllowlistRequest):
    if req.operation == "add":
        orchestrator.add_allowlist(req.path)
        return {"success": True, "message": f"Added '{req.path}' to allowlist."}
    else:
        orchestrator.remove_allowlist(req.path)
        return {"success": True, "message": f"Removed '{req.path}' from allowlist."}

@app.get("/api/history")
def get_history():
    return orchestrator.get_history()

@app.get("/api/settings")
def get_settings():
    return orchestrator.get_settings()

@app.post("/api/settings")
def save_settings(req: SettingsUpdateRequest):
    orchestrator.update_settings(req.settings)
    return {"success": True, "settings": orchestrator.get_settings()}

@app.get("/api/folder_details")
def folder_details(path: str = Query(...)):
    res = orchestrator.action_layer._inspect_folder(path)
    return res

@app.post("/api/open_folder")
def open_folder_endpoint(req: ActionRequest):
    res = orchestrator.open_folder_in_os(req.path)
    return res

# Multi-Node / Multi-System Architecture
from fastapi.responses import FileResponse
from core.node_manager import NodeManager

node_manager = NodeManager()

class NodeReportRequest(BaseModel):
    node_id: str
    hostname: str
    os_type: str
    ip_address: str
    scan_data: Dict[str, Any]

@app.get("/api/nodes")
def get_nodes():
    return node_manager.get_nodes()

@app.post("/api/nodes/report")
def report_node_scan(req: NodeReportRequest):
    node = node_manager.register_or_update_node(
        node_id=req.node_id,
        hostname=req.hostname,
        os_type=req.os_type,
        ip_address=req.ip_address,
        scan_data=req.scan_data
    )
    return {"success": True, "message": f"Scan registered for system: {req.hostname}", "node_id": req.node_id}

@app.get("/api/nodes/{node_id}/scan")
def get_node_scan(node_id: str):
    if node_id == "local":
        return run_scan()
    scan = node_manager.get_node_scan(node_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Node scan not found")
    return scan

@app.delete("/api/nodes/{node_id}")
def delete_node(node_id: str):
    node_manager.remove_node(node_id)
    return {"success": True}

# Serve agent scripts for 1-click execution on remote machines
@app.get("/agent/scan.ps1")
def get_agent_ps1():
    p = os.path.join(os.path.dirname(__file__), "agent", "scan.ps1")
    return FileResponse(p, media_type="text/plain", filename="scan.ps1")

@app.get("/agent/agent.py")
def get_agent_py():
    p = os.path.join(os.path.dirname(__file__), "agent", "agent.py")
    return FileResponse(p, media_type="text/plain", filename="agent.py")

@app.get("/agent/scan.sh")
def get_agent_sh():
    p = os.path.join(os.path.dirname(__file__), "agent", "scan.sh")
    return FileResponse(p, media_type="text/plain", filename="scan.sh")

# Root Frontend UI
@app.get("/", response_class=HTMLResponse)

def index():
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Application Leftover Folder Scanner</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
  <script src="https://cdn.tailwindcss.com"></script>
  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            sans: ['Inter', 'sans-serif'],
            mono: ['JetBrains Mono', 'monospace'],
          },
          colors: {
            brand: {
              50: '#eff6ff',
              100: '#dbeafe',
              500: '#3b82f6',
              600: '#2563eb',
              700: '#1d4ed8',
              800: '#1e40af',
              900: '#1e3a8a',
            }
          }
        }
      }
    }
  </script>
  <style>
    body {
      background-color: #0d131f;
      color: #e2e8f0;
    }
    .glass-card {
      background: rgba(22, 30, 49, 0.85);
      border: 1px solid rgba(255, 255, 255, 0.08);
      backdrop-filter: blur(12px);
    }
    .badge-deleted {
      background: rgba(239, 68, 68, 0.15);
      color: #f87171;
      border: 1px solid rgba(239, 68, 68, 0.3);
    }
    .badge-exists {
      background: rgba(34, 197, 94, 0.15);
      color: #4ade80;
      border: 1px solid rgba(34, 197, 94, 0.3);
    }
    .badge-protected {
      background: rgba(234, 179, 8, 0.15);
      color: #facc15;
      border: 1px solid rgba(234, 179, 8, 0.3);
    }
    .badge-unknown {
      background: rgba(148, 163, 184, 0.15);
      color: #cbd5e1;
      border: 1px solid rgba(148, 163, 184, 0.3);
    }
    .glow-blue {
      box-shadow: 0 0 25px -5px rgba(59, 130, 246, 0.25);
    }
    .glow-red {
      box-shadow: 0 0 25px -5px rgba(239, 68, 68, 0.3);
    }
  </style>
</head>
<body class="min-h-screen flex flex-col font-sans selection:bg-blue-600 selection:text-white">

  <!-- Top App Navigation -->
  <header class="border-b border-slate-800 bg-[#101827]/90 sticky top-0 z-40 backdrop-blur">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
      <div class="flex items-center space-x-3">
        <div class="w-10 h-10 rounded-xl bg-gradient-to-tr from-blue-600 to-indigo-500 flex items-center justify-center shadow-lg shadow-blue-500/20 text-white font-bold">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
          </svg>
        </div>
        <div>
          <h1 class="text-lg font-bold text-white tracking-tight flex items-center gap-2">
            Application Leftover Folder Scanner
            <span class="text-xs px-2 py-0.5 rounded-full bg-blue-500/20 text-blue-400 font-medium border border-blue-500/30">Architecture v1.0</span>
          </h1>
          <p class="text-xs text-slate-400">Deep Correlation & Decision Engine for Residual App Directories</p>
        </div>
      </div>

      <!-- Navigation Tabs -->
      <nav class="flex items-center space-x-1">
        <button onclick="switchTab('dashboard')" id="tab-btn-dashboard" class="px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 text-white bg-blue-600 shadow-sm">
          <span>🏠</span> Dashboard
        </button>
        <button onclick="switchTab('results')" id="tab-btn-results" class="px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 text-slate-400 hover:text-white hover:bg-slate-800">
          <span>📋</span> Results
          <span id="nav-leftover-badge" class="hidden text-xs px-1.5 py-0.2 rounded-full bg-red-500 text-white font-bold">0</span>
        </button>
        <button onclick="switchTab('actions')" id="tab-btn-actions" class="px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 text-slate-400 hover:text-white hover:bg-slate-800">
          <span>⚡</span> Action Center
        </button>
        <button onclick="switchTab('settings')" id="tab-btn-settings" class="px-4 py-2 rounded-lg text-sm font-medium transition flex items-center gap-2 text-slate-400 hover:text-white hover:bg-slate-800">
          <span>⚙️</span> Settings & History
        </button>
      </nav>

      <!-- Target System & Scan Controls Header -->
      <div class="flex items-center space-x-2">
        <div class="flex items-center gap-1.5 bg-slate-800/90 px-2.5 py-1.5 rounded-lg border border-slate-700">
          <span class="text-xs text-slate-400 font-semibold">System:</span>
          <select id="nodeSelector" onchange="onNodeSelected()" class="bg-slate-900 border border-slate-700 text-xs rounded px-2 py-0.5 text-white font-medium focus:outline-none cursor-pointer">
            <option value="local">🖥️ Host (192.168.0.139)</option>
          </select>
        </div>

        <button onclick="openConnectNodeModal()" class="px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs transition flex items-center gap-1.5 shadow active:scale-95">
          <span>➕</span> Scan Another System
        </button>

        <label class="flex items-center gap-1.5 text-xs text-slate-300 bg-slate-800/80 px-2.5 py-1.5 rounded-lg border border-slate-700 cursor-pointer hover:border-slate-600 transition">
          <input type="checkbox" id="demoModeToggle" checked onchange="toggleDemoMode()" class="rounded bg-slate-900 border-slate-700 text-blue-600 focus:ring-blue-500">
          <span>Architecture Demo</span>
        </label>

        <button onclick="triggerScan()" id="btnGlobalScan" class="px-4 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-semibold shadow-md flex items-center gap-2 transition active:scale-95">
          <svg id="scanSpinner" class="hidden animate-spin h-3.5 w-3.5 text-white" fill="none" viewBox="0 0 24 24">
            <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
            <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z"></path>
          </svg>
          <span id="scanBtnText">Run Scan Now</span>
        </button>
      </div>
    </div>
  </header>


  <!-- Main Content Body -->
  <main class="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6 space-y-6">

    <!-- TAB 1: DASHBOARD -->
    <section id="view-dashboard" class="space-y-6">
      
      <!-- Top Metric Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        
        <div class="glass-card rounded-2xl p-5 border-l-4 border-l-red-500">
          <div class="flex justify-between items-start">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Leftovers Found</span>
            <div class="p-2 rounded-xl bg-red-500/10 text-red-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path></svg>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span id="metric-leftovers" class="text-3xl font-extrabold text-white">0</span>
            <span class="text-xs text-red-400 font-medium">Orphan folders</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">Belongs to uninstalled apps</p>
        </div>

        <div class="glass-card rounded-2xl p-5 border-l-4 border-l-emerald-500">
          <div class="flex justify-between items-start">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Recoverable Space</span>
            <div class="p-2 rounded-xl bg-emerald-500/10 text-emerald-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2 1 3 3 3h10c2 0 3-1 3-3V7c0-2-1-3-3-3H7C5 4 4 5 4 7zm0 5h16"></path></svg>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span id="metric-space" class="text-3xl font-extrabold text-white">0 B</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">Wasted residual storage</p>
        </div>

        <div class="glass-card rounded-2xl p-5 border-l-4 border-l-yellow-500">
          <div class="flex justify-between items-start">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">System Protected</span>
            <div class="p-2 rounded-xl bg-yellow-500/10 text-yellow-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path></svg>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span id="metric-protected" class="text-3xl font-extrabold text-white">0</span>
            <span class="text-xs text-yellow-400 font-medium">Safe & locked</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">Never deleted by safety rules</p>
        </div>

        <div class="glass-card rounded-2xl p-5 border-l-4 border-l-blue-500">
          <div class="flex justify-between items-start">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Active Applications</span>
            <div class="p-2 rounded-xl bg-blue-500/10 text-blue-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4"></path></svg>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span id="metric-active" class="text-3xl font-extrabold text-white">0</span>
            <span class="text-xs text-blue-400 font-medium">Verified valid</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">Correlated with installed apps</p>
        </div>

        <div class="glass-card rounded-2xl p-5 border-l-4 border-l-purple-500">
          <div class="flex justify-between items-start">
            <span class="text-xs font-semibold uppercase tracking-wider text-slate-400">Quarantine Vault</span>
            <div class="p-2 rounded-xl bg-purple-500/10 text-purple-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"></path></svg>
            </div>
          </div>
          <div class="mt-2 flex items-baseline gap-2">
            <span id="metric-quarantine" class="text-3xl font-extrabold text-white">0</span>
            <span class="text-xs text-purple-400 font-medium">Restorable</span>
          </div>
          <p class="text-xs text-slate-400 mt-1">Safe non-permanent storage</p>
        </div>

      </div>

      <!-- Main Layout: Left: Architecture & Flow / Right: Safety Rules & Quick Prompts -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        
        <!-- Architecture Flow Card (2 cols) -->
        <div class="glass-card rounded-2xl p-6 lg:col-span-2 space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-4">
            <div>
              <h2 class="text-base font-bold text-white flex items-center gap-2">
                <span>🔄</span> How It Works: 6-Step Detection Flow
              </h2>
              <p class="text-xs text-slate-400">Standard operating pipeline based on system architecture</p>
            </div>
            <span class="text-xs px-2.5 py-1 rounded-full bg-slate-800 text-slate-300 font-mono" id="scanTimestamp">Last scanned: Not yet</span>
          </div>

          <div class="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2">
            
            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex gap-3 items-start">
              <div class="w-7 h-7 rounded-lg bg-blue-600/20 text-blue-400 font-bold flex items-center justify-center shrink-0 text-xs border border-blue-500/30">1</div>
              <div class="text-xs">
                <p class="font-semibold text-white">Scan Installed Apps</p>
                <p class="text-slate-400 mt-0.5">Scans registry uninstall keys & system directories</p>
              </div>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex gap-3 items-start">
              <div class="w-7 h-7 rounded-lg bg-blue-600/20 text-blue-400 font-bold flex items-center justify-center shrink-0 text-xs border border-blue-500/30">2</div>
              <div class="text-xs">
                <p class="font-semibold text-white">Find Target Folders</p>
                <p class="text-slate-400 mt-0.5">Scans Program Files, ProgramData & AppData</p>
              </div>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex gap-3 items-start">
              <div class="w-7 h-7 rounded-lg bg-blue-600/20 text-blue-400 font-bold flex items-center justify-center shrink-0 text-xs border border-blue-500/30">3</div>
              <div class="text-xs">
                <p class="font-semibold text-white">Deep Correlation</p>
                <p class="text-slate-400 mt-0.5">Analyzes registry, locks, running procs & services</p>
              </div>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex gap-3 items-start">
              <div class="w-7 h-7 rounded-lg bg-yellow-600/20 text-yellow-400 font-bold flex items-center justify-center shrink-0 text-xs border border-yellow-500/30">4</div>
              <div class="text-xs">
                <p class="font-semibold text-white">Ask User Prompt</p>
                <p class="text-slate-400 mt-0.5">If leftover detected, display decision dialog</p>
              </div>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex gap-3 items-start">
              <div class="w-7 h-7 rounded-lg bg-red-600/20 text-red-400 font-bold flex items-center justify-center shrink-0 text-xs border border-red-500/30">5</div>
              <div class="text-xs">
                <p class="font-semibold text-white">Safe Execution</p>
                <p class="text-slate-400 mt-0.5">Delete to Quarantine, Keep/Allow, or Ignore</p>
              </div>
            </div>

            <div class="p-3.5 rounded-xl bg-slate-900/60 border border-slate-800 flex gap-3 items-start">
              <div class="w-7 h-7 rounded-lg bg-emerald-600/20 text-emerald-400 font-bold flex items-center justify-center shrink-0 text-xs border border-emerald-500/30">6</div>
              <div class="text-xs">
                <p class="font-semibold text-white">Save State</p>
                <p class="text-slate-400 mt-0.5">Updates allowlist, quarantine manifest & logs</p>
              </div>
            </div>

          </div>

          <!-- Highlight Preview: Example Leftovers -->
          <div class="pt-4 border-t border-slate-800">
            <div class="flex items-center justify-between mb-3">
              <h3 class="text-xs font-semibold uppercase tracking-wider text-slate-300">Quick Leftover Action Queue</h3>
              <button onclick="switchTab('actions')" class="text-xs text-blue-400 hover:text-blue-300 font-medium">Open Decision Center &rarr;</button>
            </div>
            <div id="dashboardLeftoverList" class="space-y-2">
              <p class="text-xs text-slate-500 italic py-2">Click "Run Scan Now" to populate detected leftovers.</p>
            </div>
          </div>

        </div>

        <!-- Safety Rules Column (1 col) -->
        <div class="glass-card rounded-2xl p-6 space-y-4">
          <div class="flex items-center gap-2 border-b border-slate-800 pb-3">
            <div class="p-1.5 rounded-lg bg-blue-500/20 text-blue-400">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
            </div>
            <div>
              <h2 class="text-base font-bold text-white">Safety Rules Engine</h2>
              <p class="text-xs text-slate-400">Enforced at all system boundaries</p>
            </div>
          </div>

          <ul class="space-y-3 text-xs">
            <li class="flex items-start gap-2.5 p-2 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <span class="text-emerald-400 font-bold text-sm">✓</span>
              <div>
                <span class="font-semibold text-white">Never delete system / Windows folders</span>
                <p class="text-slate-400 mt-0.5">Strict protection for System32, WindowsApps, WinSxS, /bin, etc.</p>
              </div>
            </li>

            <li class="flex items-start gap-2.5 p-2 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <span class="text-emerald-400 font-bold text-sm">✓</span>
              <div>
                <span class="font-semibold text-white">Check running processes & services</span>
                <p class="text-slate-400 mt-0.5">Locked or running process folders are automatically protected</p>
              </div>
            </li>

            <li class="flex items-start gap-2.5 p-2 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <span class="text-emerald-400 font-bold text-sm">✓</span>
              <div>
                <span class="font-semibold text-white">Verify registry references & signatures</span>
                <p class="text-slate-400 mt-0.5">Validates software associations before categorizing</p>
              </div>
            </li>

            <li class="flex items-start gap-2.5 p-2 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <span class="text-emerald-400 font-bold text-sm">✓</span>
              <div>
                <span class="font-semibold text-white">Move deleted items to quarantine (not permanent)</span>
                <p class="text-slate-400 mt-0.5">Items can be 100% restored if needed</p>
              </div>
            </li>

            <li class="flex items-start gap-2.5 p-2 rounded-lg bg-slate-900/50 border border-slate-800/80">
              <span class="text-emerald-400 font-bold text-sm">✓</span>
              <div>
                <span class="font-semibold text-white">Always ask the user for non-system folders</span>
                <p class="text-slate-400 mt-0.5">Zero silent or automated destructive deletions</p>
              </div>
            </li>
          </ul>

          <div class="mt-4 p-3 rounded-xl bg-blue-950/40 border border-blue-800/40 text-xs text-blue-200">
            <span class="font-bold">Recommendation:</span> Run a scan in Demo Simulation to review the diagram's test data (Google Chrome leftover 438 MB, Discord, etc.), or disable demo mode to scan this machine!
          </div>

        </div>

      </div>

    </section>

    <!-- TAB 2: RESULTS (Orphan Folders / Details) -->
    <section id="view-results" class="hidden space-y-4">
      
      <!-- Filters and Search Toolbar -->
      <div class="glass-card rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        
        <div class="flex items-center space-x-2">
          <span class="text-xs font-semibold text-slate-400 uppercase tracking-wider">Filter:</span>
          <button onclick="setFilter('all')" id="filter-all" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-600 text-white">All (<span id="count-all">0</span>)</button>
          <button onclick="setFilter('deleted')" id="filter-deleted" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:text-white">Leftovers (<span id="count-deleted">0</span>)</button>
          <button onclick="setFilter('exists')" id="filter-exists" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:text-white">Active Apps (<span id="count-exists">0</span>)</button>
          <button onclick="setFilter('protected')" id="filter-protected" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:text-white">System Protected (<span id="count-protected">0</span>)</button>
          <button onclick="setFilter('unknown')" id="filter-unknown" class="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:text-white">Uncertain (<span id="count-unknown">0</span>)</button>
        </div>

        <div class="flex items-center space-x-3">
          <input type="text" id="searchInput" oninput="renderTable()" placeholder="Search folders or apps..." class="bg-slate-900 border border-slate-700 text-xs rounded-lg px-3 py-2 w-64 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500">
        </div>

      </div>

      <!-- Scanned Items Table -->
      <div class="glass-card rounded-2xl overflow-hidden shadow-xl">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th class="py-3.5 px-4 font-semibold">Classification</th>
                <th class="py-3.5 px-4 font-semibold">Folder Path / Name</th>
                <th class="py-3.5 px-4 font-semibold">Associated Application</th>
                <th class="py-3.5 px-4 font-semibold">Size</th>
                <th class="py-3.5 px-4 font-semibold">Analysis Reason</th>
                <th class="py-3.5 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="scannedTableBody" class="divide-y divide-slate-800/60 font-mono">
              <!-- Rendered via JS -->
            </tbody>
          </table>
        </div>
      </div>

    </section>

    <!-- TAB 3: ACTION CENTER -->
    <section id="view-actions" class="hidden space-y-6">
      
      <div class="glass-card rounded-2xl p-6">
        <div class="flex items-center justify-between border-b border-slate-800 pb-4 mb-4">
          <div>
            <h2 class="text-base font-bold text-white flex items-center gap-2">
              <span>⚡</span> Leftover Folder Action Center
            </h2>
            <p class="text-xs text-slate-400">Review orphan leftover directories one by one using the architecture prompt</p>
          </div>
          <button onclick="batchQuarantineAllLeftovers()" class="px-3.5 py-1.5 rounded-lg bg-red-600/90 hover:bg-red-500 text-white font-semibold text-xs transition flex items-center gap-2">
            <span>🗑️</span> Move All Safe Leftovers to Quarantine
          </button>
        </div>

        <!-- Leftovers Prompt Cards Container -->
        <div id="actionCardsContainer" class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <!-- Rendered via JS -->
        </div>

      </div>

    </section>

    <!-- TAB 4: SETTINGS & HISTORY -->
    <section id="view-settings" class="hidden space-y-6">
      
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        <!-- Allowlist Manager -->
        <div class="glass-card rounded-2xl p-6 space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 class="text-base font-bold text-white flex items-center gap-2">
                <span>🛡️</span> Allowlist (Folders to Keep)
              </h2>
              <p class="text-xs text-slate-400">Paths excluded from all future leftover scans</p>
            </div>
          </div>

          <div class="flex gap-2">
            <input type="text" id="allowlistInput" placeholder="Enter full folder path to allowlist..." class="flex-1 bg-slate-900 border border-slate-700 text-xs rounded-lg px-3 py-2 text-white placeholder-slate-500 focus:outline-none focus:border-blue-500">
            <button onclick="addAllowlistPath()" class="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs">Add Path</button>
          </div>

          <div id="allowlistList" class="space-y-2 max-h-60 overflow-y-auto font-mono text-xs">
            <!-- Allowlist items -->
          </div>
        </div>

        <!-- Safety Settings Toggles -->
        <div class="glass-card rounded-2xl p-6 space-y-4">
          <div class="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h2 class="text-base font-bold text-white flex items-center gap-2">
                <span>⚙️</span> Safety & Execution Preferences
              </h2>
              <p class="text-xs text-slate-400">Configure safety rules and deletion policies</p>
            </div>
            <button onclick="saveSafetySettings()" class="px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs">Save Settings</button>
          </div>

          <div class="space-y-3 text-xs">
            
            <label class="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 cursor-pointer">
              <div>
                <p class="font-semibold text-white">Never delete system / Windows folders</p>
                <p class="text-slate-400 text-[11px]">Strict hard block against critical system directories</p>
              </div>
              <input type="checkbox" id="set_never_delete_system" checked class="rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-blue-500 w-4 h-4">
            </label>

            <label class="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 cursor-pointer">
              <div>
                <p class="font-semibold text-white">Check running processes and services</p>
                <p class="text-slate-400 text-[11px]">Prevent deletion of folders currently in use</p>
              </div>
              <input type="checkbox" id="set_check_running" checked class="rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-blue-500 w-4 h-4">
            </label>

            <label class="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 cursor-pointer">
              <div>
                <p class="font-semibold text-white">Always move to Quarantine (not permanent)</p>
                <p class="text-slate-400 text-[11px]">Safety first: items are isolated and restorable</p>
              </div>
              <input type="checkbox" id="set_quarantine" checked class="rounded bg-slate-800 border-slate-700 text-blue-600 focus:ring-blue-500 w-4 h-4">
            </label>

            <label class="flex items-center justify-between p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 cursor-pointer">
              <div>
                <p class="font-semibold text-white">Allow permanent delete option</p>
                <p class="text-slate-400 text-[11px]">Permits permanent purge (requires confirmation)</p>
              </div>
              <input type="checkbox" id="set_allow_perm" class="rounded bg-slate-800 border-slate-700 text-red-600 focus:ring-red-500 w-4 h-4">
            </label>

          </div>
        </div>

      </div>

      <!-- Quarantine Repository View -->
      <div class="glass-card rounded-2xl p-6 space-y-4">
        <div class="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 class="text-base font-bold text-white flex items-center gap-2">
              <span>📦</span> Quarantine Repository (Deleted Items Vault)
            </h2>
            <p class="text-xs text-slate-400">Safely isolated leftover folders that can be restored or purged</p>
          </div>
          <span id="quarantineTotalBadge" class="text-xs px-2.5 py-1 rounded-full bg-purple-500/20 text-purple-300 font-mono">0 items</span>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th class="py-3 px-4 font-semibold">ID</th>
                <th class="py-3 px-4 font-semibold">Original Path</th>
                <th class="py-3 px-4 font-semibold">Application</th>
                <th class="py-3 px-4 font-semibold">Size</th>
                <th class="py-3 px-4 font-semibold">Quarantined At</th>
                <th class="py-3 px-4 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody id="quarantineTableBody" class="divide-y divide-slate-800/60 font-mono">
              <!-- Rendered via JS -->
            </tbody>
          </table>
        </div>
      </div>

      <!-- Scan History Log -->
      <div class="glass-card rounded-2xl p-6 space-y-4">
        <div class="flex items-center justify-between border-b border-slate-800 pb-3">
          <div>
            <h2 class="text-base font-bold text-white flex items-center gap-2">
              <span>🕒</span> Scan History Log
            </h2>
            <p class="text-xs text-slate-400">Historical audit trail of all previous scans</p>
          </div>
        </div>

        <div class="overflow-x-auto">
          <table class="w-full text-left text-xs">
            <thead class="bg-slate-900/90 text-slate-400 uppercase text-[10px] tracking-wider border-b border-slate-800">
              <tr>
                <th class="py-3 px-4 font-semibold">Timestamp</th>
                <th class="py-3 px-4 font-semibold">Duration</th>
                <th class="py-3 px-4 font-semibold">Folders Scanned</th>
                <th class="py-3 px-4 font-semibold">Leftovers Found</th>
                <th class="py-3 px-4 font-semibold">Recoverable Space</th>
              </tr>
            </thead>
            <tbody id="historyTableBody" class="divide-y divide-slate-800/60 font-mono">
              <!-- Rendered via JS -->
            </tbody>
          </table>
        </div>
      </div>

    </section>

  </main>

  <!-- MODAL: EXAMPLE USER PROMPT (EXACT REPLICA FROM ARCHITECTURE DIAGRAM) -->
  <div id="userPromptModal" class="hidden fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-[#151c2e] border-2 border-red-500/80 rounded-2xl max-w-lg w-full p-6 shadow-2xl glow-red space-y-5 transform transition-all">
      
      <!-- Header with Warning Icon -->
      <div class="flex items-start gap-3.5">
        <div class="w-12 h-12 rounded-xl bg-amber-500/20 text-amber-400 flex items-center justify-center shrink-0 border border-amber-500/40">
          <svg class="w-7 h-7" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"></path>
          </svg>
        </div>
        <div>
          <h3 class="text-base font-bold text-white tracking-wide">Leftover Application Folder Detected</h3>
          <p class="text-xs text-slate-400">Architecture Decision Dialog (Layer 4/5)</p>
        </div>
      </div>

      <!-- Details Card -->
      <div class="p-4 rounded-xl bg-slate-900/80 border border-slate-800 space-y-2 text-xs">
        <div class="flex justify-between items-center py-1 border-b border-slate-800/60">
          <span class="text-slate-400 font-medium">Application:</span>
          <span id="promptApp" class="font-bold text-white text-sm">Google Chrome</span>
        </div>
        <div class="flex justify-between items-center py-1 border-b border-slate-800/60">
          <span class="text-slate-400 font-medium">Status:</span>
          <span class="text-red-400 font-semibold flex items-center gap-1">
            <span class="w-1.5 h-1.5 rounded-full bg-red-500 inline-block"></span>
            Application is not installed
          </span>
        </div>
        <div class="py-1 border-b border-slate-800/60">
          <span class="text-slate-400 font-medium block mb-1">Leftover folder:</span>
          <span id="promptPath" class="font-mono text-[11px] text-blue-300 break-all bg-slate-950 px-2 py-1 rounded block border border-slate-800">
            C:\\Users\\User\\AppData\\Local\\Google\\Chrome
          </span>
        </div>
        <div class="flex justify-between items-center py-1">
          <span class="text-slate-400 font-medium">Size:</span>
          <span id="promptSize" class="font-bold text-emerald-400 text-sm">438 MB</span>
        </div>
      </div>

      <p class="text-xs text-slate-300 italic">
        This folder appears to belong to an application that is no longer installed.<br>
      <div class="flex items-center gap-2 p-2.5 rounded-xl bg-red-950/40 border border-red-800/60 text-xs text-red-200">
        <input type="checkbox" id="promptPermanentCheckbox" checked class="rounded bg-slate-900 border-red-700 text-red-600 focus:ring-red-500 w-4 h-4 cursor-pointer">
        <label for="promptPermanentCheckbox" class="cursor-pointer select-none">
          <strong class="text-white">Permanently delete from disk</strong> <span class="text-slate-400">(Removes folder and files completely from system)</span>
        </label>
      </div>

      <!-- 4 Action Buttons Matching Diagram Colors -->
      <div class="grid grid-cols-2 gap-3 pt-1">

        <button onclick="promptDecision('delete')" class="px-4 py-3 rounded-xl bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white font-bold text-xs shadow-lg shadow-red-500/20 flex items-center justify-center gap-2 transition active:scale-95">
          <span>🗑️</span> Delete Folder
        </button>
        <button onclick="promptDecision('keep')" class="px-4 py-3 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold text-xs shadow-lg shadow-emerald-500/20 flex items-center justify-center gap-2 transition active:scale-95">
          <span>✔️</span> Keep / Allow
        </button>
        <button onclick="promptDecision('view')" class="px-4 py-3 rounded-xl bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white font-bold text-xs shadow-lg shadow-blue-500/20 flex items-center justify-center gap-2 transition active:scale-95">
          <span>📁</span> View Folder
        </button>
        <button onclick="promptDecision('ignore')" class="px-4 py-3 rounded-xl bg-gradient-to-r from-slate-700 to-slate-800 hover:from-slate-600 hover:to-slate-700 text-slate-200 font-bold text-xs flex items-center justify-center gap-2 transition active:scale-95">
          <span>👁️</span> Ignore
        </button>
      </div>

      <div class="flex justify-end pt-1">
        <button onclick="closePromptModal()" class="text-xs text-slate-400 hover:text-white transition">Cancel / Close</button>
      </div>

    </div>
  </div>

  <!-- FOLDER INSPECTION DETAILS MODAL -->
  <div id="folderDetailsModal" class="hidden fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-[#151c2e] border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl space-y-4">
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <h3 class="text-sm font-bold text-white flex items-center gap-2">
          <span>📁</span> Folder File Inspection
        </h3>
        <button onclick="closeFolderDetailsModal()" class="text-slate-400 hover:text-white">&times;</button>
      </div>
      <div id="folderDetailsContent" class="text-xs space-y-3 font-mono">
        <!-- Rendered via JS -->
      </div>
    </div>
  </div>

  <!-- MODAL: CONNECT & SCAN ANOTHER SYSTEM -->
  <div id="connectNodeModal" class="hidden fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
    <div class="bg-[#151c2e] border border-slate-700 rounded-2xl max-w-2xl w-full p-6 shadow-2xl space-y-4">
      
      <div class="flex items-center justify-between border-b border-slate-800 pb-3">
        <div class="flex items-center gap-3">
          <div class="w-10 h-10 rounded-xl bg-emerald-500/20 text-emerald-400 font-bold flex items-center justify-center border border-emerald-500/30 text-lg">
            🌐
          </div>
          <div>
            <h3 class="text-base font-bold text-white">Scan Another System On Your Network</h3>
            <p class="text-xs text-slate-400">Because browsers are sandboxed, run this 1-click command on the target system to scan its local hard drive</p>
          </div>
        </div>
        <button onclick="closeConnectNodeModal()" class="text-slate-400 hover:text-white text-xl font-bold">&times;</button>
      </div>

      <div class="space-y-4 text-xs">
        
        <!-- Windows PowerShell -->
        <div class="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <span class="font-bold text-white flex items-center gap-2">
              <span class="text-blue-400">🪟 Windows System</span> (PowerShell - No Python Needed)
            </span>
            <button onclick="copyCmd('irm http://192.168.0.139:8090/agent/scan.ps1 | iex')" class="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-semibold text-[11px] transition">
              Copy Command
            </button>
          </div>
          <p class="text-slate-400 text-[11px]">Open PowerShell on your Windows laptop/PC and paste:</p>
          <pre class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-blue-300 text-[11px] select-all overflow-x-auto">irm http://192.168.0.139:8090/agent/scan.ps1 | iex</pre>
        </div>

        <!-- Linux / macOS -->
        <div class="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <span class="font-bold text-white flex items-center gap-2">
              <span class="text-emerald-400">🐧 Linux / macOS System</span> (Bash Terminal)
            </span>
            <button onclick="copyCmd('curl -sSL http://192.168.0.139:8090/agent/scan.sh | bash')" class="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-[11px] transition">
              Copy Command
            </button>
          </div>
          <p class="text-slate-400 text-[11px]">Open Terminal on the Linux/Mac machine and paste:</p>
          <pre class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-emerald-300 text-[11px] select-all overflow-x-auto">curl -sSL http://192.168.0.139:8090/agent/scan.sh | bash</pre>
        </div>

        <!-- Cross-Platform Python -->
        <div class="p-3.5 rounded-xl bg-slate-900 border border-slate-800 space-y-2">
          <div class="flex items-center justify-between">
            <span class="font-bold text-white flex items-center gap-2">
              <span class="text-yellow-400">🐍 Python 3 (Any Operating System)</span>
            </span>
            <button onclick="copyCmd('python3 -c &quot;import urllib.request; exec(urllib.request.urlopen(\'http://192.168.0.139:8090/agent/agent.py\').read())&quot;')" class="px-2.5 py-1 rounded bg-yellow-600 hover:bg-yellow-500 text-white font-semibold text-[11px] transition">
              Copy Command
            </button>
          </div>
          <pre class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 font-mono text-yellow-200 text-[11px] select-all overflow-x-auto">python3 -c "import urllib.request; exec(urllib.request.urlopen('http://192.168.0.139:8090/agent/agent.py').read())"</pre>
        </div>

      <div class="pt-3 border-t border-slate-800 space-y-2">
        <h4 class="font-bold text-white text-xs flex items-center justify-between">
          <span>Connected Remote Systems</span>
          <span id="connectedCountBadge" class="text-[10px] text-slate-400 font-mono">0 remote devices</span>
        </h4>
        <div id="connectedNodesList" class="space-y-1.5 max-h-36 overflow-y-auto">
          <!-- Populated via JS -->
        </div>
      </div>

      <div class="flex justify-end pt-2">
        <button onclick="closeConnectNodeModal()" class="px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs">Close</button>
      </div>


    </div>
  </div>

  <!-- TOAST NOTIFICATION CONTAINER -->
  <div id="toastContainer" class="fixed bottom-5 right-5 z-50 space-y-2"></div>

  <!-- APPLICATION JAVASCRIPT LOGIC -->
  <script>
    let currentScanData = null;
    let currentFilter = 'all';
    let activePromptItem = null;
    let currentNodeId = 'local';
    let knownNodes = {};

    function openConnectNodeModal() {
      document.getElementById('connectNodeModal').classList.remove('hidden');
    }

    function closeConnectNodeModal() {
      document.getElementById('connectNodeModal').classList.add('hidden');
    }

    function copyCmd(cmd) {
      navigator.clipboard.writeText(cmd);
      showToast('Command copied to clipboard! Paste it into the target computer.', 'success');
    }

    // Node Discovery & Selection
    async function fetchNodes() {
      try {
        const res = await fetch('/api/nodes');
        const nodes = await res.json();
        const sel = document.getElementById('nodeSelector');
        
        let existingVal = sel.value;
        sel.innerHTML = `<option value="local">🖥️ Host (192.168.0.139 - Linux)</option>`;

        nodes.forEach(n => {
          const opt = document.createElement('option');
          opt.value = n.node_id;
          opt.innerText = `💻 ${n.hostname} (${n.os_type} - ${n.leftovers_detected} leftovers)`;
          sel.appendChild(opt);

          if (!knownNodes[n.node_id]) {
            knownNodes[n.node_id] = n;
            showToast(`New system connected: ${n.hostname} (${n.os_type})!`, 'success');
          }
        });

        sel.value = existingVal;

        // Render connected nodes list in modal
        const listDiv = document.getElementById('connectedNodesList');
        const badge = document.getElementById('connectedCountBadge');
        if (badge) badge.innerText = `${nodes.length} remote devices`;

        if (listDiv) {
          if (nodes.length === 0) {
            listDiv.innerHTML = `<p class="text-slate-500 italic text-[11px] py-1">No remote machines registered yet.</p>`;
          } else {
            listDiv.innerHTML = nodes.map(n => `
              <div class="p-2 rounded-lg bg-slate-950 border border-slate-800 flex items-center justify-between text-xs">
                <div>
                  <span class="font-bold text-white">${n.hostname}</span>
                  <span class="text-slate-400 text-[11px] ml-1">(${n.ip_address} • ${n.os_type})</span>
                  <div class="text-[10px] text-emerald-400 font-mono mt-0.5">${n.leftovers_detected} leftovers • ${n.recoverable_space} recoverable</div>
                </div>
                <button onclick="removeNode('${n.node_id}')" class="px-2 py-1 rounded bg-red-600/20 text-red-300 border border-red-500/30 hover:bg-red-600 hover:text-white text-[10px] font-bold transition">
                  Remove Device
                </button>
              </div>
            `).join('');
          }
        }
      } catch (e) {
        console.error("Error fetching nodes:", e);
      }
    }

    async function removeNode(nodeId) {
      if (!confirm('Remove this machine from the dashboard?')) return;
      try {
        await fetch(`/api/nodes/${nodeId}`, { method: 'DELETE' });
        delete knownNodes[nodeId];
        showToast('Device removed from dashboard.', 'info');
        fetchNodes();
        if (currentNodeId === nodeId) {
          document.getElementById('nodeSelector').value = 'local';
          onNodeSelected();
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    async function onNodeSelected() {
      const sel = document.getElementById('nodeSelector');
      currentNodeId = sel.value;

      if (currentNodeId === 'local') {
        document.getElementById('demoModeToggle').parentElement.classList.remove('hidden');
        triggerScan();
      } else {
        document.getElementById('demoModeToggle').parentElement.classList.add('hidden');
        try {
          showToast(`Loading scan from system: ${currentNodeId}...`, 'info');
          const res = await fetch(`/api/nodes/${currentNodeId}/scan`);
          const data = await res.json();
          currentScanData = data;
          updateDashboardMetrics(data);
          renderTable();
          renderActionCards();
          document.getElementById('scanTimestamp').innerText = `Scanned: ${data.timestamp} (${data.duration_seconds}s)`;
          showToast(`Loaded ${data.leftovers_detected} leftover folders from remote system.`, 'success');
        } catch (e) {
          showToast(`Error loading node scan: ${e.message}`, 'error');
        }
      }
    }

    // Auto-poll nodes every 5 seconds
    setInterval(fetchNodes, 5000);



    // Tab Navigation
    function switchTab(tabId) {
      ['dashboard', 'results', 'actions', 'settings'].forEach(t => {
        document.getElementById(`view-${t}`).classList.add('hidden');
        const btn = document.getElementById(`tab-btn-${t}`);
        btn.classList.remove('bg-blue-600', 'text-white', 'shadow-sm');
        btn.classList.add('text-slate-400');
      });

      document.getElementById(`view-${tabId}`).classList.remove('hidden');
      const activeBtn = document.getElementById(`tab-btn-${tabId}`);
      activeBtn.classList.add('bg-blue-600', 'text-white', 'shadow-sm');
      activeBtn.classList.remove('text-slate-400');

      if (tabId === 'settings') {
        loadSettingsAndQuarantine();
      }
    }

    // Toast Alert Helper
    function showToast(msg, type = 'info') {
      const c = document.getElementById('toastContainer');
      const t = document.createElement('div');
      const colors = {
        success: 'border-emerald-500 bg-emerald-950/90 text-emerald-200',
        error: 'border-red-500 bg-red-950/90 text-red-200',
        info: 'border-blue-500 bg-blue-950/90 text-blue-200'
      };
      t.className = `p-3.5 rounded-xl border text-xs shadow-xl backdrop-blur max-w-sm flex items-center gap-2 transition-all transform duration-300 ${colors[type] || colors.info}`;
      t.innerHTML = `<span>${type === 'success' ? '✓' : type === 'error' ? '✗' : 'ℹ'}</span> <span>${msg}</span>`;
      c.appendChild(t);
      setTimeout(() => {
        t.style.opacity = '0';
        setTimeout(() => t.remove(), 300);
      }, 4000);
    }

    // Run Full Scan
    async function triggerScan() {
      const btn = document.getElementById('btnGlobalScan');
      const spinner = document.getElementById('scanSpinner');
      const text = document.getElementById('scanBtnText');
      const demo = document.getElementById('demoModeToggle').checked;

      btn.disabled = true;
      spinner.classList.remove('hidden');
      text.innerText = 'Scanning...';

      try {
        const res = await fetch(`/api/scan?demo=${demo}`);
        const data = await res.json();
        currentScanData = data;
        updateDashboardMetrics(data);
        renderTable();
        renderActionCards();
        document.getElementById('scanTimestamp').innerText = `Last scanned: ${data.timestamp} (${data.duration_seconds}s)`;
        showToast(`Scan complete: ${data.leftovers_detected} leftover folders found (${data.total_space_recoverable_formatted})`, 'success');
      } catch (err) {
        showToast(`Scan error: ${err.message}`, 'error');
      } finally {
        btn.disabled = false;
        spinner.classList.add('hidden');
        text.innerText = 'Run Scan Now';
      }
    }

    function toggleDemoMode() {
      triggerScan();
    }

    // Update Dashboard Top Metrics
    function updateDashboardMetrics(data) {
      document.getElementById('metric-leftovers').innerText = data.leftovers_detected;
      document.getElementById('metric-space').innerText = data.total_space_recoverable_formatted;
      document.getElementById('metric-protected').innerText = data.system_protected_count;
      document.getElementById('metric-active').innerText = data.active_apps_count;

      const badge = document.getElementById('nav-leftover-badge');
      if (data.leftovers_detected > 0) {
        badge.innerText = data.leftovers_detected;
        badge.classList.remove('hidden');
      } else {
        badge.classList.add('hidden');
      }

      // Quick dashboard leftover list
      const list = document.getElementById('dashboardLeftoverList');
      const leftovers = data.items.filter(i => i.decision === 'Application Deleted');
      if (leftovers.length === 0) {
        list.innerHTML = `<p class="text-xs text-emerald-400 py-2">✓ No residual leftover folders detected!</p>`;
        return;
      }

      list.innerHTML = leftovers.slice(0, 4).map(it => `
        <div class="p-2.5 rounded-xl bg-slate-900/80 border border-slate-800 flex items-center justify-between text-xs">
          <div class="space-y-0.5">
            <span class="font-bold text-white">${it.associated_app_name || it.name}</span>
            <span class="text-slate-400 block font-mono text-[11px] truncate max-w-sm">${it.path}</span>
          </div>
          <div class="flex items-center gap-3">
            <span class="font-mono text-emerald-400 font-bold">${it.size_formatted}</span>
            <button onclick="openUserPrompt('${it.path}')" class="px-2.5 py-1 rounded-lg bg-red-600/20 text-red-300 border border-red-500/30 hover:bg-red-600 hover:text-white transition">
              Review Action
            </button>
          </div>
        </div>
      `).join('');
    }

    // Set filter on Results table
    function setFilter(f) {
      currentFilter = f;
      ['all', 'deleted', 'exists', 'protected', 'unknown'].forEach(cat => {
        const btn = document.getElementById(`filter-${cat}`);
        if (cat === f) {
          btn.className = 'px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-600 text-white';
        } else {
          btn.className = 'px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800 text-slate-300 hover:text-white';
        }
      });
      renderTable();
    }

    // Render Results Table
    function renderTable() {
      if (!currentScanData) return;
      const tbody = document.getElementById('scannedTableBody');
      const search = document.getElementById('searchInput').value.toLowerCase();

      let items = currentScanData.items;

      // Update counters
      document.getElementById('count-all').innerText = items.length;
      document.getElementById('count-deleted').innerText = items.filter(i => i.decision === 'Application Deleted').length;
      document.getElementById('count-exists').innerText = items.filter(i => i.decision === 'Application Exists').length;
      document.getElementById('count-protected').innerText = items.filter(i => i.decision === 'System Protected').length;
      document.getElementById('count-unknown').innerText = items.filter(i => i.decision === 'Unknown / Uncertain').length;

      if (currentFilter === 'deleted') items = items.filter(i => i.decision === 'Application Deleted');
      if (currentFilter === 'exists') items = items.filter(i => i.decision === 'Application Exists');
      if (currentFilter === 'protected') items = items.filter(i => i.decision === 'System Protected');
      if (currentFilter === 'unknown') items = items.filter(i => i.decision === 'Unknown / Uncertain');

      if (search) {
        items = items.filter(i => i.name.toLowerCase().includes(search) || i.path.toLowerCase().includes(search) || (i.associated_app_name && i.associated_app_name.toLowerCase().includes(search)));
      }

      if (items.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="text-center py-8 text-slate-500">No items match the active filter or query.</td></tr>`;
        return;
      }

      tbody.innerHTML = items.map(it => {
        let badge = '';
        if (it.decision === 'Application Deleted') {
          badge = `<span class="px-2 py-0.5 rounded-md text-[10px] font-bold badge-deleted">APPLICATION DELETED</span>`;
        } else if (it.decision === 'Application Exists') {
          badge = `<span class="px-2 py-0.5 rounded-md text-[10px] font-bold badge-exists">APPLICATION EXISTS</span>`;
        } else if (it.decision === 'System Protected') {
          badge = `<span class="px-2 py-0.5 rounded-md text-[10px] font-bold badge-protected">SYSTEM PROTECTED</span>`;
        } else {
          badge = `<span class="px-2 py-0.5 rounded-md text-[10px] font-bold badge-unknown">UNKNOWN / UNCERTAIN</span>`;
        }

        return `
          <tr class="hover:bg-slate-900/40 transition">
            <td class="py-3 px-4">${badge}</td>
            <td class="py-3 px-4">
              <span class="font-bold text-white font-sans text-xs block">${it.name}</span>
              <span class="text-slate-400 text-[11px] truncate max-w-xs block">${it.path}</span>
            </td>
            <td class="py-3 px-4 font-sans text-slate-300 font-medium">
              ${it.associated_app_name || '<span class="text-slate-500 italic">None</span>'}
            </td>
            <td class="py-3 px-4 font-bold text-slate-200">${it.size_formatted}</td>
            <td class="py-3 px-4 font-sans text-slate-400 text-[11px] max-w-xs">
              ${it.decision_reason}
            </td>
            <td class="py-3 px-4 text-right space-x-1">
              ${it.decision === 'Application Deleted' ? `
                <button onclick="openUserPrompt('${it.path}')" class="px-2.5 py-1 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-[11px] transition">
                  Prompt Action
                </button>
                <button onclick="inspectAndOpenFolder('${it.path}')" class="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold text-[11px] transition">
                  View Folder
                </button>
              ` : `
                <button onclick="inspectAndOpenFolder('${it.path}')" class="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition">
                  View Folder
                </button>
              `}
            </td>
          </tr>
        `;
      }).join('');
    }

    // Render Action Center Prompt Cards
    function renderActionCards() {
      if (!currentScanData) return;
      const c = document.getElementById('actionCardsContainer');
      const leftovers = currentScanData.items.filter(i => i.decision === 'Application Deleted');

      if (leftovers.length === 0) {
        c.innerHTML = `<div class="col-span-2 text-center py-12 text-slate-400">No leftover folders currently need user decision!</div>`;
        return;
      }

      c.innerHTML = leftovers.map(it => `
        <div class="glass-card rounded-2xl p-5 border-2 border-red-500/40 space-y-3">
          <div class="flex items-start justify-between">
            <div class="flex items-center gap-2.5">
              <div class="p-2 rounded-lg bg-red-500/20 text-red-400 font-bold">⚠️</div>
              <div>
                <h4 class="font-bold text-white text-sm">${it.associated_app_name || it.name}</h4>
                <span class="text-[11px] text-red-400 font-semibold">Application is not installed</span>
              </div>
            </div>
            <span class="text-emerald-400 font-bold font-mono text-sm">${it.size_formatted}</span>
          </div>

          <div class="p-2.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] font-mono text-blue-300 break-all">
            ${it.path}
          </div>

          <div class="grid grid-cols-4 gap-2 pt-1">
            <button onclick="executeDirectAction('${it.path}', 'delete', '${it.associated_app_name || ''}')" class="px-2 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white font-bold text-[11px] transition">
              Delete
            </button>
            <button onclick="executeDirectAction('${it.path}', 'keep', '${it.associated_app_name || ''}')" class="px-2 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] transition">
              Keep / Allow
            </button>
            <button onclick="inspectAndOpenFolder('${it.path}')" class="px-2 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-bold text-[11px] transition">
              View Folder
            </button>
            <button onclick="executeDirectAction('${it.path}', 'ignore', '${it.associated_app_name || ''}')" class="px-2 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] transition">
              Ignore
            </button>
          </div>
        </div>
      `).join('');
    }


    // Open User Prompt Modal (Exact diagram match)
    function openUserPrompt(path) {
      if (!currentScanData) return;
      const item = currentScanData.items.find(i => i.path === path);
      if (!item) return;

      activePromptItem = item;
      document.getElementById('promptApp').innerText = item.associated_app_name || item.name;
      document.getElementById('promptPath').innerText = item.path;
      document.getElementById('promptSize').innerText = item.size_formatted;

      document.getElementById('userPromptModal').classList.remove('hidden');
    }

    function closePromptModal() {
      document.getElementById('userPromptModal').classList.add('hidden');
      activePromptItem = null;
    }

    // Modal Decision Click
    async function promptDecision(action) {
      if (!activePromptItem) return;
      const item = activePromptItem;
      const permCheckbox = document.getElementById('promptPermanentCheckbox');
      const isPermanent = permCheckbox ? permCheckbox.checked : false;

      closePromptModal();

      if (action === 'view') {
        inspectAndOpenFolder(item.path);
        return;
      }

      if (action === 'delete' && isPermanent) {
        if (!confirm(`Are you sure you want to PERMANENTLY remove this folder from the system?\n\nFolder: ${item.path}\n\nFiles will be permanently deleted from disk.`)) {
          return;
        }
      }

      await executeDirectAction(item.path, action, item.associated_app_name || '', isPermanent);
    }

    async function executePermanentDelete(path, appName) {
      if (!confirm(`Are you sure you want to PERMANENTLY delete this folder from your disk?\n\nPath: ${path}\n\nThis cannot be undone.`)) {
        return;
      }
      await executeDirectAction(path, 'delete', appName, true);
    }

    async function inspectAndOpenFolder(path) {
      try {
        const res = await fetch('/api/open_folder', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ path: path, action: 'view' })
        });
        const d = await res.json();
        if (d.success) {
          showToast(`Opening '${d.target_path}' in File Manager...`, 'success');
        } else {
          showToast(`Could not open file manager: ${d.error || 'Unknown error'}`, 'error');
        }
      } catch (err) {
        console.error(err);
      }
      inspectFolder(path);
    }


    // Execute Action API Call
    async function executeDirectAction(path, action, appName, permanentDelete = false) {
      try {
        const res = await fetch('/api/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            path: path,
            action: action,
            app_name: appName,
            permanent_delete: permanentDelete
          })
        });
        const data = await res.json();
        if (data.success) {
          showToast(data.message || 'Action executed successfully.', 'success');
          // Refresh scan
          triggerScan();
          loadSettingsAndQuarantine();
        } else {
          showToast(data.error || 'Action failed.', 'error');
        }
      } catch (e) {
        showToast(e.message, 'error');
      }
    }


    // Batch Move All Safe Leftovers to Quarantine
    async function batchQuarantineAllLeftovers() {
      if (!currentScanData) return;
      const leftovers = currentScanData.items.filter(i => i.decision === 'Application Deleted');
      if (leftovers.length === 0) {
        showToast('No leftover folders to quarantine.', 'info');
        return;
      }

      if (!confirm(`Are you sure you want to move all ${leftovers.length} detected leftover folders to Quarantine?`)) {
        return;
      }

      let count = 0;
      for (const it of leftovers) {
        try {
          const res = await fetch('/api/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              path: it.path,
              action: 'delete',
              app_name: it.associated_app_name || '',
              permanent_delete: false
            })
          });
          const d = await res.json();
          if (d.success) count++;
        } catch (e) {}
      }

      showToast(`Successfully quarantined ${count} leftover folders.`, 'success');
      triggerScan();
      loadSettingsAndQuarantine();
    }

    // Inspect Folder
    async function inspectFolder(path) {
      try {
        const res = await fetch(`/api/folder_details?path=${encodeURIComponent(path)}`);
        const data = await res.json();
        const content = document.getElementById('folderDetailsContent');
        content.innerHTML = `
          <div class="p-3 bg-slate-950 rounded-lg border border-slate-800 text-blue-300 break-all mb-2">
            ${data.path}
          </div>
          <div class="grid grid-cols-2 gap-2 text-slate-300">
            <div>Files: <strong class="text-white">${data.file_count}</strong></div>
            <div>Subdirectories: <strong class="text-white">${data.folder_count}</strong></div>
          </div>
          <div class="mt-3">
            <span class="text-slate-400 block mb-1">Sample Files:</span>
            <div class="bg-slate-950 p-2.5 rounded-lg border border-slate-800 max-h-40 overflow-y-auto space-y-1">
              ${data.sample_files && data.sample_files.length ? data.sample_files.map(f => `<div class="truncate text-slate-300">${f}</div>`).join('') : '<span class="text-slate-500 italic">No files found or demo simulated directory.</span>'}
            </div>
          </div>
        `;
        document.getElementById('folderDetailsModal').classList.remove('hidden');
      } catch (e) {
        showToast(e.message, 'error');
      }
    }

    function closeFolderDetailsModal() {
      document.getElementById('folderDetailsModal').classList.add('hidden');
    }

    // Settings & Quarantine & History Data Loader
    async function loadSettingsAndQuarantine() {
      // Allowlist
      const allowRes = await fetch('/api/allowlist');
      const allowData = await allowRes.json();
      const allowList = document.getElementById('allowlistList');
      if (allowData.length === 0) {
        allowList.innerHTML = `<span class="text-slate-500 italic">No paths currently allowlisted.</span>`;
      } else {
        allowList.innerHTML = allowData.map(p => `
          <div class="p-2 rounded bg-slate-900 border border-slate-800 flex items-center justify-between">
            <span class="truncate max-w-sm text-slate-300">${p}</span>
            <button onclick="removeAllowlistPath('${p}')" class="text-red-400 hover:text-red-300 text-xs font-bold">&times; Remove</button>
          </div>
        `).join('');
      }

      // Quarantine
      const quarRes = await fetch('/api/quarantine');
      const quarData = await quarRes.json();
      document.getElementById('metric-quarantine').innerText = quarData.length;
      document.getElementById('quarantineTotalBadge').innerText = `${quarData.length} items`;
      const quarTable = document.getElementById('quarantineTableBody');
      if (quarData.length === 0) {
        quarTable.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500">Quarantine is empty.</td></tr>`;
      } else {
        quarTable.innerHTML = quarData.map(it => `
          <tr class="hover:bg-slate-900/40">
            <td class="py-2.5 px-4 text-slate-400">${it.id}</td>
            <td class="py-2.5 px-4 text-blue-300 font-mono">${it.original_path}</td>
            <td class="py-2.5 px-4 font-sans font-medium text-white">${it.associated_app || '-'}</td>
            <td class="py-2.5 px-4 font-bold text-emerald-400">${it.size_formatted}</td>
            <td class="py-2.5 px-4 text-slate-400">${it.timestamp}</td>
            <td class="py-2.5 px-4 text-right space-x-2">
              <button onclick="restoreQuarantineItem('${it.id}')" class="px-2 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[10px]">Restore</button>
              <button onclick="purgeQuarantineItem('${it.id}')" class="px-2 py-1 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-[10px]">Purge</button>
            </td>
          </tr>
        `).join('');
      }

      // History
      const histRes = await fetch('/api/history');
      const histData = await histRes.json();
      const histTable = document.getElementById('historyTableBody');
      if (histData.length === 0) {
        histTable.innerHTML = `<tr><td colspan="5" class="text-center py-6 text-slate-500">No scan history recorded yet.</td></tr>`;
      } else {
        histTable.innerHTML = histData.slice(0, 10).map(h => `
          <tr class="hover:bg-slate-900/40">
            <td class="py-2 px-4 text-slate-300">${h.timestamp}</td>
            <td class="py-2 px-4 text-slate-400">${h.duration_seconds}s</td>
            <td class="py-2 px-4 text-slate-300">${h.total_folders_scanned}</td>
            <td class="py-2 px-4 font-bold text-red-400">${h.leftovers_detected}</td>
            <td class="py-2 px-4 font-bold text-emerald-400">${h.total_space_recoverable}</td>
          </tr>
        `).join('');
      }
    }

    async function addAllowlistPath() {
      const p = document.getElementById('allowlistInput').value.trim();
      if (!p) return;
      await fetch('/api/allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: p, operation: 'add' })
      });
      document.getElementById('allowlistInput').value = '';
      showToast(`Added to allowlist: ${p}`, 'success');
      loadSettingsAndQuarantine();
    }

    async function removeAllowlistPath(p) {
      await fetch('/api/allowlist', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: p, operation: 'remove' })
      });
      showToast(`Removed from allowlist: ${p}`, 'info');
      loadSettingsAndQuarantine();
    }

    async function restoreQuarantineItem(id) {
      const res = await fetch('/api/quarantine/restore', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ item_id: id })
      });
      const d = await res.json();
      if (d.success) {
        showToast('Item restored from quarantine to original location.', 'success');
        loadSettingsAndQuarantine();
      } else {
        showToast(d.detail || 'Restore failed.', 'error');
      }
    }

    async function purgeQuarantineItem(id) {
      if (!confirm('Are you sure you want to permanently delete this item from disk?')) return;
      const res = await fetch(`/api/quarantine/${id}`, { method: 'DELETE' });
      const d = await res.json();
      if (d.success) {
        showToast('Item permanently purged from quarantine.', 'info');
        loadSettingsAndQuarantine();
      } else {
        showToast(d.detail || 'Purge failed.', 'error');
      }
    }

    async function saveSafetySettings() {
      const payload = {
        safety_never_delete_system: document.getElementById('set_never_delete_system').checked,
        safety_check_running_processes: document.getElementById('set_check_running').checked,
        safety_quarantine_instead_of_delete: document.getElementById('set_quarantine').checked,
        allow_permanent_delete: document.getElementById('set_allow_perm').checked
      };
      await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ settings: payload })
      });
      showToast('Safety preferences updated successfully.', 'success');
    }

    // Auto-scan on load
    window.addEventListener('DOMContentLoaded', () => {
      triggerScan();
      loadSettingsAndQuarantine();
    });
  </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)

def start_server(host: str = "0.0.0.0", port: int = 8090):
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8090))
    start_server(port=port)
