# Application Leftover Folder Scanner

A modular, safety-first residual file analysis and cleanup platform engineered to detect and safely manage orphan application folders left behind after software uninstallation, based on the **Architecture Overview** flow.

---

## 🏛️ Architecture Layers

The platform is structured into 6 architectural layers:

```
┌─────────────────────────────────────────────────────────────┐
│ 1. User Interface (UI Layer)                                │
│    Main Dashboard • Scan Results • User Decisions • Settings│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 2. Scan Engine                                              │
│    Installed Apps Detection • File System • Registry Scanner│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 3. Correlation & Analysis Engine                            │
│    Installed Check • App Match • Protected Check • Locks    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 4. Decision Engine                                          │
│    Application Exists | Deleted | System Protected | Unknown│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 5. Action Layer                                             │
│    Delete (Quarantine) | Keep (Allowlist) | View | Ignore   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ 6. Data & History Layer                                     │
│    Allowlist • Quarantine Vault • Scan History • Settings   │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Enforced Safety Rules

1. **Never delete system / Windows folders**: Hard-coded safety boundary protecting `System32`, `WindowsApps`, `WinSxS`, `/bin`, `/lib`, `/etc`, etc.
2. **Check running processes and services**: Folders locked or executing active processes are automatically flagged and safeguarded.
3. **Verify digital signatures & registry references**: Correlates binary signatures and registry software hives.
4. **Move deleted items to Quarantine (not permanent)**: Deletions are non-permanent by default and can be restored with a single click.
5. **Always ask the user for non-system folders**: Zero silent or destructive deletions; decisions are presented via interactive prompts.

---

## 🚀 Quick Start

### 1. Native Python Desktop Dashboard (PyQt6)

Run the desktop application:

```bash
python3 gui.py
```

This launches the desktop window on your screen:
- Includes **Dashboard**, **Scan Results**, **Action Center**, and **Settings & Quarantine**.
- Clicking **"📁 View Folder"** on any item or prompt dialog **immediately opens the OS file manager** (Thunar/Nautilus on Linux, Explorer on Windows) right to that specific directory!
- Displays the **Example User Prompt** dialog matching the architecture overview.

---

### 2. Web Dashboard & Interactive UI

Launch the web platform (running on port `8090` by default):

```bash
python3 server.py
```

Open your browser to:
👉 **[http://localhost:8090](http://localhost:8090)**
*(Clicking "View Folder" in the web browser also immediately opens the folder in your desktop file manager via the background agent)*


Features:
- **Dashboard**: Real-time metrics, architecture diagram walkthrough, demo/live system mode toggle.
- **Results**: Full filterable list of scanned folders categorized with badges:
  - `APPLICATION DELETED` (Leftover orphan folders)
  - `APPLICATION EXISTS` (Active installed application folders)
  - `SYSTEM PROTECTED` (Critical OS components)
  - `UNKNOWN / UNCERTAIN` (Uncorrelated folders)
- **Action Center & User Prompt**: Exact visual replica of the architecture diagram's **Example User Prompt** with one-click action execution:
  - 🔴 **Delete Folder** (Move to Quarantine)
  - 🟢 **Keep / Allow** (Add to Allowlist)
  - 🔵 **View Folder** (Inspect files & subdirectories)
  - 🟣 **Ignore** (Skip this scan)
- **Settings & History**: Allowlist manager, Quarantine restorer/purger, and scan audit log.

---

### 2. Command Line Interface (CLI)

The scanner includes a rich terminal interface:

#### Run a scan using architecture demo data:
```bash
python3 cli.py scan --demo
```

#### Run an interactive step-by-step review prompt:
```bash
python3 cli.py scan --demo --interactive
```

#### Scan live host system:
```bash
python3 cli.py scan
```

#### Manage quarantine repository:
```bash
python3 cli.py quarantine --list
python3 cli.py quarantine --restore <ITEM_ID>
python3 cli.py quarantine --delete-perm <ITEM_ID>
```

#### Manage allowlist:
```bash
python3 cli.py allowlist --list
python3 cli.py allowlist --add "/path/to/folder"
python3 cli.py allowlist --remove "/path/to/folder"
```

#### View scan history:
```bash
python3 cli.py history
```

---

### 3. Multi-System / Remote Network Scanning

Web browsers are sandboxed for security and cannot read files from a remote computer's local hard drive without an agent script running on that machine.

To scan any other computer on your network (e.g. Windows PC, laptop, Mac, or server) and view its results on the central dashboard:

1. Open the dashboard on any device: **[http://192.168.0.139:8090](http://192.168.0.139:8090)**
2. Click **"➕ Scan Another System"**.
3. Run the 1-click command on the target system:
   - **For Windows** (PowerShell):
     ```powershell
     irm http://192.168.0.139:8090/agent/scan.ps1 | iex
     ```
   - **For Linux / macOS** (Bash):
     ```bash
     curl -sSL http://192.168.0.139:8090/agent/scan.sh | bash
     ```
   - **Using Python 3** (Any OS):
     ```bash
     python3 -c "import urllib.request; exec(urllib.request.urlopen('http://192.168.0.139:8090/agent/agent.py').read())"
     ```
4. The remote system will scan its local registry, installed apps, `Program Files`, and `AppData`, and automatically appear in the **"System"** dropdown on the dashboard!

---

## 🧪 Testing

Execute test suite covering all 6 layers:

```bash
PYTHONPATH=. pytest -v tests/test_scanner.py
```

