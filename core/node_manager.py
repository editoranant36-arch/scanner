import os
import time
import json
from typing import Dict, List, Optional, Any
from core.models import ScanSummary, FolderItem, DecisionStatus

NODES_FILE = os.path.expanduser("~/.config/app_leftover_scanner/nodes.json")

class NodeManager:
    """
    Manages multiple connected machines (nodes) reporting to the central dashboard.
    Enables scanning and managing leftover folders across different systems on the network.
    """

    def __init__(self, storage_file: str = NODES_FILE):
        self.storage_file = storage_file
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        if os.path.exists(self.storage_file):
            try:
                with open(self.storage_file, "r", encoding="utf-8") as f:
                    self.nodes = json.load(f)
            except Exception:
                self.nodes = {}

    def _save(self):
        os.makedirs(os.path.dirname(self.storage_file), exist_ok=True)
        temp_path = f"{self.storage_file}.tmp"
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(self.nodes, f, indent=2)
        os.replace(temp_path, self.storage_file)

    def register_or_update_node(self, 
                                node_id: str, 
                                hostname: str, 
                                os_type: str, 
                                ip_address: str, 
                                scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Registers a remote system or updates its scan results."""
        self.nodes[node_id] = {
            "node_id": node_id,
            "hostname": hostname,
            "os_type": os_type,
            "ip_address": ip_address,
            "last_seen": time.strftime("%Y-%m-%d %H:%M:%S"),
            "scan_data": scan_data
        }
        self._save()
        return self.nodes[node_id]

    def get_nodes(self) -> List[Dict[str, Any]]:
        """Returns list of all connected nodes."""
        node_list = []
        for nid, data in self.nodes.items():
            s = data.get("scan_data", {})
            node_list.append({
                "node_id": nid,
                "hostname": data.get("hostname", "Unknown"),
                "os_type": data.get("os_type", "Unknown"),
                "ip_address": data.get("ip_address", "Unknown"),
                "last_seen": data.get("last_seen", "-"),
                "leftovers_detected": s.get("leftovers_detected", 0),
                "recoverable_space": s.get("total_space_recoverable_formatted", "0 B"),
                "total_folders": s.get("total_folders_scanned", 0)
            })
        return node_list

    def get_node_scan(self, node_id: str) -> Optional[Dict[str, Any]]:
        node = self.nodes.get(node_id)
        if node:
            return node.get("scan_data")
        return None

    def remove_node(self, node_id: str):
        if node_id in self.nodes:
            del self.nodes[node_id]
            self._save()
