import pytest
import os
import shutil
import tempfile
from core.models import DecisionStatus, UserAction, FolderItem, InstalledApp
from core.scan_engine import ScanEngine
from core.correlation_engine import CorrelationEngine
from core.decision_engine import DecisionEngine
from core.action_layer import ActionLayer
from core.data_layer import DataAndHistoryLayer
from core.orchestrator import ScannerOrchestrator

@pytest.fixture
def temp_data_dir():
    temp_dir = tempfile.mkdtemp(prefix="scanner_test_")
    yield temp_dir
    shutil.rmtree(temp_dir, ignore_errors=True)

def test_scan_engine_demo_mode():
    engine = ScanEngine(demo_mode=True)
    apps = engine.detect_installed_apps()
    folders = engine.scan_file_system()
    sys_info = engine.scan_registry_and_system()

    assert len(apps) > 0
    assert any(a.name == "Mozilla Firefox" for a in apps)
    assert len(folders) > 0
    assert any("Chrome" in f.name for f in folders)
    assert "services" in sys_info

def test_correlation_engine():
    engine = CorrelationEngine(demo_mode=True)
    chrome_folder = FolderItem(
        path=r"C:\Users\User\AppData\Local\Google\Chrome",
        name="Chrome",
        size_bytes=459276288,
        size_formatted="438.0 MB"
    )
    installed_apps = [
        InstalledApp(name="Mozilla Firefox", display_name="Mozilla Firefox", version="125.0")
    ]
    analyzed = engine.analyze_folder(chrome_folder, installed_apps, {"services": [], "app_keys": []})

    assert analyzed.associated_app_name == "Google Chrome"
    assert not analyzed.is_protected

def test_system_protection_rule():
    engine = CorrelationEngine(demo_mode=True)
    sys_folder = FolderItem(
        path=r"C:\Windows\System32",
        name="System32"
    )
    analyzed = engine.analyze_folder(sys_folder, [], {"services": [], "app_keys": []})

    assert analyzed.is_protected is True

def test_decision_engine(temp_data_dir):
    data_layer = DataAndHistoryLayer(base_dir=temp_data_dir)
    decision_engine = DecisionEngine(data_layer=data_layer)

    # 1. Leftover folder
    leftover = FolderItem(
        path=r"C:\Users\User\AppData\Local\Google\Chrome",
        name="Chrome",
        associated_app_name="Google Chrome"
    )
    classified = decision_engine.classify_folder(leftover)
    assert classified.decision == DecisionStatus.APPLICATION_DELETED

    # 2. System protected folder
    sys_folder = FolderItem(
        path=r"C:\Windows\System32",
        name="System32",
        is_protected=True
    )
    classified_sys = decision_engine.classify_folder(sys_folder)
    assert classified_sys.decision == DecisionStatus.SYSTEM_PROTECTED

def test_action_layer_safety_enforcement(temp_data_dir):
    data_layer = DataAndHistoryLayer(base_dir=temp_data_dir)
    action_layer = ActionLayer(data_layer=data_layer)

    # Attempting to delete a system path must fail immediately
    res = action_layer.execute_action(r"C:\Windows\System32", "delete")
    assert res["success"] is False
    assert "SAFETY BLOCKED" in res["error"]

    # Allowlist action
    res_allow = action_layer.execute_action(r"C:\Users\User\CustomApp", "keep")
    assert res_allow["success"] is True
    assert data_layer.is_allowlisted(r"C:\Users\User\CustomApp")

    # Quarantine action on candidate
    res_delete = action_layer.execute_action(r"C:\Users\User\AppData\Local\Google\Chrome", "delete", app_name="Google Chrome")
    assert res_delete["success"] is True
    assert res_delete["mode"] == "quarantine"

def test_orchestrator_end_to_end(temp_data_dir):
    data_layer = DataAndHistoryLayer(base_dir=temp_data_dir)
    orchestrator = ScannerOrchestrator(data_layer=data_layer, demo_mode=True)

    summary = orchestrator.run_full_scan()
    assert summary.total_folders_scanned > 0
    assert summary.leftovers_detected >= 3
    assert summary.system_protected_count >= 2

    # Verify history was recorded
    history = orchestrator.get_history()
    assert len(history) == 1
    assert history[0]["leftovers_detected"] == summary.leftovers_detected
