#!/usr/bin/env python3
import sys
import os
from typing import Optional, List

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QTabWidget, QTableWidget, QTableWidgetItem,
    QHeaderView, QMessageBox, QDialog, QLineEdit, QCheckBox,
    QFrame, QScrollArea, QGridLayout, QSplitter
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QIcon

from core.orchestrator import ScannerOrchestrator
from core.models import DecisionStatus, FolderItem

DARK_STYLESHEET = """
QMainWindow, QWidget {
    background-color: #0d131f;
    color: #e2e8f0;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    font-size: 13px;
}
QTabWidget::pane {
    border: 1px solid #1e293b;
    background: #111827;
    border-radius: 8px;
}
QTabBar::tab {
    background: #1e293b;
    color: #94a3b8;
    padding: 10px 20px;
    margin-right: 4px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: 600;
}
QTabBar::tab:selected {
    background: #2563eb;
    color: #ffffff;
}
QTableWidget {
    background-color: #111827;
    alternate-background-color: #161f30;
    border: 1px solid #1e293b;
    gridline-color: #1e293b;
    border-radius: 8px;
    selection-background-color: #1e3a8a;
}
QHeaderView::section {
    background-color: #0b0f19;
    color: #94a3b8;
    padding: 8px;
    font-weight: bold;
    border: none;
    border-bottom: 1px solid #1e293b;
}
QPushButton {
    background-color: #2563eb;
    color: white;
    font-weight: 600;
    border-radius: 6px;
    padding: 8px 16px;
    border: none;
}
QPushButton:hover {
    background-color: #1d4ed8;
}
QPushButton:pressed {
    background-color: #1e40af;
}
QLineEdit {
    background-color: #1e293b;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 6px 12px;
    color: white;
}
QLineEdit:focus {
    border: 1px solid #3b82f6;
}
QCheckBox {
    color: #e2e8f0;
    spacing: 8px;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    border-radius: 4px;
    border: 1px solid #475569;
    background: #1e293b;
}
QCheckBox::indicator:checked {
    background: #2563eb;
}
"""

class ScanWorker(QThread):
    finished = pyqtSignal(object)

    def __init__(self, orchestrator: ScannerOrchestrator):
        super().__init__()
        self.orchestrator = orchestrator

    def run(self):
        summary = self.orchestrator.run_full_scan()
        self.finished.emit(summary)

class UserPromptDialog(QDialog):
    """
    Exact visual replica of the Example User Prompt dialog from the diagram:
    - Leftover Application Folder Detected
    - Application: <App>
    - Status: Application is not installed
    - Leftover folder: <Path>
    - Size: <Size>
    - 4 Action Buttons: [Delete Folder] [Keep / Allow] [View Folder] [Ignore]
    """
    def __init__(self, item: FolderItem, orchestrator: ScannerOrchestrator, parent=None):
        super().__init__(parent)
        self.item = item
        self.orchestrator = orchestrator
        self.action_chosen = None

        self.setWindowTitle("Leftover Application Folder Detected")
        self.setFixedSize(540, 380)
        self.setStyleSheet(DARK_STYLESHEET)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 24, 24, 24)

        # Header with Alert Banner
        header = QHBoxLayout()
        icon_lbl = QLabel("⚠️")
        icon_lbl.setFont(QFont("Segoe UI Emoji", 26))
        
        title_box = QVBoxLayout()
        title_lbl = QLabel("Leftover Application Folder Detected")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: bold; color: #f87171;")
        sub_lbl = QLabel("Decision Engine (Layer 4/5) - Residual Folder Identified")
        sub_lbl.setStyleSheet("color: #94a3b8; font-size: 11px;")
        title_box.addWidget(title_lbl)
        title_box.addWidget(sub_lbl)

        header.addWidget(icon_lbl)
        header.addLayout(title_box)
        header.addStretch()
        layout.addLayout(header)

        # Details Frame
        card = QFrame()
        card.setStyleSheet("background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; padding: 12px;")
        card_layout = QVBoxLayout(card)
        card_layout.setSpacing(8)

        def add_row(key, val, color="#ffffff"):
            row = QHBoxLayout()
            kl = QLabel(key)
            kl.setStyleSheet("color: #94a3b8; font-weight: 500; font-size: 12px;")
            vl = QLabel(val)
            vl.setStyleSheet(f"color: {color}; font-weight: bold; font-size: 12px;")
            row.addWidget(kl)
            row.addStretch()
            row.addWidget(vl)
            card_layout.addLayout(row)

        add_row("Application:", item.associated_app_name or item.name, "#ffffff")
        add_row("Status:", "Application is not installed", "#ef4444")
        add_row("Leftover folder:", item.path, "#60a5fa")
        add_row("Size:", item.size_formatted, "#34d399")

        layout.addWidget(card)

        prompt_lbl = QLabel("This folder appears to belong to an application that is no longer installed.\nWhat would you like to do?")
        prompt_lbl.setStyleSheet("color: #cbd5e1; font-style: italic; font-size: 12px;")
        layout.addWidget(prompt_lbl)

        # 4 Action Buttons
        btn_grid = QGridLayout()
        btn_grid.setSpacing(10)

        btn_delete = QPushButton("🗑️ Delete Folder")
        btn_delete.setStyleSheet("background-color: #dc2626; color: white; padding: 12px; font-size: 13px; font-weight: bold;")
        btn_delete.clicked.connect(self.on_delete)

        btn_keep = QPushButton("✔️ Keep / Allow")
        btn_keep.setStyleSheet("background-color: #059669; color: white; padding: 12px; font-size: 13px; font-weight: bold;")
        btn_keep.clicked.connect(self.on_keep)

        btn_view = QPushButton("📁 View Folder")
        btn_view.setStyleSheet("background-color: #2563eb; color: white; padding: 12px; font-size: 13px; font-weight: bold;")
        btn_view.clicked.connect(self.on_view)

        btn_ignore = QPushButton("👁️ Ignore")
        btn_ignore.setStyleSheet("background-color: #475569; color: white; padding: 12px; font-size: 13px; font-weight: bold;")
        btn_ignore.clicked.connect(self.on_ignore)

        btn_grid.addWidget(btn_delete, 0, 0)
        btn_grid.addWidget(btn_keep, 0, 1)
        btn_grid.addWidget(btn_view, 1, 0)
        btn_grid.addWidget(btn_ignore, 1, 1)

        layout.addLayout(btn_grid)

    def on_delete(self):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Delete Leftover Folder")
        msg_box.setText(f"How would you like to delete this leftover folder?\n\nFolder:\n{self.item.path}")
        btn_perm = msg_box.addButton("Permanently Delete from System", QMessageBox.ButtonRole.DestructiveRole)
        btn_quar = msg_box.addButton("Move to Quarantine (Restorable)", QMessageBox.ButtonRole.ActionRole)
        btn_cancel = msg_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        msg_box.exec()

        if msg_box.clickedButton() == btn_perm:
            res = self.orchestrator.execute_item_action(
                self.item.path, "delete",
                app_name=self.item.associated_app_name or "",
                permanent_delete=True
            )
            if res.get("success"):
                QMessageBox.information(self, "Permanently Deleted", f"Folder permanently removed from disk!\n\n{res.get('message')}")
            else:
                QMessageBox.warning(self, "Safety Blocked", res.get("error"))
            self.action_chosen = "delete"
            self.accept()
        elif msg_box.clickedButton() == btn_quar:
            res = self.orchestrator.execute_item_action(
                self.item.path, "delete",
                app_name=self.item.associated_app_name or "",
                permanent_delete=False
            )
            if res.get("success"):
                QMessageBox.information(self, "Quarantined", f"Folder moved safely to Quarantine!\n\n{res.get('message')}")
            else:
                QMessageBox.warning(self, "Safety Blocked", res.get("error"))
            self.action_chosen = "delete"
            self.accept()


    def on_keep(self):
        self.orchestrator.execute_item_action(self.item.path, "keep", app_name=self.item.associated_app_name or "")
        QMessageBox.information(self, "Added to Allowlist", f"'{self.item.path}' added to allowlist.\nIt will be skipped in future scans.")
        self.action_chosen = "keep"
        self.accept()

    def on_view(self):
        # Physically open the specific folder in the OS file manager
        res = self.orchestrator.open_folder_in_os(self.item.path)
        target = res.get("target_path", self.item.path)
        QMessageBox.information(
            self,
            "Opening in File Manager",
            f"Launched File Manager at:\n\n{target}\n\n(Status: {res.get('message', 'Opened')})"
        )

    def on_ignore(self):
        self.orchestrator.execute_item_action(self.item.path, "ignore")
        self.action_chosen = "ignore"
        self.accept()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Application Leftover Folder Scanner")
        self.resize(1100, 720)
        self.setStyleSheet(DARK_STYLESHEET)

        self.orchestrator = ScannerOrchestrator(demo_mode=True)
        self.current_summary = None

        self._init_ui()

    def _init_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(16, 16, 16, 16)
        main_layout.setSpacing(14)

        # Top Bar
        top_bar = QHBoxLayout()
        title_box = QVBoxLayout()
        app_title = QLabel("Application Leftover Folder Scanner")
        app_title.setStyleSheet("font-size: 18px; font-weight: bold; color: white;")
        app_sub = QLabel("Modular Endpoint Residual Directory & Storage Analysis")
        app_sub.setStyleSheet("font-size: 11px; color: #94a3b8;")
        title_box.addWidget(app_title)
        title_box.addWidget(app_sub)
        top_bar.addLayout(title_box)
        top_bar.addStretch()

        # Demo Toggle
        self.demo_cb = QCheckBox("Architecture Demo Data")
        self.demo_cb.setChecked(True)
        self.demo_cb.toggled.connect(self.on_demo_toggled)
        top_bar.addWidget(self.demo_cb)

        # Run Scan Button
        self.btn_scan = QPushButton("🚀 Run Scan Now")
        self.btn_scan.setStyleSheet("background-color: #2563eb; font-weight: bold; padding: 10px 20px; font-size: 13px;")
        self.btn_scan.clicked.connect(self.start_scan)
        top_bar.addWidget(self.btn_scan)

        main_layout.addLayout(top_bar)

        # Tabs
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        self._build_dashboard_tab()
        self._build_results_tab()
        self._build_actions_tab()
        self._build_settings_tab()

        # Start initial scan
        self.start_scan()

    def _build_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(16)

        # 4 Stat Cards
        cards_layout = QHBoxLayout()
        
        self.card_leftovers = self._create_stat_card("Leftovers Found", "0", "#ef4444", "Orphan folders")
        self.card_space = self._create_stat_card("Recoverable Space", "0 B", "#10b981", "Wasted disk space")
        self.card_protected = self._create_stat_card("System Protected", "0", "#f59e0b", "Protected components")
        self.card_active = self._create_stat_card("Active Apps", "0", "#3b82f6", "Currently installed")

        cards_layout.addWidget(self.card_leftovers)
        cards_layout.addWidget(self.card_space)
        cards_layout.addWidget(self.card_protected)
        cards_layout.addWidget(self.card_active)
        layout.addLayout(cards_layout)

        # Bottom section: Leftovers List & Safety Rules
        bottom_layout = QHBoxLayout()

        # Leftovers Review Card
        leftover_box = QFrame()
        leftover_box.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px;")
        l_layout = QVBoxLayout(leftover_box)
        lbl = QLabel("Action Queue: Detected Leftover Folders")
        lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        l_layout.addWidget(lbl)

        self.dash_table = QTableWidget()
        self.dash_table.setColumnCount(4)
        self.dash_table.setHorizontalHeaderLabels(["App", "Folder Path", "Size", "Action"])
        self.dash_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        l_layout.addWidget(self.dash_table)
        bottom_layout.addWidget(leftover_box, 60)

        # Safety Rules Box
        safety_box = QFrame()
        safety_box.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px;")
        s_layout = QVBoxLayout(safety_box)
        s_lbl = QLabel("🛡️ Safety Rules Engine")
        s_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: white;")
        s_layout.addWidget(s_lbl)

        rules = [
            "Never delete system / Windows folders",
            "Check running processes and services",
            "Verify registry references & signatures",
            "Move deleted items to quarantine (restorable)",
            "Always ask user for non-system folders"
        ]
        for r in rules:
            rl = QLabel(f"✓ {r}")
            rl.setStyleSheet("color: #10b981; font-size: 12px; margin-top: 4px;")
            s_layout.addWidget(rl)

        s_layout.addStretch()
        bottom_layout.addWidget(safety_box, 40)

        layout.addLayout(bottom_layout)
        self.tabs.addTab(tab, "🏠 Dashboard")

    def _create_stat_card(self, title, val, color, subtext):
        card = QFrame()
        card.setStyleSheet(f"background-color: #111827; border-left: 4px solid {color}; border-radius: 8px; padding: 12px;")
        cl = QVBoxLayout(card)
        t = QLabel(title)
        t.setStyleSheet("font-size: 11px; text-transform: uppercase; color: #94a3b8; font-weight: bold;")
        v = QLabel(val)
        v.setStyleSheet("font-size: 24px; font-weight: bold; color: white;")
        s = QLabel(subtext)
        s.setStyleSheet("font-size: 11px; color: #64748b;")
        cl.addWidget(t)
        cl.addWidget(v)
        cl.addWidget(s)
        card.val_label = v
        return card

    def _build_results_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Toolbar
        tool_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search folders or applications...")
        self.search_input.textChanged.connect(self.filter_results_table)
        tool_layout.addWidget(self.search_input)

        layout.addLayout(tool_layout)

        # Full Table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(5)
        self.results_table.setHorizontalHeaderLabels(["Status", "Folder Path", "App Name", "Size", "Actions"])
        self.results_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.results_table)

        self.tabs.addTab(tab, "📋 Scan Results")

    def _build_actions_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        
        info = QLabel("Review detected orphan folders and execute safe actions:")
        info.setStyleSheet("color: #94a3b8; margin-bottom: 8px;")
        layout.addWidget(info)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("background: transparent; border: none;")
        self.actions_container = QWidget()
        self.actions_layout = QVBoxLayout(self.actions_container)
        scroll.setWidget(self.actions_container)
        layout.addWidget(scroll)

        self.tabs.addTab(tab, "⚡ Action Center")

    def _build_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(14)

        # Allowlist Frame
        af = QFrame()
        af.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px;")
        al = QVBoxLayout(af)
        al.addWidget(QLabel("<b>Allowlist (Folders to Keep / Skip)</b>"))
        
        add_box = QHBoxLayout()
        self.allow_input = QLineEdit()
        self.allow_input.setPlaceholderText("Enter directory path to allowlist...")
        btn_add = QPushButton("Add Path")
        btn_add.clicked.connect(self.add_to_allowlist)
        add_box.addWidget(self.allow_input)
        add_box.addWidget(btn_add)
        al.addLayout(add_box)

        self.allow_table = QTableWidget()
        self.allow_table.setColumnCount(2)
        self.allow_table.setHorizontalHeaderLabels(["Allowed Path", "Action"])
        self.allow_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        al.addWidget(self.allow_table)

        layout.addWidget(af)

        # Quarantine Frame
        qf = QFrame()
        qf.setStyleSheet("background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 14px;")
        ql = QVBoxLayout(qf)
        ql.addWidget(QLabel("<b>Quarantine Vault (Deleted Restorable Items)</b>"))

        self.quar_table = QTableWidget()
        self.quar_table.setColumnCount(4)
        self.quar_table.setHorizontalHeaderLabels(["Original Path", "App", "Date", "Action"])
        self.quar_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        ql.addWidget(self.quar_table)

        layout.addWidget(qf)

        self.tabs.addTab(tab, "⚙️ Settings & Quarantine")

    def on_demo_toggled(self, checked):
        self.orchestrator.set_demo_mode(checked)
        self.start_scan()

    def start_scan(self):
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("⏳ Scanning...")
        self.worker = ScanWorker(self.orchestrator)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.start()

    def on_scan_finished(self, summary):
        self.current_summary = summary
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("🚀 Run Scan Now")

        # Update stats
        self.card_leftovers.val_label.setText(str(summary.leftovers_detected))
        self.card_space.val_label.setText(self.orchestrator.data_layer._format_size(summary.total_space_recoverable_bytes))
        self.card_protected.val_label.setText(str(summary.system_protected_count))
        self.card_active.val_label.setText(str(summary.active_apps_count))

        self.populate_dashboard_table(summary.items)
        self.populate_results_table(summary.items)
        self.populate_actions_cards(summary.items)
        self.populate_settings_data()

    def populate_dashboard_table(self, items: List[FolderItem]):
        leftovers = [i for i in items if i.decision == DecisionStatus.APPLICATION_DELETED]
        self.dash_table.setRowCount(len(leftovers))

        for row, it in enumerate(leftovers):
            self.dash_table.setItem(row, 0, QTableWidgetItem(it.associated_app_name or it.name))
            self.dash_table.setItem(row, 1, QTableWidgetItem(it.path))
            self.dash_table.setItem(row, 2, QTableWidgetItem(it.size_formatted))

            btn_box = QWidget()
            h = QHBoxLayout(btn_box)
            h.setContentsMargins(2, 2, 2, 2)
            h.setSpacing(4)

            btn_prompt = QPushButton("Review")
            btn_prompt.setStyleSheet("background-color: #dc2626; font-size: 11px; padding: 4px 8px;")
            btn_prompt.clicked.connect(lambda _, item=it: self.open_prompt_dialog(item))

            btn_view = QPushButton("View Folder")
            btn_view.setStyleSheet("background-color: #2563eb; font-size: 11px; padding: 4px 8px;")
            btn_view.clicked.connect(lambda _, item=it: self.view_folder_in_os(item.path))

            h.addWidget(btn_prompt)
            h.addWidget(btn_view)
            self.dash_table.setCellWidget(row, 3, btn_box)

    def populate_results_table(self, items: List[FolderItem]):
        self.results_table.setRowCount(len(items))

        for row, it in enumerate(items):
            status_item = QTableWidgetItem(it.decision.value)
            if it.decision == DecisionStatus.APPLICATION_DELETED:
                status_item.setForeground(QColor("#f87171"))
            elif it.decision == DecisionStatus.APPLICATION_EXISTS:
                status_item.setForeground(QColor("#4ade80"))
            elif it.decision == DecisionStatus.SYSTEM_PROTECTED:
                status_item.setForeground(QColor("#facc15"))
            else:
                status_item.setForeground(QColor("#94a3b8"))

            self.results_table.setItem(row, 0, status_item)
            self.results_table.setItem(row, 1, QTableWidgetItem(it.path))
            self.results_table.setItem(row, 2, QTableWidgetItem(it.associated_app_name or "-"))
            self.results_table.setItem(row, 3, QTableWidgetItem(it.size_formatted))

            btn_box = QWidget()
            h = QHBoxLayout(btn_box)
            h.setContentsMargins(2, 2, 2, 2)
            h.setSpacing(4)

            btn_view = QPushButton("View Folder")
            btn_view.setStyleSheet("background-color: #2563eb; font-size: 11px; padding: 4px 8px;")
            btn_view.clicked.connect(lambda _, item=it: self.view_folder_in_os(item.path))
            h.addWidget(btn_view)

            if it.decision == DecisionStatus.APPLICATION_DELETED:
                btn_prompt = QPushButton("Review")
                btn_prompt.setStyleSheet("background-color: #dc2626; font-size: 11px; padding: 4px 8px;")
                btn_prompt.clicked.connect(lambda _, item=it: self.open_prompt_dialog(item))
                h.addWidget(btn_prompt)

            self.results_table.setCellWidget(row, 4, btn_box)

    def populate_actions_cards(self, items: List[FolderItem]):
        # Clear existing
        while self.actions_layout.count():
            child = self.actions_layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

        leftovers = [i for i in items if i.decision == DecisionStatus.APPLICATION_DELETED]
        if not leftovers:
            lbl = QLabel("No leftover folders to review!")
            lbl.setStyleSheet("color: #10b981; font-size: 14px; padding: 20px;")
            self.actions_layout.addWidget(lbl)
            return

        for it in leftovers:
            card = QFrame()
            card.setStyleSheet("background-color: #111827; border: 1px solid #ef4444; border-radius: 8px; padding: 14px; margin-bottom: 8px;")
            cl = QVBoxLayout(card)

            top = QHBoxLayout()
            name_lbl = QLabel(f"<b>{it.associated_app_name or it.name}</b>")
            name_lbl.setStyleSheet("font-size: 14px; color: white;")
            size_lbl = QLabel(it.size_formatted)
            size_lbl.setStyleSheet("font-size: 14px; font-weight: bold; color: #34d399;")
            top.addWidget(name_lbl)
            top.addStretch()
            top.addWidget(size_lbl)
            cl.addLayout(top)

            path_lbl = QLabel(it.path)
            path_lbl.setStyleSheet("color: #60a5fa; font-family: monospace; font-size: 11px;")
            cl.addWidget(path_lbl)

            btn_box = QHBoxLayout()
            
            b_del = QPushButton("Delete Folder (Quarantine)")
            b_del.setStyleSheet("background-color: #dc2626; font-size: 12px;")
            b_del.clicked.connect(lambda _, item=it: self.quick_delete(item))

            b_keep = QPushButton("Keep / Allow")
            b_keep.setStyleSheet("background-color: #059669; font-size: 12px;")
            b_keep.clicked.connect(lambda _, item=it: self.quick_keep(item))

            b_view = QPushButton("View Folder (Open OS)")
            b_view.setStyleSheet("background-color: #2563eb; font-size: 12px;")
            b_view.clicked.connect(lambda _, item=it: self.view_folder_in_os(item.path))

            b_ign = QPushButton("Ignore")
            b_ign.setStyleSheet("background-color: #475569; font-size: 12px;")
            b_ign.clicked.connect(lambda _, item=it: self.quick_ignore(item))

            btn_box.addWidget(b_del)
            btn_box.addWidget(b_keep)
            btn_box.addWidget(b_view)
            btn_box.addWidget(b_ign)
            cl.addLayout(btn_box)

            self.actions_layout.addWidget(card)

    def populate_settings_data(self):
        # Allowlist
        allowed = self.orchestrator.get_allowlist()
        self.allow_table.setRowCount(len(allowed))
        for row, path in enumerate(allowed):
            self.allow_table.setItem(row, 0, QTableWidgetItem(path))
            btn_rem = QPushButton("Remove")
            btn_rem.setStyleSheet("background-color: #dc2626; font-size: 11px;")
            btn_rem.clicked.connect(lambda _, p=path: self.remove_from_allowlist(p))
            self.allow_table.setCellWidget(row, 1, btn_rem)

        # Quarantine
        quar = self.orchestrator.get_quarantine()
        self.quar_table.setRowCount(len(quar))
        for row, it in enumerate(quar):
            self.quar_table.setItem(row, 0, QTableWidgetItem(it.get("original_path", "")))
            self.quar_table.setItem(row, 1, QTableWidgetItem(it.get("associated_app", "")))
            self.quar_table.setItem(row, 2, QTableWidgetItem(it.get("timestamp", "")))

            box = QWidget()
            h = QHBoxLayout(box)
            h.setContentsMargins(2, 2, 2, 2)
            
            btn_rest = QPushButton("Restore")
            btn_rest.setStyleSheet("background-color: #059669; font-size: 10px; padding: 4px;")
            btn_rest.clicked.connect(lambda _, qid=it["id"]: self.restore_quarantine_item(qid))

            btn_purge = QPushButton("Purge")
            btn_purge.setStyleSheet("background-color: #dc2626; font-size: 10px; padding: 4px;")
            btn_purge.clicked.connect(lambda _, qid=it["id"]: self.purge_quarantine_item(qid))

            h.addWidget(btn_rest)
            h.addWidget(btn_purge)
            self.quar_table.setCellWidget(row, 3, box)

    def open_prompt_dialog(self, item: FolderItem):
        dlg = UserPromptDialog(item, self.orchestrator, self)
        dlg.exec()
        self.start_scan()

    def view_folder_in_os(self, path: str):
        """Directly invokes the operating system's file manager for this specific folder."""
        res = self.orchestrator.open_folder_in_os(path)
        target = res.get("target_path", path)
        QMessageBox.information(
            self,
            "View Folder",
            f"Opened in File Manager:\n\n{target}\n\nStatus: {res.get('message', 'Opened')}"
        )

    def quick_delete(self, item: FolderItem):
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle("Delete Leftover Folder")
        msg_box.setText(f"Delete leftover folder:\n\n{item.path}\n\nChoose an action:")
        btn_perm = msg_box.addButton("Permanently Delete from System", QMessageBox.ButtonRole.DestructiveRole)
        btn_quar = msg_box.addButton("Move to Quarantine", QMessageBox.ButtonRole.ActionRole)
        btn_cancel = msg_box.addButton("Cancel", QMessageBox.ButtonRole.RejectRole)
        msg_box.exec()

        if msg_box.clickedButton() == btn_perm:
            res = self.orchestrator.execute_item_action(
                item.path, "delete",
                app_name=item.associated_app_name or "",
                permanent_delete=True
            )
            if res.get("success"):
                QMessageBox.information(self, "Permanently Deleted", f"Folder permanently removed from disk!\n\n{res.get('message')}")
            else:
                QMessageBox.warning(self, "Safety Blocked", res.get("error"))
            self.start_scan()
        elif msg_box.clickedButton() == btn_quar:
            res = self.orchestrator.execute_item_action(
                item.path, "delete",
                app_name=item.associated_app_name or "",
                permanent_delete=False
            )
            if res.get("success"):
                QMessageBox.information(self, "Quarantined", f"Folder moved safely to Quarantine!\n\n{res.get('message')}")
            else:
                QMessageBox.warning(self, "Safety Blocked", res.get("error"))
            self.start_scan()


    def quick_keep(self, item: FolderItem):
        self.orchestrator.execute_item_action(item.path, "keep", app_name=item.associated_app_name or "")
        QMessageBox.information(self, "Allowlisted", f"'{item.path}' added to allowlist.")
        self.start_scan()

    def quick_ignore(self, item: FolderItem):
        self.orchestrator.execute_item_action(item.path, "ignore")
        self.start_scan()

    def add_to_allowlist(self):
        p = self.allow_input.text().strip()
        if p:
            self.orchestrator.add_allowlist(p)
            self.allow_input.clear()
            self.populate_settings_data()

    def remove_from_allowlist(self, p):
        self.orchestrator.remove_allowlist(p)
        self.populate_settings_data()

    def restore_quarantine_item(self, qid):
        ok = self.orchestrator.restore_quarantine(qid)
        if ok:
            QMessageBox.information(self, "Restored", "Folder restored successfully to original path.")
        else:
            QMessageBox.warning(self, "Error", "Failed to restore quarantine folder.")
        self.populate_settings_data()

    def purge_quarantine_item(self, qid):
        reply = QMessageBox.question(self, "Confirm Purge", "Permanently delete this folder from disk?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.orchestrator.delete_quarantine_permanent(qid)
            self.populate_settings_data()

    def filter_results_table(self, query):
        q = query.lower()
        for row in range(self.results_table.rowCount()):
            path = self.results_table.item(row, 1).text().lower()
            app = self.results_table.item(row, 2).text().lower()
            match = q in path or q in app
            self.results_table.setRowHidden(row, not match)

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
