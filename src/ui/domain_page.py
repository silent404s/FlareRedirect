"""Domain Manager Page (Multi-Account Enabled, Simplified Columns & Single Redirect Modal).
Displays accessible Cloudflare zones, current redirect target, and instant 301 redirection.
"""

from typing import List, Optional, Dict, Any
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QComboBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QProgressBar,
    QCheckBox,
    QFrame,
    QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from src.cloudflare.zones import ZoneItem, group_zones_by_target
from src.security.session import active_session
from src.ui.workers import FetchZonesWorker
from src.ui.bulk_dialog import BulkRedirectDialog
from src.ui.single_dialog import SingleRedirectDialog
from src.cloudflare.redirects import (
    get_zone_redirect_ruleset,
    delete_matching_redirects_for_domain,
)


class DomainPage(QWidget):
    """Page for viewing and searching Cloudflare zones with streamlined 301 redirects."""

    view_redirects_for_zone = Signal(str, str)  # zone_id, zone_name (retained for compatibility)
    show_toast = Signal(str, bool)
    zones_updated = Signal(list)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.all_zones: List[ZoneItem] = []
        self.current_filtered_zones: List[ZoneItem] = []
        self.zone_targets_cache: Dict[str, str] = {}
        self.worker: Optional[FetchZonesWorker] = None
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        # Header Row
        header_row = QHBoxLayout()
        title_lbl = QLabel("Domain Manager")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 700; color: #F8FAFC;")
        header_row.addWidget(title_lbl)

        self.count_badge = QLabel("0 Domain")
        self.count_badge.setStyleSheet(
            "background-color: #1E293B; color: #94A3B8; border-radius: 10px; padding: 2px 8px; font-size: 11px; font-weight: 600;"
        )
        header_row.addWidget(self.count_badge)

        header_row.addStretch()

        self.bulk_btn = QPushButton("⚡ Setup Bulk Redirect")
        self.bulk_btn.setProperty("class", "btn-neon-cyan")
        self.bulk_btn.clicked.connect(self._open_bulk_dialog)
        header_row.addWidget(self.bulk_btn)

        self.refresh_btn = QPushButton("🔄 Refresh")
        self.refresh_btn.setProperty("class", "btn-secondary")
        self.refresh_btn.clicked.connect(self.load_domains)
        header_row.addWidget(self.refresh_btn)
        layout.addLayout(header_row)

        # Controls Row
        ctrl_card = QFrame()
        ctrl_card.setStyleSheet("background-color: #0F172A; border: 1px solid #1E293B; border-radius: 8px; padding: 6px 12px;")
        ctrl_layout = QHBoxLayout(ctrl_card)
        ctrl_layout.setContentsMargins(6, 4, 6, 4)
        ctrl_layout.setSpacing(10)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍 Cari domain...")
        self.search_input.textChanged.connect(self._filter_table)
        ctrl_layout.addWidget(self.search_input, stretch=3)

        # Account Filter
        acc_lbl = QLabel("Akun:")
        acc_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 500;")
        ctrl_layout.addWidget(acc_lbl)

        self.account_combo = QComboBox()
        self.account_combo.addItem("Semua Akun", "all")
        self.account_combo.currentIndexChanged.connect(self._on_account_filter_changed)
        ctrl_layout.addWidget(self.account_combo, stretch=2)

        # Status Filter
        filter_lbl = QLabel("Status:")
        filter_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 500;")
        ctrl_layout.addWidget(filter_lbl)

        self.status_combo = QComboBox()
        self.status_combo.addItems(["All", "Active", "Pending", "Initializing", "Moved"])
        self.status_combo.currentTextChanged.connect(self._filter_table)
        ctrl_layout.addWidget(self.status_combo, stretch=1)

        # View Mode Toggle: All vs Group by Target
        self.view_mode_combo = QComboBox()
        self.view_mode_combo.addItem("Tampilan: Semua Domain", "list")
        self.view_mode_combo.addItem("Tampilan: Grup per Target", "group")
        self.view_mode_combo.currentIndexChanged.connect(self._filter_table)
        ctrl_layout.addWidget(self.view_mode_combo, stretch=2)

        # Select All Checkbox
        self.select_all_chk = QCheckBox("Pilih Semua")
        self.select_all_chk.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 500;")
        self.select_all_chk.stateChanged.connect(self._toggle_select_all)
        ctrl_layout.addWidget(self.select_all_chk)

        layout.addWidget(ctrl_card)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Empty state label
        self.empty_lbl = QLabel("Tidak ada domain yang ditemukan. Hubungkan akun Cloudflare terlebih dahulu.")
        self.empty_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_lbl.setStyleSheet("color: #64748B; font-size: 13px; padding: 40px;")
        self.empty_lbl.hide()
        layout.addWidget(self.empty_lbl)

        # Simplified Table: [Pilih] | Domain | Akun CF | Status | Target Redirect Saat Ini | Aksi
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Pilih", "Nama Domain", "Akun CF", "Status CF", "Target Redirect (301)", "Aksi"
        ])
        d_header = self.table.horizontalHeader()
        d_header.setMinimumSectionSize(50)
        d_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        d_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        d_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        d_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        d_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        d_header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(1, 180)
        self.table.setColumnWidth(2, 130)
        self.table.setAlternatingRowColors(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setDefaultSectionSize(28)
        layout.addWidget(self.table)

    def refresh_account_combo(self):
        self.account_combo.blockSignals(True)
        cur_data = self.account_combo.currentData()
        self.account_combo.clear()
        self.account_combo.addItem("Semua Akun", "all")
        for acc in active_session.get_all_accounts():
            self.account_combo.addItem(f"👤 {acc.label}", acc.account_id)

        idx = self.account_combo.findData(cur_data)
        if idx >= 0:
            self.account_combo.setCurrentIndex(idx)
        else:
            self.account_combo.setCurrentIndex(0)
        self.account_combo.blockSignals(False)

    def _on_account_filter_changed(self):
        self.load_domains()

    def load_domains(self):
        self.refresh_account_combo()
        target_acc_id = self.account_combo.currentData() or "all"

        self.progress_bar.show()
        self.refresh_btn.setEnabled(False)

        self.worker = FetchZonesWorker(
            status_filter=self.status_combo.currentText(),
            account_id=target_acc_id,
            parent=self,
        )
        self.worker.finished.connect(self._on_zones_loaded)
        self.worker.error.connect(self._on_zones_error)
        self.worker.start()

    def _on_zones_loaded(self, zones: List[ZoneItem]):
        self.progress_bar.hide()
        self.refresh_btn.setEnabled(True)
        self.all_zones = zones
        self._filter_table()
        self.zones_updated.emit(zones)
        self.show_toast.emit(f"Berhasil memuat {len(zones)} domain dari Cloudflare.", False)

    def _on_zones_error(self, err_msg: str):
        self.progress_bar.hide()
        self.refresh_btn.setEnabled(True)
        self.show_toast.emit(f"Gagal memuat domain: {err_msg}", True)

    def _toggle_select_all(self, state: int):
        checked = (state == Qt.CheckState.Checked.value or state == 2)
        for row in range(self.table.rowCount()):
            chk = self.table.cellWidget(row, 0)
            if isinstance(chk, QCheckBox):
                chk.setChecked(checked)

    def _filter_table(self):
        query = self.search_input.text().strip().lower()
        selected_status = self.status_combo.currentText().lower()
        selected_acc_id = self.account_combo.currentData()
        view_mode = self.view_mode_combo.currentData()

        filtered = []
        for z in self.all_zones:
            if query and query not in z.name.lower():
                continue
            if selected_status != "all" and z.status.lower() != selected_status:
                continue
            if selected_acc_id and selected_acc_id != "all" and z.account_id != selected_acc_id:
                continue
            filtered.append(z)

        self.current_filtered_zones = filtered
        self.count_badge.setText(f"{len(filtered)} Domain")
        self.table.setRowCount(len(filtered))

        if len(filtered) == 0:
            self.empty_lbl.show()
            self.table.hide()
            return
        else:
            self.empty_lbl.hide()
            self.table.show()

        mono_font = QFont("Consolas", 9)

        for row, z in enumerate(filtered):
            # 0. Checkbox
            chk = QCheckBox()
            chk.setStyleSheet("margin-left: 6px;")
            self.table.setCellWidget(row, 0, chk)

            # 1. Domain Name
            name_item = QTableWidgetItem(z.name)
            name_item.setFont(mono_font)
            name_item.setForeground(QColor("#F8FAFC"))
            self.table.setItem(row, 1, name_item)

            # 2. Account CF
            acc_item = QTableWidgetItem(z.account_label)
            acc_item.setForeground(QColor("#38BDF8"))
            self.table.setItem(row, 2, acc_item)

            # 3. Status CF
            is_active = (z.status.lower() == "active")
            status_item = QTableWidgetItem(f"● {z.status.upper()}" if is_active else f"○ {z.status.upper()}")
            status_item.setForeground(QColor("#34D399" if is_active else "#FBBF24"))
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 3, status_item)

            # 4. Target Redirect
            cur_target = self.zone_targets_cache.get(z.id, "-")
            target_item = QTableWidgetItem(cur_target)
            target_item.setFont(mono_font)
            target_item.setForeground(QColor("#00F0FF" if cur_target != "-" else "#64748B"))
            self.table.setItem(row, 4, target_item)

            # 5. Action Cell (Redirect Button & Clean Delete Button)
            action_widget = QWidget()
            act_layout = QHBoxLayout(action_widget)
            act_layout.setContentsMargins(4, 2, 4, 2)
            act_layout.setSpacing(6)

            redirect_btn = QPushButton("⚡ Redirect")
            redirect_btn.setProperty("class", "btn-primary")
            redirect_btn.setStyleSheet("padding: 2px 10px; font-size: 11px; font-weight: 600;")
            redirect_btn.clicked.connect(lambda checked=False, zone=z: self._open_single_redirect(zone))
            act_layout.addWidget(redirect_btn)

            del_btn = QPushButton("🗑️")
            del_btn.setProperty("class", "btn-secondary")
            del_btn.setToolTip("Bersihkan semua redirect rule untuk domain ini")
            del_btn.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            del_btn.clicked.connect(lambda checked=False, zone=z: self._delete_domain_redirects(zone))
            act_layout.addWidget(del_btn)

            self.table.setCellWidget(row, 5, action_widget)

    def _open_single_redirect(self, zone: ZoneItem):
        cur_target = self.zone_targets_cache.get(zone.id, "")
        dlg = SingleRedirectDialog(zone, current_target=cur_target, parent=self)
        dlg.redirect_saved.connect(self._on_single_redirect_saved)
        dlg.exec()

    def _on_single_redirect_saved(self, data: Dict[str, Any]):
        zone_id = data.get("zone_id")
        target_url = data.get("destination_url")
        if zone_id and target_url:
            self.zone_targets_cache[zone_id] = target_url
            self._filter_table()
            self.show_toast.emit(f"301 Redirect berhasil dipasang ke {target_url}", False)

    def _delete_domain_redirects(self, zone: ZoneItem):
        confirm = QMessageBox.question(
            self,
            "Konfirmasi Hapus Redirect",
            f"Hapus semua aturan redirect untuk domain '{zone.name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm == QMessageBox.StandardButton.Yes:
            try:
                count = delete_matching_redirects_for_domain(zone.id, zone.name, account_id=zone.account_id)
                self.zone_targets_cache.pop(zone.id, None)
                self._filter_table()
                self.show_toast.emit(f"{count} aturan redirect berhasil dihapus untuk {zone.name}.", False)
            except Exception as exc:
                QMessageBox.critical(self, "Gagal Menghapus", str(exc))

    def _open_bulk_dialog(self):
        selected_ids = []
        for row in range(self.table.rowCount()):
            chk = self.table.cellWidget(row, 0)
            if isinstance(chk, QCheckBox) and chk.isChecked() and row < len(self.current_filtered_zones):
                selected_ids.append(self.current_filtered_zones[row].id)

        dlg = BulkRedirectDialog(self.all_zones, preselected_zone_ids=selected_ids, parent=self)
        dlg.bulk_completed.connect(
            lambda count: self.show_toast.emit(f"{count} aturan bulk redirect berhasil dibuat!", False)
        )
        dlg.exec()

    def set_zones(self, zones: List[ZoneItem]):
        self.all_zones = zones
        self._filter_table()

    def clear(self):
        self.all_zones = []
        self.zone_targets_cache.clear()
        self.table.setRowCount(0)
        self.empty_lbl.hide()
        self.count_badge.setText("0 Domain")
