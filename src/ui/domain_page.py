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
from src.cloudflare.zones import ZoneItem
from src.security.session import active_session
from src.ui.workers import (
    FetchZonesWorker,
    BulkDeleteDomainRedirectsWorker,
    CheckLiveRedirectsWorker,
)
from src.ui.bulk_dialog import BulkRedirectDialog
from src.ui.single_dialog import SingleRedirectDialog
from src.cloudflare.redirects import delete_matching_redirects_for_domain
from src import config_manager


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
        self.redirect_checks_cache: Dict[str, Dict[str, Any]] = {}
        self.worker: Optional[FetchZonesWorker] = None
        self.check_worker: Optional[CheckLiveRedirectsWorker] = None
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

        self.check_redirects_btn = QPushButton("🔍 Cek Live Redirect")
        self.check_redirects_btn.setProperty("class", "btn-neon-cyan")
        self.check_redirects_btn.setToolTip("Periksa langsung status live redirect (301/302) dan deteksi rantai redirect ganda (>1x)")
        self.check_redirects_btn.clicked.connect(self._start_live_redirect_check)
        header_row.addWidget(self.check_redirects_btn)

        self.bulk_btn = QPushButton("⚡ Setup Bulk Redirect")
        self.bulk_btn.setProperty("class", "btn-primary")
        self.bulk_btn.clicked.connect(self._open_bulk_dialog)
        header_row.addWidget(self.bulk_btn)

        self.bulk_delete_btn = QPushButton("🗑️ Hapus Redirect Terpilih")
        self.bulk_delete_btn.setProperty("class", "btn-danger")
        self.bulk_delete_btn.setStyleSheet("padding: 5px 12px; font-size: 11px; font-weight: 600;")
        self.bulk_delete_btn.clicked.connect(self._delete_selected_redirects)
        header_row.addWidget(self.bulk_delete_btn)

        self.refresh_btn = QPushButton("🔄 Refresh dari CF")
        self.refresh_btn.setProperty("class", "btn-secondary")
        self.refresh_btn.setToolTip("Muat ulang daftar domain langsung dari server Cloudflare dan perbarui penyimpanan lokal.")
        self.refresh_btn.clicked.connect(lambda: self.load_domains(force_refresh=True))
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
        filter_lbl = QLabel("Status CF:")
        filter_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 500;")
        ctrl_layout.addWidget(filter_lbl)

        self.status_combo = QComboBox()
        self.status_combo.addItems(["All", "Active", "Pending", "Initializing", "Moved"])
        self.status_combo.currentTextChanged.connect(self._filter_table)
        ctrl_layout.addWidget(self.status_combo, stretch=1)

        # Redirect Status Filter (Alert filter for >1x redirect)
        redir_lbl = QLabel("Redirect:")
        redir_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 500;")
        ctrl_layout.addWidget(redir_lbl)

        self.redirect_filter_combo = QComboBox()
        self.redirect_filter_combo.addItem("Semua Redirect", "all")
        self.redirect_filter_combo.addItem("⚠️ Multiple Redirect (>1x)", "multiple")
        self.redirect_filter_combo.addItem("✅ Normal (1x Redirect)", "single")
        self.redirect_filter_combo.addItem("○ Tanpa Redirect (200 OK)", "none")
        self.redirect_filter_combo.addItem("✕ Gagal / Error", "error")
        self.redirect_filter_combo.addItem("Belum Diperiksa", "untested")
        self.redirect_filter_combo.currentIndexChanged.connect(self._filter_table)
        ctrl_layout.addWidget(self.redirect_filter_combo, stretch=2)

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

        # Live Redirect Check Progress Card
        self.check_progress_card = QFrame()
        self.check_progress_card.setStyleSheet(
            "background-color: #0B132B; border: 1px solid #38BDF8; border-radius: 8px; padding: 6px 12px;"
        )
        self.check_progress_card.hide()
        chk_p_layout = QHBoxLayout(self.check_progress_card)
        chk_p_layout.setContentsMargins(6, 4, 6, 4)
        chk_p_layout.setSpacing(10)

        self.check_status_lbl = QLabel("Mengecek live redirect...")
        self.check_status_lbl.setStyleSheet("color: #38BDF8; font-weight: 600; font-size: 12px;")
        chk_p_layout.addWidget(self.check_status_lbl, stretch=2)

        self.check_progress_bar = QProgressBar()
        self.check_progress_bar.setStyleSheet(
            "QProgressBar { height: 16px; border-radius: 4px; text-align: center; color: #FFFFFF; font-weight: 600; font-size: 10px; background: #090D16; } "
            "QProgressBar::chunk { background-color: #00F0FF; border-radius: 4px; }"
        )
        chk_p_layout.addWidget(self.check_progress_bar, stretch=3)

        self.cancel_check_btn = QPushButton("🛑 Batal")
        self.cancel_check_btn.setProperty("class", "btn-secondary")
        self.cancel_check_btn.setStyleSheet("padding: 2px 12px; font-size: 11px;")
        self.cancel_check_btn.clicked.connect(self._cancel_live_redirect_check)
        chk_p_layout.addWidget(self.cancel_check_btn)

        layout.addWidget(self.check_progress_card)

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

        # Simplified Table: [Pilih] | Domain | Akun CF | Status | Target Live Redirect | Aksi
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Pilih", "Nama Domain", "Akun CF", "Status CF", "Target Live Redirect", "Aksi"
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
        if self.all_zones:
            self._filter_table()
        else:
            self.load_domains(force_refresh=False)

    def load_domains(self, force_refresh: bool = False):
        self.refresh_account_combo()
        target_acc_id = self.account_combo.currentData() or "all"

        # 1. Coba muat dari cache lokal jika tidak dipaksa refresh dari server CF
        if not force_refresh:
            cached_data = config_manager.load_cached_domains()
            cached_zones = cached_data.get("zones", [])
            cached_targets = cached_data.get("targets", {})
            self.redirect_checks_cache = cached_data.get("redirect_checks", {})

            if cached_zones:
                self.all_zones = [ZoneItem(item) for item in cached_zones]
                self.zone_targets_cache.update(cached_targets)

                # Sinkronkan zones ke akun masing-masing di session in-memory
                for acc in active_session.get_all_accounts():
                    matched = []
                    for z in self.all_zones:
                        if (z.account_label and z.account_label.lower() == acc.label.lower()) or (z.account_id and z.account_id == acc.account_id):
                            z.account_id = acc.account_id
                            z.account_label = acc.label
                            matched.append(z)
                    acc.zones = matched

                self._filter_table()
                self.zones_updated.emit(self.all_zones)
                self.show_toast.emit(f"Memuat {len(self.all_zones)} domain dari penyimpanan lokal.", False)
                return

        # 2. Jika force_refresh atau cache lokal belum ada, ambil langsung dari Cloudflare API
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
        # Simpan ke cache lokal untuk start berikutnya
        config_manager.save_cached_domains(zones, self.zone_targets_cache, redirect_checks=self.redirect_checks_cache)
        self._filter_table()
        self.zones_updated.emit(zones)
        self.show_toast.emit(f"Berhasil memuat {len(zones)} domain dari Cloudflare dan disimpan ke penyimpanan lokal.", False)

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
        redir_filter = self.redirect_filter_combo.currentData() if hasattr(self, "redirect_filter_combo") else "all"

        filtered = []
        for z in self.all_zones:
            if query and query not in z.name.lower():
                continue
            if selected_status != "all" and z.status.lower() != selected_status:
                continue
            if selected_acc_id and selected_acc_id != "all" and z.account_id != selected_acc_id:
                continue

            # Redirect status filter
            chk = self.redirect_checks_cache.get(z.name.lower())
            if redir_filter == "multiple":
                if not chk or not (chk.get("is_multiple") or chk.get("hops", 0) > 1):
                    continue
            elif redir_filter == "single":
                if not chk or chk.get("hops", 0) != 1:
                    continue
            elif redir_filter == "none":
                if not chk or chk.get("has_redirect") or chk.get("error"):
                    continue
            elif redir_filter == "error":
                if not chk or not chk.get("error"):
                    continue
            elif redir_filter == "untested":
                if chk:
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

            # 4. Target Live Redirect Cell
            chk_data = self.redirect_checks_cache.get(z.name.lower())
            if chk_data:
                hops = chk_data.get("hops", 0)
                target = chk_data.get("target_url", "")
                code = chk_data.get("status_code")
                err = chk_data.get("error")

                if chk_data.get("is_multiple") or hops > 1:
                    code_tag = f"[{code} • {hops}x]" if code else f"[{hops}x]"
                    disp = f"⚠️ {code_tag} {target}"
                    target_item = QTableWidgetItem(disp)
                    target_item.setFont(mono_font)
                    target_item.setForeground(QColor("#F59E0B"))  # Amber Warning
                    chain_list = chk_data.get("chain", [])
                    chain_str = " → ".join(chain_list) if chain_list else target
                    target_item.setToolTip(f"⚠️ PERINGATAN: Terdeteksi {hops}x Redirects (> 1x)!\nRantai Pengalihan: {z.name} → {chain_str}")
                elif hops == 1:
                    code_tag = f"[{code}]" if code else "[301]"
                    disp = f"✅ {code_tag} {target}"
                    target_item = QTableWidgetItem(disp)
                    target_item.setFont(mono_font)
                    target_item.setForeground(QColor("#00F0FF"))  # Cyan Normal
                    target_item.setToolTip(f"Normal 1x Redirect ({code}): {target}")
                elif err:
                    disp = f"✕ {err}"
                    target_item = QTableWidgetItem(disp)
                    target_item.setFont(mono_font)
                    target_item.setForeground(QColor("#EF4444"))  # Red Error
                    target_item.setToolTip(f"Gagal memeriksa domain: {err}")
                else:
                    code_str = f"{code} OK" if code else "200 OK"
                    disp = f"○ {code_str} (Tanpa Redirect)"
                    target_item = QTableWidgetItem(disp)
                    target_item.setFont(mono_font)
                    target_item.setForeground(QColor("#64748B"))  # Muted Gray
                    target_item.setToolTip("Domain aktif langsung tanpa aturan redirect.")
            else:
                cur_target = self.zone_targets_cache.get(z.id, "-")
                if cur_target != "-":
                    disp = f"[Aturan CF] {cur_target}"
                    target_item = QTableWidgetItem(disp)
                    target_item.setFont(mono_font)
                    target_item.setForeground(QColor("#94A3B8"))
                    target_item.setToolTip("Target dari konfigurasi aturan lokal (belum diperiksa live).")
                else:
                    disp = "- (Belum dicek)"
                    target_item = QTableWidgetItem(disp)
                    target_item.setFont(mono_font)
                    target_item.setForeground(QColor("#475569"))
                    target_item.setToolTip("Klik tombol '🔍 Cek Live Redirect' untuk memeriksa.")

            self.table.setItem(row, 4, target_item)

            # 5. Action Cell (Redirect Button, Single Check Button & Clean Delete Button)
            action_widget = QWidget()
            act_layout = QHBoxLayout(action_widget)
            act_layout.setContentsMargins(4, 2, 4, 2)
            act_layout.setSpacing(6)

            redirect_btn = QPushButton("⚡ Redirect")
            redirect_btn.setProperty("class", "btn-primary")
            redirect_btn.setStyleSheet("padding: 2px 10px; font-size: 11px; font-weight: 600;")
            redirect_btn.clicked.connect(lambda checked=False, zone=z: self._open_single_redirect(zone))
            act_layout.addWidget(redirect_btn)

            check_single_btn = QPushButton("🔍")
            check_single_btn.setProperty("class", "btn-secondary")
            check_single_btn.setToolTip("Cek status live redirect untuk domain ini")
            check_single_btn.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            check_single_btn.clicked.connect(lambda checked=False, zone=z: self._check_single_domain_redirect(zone))
            act_layout.addWidget(check_single_btn)

            del_btn = QPushButton("🗑️")
            del_btn.setProperty("class", "btn-secondary")
            del_btn.setToolTip("Bersihkan semua redirect rule untuk domain ini")
            del_btn.setStyleSheet("padding: 2px 6px; font-size: 11px;")
            del_btn.clicked.connect(lambda checked=False, zone=z: self._delete_domain_redirects(zone))
            act_layout.addWidget(del_btn)

            self.table.setCellWidget(row, 5, action_widget)

    def _start_live_redirect_check(self):
        """Starts live redirect checks for selected or all domains currently listed."""
        if self.check_worker and self.check_worker.isRunning():
            self.show_toast.emit("Pengecekan live redirect sedang berjalan.", True)
            return

        selected_zones: List[ZoneItem] = []
        for row in range(self.table.rowCount()):
            chk = self.table.cellWidget(row, 0)
            if isinstance(chk, QCheckBox) and chk.isChecked() and row < len(self.current_filtered_zones):
                selected_zones.append(self.current_filtered_zones[row])

        if selected_zones:
            target_domains = [z.name for z in selected_zones]
            confirm_msg = f"Mulai pengecekan live redirect untuk {len(target_domains)} domain terpilih?"
        else:
            target_domains = [z.name for z in self.current_filtered_zones]
            if not target_domains:
                self.show_toast.emit("Tidak ada domain yang dapat diperiksa.", True)
                return
            confirm_msg = (
                f"Mulai pengecekan live redirect untuk seluruh {len(target_domains)} domain pada daftar?\n\n"
                f"Pengecekan berjalan otomatis di latar belakang secara multi-threaded (cepat & tidak lag)."
            )

        if len(target_domains) > 50:
            reply = QMessageBox.question(
                self,
                "Konfirmasi Cek Live Redirect",
                confirm_msg,
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        self.check_progress_bar.setRange(0, len(target_domains))
        self.check_progress_bar.setValue(0)
        self.check_status_lbl.setText(f"Memulai pengecekan {len(target_domains)} domain...")
        self.check_progress_card.show()
        self.check_redirects_btn.setEnabled(False)
        self.cancel_check_btn.setEnabled(True)

        self.check_worker = CheckLiveRedirectsWorker(
            domains=target_domains,
            max_workers=15,
            timeout=6.0,
            parent=self,
        )
        self.check_worker.progress.connect(self._on_check_progress)
        self.check_worker.finished.connect(self._on_check_finished)
        self.check_worker.error.connect(self._on_check_error)
        self.check_worker.start()

    def _cancel_live_redirect_check(self):
        if self.check_worker and self.check_worker.isRunning():
            self.check_worker.cancel()
            self.check_status_lbl.setText("Menghentikan pengecekan...")
            self.cancel_check_btn.setEnabled(False)

    def _on_check_progress(self, current: int, total: int, domain: str, res: dict):
        self.check_progress_bar.setValue(current)
        self.redirect_checks_cache[domain.lower()] = res

        mult_count = sum(1 for r in self.redirect_checks_cache.values() if r.get("is_multiple"))
        self.check_status_lbl.setText(
            f"Mengecek {current}/{total} domain (⚠️ {mult_count} >1x redirect) — {domain}"
        )

        # Save to disk and update table incrementally every 25 domains
        if current % 25 == 0 or current == total:
            config_manager.save_cached_redirect_checks(self.redirect_checks_cache)
            self._filter_table()

    def _on_check_finished(self, results: dict):
        self.check_progress_card.hide()
        self.check_redirects_btn.setEnabled(True)
        self.cancel_check_btn.setEnabled(True)

        self.redirect_checks_cache.update(results)
        config_manager.save_cached_redirect_checks(self.redirect_checks_cache)
        self._filter_table()

        total = len(results)
        multiple_count = sum(1 for r in results.values() if r.get("is_multiple"))
        single_count = sum(1 for r in results.values() if r.get("hops") == 1)
        none_count = sum(1 for r in results.values() if not r.get("has_redirect") and not r.get("error"))

        msg = (
            f"Pengecekan selesai! {total} domain diperiksa: "
            f"{single_count} Normal (1x), {multiple_count} Multiple (>1x), {none_count} Tanpa Redirect."
        )
        self.show_toast.emit(msg, multiple_count > 0)

    def _on_check_error(self, err_msg: str):
        self.check_progress_card.hide()
        self.check_redirects_btn.setEnabled(True)
        self.cancel_check_btn.setEnabled(True)
        self.show_toast.emit(f"Gagal memeriksa redirect: {err_msg}", True)

    def _check_single_domain_redirect(self, zone: ZoneItem):
        self.show_toast.emit(f"Memeriksa live redirect '{zone.name}'...", False)
        worker = CheckLiveRedirectsWorker(domains=[zone.name], max_workers=1, timeout=6.0, parent=self)

        def on_single_done(res_dict: dict):
            if zone.name.lower() in res_dict:
                res = res_dict[zone.name.lower()]
                self.redirect_checks_cache[zone.name.lower()] = res
                config_manager.update_cached_redirect_check(zone.name, res)
                self._filter_table()
                if res.get("is_multiple"):
                    self.show_toast.emit(f"⚠️ '{zone.name}' terdeteksi {res.get('hops')}x Redirects!", True)
                elif res.get("hops") == 1:
                    self.show_toast.emit(f"✅ '{zone.name}' normal 1x redirect ({res.get('status_code')}) ke {res.get('target_url')}", False)
                elif res.get("error"):
                    self.show_toast.emit(f"✕ '{zone.name}': {res.get('error')}", True)
                else:
                    self.show_toast.emit(f"○ '{zone.name}': 200 OK (Tanpa Redirect)", False)

        worker.finished.connect(on_single_done)
        worker.start()

    def _open_single_redirect(self, zone: ZoneItem):
        cur_target = self.zone_targets_cache.get(zone.id, "")
        dlg = SingleRedirectDialog(zone, current_target=cur_target, parent=self)
        dlg.redirect_saved.connect(self._on_single_redirect_saved)
        dlg.exec()

    def _on_single_redirect_saved(self, data: Dict[str, Any]):
        zone_id = data.get("zone_id")
        target_url = data.get("destination_url")
        if zone_id:
            if data.get("deleted") or target_url == "-":
                self.zone_targets_cache.pop(zone_id, None)
                config_manager.update_cached_target(zone_id, None)
                self.show_toast.emit("Aturan 301 Redirect berhasil dihapus.", False)
            elif target_url:
                self.zone_targets_cache[zone_id] = target_url
                config_manager.update_cached_target(zone_id, target_url)
                self.show_toast.emit(f"301 Redirect berhasil dipasang ke {target_url}", False)
            self._filter_table()

    def _delete_selected_redirects(self):
        selected_zones: List[ZoneItem] = []
        for row in range(self.table.rowCount()):
            chk = self.table.cellWidget(row, 0)
            if isinstance(chk, QCheckBox) and chk.isChecked() and row < len(self.current_filtered_zones):
                selected_zones.append(self.current_filtered_zones[row])

        if not selected_zones:
            QMessageBox.warning(
                self,
                "Belum Ada Domain Dipilih",
                "Silakan centang satu atau beberapa domain pada tabel terlebih dahulu untuk menghapus aturan redirect.",
            )
            return

        confirm = QMessageBox.question(
            self,
            "Konfirmasi Hapus Redirect Massal",
            f"Apakah Anda yakin ingin menghapus seluruh aturan redirect untuk {len(selected_zones)} domain yang dicentang?\n\n"
            "Tindakan ini akan membersihkan semua aturan redirect di Cloudflare untuk domain-domain tersebut.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self._pending_bulk_deleted_zones = selected_zones
        self.progress_bar.show()
        self.bulk_delete_btn.setEnabled(False)
        self.refresh_btn.setEnabled(False)

        self.bulk_del_worker = BulkDeleteDomainRedirectsWorker(selected_zones, parent=self)
        self.bulk_del_worker.progress.connect(lambda cur, tot, msg: self.show_toast.emit(f"[{cur}/{tot}] {msg}", False))
        self.bulk_del_worker.finished.connect(self._on_bulk_delete_finished)
        self.bulk_del_worker.error.connect(self._on_bulk_delete_error)
        self.bulk_del_worker.start()

    def _on_bulk_delete_finished(self, count: int):
        self.progress_bar.hide()
        self.bulk_delete_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        if hasattr(self, "_pending_bulk_deleted_zones"):
            for z in self._pending_bulk_deleted_zones:
                self.zone_targets_cache.pop(z.id, None)
                config_manager.update_cached_target(z.id, None)
            self._pending_bulk_deleted_zones = []
        self._filter_table()
        self.show_toast.emit(f"Selesai! Total {count} aturan redirect berhasil dihapus.", False)

    def _on_bulk_delete_error(self, err_msg: str):
        self.progress_bar.hide()
        self.bulk_delete_btn.setEnabled(True)
        self.refresh_btn.setEnabled(True)
        QMessageBox.critical(self, "Gagal Menghapus Redirect Massal", err_msg)

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
                config_manager.update_cached_target(zone.id, None)
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
        def _on_bulk_done(count: int):
            if dlg.last_applied:
                self.zone_targets_cache.update(dlg.last_applied)
                config_manager.save_cached_domains(self.all_zones, self.zone_targets_cache)
                self._filter_table()
            self.show_toast.emit(f"{count} aturan bulk redirect berhasil dibuat!", False)
        dlg.bulk_completed.connect(_on_bulk_done)
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
