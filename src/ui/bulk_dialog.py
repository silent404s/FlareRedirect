"""Bulk Redirect Manager Dialog (Simplified 1-Screen Workflow with Multi-Account Auto-Discovery).
Features:
1. Target URL Input (at the top).
2. Domain List Text Area (paste clean domains or raw URLs).
3. 'Validasi (Pre-check)' Button:
   - Resolves Public DNS IP (FlarePilot engine).
   - Auto-discovers which Cloudflare account owns the domain across all connected accounts.
   - Live HTTP pre-flight redirect check.
   - Cloudflare conflict & anomaly detection.
4. 'Eksekusi 301' Button:
   - Executes batch 301 redirect creation automatically routed to each domain's respective Cloudflare account.
   - User NEVER needs to manually switch or select accounts!
"""

from typing import List, Dict, Any, Optional
from PySide6.QtWidgets import (
    QDialog,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QCheckBox,
    QProgressBar,
    QMessageBox,
    QFrame,
    QApplication,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont

from src.cloudflare.zones import ZoneItem, find_matching_zone_for_raw
from src.security.validation import (
    clean_domain_input,
    validate_destination_url,
)
from src.ui.workers import (
    BulkCreateRedirectsWorker,
    PreflightValidationWorker,
)


class BulkRedirectDialog(QDialog):
    """Modern single-screen dialog for batch 301 redirect creation with FlarePilot-style auto account resolution."""

    bulk_completed = Signal(int)  # emits number of created rules

    def __init__(self, zones: List[ZoneItem], preselected_zone_ids: Optional[List[str]] = None, parent=None):
        super().__init__(parent)
        self.zones = zones or []
        self.preselected_zone_ids = set(preselected_zone_ids or [])
        self.worker: Optional[BulkCreateRedirectsWorker] = None
        self.preflight_worker: Optional[PreflightValidationWorker] = None
        self.last_applied: Dict[str, str] = {}

        self.validated_items: List[Dict[str, Any]] = []

        self.setWindowTitle("⚡ Bulk Redirect Manager — Multi-Account 301 URL Forwarding")
        screen = QApplication.primaryScreen()
        if screen:
            avail = screen.availableGeometry()
            target_w = min(1080, max(820, int(avail.width() * 0.90)))
            target_h = min(660, max(500, int(avail.height() * 0.90)))
            self.resize(target_w, target_h)
        else:
            self.resize(960, 600)
        self.setMinimumSize(780, 480)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F172A;
                border: 1px solid #1E293B;
                border-radius: 10px;
            }
        """)
        self._init_ui()
        self._prefill_selected_zones()

    def _init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(10)

        # 1. Header Card
        header_frame = QFrame()
        header_frame.setProperty("class", "card")
        h_layout = QVBoxLayout(header_frame)
        h_layout.setContentsMargins(14, 8, 14, 8)
        h_layout.setSpacing(2)

        title_lbl = QLabel("⚡ Bulk Redirect Manager (Auto Multi-Account Routing)")
        title_lbl.setStyleSheet("font-size: 15px; font-weight: 700; color: #F8FAFC;")
        h_layout.addWidget(title_lbl)

        desc_lbl = QLabel(
            "Terapkan aturan 301 Permanent Redirect ke banyak domain sekaligus. "
            "Sistem secara otomatis mendeteksi akun Cloudflare dan IP publik untuk setiap domain tanpa perlu memilih akun secara manual."
        )
        desc_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        h_layout.addWidget(desc_lbl)
        main_layout.addWidget(header_frame)

        # 2. Target URL Input Frame (At the Top)
        target_frame = QFrame()
        target_frame.setStyleSheet("background: #090D16; border: 1px solid #1E293B; border-radius: 8px; padding: 10px;")
        t_layout = QVBoxLayout(target_frame)
        t_layout.setContentsMargins(10, 8, 10, 8)
        t_layout.setSpacing(6)

        t_row = QHBoxLayout()
        t_lbl = QLabel("🎯 URL Tujuan (Target 301):")
        t_lbl.setStyleSheet("font-weight: 700; color: #38BDF8; font-size: 12px;")
        t_row.addWidget(t_lbl)

        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText("https://linkrtpgacor77.com/habanero.html")
        self.target_url_input.setStyleSheet("""
            QLineEdit {
                background-color: #050811;
                border: 1px solid #38BDF8;
                border-radius: 6px;
                padding: 6px 10px;
                color: #F8FAFC;
                font-size: 12px;
            }
            QLineEdit:focus {
                border: 1px solid #00F0FF;
            }
        """)
        t_row.addWidget(self.target_url_input, stretch=1)
        t_layout.addLayout(t_row)

        opts_row = QHBoxLayout()
        self.preserve_path_chk = QCheckBox("Preserve Sub-Path (Jangan dicentang jika target halaman spesifik /habanero.html)")
        self.preserve_path_chk.setChecked(False)
        self.preserve_path_chk.setStyleSheet("color: #94A3B8; font-size: 11px;")
        opts_row.addWidget(self.preserve_path_chk)

        query_info = QLabel("Query String: <b>Nonaktif (False)</b> | Status: <b>301 Mutlak</b>")
        query_info.setStyleSheet("color: #64748B; font-size: 11px;")
        opts_row.addStretch()
        opts_row.addWidget(query_info)
        t_layout.addLayout(opts_row)

        main_layout.addWidget(target_frame)

        # 3. Domain List Text Area & Action
        input_box = QFrame()
        input_box.setStyleSheet("background: #090D16; border: 1px solid #1E293B; border-radius: 8px; padding: 8px;")
        ib_layout = QVBoxLayout(input_box)
        ib_layout.setContentsMargins(10, 8, 10, 8)
        ib_layout.setSpacing(6)

        ib_header = QHBoxLayout()
        ib_lbl = QLabel("📋 Daftar Domain Asal (Satu per baris — bebas dari berbagai akun Cloudflare yang berbeda):")
        ib_lbl.setStyleSheet("color: #CBD5E1; font-weight: 600; font-size: 11px;")
        ib_header.addWidget(ib_lbl)
        ib_header.addStretch()

        self.domain_count_lbl = QLabel("0 domain")
        self.domain_count_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        ib_header.addWidget(self.domain_count_lbl)
        ib_layout.addLayout(ib_header)

        self.domain_text_area = QTextEdit()
        self.domain_text_area.setPlaceholderText(
            "Paste daftar domain di sini (bisa campuran dari akun Cloudflare mana saja)...\n"
            "gacor77terbaik.org\n"
            "angkapasaranresmi.com\n"
            "www.gacor77.biz\n"
            "https://gacorseo.com/"
        )
        self.domain_text_area.setMinimumHeight(75)
        self.domain_text_area.setMaximumHeight(120)
        self.domain_text_area.setStyleSheet("""
            QTextEdit {
                background-color: #050811;
                border: 1px solid #1E293B;
                border-radius: 6px;
                padding: 6px;
                color: #F8FAFC;
                font-family: Consolas, monospace;
                font-size: 12px;
            }
        """)
        self.domain_text_area.textChanged.connect(self._on_text_changed)
        ib_layout.addWidget(self.domain_text_area)

        # Validation Bar
        action_row = QHBoxLayout()
        self.validate_btn = QPushButton("🔍 1. Validasi & Auto-Detect Akun")
        self.validate_btn.setProperty("class", "btn-secondary")
        self.validate_btn.setStyleSheet("padding: 6px 14px; font-weight: 700; font-size: 11px;")
        self.validate_btn.clicked.connect(self._run_preflight_validation)
        action_row.addWidget(self.validate_btn)

        self.val_summary_lbl = QLabel("")
        self.val_summary_lbl.setStyleSheet("font-weight: 600; font-size: 11px;")
        action_row.addWidget(self.val_summary_lbl)

        action_row.addStretch()

        self.execute_btn = QPushButton("🚀 2. Eksekusi 301")
        self.execute_btn.setProperty("class", "btn-primary")
        self.execute_btn.setStyleSheet("padding: 6px 18px; font-weight: 700; font-size: 12px;")
        self.execute_btn.setEnabled(False)
        self.execute_btn.clicked.connect(self._execute_bulk_redirect)
        action_row.addWidget(self.execute_btn)

        ib_layout.addLayout(action_row)
        main_layout.addWidget(input_box)

        # 4. Progress Bar
        self.prog_frame = QFrame()
        self.prog_frame.hide()
        prog_layout = QVBoxLayout(self.prog_frame)
        prog_layout.setContentsMargins(0, 0, 0, 0)
        self.prog_lbl = QLabel("Memproses...")
        self.prog_lbl.setStyleSheet("color: #00F0FF; font-size: 11px; font-weight: 600;")
        prog_layout.addWidget(self.prog_lbl)
        self.prog_bar = QProgressBar()
        self.prog_bar.setRange(0, 100)
        prog_layout.addWidget(self.prog_bar)
        main_layout.addWidget(self.prog_frame)

        # 5. Preview Table (7 Kolom: Status, Domain, IP Publik, Akun CF, Status Live HTTP, Target, Status CF)
        self.preview_table = QTableWidget()
        self.preview_table.setColumnCount(7)
        self.preview_table.setHorizontalHeaderLabels([
            "Status", "Domain Asal", "Public IP", "Akun CF Terdeteksi", "Status Live (HTTP)", "Target Baru", "Status Cloudflare"
        ])
        p_header = self.preview_table.horizontalHeader()
        p_header.setMinimumSectionSize(50)
        p_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        p_header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        p_header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        p_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        p_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Interactive)
        p_header.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        p_header.setSectionResizeMode(6, QHeaderView.ResizeMode.Interactive)
        self.preview_table.setColumnWidth(1, 150)
        self.preview_table.setColumnWidth(2, 115)
        self.preview_table.setColumnWidth(3, 135)
        self.preview_table.setColumnWidth(4, 125)
        self.preview_table.setColumnWidth(6, 175)
        self.preview_table.setAlternatingRowColors(True)
        self.preview_table.verticalHeader().setDefaultSectionSize(26)
        main_layout.addWidget(self.preview_table, stretch=1)

        # 6. Footer
        footer_layout = QHBoxLayout()
        self.footer_lbl = QLabel(f"Sistem Auto-Detect aktif untuk seluruh akun Cloudflare yang terhubung.")
        self.footer_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        footer_layout.addWidget(self.footer_lbl)
        footer_layout.addStretch()

        self.close_btn = QPushButton("Tutup")
        self.close_btn.setProperty("class", "btn-secondary")
        self.close_btn.clicked.connect(self.close)
        footer_layout.addWidget(self.close_btn)
        main_layout.addLayout(footer_layout)

        # Compatibility attributes for test access
        self.tab2_text = self.domain_text_area
        self.tab2_default_dest = self.target_url_input
        self.tab2_parsed_items: List[Dict[str, Any]] = []

    def _prefill_selected_zones(self):
        if self.preselected_zone_ids:
            domains = []
            for z in self.zones:
                if z.id in self.preselected_zone_ids:
                    domains.append(z.name)
            if domains:
                self.domain_text_area.setPlainText("\n".join(domains))

    def _on_text_changed(self):
        lines = [line.strip() for line in self.domain_text_area.toPlainText().splitlines() if line.strip()]
        self.domain_count_lbl.setText(f"{len(lines)} domain terdeteksi")
        self.execute_btn.setEnabled(False)

    def _run_preflight_validation(self):
        target = self.target_url_input.text().strip()
        if not target:
            QMessageBox.warning(self, "URL Tujuan Kosong", "Silakan masukkan URL Tujuan (Target 301) di bagian atas terlebih dahulu.")
            return

        try:
            norm_target, _ = validate_destination_url(target)
        except Exception as exc:
            QMessageBox.critical(self, "URL Tujuan Tidak Valid", str(exc))
            return

        raw_lines = [line.strip() for line in self.domain_text_area.toPlainText().splitlines() if line.strip()]
        if not raw_lines:
            QMessageBox.warning(self, "Daftar Domain Kosong", "Silakan masukkan setidaknya satu nama domain pada kotak teks.")
            return

        clean_domains = []
        for line in raw_lines:
            if line.startswith("#"):
                continue
            clean_token = line.split("->")[0].split(",")[0].split()[0].strip()
            if clean_token:
                clean_domains.append(clean_token)

        self.validate_btn.setEnabled(False)
        self.execute_btn.setEnabled(False)
        self.prog_frame.show()
        self.prog_bar.setRange(0, len(clean_domains))
        self.prog_bar.setValue(0)

        self.preflight_worker = PreflightValidationWorker(
            raw_domains=clean_domains,
            target_url=norm_target,
            available_zones=self.zones,
            parent=self,
        )
        self.preflight_worker.progress.connect(self._on_preflight_progress)
        self.preflight_worker.finished.connect(self._on_preflight_finished)
        self.preflight_worker.error.connect(self._on_preflight_error)
        self.preflight_worker.start()

    def _on_preflight_progress(self, current: int, total: int, msg: str):
        self.prog_bar.setValue(current)
        self.prog_lbl.setText(f"[{current}/{total}] {msg}")

    def _on_preflight_finished(self, validated_items: List[Dict[str, Any]]):
        self.prog_frame.hide()
        self.validate_btn.setEnabled(True)
        self.validated_items = validated_items

        self.preview_table.setRowCount(len(validated_items))
        mono_font = QFont("Consolas", 9)

        valid_count = 0
        anomaly_count = 0
        detected_accounts = set()

        # Populate tab2_parsed_items for backward test compatibility
        self.tab2_parsed_items = []

        for row, item in enumerate(validated_items):
            domain = item["raw_domain"]
            public_ip = item.get("public_ip", "-")
            is_cf_ip = item.get("is_cf_ip", False)
            acc_label = item.get("account_label", "-")
            zone = item.get("zone")
            http_info = item.get("http_check", {})
            cf_info = item.get("cf_conflict", {})

            has_zone = zone is not None
            c_status = cf_info.get("status")

            if has_zone:
                valid_count += 1
                detected_accounts.add(acc_label)
            if c_status == "REDFLAG_ANOMALY":
                anomaly_count += 1

            self.tab2_parsed_items.append({
                "source": domain,
                "destination": item["target_url"],
                "status_code": 301,
                "valid": has_zone,
                "zone_id": zone.id if zone else None,
                "reason": "OK" if has_zone else "Zona tidak ditemukan di akun manapun",
            })

            # Col 0: Status
            if not has_zone:
                st_item = QTableWidgetItem("✕ No Account")
                st_item.setForeground(QColor("#EF4444"))
            elif c_status == "REDFLAG_ANOMALY":
                st_item = QTableWidgetItem("⚠️ Redflag")
                st_item.setForeground(QColor("#F87171"))
            elif c_status == "DUPLICATE":
                st_item = QTableWidgetItem("● Duplikat")
                st_item.setForeground(QColor("#FBBF24"))
            else:
                st_item = QTableWidgetItem("✓ Siap (CF)")
                st_item.setForeground(QColor("#34D399"))
            st_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.preview_table.setItem(row, 0, st_item)

            # Col 1: Domain
            d_item = QTableWidgetItem(domain)
            d_item.setFont(mono_font)
            d_item.setForeground(QColor("#F8FAFC"))
            self.preview_table.setItem(row, 1, d_item)

            # Col 2: Public IP (FlarePilot)
            ip_item = QTableWidgetItem(public_ip)
            ip_item.setFont(mono_font)
            if is_cf_ip:
                ip_item.setForeground(QColor("#34D399"))
                ip_item.setToolTip(f"{public_ip} (Cloudflare Proxy Aktif)")
            elif public_ip in ("Gagal Resolusi IP", "-"):
                ip_item.setForeground(QColor("#FBBF24"))
                ip_item.setToolTip("Tidak dapat meresolusi IP publik domain.")
            else:
                ip_item.setForeground(QColor("#38BDF8"))
                ip_item.setToolTip(f"{public_ip} (Origin / Direct IP)")
            self.preview_table.setItem(row, 2, ip_item)

            # Col 3: Detected Cloudflare Account
            acc_item = QTableWidgetItem(f"👤 {acc_label}" if has_zone else "✕ Tidak Ditemukan")
            acc_item.setForeground(QColor("#38BDF8" if has_zone else "#64748B"))
            self.preview_table.setItem(row, 3, acc_item)

            # Col 4: Live HTTP Status
            if http_info.get("has_redirect"):
                live_text = f"Redirect ({http_info.get('status_code')})"
                live_color = "#38BDF8"
            elif http_info.get("status_code"):
                live_text = f"HTTP {http_info.get('status_code')}"
                live_color = "#94A3B8"
            else:
                live_text = "Offline / Gagal"
                live_color = "#64748B"
            live_item = QTableWidgetItem(live_text)
            live_item.setForeground(QColor(live_color))
            live_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.preview_table.setItem(row, 4, live_item)

            # Col 5: Target Baru
            t_item = QTableWidgetItem(item["target_url"])
            t_item.setFont(mono_font)
            t_item.setForeground(QColor("#CBD5E1"))
            self.preview_table.setItem(row, 5, t_item)

            # Col 6: Status Cloudflare Conflict
            cf_text = cf_info.get("message", "-")
            cf_item = QTableWidgetItem(cf_text)
            cf_color = "#34D399" if c_status == "CLEAR" else ("#F87171" if c_status == "REDFLAG_ANOMALY" else "#FBBF24")
            cf_item.setForeground(QColor(cf_color))
            self.preview_table.setItem(row, 6, cf_item)

        acc_summary = f"{len(detected_accounts)} akun CF terdeteksi"
        summary_msg = f"Hasil: {valid_count} domain siap ({acc_summary})."
        if anomaly_count > 0:
            summary_msg += f" (⚠️ {anomaly_count} Redflag terdeteksi — akan dibersihkan otomatis)"
        self.val_summary_lbl.setText(summary_msg)
        self.val_summary_lbl.setStyleSheet("color: #38BDF8; font-weight: 600;")

        if valid_count > 0:
            self.execute_btn.setEnabled(True)

    def _on_preflight_error(self, err_msg: str):
        self.prog_frame.hide()
        self.validate_btn.setEnabled(True)
        QMessageBox.critical(self, "Gagal Validasi", f"Error saat validasi pre-flight:\n{err_msg}")

    def _execute_bulk_redirect(self):
        items_to_create = []
        accounts_involved = set()

        for item in self.validated_items:
            zone = item.get("zone")
            acc_id = item.get("account_id")
            if zone and acc_id:
                acc_label = item.get("account_label") or "Akun Cloudflare"
                accounts_involved.add(acc_label)
                items_to_create.append({
                    "zone_id": zone.id,
                    "account_id": acc_id,
                    "account_label": acc_label,
                    "source_hostname": item["raw_domain"],
                    "destination_url": item["target_url"],
                    "coverage": "both",
                    "status_code": 301,
                    "preserve_path": self.preserve_path_chk.isChecked(),
                    "preserve_query_string": False,
                    "enabled": True,
                })

        if not items_to_create:
            QMessageBox.warning(
                self,
                "Tidak Ada Domain Valid",
                "Tidak ada domain yang terhubung dengan akun Cloudflare aktif untuk dieksekusi."
            )
            return

        acc_list_str = "\n".join([f"• {a}" for a in accounts_involved])
        confirm = QMessageBox.question(
            self,
            "Konfirmasi Eksekusi Auto Multi-Account",
            f"Anda akan menerapkan aturan 301 Redirect ke {len(items_to_create)} domain.\n\n"
            f"Akun Cloudflare yang otomatis memproses:\n{acc_list_str}\n\n"
            "Aturan lama/anomali pada domain-domain ini akan otomatis dibersihkan dan digantikan dengan rule baru.\n\n"
            "Lanjutkan eksekusi?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        self.validate_btn.setEnabled(False)
        self.execute_btn.setEnabled(False)
        self.prog_frame.show()
        self.prog_bar.setRange(0, len(items_to_create))
        self.prog_bar.setValue(0)

        self.worker = BulkCreateRedirectsWorker(items_to_create, parent=self)
        self.worker.progress.connect(self._on_exec_progress)
        self.worker.finished.connect(self._on_exec_finished)
        self.worker.error.connect(self._on_exec_error)
        self.worker.start()

    def _on_exec_progress(self, current: int, total: int, msg: str):
        self.prog_bar.setValue(current)
        self.prog_lbl.setText(f"[{current}/{total}] {msg}")

    def _on_exec_finished(self, summary: Dict[str, Any]):
        self.prog_frame.hide()
        self.validate_btn.setEnabled(True)
        self.execute_btn.setEnabled(True)

        success = summary.get("success", 0)
        failed = summary.get("failed", 0)
        errors = summary.get("errors", [])
        self.last_applied = summary.get("applied", {})

        msg = f"Eksekusi Selesai!\n\n✓ Berhasil: {success} domain\n"
        if failed > 0:
            msg += f"✕ Gagal: {failed} domain\n\nDetail:\n" + "\n".join(errors[:5])

        QMessageBox.information(self, "Hasil Bulk Redirect", msg)
        self.bulk_completed.emit(success)
        self.accept()

    def _on_exec_error(self, err_msg: str):
        self.prog_frame.hide()
        self.validate_btn.setEnabled(True)
        self.execute_btn.setEnabled(True)
        QMessageBox.critical(self, "Gagal Eksekusi", f"Terjadi kesalahan saat eksekusi:\n{err_msg}")

    def _auto_format_tab2_text(self):
        target = self.target_url_input.text().strip() or "https://target.com/"
        raw_lines = [line.strip() for line in self.domain_text_area.toPlainText().splitlines() if line.strip()]
        formatted = []
        for line in raw_lines:
            clean = line.split("->")[0].split(",")[0].split()[0].strip()
            formatted.append(f"{clean} -> {target} 301")
        self.domain_text_area.setPlainText("\n".join(formatted))
        self._parse_tab2_text()

    def _parse_tab2_text(self):
        target = self.tab2_default_dest.text().strip() or "https://default.com/"
        raw_lines = [line.strip() for line in self.tab2_text.toPlainText().splitlines() if line.strip()]
        self.tab2_parsed_items = []
        for line in raw_lines:
            if line.startswith("#"):
                continue
            if "->" in line:
                parts = line.split("->")
                src = parts[0].strip()
                dst = parts[1].strip().split()[0]
            elif "," in line:
                parts = line.split(",")
                src = parts[0].strip()
                dst = parts[1].strip()
            else:
                src = line.strip()
                dst = target

            try:
                norm_src = clean_domain_input(src)
                matched_zone = find_matching_zone_for_raw(norm_src, self.zones)
                is_valid = matched_zone is not None and "." in norm_src
                reason = "OK" if is_valid else "Zona tidak ditemukan di akun"
            except Exception as exc:
                norm_src = src
                matched_zone = None
                is_valid = False
                reason = f"Domain tidak valid: {str(exc)}"

            self.tab2_parsed_items.append({
                "source": norm_src,
                "destination": dst,
                "status_code": 301,
                "valid": is_valid,
                "reason": reason,
            })
