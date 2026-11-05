"""Single Redirect Dialog for FlareRedirect.
Compact, focused modal dialog for creating or updating a 301 redirect on a single domain.
"""

from typing import Optional, Dict, Any
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QCheckBox,
    QFrame,
    QProgressBar,
    QMessageBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QColor

from src.cloudflare.zones import ZoneItem
from src.security.validation import validate_destination_url
from src.ui.workers import CreateRedirectWorker, SinglePreflightWorker


class SingleRedirectDialog(QDialog):
    """Modal dialog for setting up 301 redirect for a single zone."""

    redirect_saved = Signal(dict)

    def __init__(self, zone: ZoneItem, current_target: str = "", parent=None):
        super().__init__(parent)
        self.zone = zone
        self.current_target = current_target
        self.create_worker: Optional[CreateRedirectWorker] = None
        self.preflight_worker: Optional[SinglePreflightWorker] = None

        self.setWindowTitle(f"⚡ Setup 301 Redirect — {zone.name}")
        self.resize(520, 380)
        self.setMinimumSize(480, 340)
        self.setStyleSheet("""
            QDialog {
                background-color: #0F172A;
                border: 1px solid #1E293B;
                border-radius: 10px;
            }
        """)
        self._init_ui()
        self._run_initial_preflight()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(12)

        # Header Info Card
        header_card = QFrame()
        header_card.setStyleSheet("background-color: #090D16; border: 1px solid #1E293B; border-radius: 8px; padding: 10px;")
        h_layout = QVBoxLayout(header_card)
        h_layout.setSpacing(4)

        row1 = QHBoxLayout()
        d_lbl = QLabel(f"🌐 <b>{self.zone.name}</b>")
        d_lbl.setStyleSheet("font-size: 14px; color: #F8FAFC;")
        row1.addWidget(d_lbl)
        row1.addStretch()

        acc_badge = QLabel(f"👤 {self.zone.account_label}")
        acc_badge.setStyleSheet("color: #38BDF8; font-size: 11px; background: #032742; padding: 2px 8px; border-radius: 6px;")
        row1.addWidget(acc_badge)
        h_layout.addLayout(row1)

        rule_std_lbl = QLabel("Mode: <b>ALL INCOMING 301</b> (Query String dimatikan otomatis)")
        rule_std_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        h_layout.addWidget(rule_std_lbl)

        layout.addWidget(header_card)

        # Target URL Input Form
        form_frame = QFrame()
        form_frame.setStyleSheet("background-color: #090D16; border: 1px solid #1E293B; border-radius: 8px; padding: 12px;")
        form_layout = QVBoxLayout(form_frame)
        form_layout.setSpacing(8)

        t_lbl = QLabel("🎯 URL Tujuan Redirect:")
        t_lbl.setStyleSheet("color: #38BDF8; font-weight: 700; font-size: 12px;")
        form_layout.addWidget(t_lbl)

        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://linkrtpgacor77.com/habanero.html")
        self.target_input.setText(self.current_target)
        self.target_input.setStyleSheet("""
            QLineEdit {
                background-color: #050811;
                border: 1px solid #38BDF8;
                border-radius: 6px;
                padding: 8px 10px;
                color: #F8FAFC;
                font-size: 13px;
            }
            QLineEdit:focus {
                border: 1px solid #00F0FF;
            }
        """)
        self.target_input.textChanged.connect(self._on_target_changed)
        form_layout.addWidget(self.target_input)

        # Options
        self.preserve_path_chk = QCheckBox("Preserve Sub-Path (Jangan centang jika target file spesifik /habanero.html)")
        self.preserve_path_chk.setChecked(False)
        self.preserve_path_chk.setStyleSheet("color: #94A3B8; font-size: 11px;")
        form_layout.addWidget(self.preserve_path_chk)

        layout.addWidget(form_frame)

        # Pre-flight Live & Conflict Status Card
        self.status_box = QFrame()
        self.status_box.setStyleSheet("background-color: #050811; border: 1px dashed #334155; border-radius: 6px; padding: 8px;")
        sb_layout = QVBoxLayout(self.status_box)
        sb_layout.setSpacing(4)

        self.status_lbl = QLabel("🔍 Memeriksa status live domain & konflik Cloudflare...")
        self.status_lbl.setStyleSheet("color: #94A3B8; font-size: 11px;")
        sb_layout.addWidget(self.status_lbl)

        layout.addWidget(self.status_box)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Bottom Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.cancel_btn = QPushButton("Batal")
        self.cancel_btn.setProperty("class", "btn-secondary")
        self.cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(self.cancel_btn)

        btn_layout.addStretch()

        self.submit_btn = QPushButton("🚀 Terapkan Redirect 301")
        self.submit_btn.setProperty("class", "btn-primary")
        self.submit_btn.setStyleSheet("padding: 8px 18px; font-weight: 700; font-size: 12px;")
        self.submit_btn.clicked.connect(self._on_submit)
        btn_layout.addWidget(self.submit_btn)

        layout.addLayout(btn_layout)

    def _run_initial_preflight(self):
        target = self.target_input.text().strip()
        self.status_lbl.setText("🔍 Memeriksa status live domain & aturan Cloudflare...")
        self.preflight_worker = SinglePreflightWorker(
            domain=self.zone.name,
            zone_id=self.zone.id,
            target_url=target if target else "https://placeholder.invalid",
            account_id=self.zone.account_id,
            parent=self,
        )
        self.preflight_worker.finished.connect(self._on_preflight_finished)
        self.preflight_worker.start()

    def _on_target_changed(self):
        pass

    def _on_preflight_finished(self, data: Dict[str, Any]):
        http_info = data.get("http_check", {})
        cf_info = data.get("cf_conflict")

        status_lines = []
        if http_info.get("has_redirect"):
            loc = http_info.get("location", "-")
            status_lines.append(f"• <b>Live Server:</b> Sudah redirect ({http_info.get('status_code')}) ke <code>{loc}</code>")
        else:
            status_lines.append("• <b>Live Server:</b> Tidak ada redirect aktif di level web server (Aman).")

        if cf_info:
            c_status = cf_info.get("status")
            if c_status == "REDFLAG_ANOMALY":
                status_lines.append(f"• <b>Cloudflare Rules:</b> <span style='color: #EF4444; font-weight:700;'>⚠️ REDFLAG: Ditemukan {cf_info.get('count')} rules ganda!</span> Akan dibersihkan otomatis saat eksekusi.")
            elif c_status == "DUPLICATE":
                status_lines.append(f"• <b>Cloudflare Rules:</b> <span style='color: #FBBF24;'>Aturan dengan target identik sudah aktif.</span>")
            elif c_status == "OVERWRITE":
                status_lines.append(f"• <b>Cloudflare Rules:</b> Ada 1 aturan lama (akan diperbarui ke target baru).")
            elif c_status == "CLEAR":
                status_lines.append("• <b>Cloudflare Rules:</b> <span style='color: #34D399;'>Zona bersih, siap pasang rule baru.</span>")

        self.status_lbl.setText("<br>".join(status_lines))

    def _on_submit(self):
        target = self.target_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Input Kosong", "Silakan masukkan URL tujuan redirect terlebih dahulu.")
            return

        try:
            norm_target, _ = validate_destination_url(target, source_host=self.zone.name)
        except Exception as exc:
            QMessageBox.critical(self, "URL Tidak Valid", str(exc))
            return

        self.submit_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.show()

        self.create_worker = CreateRedirectWorker(
            zone_id=self.zone.id,
            source_hostname=self.zone.name,
            destination_url=norm_target,
            coverage="both",
            status_code=301,
            preserve_path=self.preserve_path_chk.isChecked(),
            preserve_query_string=False,
            account_id=self.zone.account_id,
            parent=self,
        )
        self.create_worker.finished.connect(self._on_create_finished)
        self.create_worker.error.connect(self._on_create_error)
        self.create_worker.start()

    def _on_create_finished(self, res: Dict[str, Any]):
        self.progress_bar.hide()
        self.submit_btn.setEnabled(True)
        self.cancel_btn.setEnabled(True)

        msg = "Aturan 301 Redirect berhasil diterapkan ke Cloudflare!"
        if res.get("status") == "DUPLICATE_SKIPPED":
            msg = "Rule sudah aktif dengan target yang sama (Duplikasi dicegah)."
        elif res.get("soft_fail"):
            msg = f"Rule berhasil aktif di Cloudflare! ({res.get('message')})"

        QMessageBox.information(self, "Berhasil", msg)
        self.redirect_saved.emit({
            "zone_id": self.zone.id,
            "destination_url": self.target_input.text().strip(),
        })
        self.accept()

    def _on_create_error(self, err_msg: str):
        self.progress_bar.hide()
        self.submit_btn.setEnabled(True)
        self.cancel_btn.setEnabled(True)
        QMessageBox.critical(self, "Gagal Menerapkan Redirect", f"Terjadi kesalahan:\n\n{err_msg}")

