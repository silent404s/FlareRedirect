"""Connect Cloudflare Page (Multi-Account Edition with Persistent Profiles).
Allows users to add multiple Cloudflare accounts (Token or Global API Key),
switch active accounts, and manage persistent profiles in local config.json.
"""

from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QFrame,
    QProgressBar,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QMessageBox,
    QScrollArea,
    QRadioButton,
    QButtonGroup,
    QCheckBox,
)
from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QFont
from src.security.session import active_session
from src.ui.workers import ConnectWorker
import src.config_manager as config_manager


class ConnectPage(QWidget):
    """Page for connecting and managing multiple Cloudflare accounts."""

    connection_changed = Signal(bool)  # is_connected
    show_toast = Signal(str, bool)     # message, is_error
    account_switched = Signal(str)     # account_id

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: ConnectWorker = None
        self._init_ui()

    def _init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent;")

        scroll_widget = QWidget()
        scroll_widget.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(scroll_widget)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(12)

        # Title & Subtitle
        header_layout = QVBoxLayout()
        header_title = QLabel("Koneksi Cloudflare API (Multi-Akun & Penyimpanan Kredensial)")
        header_title.setStyleSheet("font-size: 16px; font-weight: 700; color: #F8FAFC;")
        header_sub = QLabel(
            "Hubungkan dan simpan profil akun Cloudflare Anda secara otomatis. "
            "Kredensial disimpan di file lokal config.json dan dilindungi .gitignore sehingga tidak akan pernah ter-push ke GitHub."
        )
        header_sub.setWordWrap(True)
        header_sub.setStyleSheet("font-size: 11px; color: #94A3B8; margin-top: 2px;")
        header_layout.addWidget(header_title)
        header_layout.addWidget(header_sub)
        layout.addLayout(header_layout)

        # Add Account Form Card
        form_card = QFrame()
        form_card.setProperty("class", "card")
        form_layout = QVBoxLayout(form_card)
        form_layout.setContentsMargins(14, 12, 14, 12)
        form_layout.setSpacing(10)

        form_title = QLabel("➕ Tambah / Hubungkan Akun Cloudflare")
        form_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #F8FAFC;")
        form_layout.addWidget(form_title)

        # Auth Method Selector
        auth_row = QHBoxLayout()
        auth_row.setSpacing(16)
        auth_lbl = QLabel("Metode Autentikasi:")
        auth_lbl.setStyleSheet("font-weight: 600; color: #CBD5E1; font-size: 12px;")
        auth_row.addWidget(auth_lbl)

        self.auth_group = QButtonGroup(self)
        self.radio_token = QRadioButton("API Token (Rekomendasi)")
        self.radio_token.setChecked(True)
        self.radio_token.toggled.connect(self._toggle_auth_method)
        self.auth_group.addButton(self.radio_token)
        auth_row.addWidget(self.radio_token)

        self.radio_key = QRadioButton("Global API Key + Email")
        self.radio_key.toggled.connect(self._toggle_auth_method)
        self.auth_group.addButton(self.radio_key)
        auth_row.addWidget(self.radio_key)
        auth_row.addStretch()
        form_layout.addLayout(auth_row)

        inputs_row = QHBoxLayout()
        inputs_row.setSpacing(12)

        # Account Label / Alias
        lbl_vbox = QVBoxLayout()
        lbl_label = QLabel("Label / Nama Akun:")
        lbl_label.setStyleSheet("font-weight: 600; color: #E2E8F0; font-size: 12px;")
        self.label_input = QLineEdit()
        self.label_input.setPlaceholderText("Contoh: Akun Utama / Nagawin")
        lbl_vbox.addWidget(lbl_label)
        lbl_vbox.addWidget(self.label_input)
        inputs_row.addLayout(lbl_vbox, stretch=2)

        # Token Input Container
        self.token_container = QWidget()
        tok_vbox = QVBoxLayout(self.token_container)
        tok_vbox.setContentsMargins(0, 0, 0, 0)
        tok_label = QLabel("Cloudflare API Token:")
        tok_label.setStyleSheet("font-weight: 600; color: #E2E8F0; font-size: 12px;")

        tok_hbox = QHBoxLayout()
        self.token_input = QLineEdit()
        self.token_input.setPlaceholderText("Tempel token API di sini (contoh: v8x_abc...)")
        self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.token_input.returnPressed.connect(self.handle_connect)
        tok_hbox.addWidget(self.token_input)

        self.toggle_echo_btn = QPushButton("👁️ Show")
        self.toggle_echo_btn.setProperty("class", "btn-secondary")
        self.toggle_echo_btn.setStyleSheet("padding: 6px 12px;")
        self.toggle_echo_btn.clicked.connect(self.toggle_token_visibility)
        tok_hbox.addWidget(self.toggle_echo_btn)

        self.clear_btn = QPushButton("Clear")
        self.clear_btn.setProperty("class", "btn-secondary")
        self.clear_btn.setStyleSheet("padding: 6px 12px;")
        self.clear_btn.clicked.connect(self.clear_input_token)
        tok_hbox.addWidget(self.clear_btn)

        tok_vbox.addWidget(tok_label)
        tok_vbox.addLayout(tok_hbox)
        inputs_row.addWidget(self.token_container, stretch=4)

        # Global Key + Email Container (Initially Hidden)
        self.key_container = QWidget()
        self.key_container.hide()
        key_hbox = QHBoxLayout(self.key_container)
        key_hbox.setContentsMargins(0, 0, 0, 0)
        key_hbox.setSpacing(10)

        email_vbox = QVBoxLayout()
        email_lbl = QLabel("Email Cloudflare:")
        email_lbl.setStyleSheet("font-weight: 600; color: #E2E8F0; font-size: 12px;")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("email@domain.com")
        email_vbox.addWidget(email_lbl)
        email_vbox.addWidget(self.email_input)
        key_hbox.addLayout(email_vbox, stretch=2)

        gkey_vbox = QVBoxLayout()
        gkey_lbl = QLabel("Global API Key:")
        gkey_lbl.setStyleSheet("font-weight: 600; color: #E2E8F0; font-size: 12px;")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Global API Key Cloudflare")
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.returnPressed.connect(self.handle_connect)
        gkey_vbox.addWidget(gkey_lbl)
        gkey_vbox.addWidget(self.key_input)
        key_hbox.addLayout(gkey_vbox, stretch=2)

        inputs_row.addWidget(self.key_container, stretch=4)
        form_layout.addLayout(inputs_row)

        # Options & Connect button row
        bottom_form_row = QHBoxLayout()
        self.save_local_chk = QCheckBox("💾 Simpan ke config.json agar otomatis aktif setiap membuka aplikasi")
        self.save_local_chk.setChecked(True)
        self.save_local_chk.setStyleSheet("color: #38BDF8; font-weight: 500; font-size: 12px;")
        bottom_form_row.addWidget(self.save_local_chk)
        bottom_form_row.addStretch()

        self.connect_btn = QPushButton("🔗 Hubungkan & Simpan Akun")
        self.connect_btn.setProperty("class", "btn-primary")
        self.connect_btn.setMinimumHeight(38)
        self.connect_btn.clicked.connect(self.handle_connect)
        bottom_form_row.addWidget(self.connect_btn)

        form_layout.addLayout(bottom_form_row)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.hide()
        form_layout.addWidget(self.progress_bar)

        layout.addWidget(form_card)

        # Connected Accounts List Card
        list_card = QFrame()
        list_card.setProperty("class", "card")
        list_layout = QVBoxLayout(list_card)
        list_layout.setContentsMargins(20, 18, 20, 18)
        list_layout.setSpacing(12)

        top_list_row = QHBoxLayout()
        list_title = QLabel("📋 Daftar Akun Cloudflare Terhubung & Tersimpan")
        list_title.setStyleSheet("font-size: 15px; font-weight: 700; color: #F8FAFC;")
        top_list_row.addWidget(list_title)
        top_list_row.addStretch()

        self.disconnect_all_btn = QPushButton("⚠️ Putuskan Semua Akun")
        self.disconnect_all_btn.setProperty("class", "btn-danger")
        self.disconnect_all_btn.setStyleSheet("padding: 6px 14px; font-size: 12px;")
        self.disconnect_all_btn.clicked.connect(self.handle_disconnect_all)
        top_list_row.addWidget(self.disconnect_all_btn)

        list_layout.addLayout(top_list_row)

        self.account_table = QTableWidget()
        self.account_table.setColumnCount(6)
        self.account_table.setHorizontalHeaderLabels([
            "Nama / Label Akun", "Metode Auth", "Status", "Total Domain", "Waktu Terhubung", "Aksi"
        ])
        acc_header = self.account_table.horizontalHeader()
        acc_header.setMinimumSectionSize(60)
        acc_header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        acc_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        acc_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        acc_header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
        acc_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        acc_header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.account_table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.account_table.setAlternatingRowColors(True)
        self.account_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.account_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        list_layout.addWidget(self.account_table)

        layout.addWidget(list_card)

        # Security & Privacy Shield Box
        guide_frame = QFrame()
        guide_frame.setProperty("class", "card")
        guide_layout = QVBoxLayout(guide_frame)
        guide_layout.setContentsMargins(14, 10, 14, 10)
        guide_layout.setSpacing(6)

        guide_title = QLabel("🛡️ Jaminan Keamanan & Git Privacy Shield")
        guide_title.setStyleSheet("font-size: 12px; font-weight: 700; color: #10B981;")
        guide_layout.addWidget(guide_title)

        guide_text = QLabel(
            "&bull; <b>Zero-Leak GitHub:</b> File konfigurasi <code>config.json</code> terdaftar di <code>.gitignore</code> sehingga kredensial Anda tidak akan terkirim saat push ke repository publik.<br>"
            "&bull; <b>Multi-Akun Otomatis:</b> Semua akun yang tersimpan di sini akan otomatis dimuat saat aplikasi dijalankan kembali. Bulk Redirect akan otomatis mendeteksi dan menggunakan token yang sesuai tanpa switch manual."
        )
        guide_text.setTextFormat(Qt.TextFormat.RichText)
        guide_text.setStyleSheet("color: #CBD5E1; font-size: 11px;")
        guide_layout.addWidget(guide_text)

        layout.addWidget(guide_frame)

        scroll.setWidget(scroll_widget)
        root_layout.addWidget(scroll)

        self.refresh_account_table()

    def _toggle_auth_method(self):
        is_token = self.radio_token.isChecked()
        self.token_container.setVisible(is_token)
        self.key_container.setVisible(not is_token)

    def toggle_token_visibility(self):
        if self.token_input.echoMode() == QLineEdit.EchoMode.Password:
            self.token_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_echo_btn.setText("🔒 Hide")
        else:
            self.token_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_echo_btn.setText("👁️ Show")

    def clear_input_token(self):
        self.token_input.clear()
        self.email_input.clear()
        self.key_input.clear()
        self.label_input.clear()

    def handle_connect(self):
        is_token = self.radio_token.isChecked()
        auth_method = "token" if is_token else "key"
        token = self.token_input.text().strip() if is_token else ""
        global_key = self.key_input.text().strip() if not is_token else ""
        email = self.email_input.text().strip() if not is_token else ""
        label = self.label_input.text().strip()

        if is_token and not token:
            self.show_toast.emit("Silakan masukkan Cloudflare API Token terlebih dahulu.", True)
            return
        if not is_token and (not global_key or not email):
            self.show_toast.emit("Silakan lengkapi Email dan Global API Key terlebih dahulu.", True)
            return

        self.connect_btn.setEnabled(False)
        self.progress_bar.show()

        self.worker = ConnectWorker(
            token=token,
            label=label,
            auth_method=auth_method,
            global_api_key=global_key,
            email=email,
            parent=self,
        )
        self.worker.finished.connect(self._on_connect_success)
        self.worker.error.connect(self._on_connect_error)
        self.worker.start()

    def _on_connect_success(self, result: dict):
        self.progress_bar.hide()
        self.connect_btn.setEnabled(True)

        final_label = result.get("label", "")
        auth_method = result.get("auth_method", "token")
        tok = result.get("token", "")
        gkey = result.get("global_api_key", "")
        em = result.get("email", "")

        # Persist to local config.json if checked
        if self.save_local_chk.isChecked() and final_label:
            profile_payload = {
                "auth_method": auth_method,
                "api_token": tok,
                "global_api_key": gkey,
                "email": em,
            }
            config_manager.save_profile(final_label, profile_payload, set_as_current=True)

        # Update domain cache with newly discovered zones from this account
        new_zones = result.get("zones", [])
        if new_zones:
            cached_data = config_manager.load_cached_domains()
            existing_zones = cached_data.get("zones", [])
            existing_ids = {z.get("id") if isinstance(z, dict) else getattr(z, "id", "") for z in existing_zones}
            for nz in new_zones:
                nz_id = nz.get("id") if isinstance(nz, dict) else getattr(nz, "id", "")
                if nz_id not in existing_ids:
                    existing_zones.append(nz)
            config_manager.save_cached_domains(existing_zones, cached_data.get("targets", {}))

        self.clear_input_token()
        self.show_toast.emit(result.get("message", "Akun berhasil terhubung!"), False)
        self.refresh_account_table()
        self.connection_changed.emit(True)

    def _on_connect_error(self, err_msg: str):
        self.progress_bar.hide()
        self.connect_btn.setEnabled(True)
        self.show_toast.emit(f"Koneksi akun gagal: {err_msg}", True)

    def refresh_account_table(self):
        accounts = active_session.get_all_accounts()
        self.account_table.setRowCount(len(accounts))
        active_id = active_session.active_id

        self.disconnect_all_btn.setEnabled(len(accounts) > 0)
        mono_font = QFont("Consolas", 9)
        self.account_table.verticalHeader().setDefaultSectionSize(30)

        for row, acc in enumerate(accounts):
            is_active = (acc.account_id == active_id)

            # 0. Label
            lbl_item = QTableWidgetItem(f"★ {acc.label} (Aktif)" if is_active else acc.label)
            lbl_item.setForeground(QColor("#38BDF8" if is_active else "#F8FAFC"))
            self.account_table.setItem(row, 0, lbl_item)

            # 1. Auth Method
            method_str = "🔑 Global Key" if acc.auth_method == "key" else "🛡️ API Token"
            method_item = QTableWidgetItem(method_str)
            method_item.setForeground(QColor("#F59E0B" if acc.auth_method == "key" else "#10B981"))
            method_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.account_table.setItem(row, 1, method_item)

            # 2. Status
            status_item = QTableWidgetItem("● Aktif" if is_active else "○ Siaga")
            status_item.setForeground(QColor("#34D399" if is_active else "#94A3B8"))
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.account_table.setItem(row, 2, status_item)

            # 3. Domain count
            dom_item = QTableWidgetItem(f"{len(acc.zones)} Domain")
            dom_item.setForeground(QColor("#CBD5E1"))
            dom_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.account_table.setItem(row, 3, dom_item)

            # 4. Connected At
            time_item = QTableWidgetItem(acc.connected_at)
            time_item.setFont(mono_font)
            time_item.setForeground(QColor("#94A3B8"))
            self.account_table.setItem(row, 4, time_item)

            # 5. Action Buttons
            action_widget = QWidget()
            action_layout = QHBoxLayout(action_widget)
            action_layout.setContentsMargins(2, 2, 2, 2)
            action_layout.setSpacing(6)

            if not is_active:
                switch_btn = QPushButton("Gunakan Akun Ini")
                switch_btn.setProperty("class", "btn-action-edit")
                switch_btn.setStyleSheet("padding: 2px 8px; font-size: 11px;")
                switch_btn.clicked.connect(lambda checked=False, aid=acc.account_id, albl=acc.label: self._switch_to_account(aid, albl))
                action_layout.addWidget(switch_btn)

            rm_btn = QPushButton("Putuskan")
            rm_btn.setProperty("class", "btn-action-delete")
            rm_btn.setStyleSheet("padding: 2px 8px; font-size: 11px;")
            rm_btn.clicked.connect(lambda checked=False, aid=acc.account_id, albl=acc.label: self._remove_account(aid, albl))
            action_layout.addWidget(rm_btn)

            self.account_table.setCellWidget(row, 5, action_widget)

    def _switch_to_account(self, account_id: str, label: str):
        active_session.switch_account(account_id)
        config_manager.set_current_profile(label)
        self.refresh_account_table()
        self.show_toast.emit(f"Beralih ke akun: {label}", False)
        self.account_switched.emit(account_id)
        self.connection_changed.emit(True)

    def _remove_account(self, account_id: str, label: str):
        reply = QMessageBox.question(
            self,
            "Putuskan Akun",
            f"Apakah Anda yakin ingin memutuskan akun '{label}'?\n\n"
            "Kredensial akan dibersihkan dari RAM dan dihapus dari penyimpanan lokal config.json.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            active_session.remove_account(account_id)
            config_manager.delete_profile(label)
            self.refresh_account_table()
            is_conn = active_session.is_connected
            self.show_toast.emit(f"Akun '{label}' telah diputuskan dan dihapus dari config.", False)
            self.connection_changed.emit(is_conn)

    def handle_disconnect_all(self):
        reply = QMessageBox.question(
            self,
            "Putuskan Semua Akun",
            "Apakah Anda yakin ingin memutuskan seluruh akun Cloudflare?\n"
            "Semua profil di RAM dan penyimpanan lokal (config.json) akan dibersihkan.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            active_session.disconnect_all()
            config_manager.clear_all_profiles()
            self.refresh_account_table()
            self.show_toast.emit("Seluruh akun telah diputuskan dan konfigurasi lokal dibersihkan.", False)
            self.connection_changed.emit(False)
