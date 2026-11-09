"""Test for UI MainWindow instantiation and theme toggling.
Uses PySide6 QTest or headless offscreen platform.
"""

import os
import pytest
from PySide6.QtWidgets import QApplication
from src.ui.main_window import MainWindow


@pytest.fixture(scope="session")
def qapp():
    # Set offscreen platform for headless CI / testing environments
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def test_main_window_instantiation(qapp, monkeypatch):
    monkeypatch.setattr("src.config_manager.load_config", lambda: {})
    monkeypatch.setattr("src.config_manager.load_cached_domains", lambda: {"zones": [], "targets": {}})
    window = MainWindow()
    assert "FlareRedirect" in window.windowTitle()
    assert window.stack.count() == 6

    # Test page switching
    window.switch_page("domains")
    assert window.stack.currentIndex() == 1

    window.switch_page("redirects")
    assert window.stack.currentIndex() == 2

    # Test theme toggle
    initial_theme = window.is_dark_theme
    window.toggle_theme()
    assert window.is_dark_theme != initial_theme
    window.toggle_theme()
    window.close()


def test_redirect_page_safe_zone_info_when_empty(qapp):
    from src.ui.redirect_page import RedirectPage

    page = RedirectPage()
    # When no zone is set
    zid, zname = page._get_current_zone_info()
    assert zid is None
    assert zname == ""

    # Ensure opening dialogs does not throw IndexError
    toast_messages = []
    page.show_toast.connect(lambda msg, err: toast_messages.append((msg, err)))

    page._open_add_dialog()
    assert len(toast_messages) == 1
    assert "Pilih zona" in toast_messages[0][0]

    page._open_delete_all_dialog()
    assert len(toast_messages) == 2
    assert "Pilih zona" in toast_messages[1][0]


def test_redirect_page_list_selection(qapp):
    from src.ui.redirect_page import RedirectPage
    from src.cloudflare.redirects import RedirectRule

    page = RedirectPage()
    # Add dummy rules
    rules = [
        RedirectRule(
            {
                "id": "rule_1",
                "enabled": True,
                "expression": 'http.host eq "example.com"',
                "action_parameters": {
                    "from_value": {
                        "status_code": 301,
                        "preserve_query_string": True,
                        "target_url": {"value": "https://target.com"},
                    }
                },
            },
            zone_id="zone_1",
            ruleset_id="rs_1",
        ),
        RedirectRule(
            {
                "id": "rule_2",
                "enabled": False,
                "expression": 'true',
                "action_parameters": {
                    "from_value": {
                        "status_code": 302,
                        "preserve_query_string": False,
                        "target_url": {"value": "https://target2.com"},
                    }
                },
            },
            zone_id="zone_1",
            ruleset_id="rs_1",
        ),
    ]

    page._on_redirects_loaded("rs_1", rules)
    assert page.table.rowCount() == 2

    # Test Select All in list
    page._toggle_select_all_clicked()
    selected = page._get_selected_rules()
    assert len(selected) == 2

    # Test Deselect All in list
    page._deselect_all()
    selected = page._get_selected_rules()
    assert len(selected) == 0


def test_connect_page_multi_account_persistence(qapp, tmp_path, monkeypatch):
    import src.config_manager as cm
    from src.ui.connect_page import ConnectPage
    from src.security.session import active_session

    fake_config = tmp_path / "connect_test_config.json"
    monkeypatch.setattr(cm, "get_config_path", lambda: fake_config)

    active_session.disconnect_all()
    page = ConnectPage()

    # Simulate successfully connecting 5 distinct accounts
    for i in range(1, 6):
        res = {
            "status": "active",
            "zones": [],
            "account_id": f"acc_{i}",
            "label": f"Akun Cloudflare #{i}",
            "auth_method": "token",
            "token": f"token_secret_{i}",
            "global_api_key": "",
            "email": "",
            "message": f"Akun Akun Cloudflare #{i} berhasil terhubung",
        }
        # Add to session as ConnectWorker does
        active_session.add_account(label=res["label"], token=res["token"])
        page._on_connect_success(res)

    # 1. Verify in-memory session has 5 accounts
    assert active_session.account_count == 5
    # 2. Verify UI table has 5 rows
    assert page.account_table.rowCount() == 5
    # 3. Verify config.json has all 5 profiles saved
    profiles = cm.get_profiles()
    assert len(profiles) == 5
    for i in range(1, 6):
        assert f"Akun Cloudflare #{i}" in profiles
        assert profiles[f"Akun Cloudflare #{i}"]["api_token"] == f"token_secret_{i}"

    # 4. Simulate app restart: clear RAM
    active_session.disconnect_all()
    assert active_session.account_count == 0

    # Rehydrate from config.json
    for name, prof in cm.get_profiles().items():
        active_session.add_account(label=name, token=prof["api_token"])

    assert active_session.account_count == 5
    page.refresh_account_table()
    assert page.account_table.rowCount() == 5

    # 5. Remove 1 account and verify 4 remain in config
    acc_to_remove = active_session.get_all_accounts()[0]
    active_session.remove_account(acc_to_remove.account_id)
    cm.delete_profile(acc_to_remove.label)
    assert active_session.account_count == 4
    assert len(cm.get_profiles()) == 4
    assert acc_to_remove.label not in cm.get_profiles()
    active_session.disconnect_all()


def test_redirect_page_no_startup_eager_fetch_and_unconnected_account(qapp):
    from src.ui.redirect_page import RedirectPage
    from src.cloudflare.zones import ZoneItem
    from src.security.session import active_session

    active_session.disconnect_all()
    page = RedirectPage()

    z1 = ZoneItem({"id": "z_naga", "name": "naga-domain.com", "status": "active"}, account_label="NAGA")
    z2 = ZoneItem({"id": "z_indra", "name": "indra-domain.com", "status": "active"}, account_label="Indra")

    # 1. set_zones does NOT eagerly launch background worker on startup
    page.set_zones([z1, z2])
    assert page.zone_combo.count() == 2
    assert not page.progress_bar.isVisible()

    # 2. When zone belongs to unconnected account (NAGA is not in active_session)
    toast_errors = []
    page.show_toast.connect(lambda msg, err: toast_errors.append((msg, err)))
    page.load_redirects_for_selected_zone()

    # Must show friendly notice instead of making failing 403 API call
    assert not page.progress_bar.isVisible()
    assert "NAGA" in page.empty_lbl.text()
    assert "belum terhubung" in page.empty_lbl.text()
    assert len(toast_errors) == 0  # No 403 error toast popped up!


def test_domain_page_live_redirect_filter_and_alert(qapp):
    from src.ui.domain_page import DomainPage
    from src.cloudflare.zones import ZoneItem

    page = DomainPage()
    z1 = ZoneItem({"id": "z1", "name": "single-redir.com", "status": "active"}, account_label="Indra")
    z2 = ZoneItem({"id": "z2", "name": "multi-redir.com", "status": "active"}, account_label="Indra")
    z3 = ZoneItem({"id": "z3", "name": "direct-site.com", "status": "active"}, account_label="Indra")

    page.all_zones = [z1, z2, z3]
    page.redirect_checks_cache = {
        "single-redir.com": {
            "status_code": 301,
            "target_url": "https://target1.com",
            "hops": 1,
            "is_multiple": False,
            "has_redirect": True,
            "chain": ["https://target1.com"],
        },
        "multi-redir.com": {
            "status_code": 302,
            "target_url": "https://final2.com",
            "hops": 2,
            "is_multiple": True,
            "has_redirect": True,
            "chain": ["https://hop1.com", "https://final2.com"],
        },
        "direct-site.com": {
            "status_code": 200,
            "target_url": "",
            "hops": 0,
            "is_multiple": False,
            "has_redirect": False,
            "chain": [],
        },
    }

    # 1. Filter: All
    page._filter_table()
    assert page.table.rowCount() == 3

    # 2. Filter: Multiple (>1x)
    idx_mult = page.redirect_filter_combo.findData("multiple")
    page.redirect_filter_combo.setCurrentIndex(idx_mult)
    assert page.table.rowCount() == 1
    assert page.table.item(0, 1).text() == "multi-redir.com"
    target_text = page.table.item(0, 4).text()
    assert "⚠️" in target_text
    assert "2x" in target_text

    # 3. Filter: Single (1x)
    idx_single = page.redirect_filter_combo.findData("single")
    page.redirect_filter_combo.setCurrentIndex(idx_single)
    assert page.table.rowCount() == 1
    assert page.table.item(0, 1).text() == "single-redir.com"
    assert "✅" in page.table.item(0, 4).text()

    # 4. Filter: None (200 OK)
    idx_none = page.redirect_filter_combo.findData("none")
    page.redirect_filter_combo.setCurrentIndex(idx_none)
    assert page.table.rowCount() == 1
    assert page.table.item(0, 1).text() == "direct-site.com"
    assert "○" in page.table.item(0, 4).text()




