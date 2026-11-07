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

