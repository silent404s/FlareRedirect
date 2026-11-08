"""Unit tests for in-memory multi-account session token lifecycle and audit logging.
"""

import pytest
from src.security.session import MultiAccountSessionManager
from src.utils.audit import SessionAuditLog


def test_multi_account_lifecycle():
    manager = MultiAccountSessionManager()
    assert not manager.is_connected
    assert manager.account_count == 0

    # Add Account 1
    acc1_id = manager.add_account("Akun Pribadi", "token_account_1_abcdef")
    assert manager.is_connected
    assert manager.account_count == 1
    assert manager.active_id == acc1_id
    assert manager.get_token() == "token_account_1_abcdef"

    # Add Account 2
    acc2_id = manager.add_account("Akun Bisnis", "token_account_2_123456")
    assert manager.account_count == 2
    # Active is still acc1 until switched
    assert manager.active_id == acc1_id

    # Switch to Account 2
    manager.switch_account(acc2_id)
    assert manager.active_id == acc2_id
    assert manager.get_token() == "token_account_2_123456"

    # Check token_for specific account
    assert manager.get_token_for(acc1_id) == "token_account_1_abcdef"
    assert manager.get_token_for(acc2_id) == "token_account_2_123456"

    # Remove single account
    manager.remove_account(acc2_id)
    assert manager.account_count == 1
    assert manager.active_id == acc1_id
    assert manager.get_token() == "token_account_1_abcdef"

    # Disconnect all & zero memory
    manager.disconnect_all()
    assert not manager.is_connected
    assert manager.account_count == 0
    assert manager.get_token() is None


def test_session_empty_token_rejection():
    manager = MultiAccountSessionManager()
    with pytest.raises(ValueError):
        manager.add_account("Test", "   ")


def test_session_audit_log_clean():
    audit = SessionAuditLog()
    audit.record("CREATE_REDIRECT", "example.com", "SUCCESS", "Created rule for test")
    entries = audit.get_entries()
    assert len(entries) == 1
    assert entries[0].target == "example.com"
    assert entries[0].status == "SUCCESS"

    # Ensure sensitive Bearer headers are masked if passed
    audit.record("API_CALL", "example.com", "FAILED", "Error with Bearer 1234567890abcdef1234567890abcdef")
    entries = audit.get_entries()
    assert len(entries) == 2
    assert "Bearer [REDACTED]" in entries[1].details

    csv_data = audit.export_csv()
    assert "CREATE_REDIRECT" in csv_data

    json_data = audit.export_json()
    assert "example.com" in json_data


def test_session_cleanup_on_exit():
    manager = MultiAccountSessionManager()
    manager.add_account("Akun Exit", "temporary_session_token_123")
    assert manager.is_connected
    # Simulate app exit
    manager.disconnect()
    assert not manager.is_connected
    assert manager.get_token() is None


def test_session_global_api_key_auth():
    manager = MultiAccountSessionManager()
    aid = manager.add_account(
        label="Akun Global Key",
        auth_method="key",
        global_api_key="my_global_key_abc123",
        email="admin@example.com",
    )
    assert manager.is_connected
    headers = manager.get_auth_headers_for(aid)
    assert headers["X-Auth-Key"] == "my_global_key_abc123"
    assert headers["X-Auth-Email"] == "admin@example.com"


def test_multi_account_unique_labels_and_get_account():
    manager = MultiAccountSessionManager()

    # Empty labels get unique auto-generated names
    id1 = manager.add_account("", "token1")
    id2 = manager.add_account("", "token2")
    acc1 = manager.get_account(id1)
    acc2 = manager.get_account(id2)
    assert acc1 is not None and acc1.label == "Akun CF #1"
    assert acc2 is not None and acc2.label == "Akun CF #2"

    # Duplicate explicit labels get unique auto-suffixed names
    id3 = manager.add_account("Indra", "token3")
    id4 = manager.add_account("Indra", "token4")
    acc3 = manager.get_account(id3)
    acc4 = manager.get_account(id4)
    assert acc3 is not None and acc3.label == "Indra"
    assert acc4 is not None and acc4.label == "Indra (2)"


def test_multi_account_save_and_rehydrate_five_accounts(tmp_path, monkeypatch):
    import src.config_manager as cm

    fake_config = tmp_path / "multi_acc_config.json"
    monkeypatch.setattr(cm, "get_config_path", lambda: fake_config)

    # Simulate connecting 5 accounts sequentially
    tokens = [f"token_test_{i}" for i in range(1, 6)]
    labels = ["Akun Utama", "Akun Kedua", "Akun Ketiga", "Akun Keempat", "Akun Kelima"]

    manager1 = MultiAccountSessionManager()
    for lbl, tok in zip(labels, tokens):
        aid = manager1.add_account(lbl, tok)
        # Ensure we can switch to each newly connected account and get its real label
        manager1.switch_account(aid)
        acc_obj = manager1.get_account(aid)
        assert acc_obj is not None
        assert acc_obj.label == lbl

        # Save to persistent config
        cm.save_profile(acc_obj.label, {"auth_method": "token", "api_token": tok, "global_api_key": "", "email": ""})

    # Verify config.json contains ALL 5 profiles (none overwritten!)
    saved_profiles = cm.get_profiles()
    assert len(saved_profiles) == 5
    for lbl in labels:
        assert lbl in saved_profiles

    # Simulate application restart: rehydrate accounts from config.json
    manager2 = MultiAccountSessionManager()
    for name, prof in saved_profiles.items():
        manager2.add_account(label=name, token=prof["api_token"], auth_method=prof["auth_method"])

    assert manager2.account_count == 5
    loaded_labels = {a.label for a in manager2.get_all_accounts()}
    assert loaded_labels == set(labels)


