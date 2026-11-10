"""Unit tests for centralized configuration management.
"""

from pathlib import Path
from src.config import Settings


def test_settings_defaults():
    s = Settings()
    assert s.APP_NAME == "FlareRedirect"
    assert s.APP_VERSION == "1.4.1"
    assert s.APP_ENV in ("production", "development", "testing")
    assert s.CLOUDFLARE_API_BASE_URL == "https://api.cloudflare.com/client/v4"
    assert s.TIMEOUT_CONNECT == 10.0
    assert s.TIMEOUT_READ == 25.0
    assert s.ZONES_PER_PAGE == 50
    assert s.MAX_AUDIT_LOG_ENTRIES == 2000


def test_env_example_file_exists():
    root = Path(__file__).resolve().parent.parent
    env_example = root / ".env.example"
    assert env_example.is_file()
    content = env_example.read_text(encoding="utf-8")
    assert "CLOUDFLARE_API_BASE_URL" in content
    assert "CF_TIMEOUT_CONNECT" in content
    assert "MAX_AUDIT_LOG_ENTRIES" in content


def test_config_json_example_exists_and_safe():
    root = Path(__file__).resolve().parent.parent
    cfg_example = root / "config.json.example"
    assert cfg_example.is_file()
    import json
    data = json.loads(cfg_example.read_text(encoding="utf-8"))
    assert "api_profiles" in data
    # Ensure no real tokens are stored in template
    for prof in data["api_profiles"].values():
        assert prof["api_token"] == ""
        assert prof["global_api_key"] == ""


def test_gitignore_protects_config_json():
    root = Path(__file__).resolve().parent.parent
    gitignore_file = root / ".gitignore"
    assert gitignore_file.is_file()
    content = gitignore_file.read_text(encoding="utf-8")
    assert "config.json" in content
    assert ".env" in content


def test_config_manager_crud(tmp_path, monkeypatch):
    import src.config_manager as cm
    fake_config = tmp_path / "test_config.json"
    monkeypatch.setattr(cm, "get_config_path", lambda: fake_config)

    # 1. Load when missing
    cfg = cm.load_config()
    assert cfg["api_profiles"] == {}

    # 2. Save profile
    cm.save_profile("Akun Test", {"auth_method": "token", "api_token": "token123", "global_api_key": "", "email": ""})
    profiles = cm.get_profiles()
    assert "Akun Test" in profiles
    assert profiles["Akun Test"]["api_token"] == "token123"

    # 3. Add second profile and switch current
    cm.save_profile("Akun Kedua", {"auth_method": "key", "api_token": "", "global_api_key": "key456", "email": "test@domain.com"})
    assert cm.load_config()["current_profile"] == "Akun Kedua"

    # 4. Set current profile
    cm.set_current_profile("Akun Test")
    assert cm.load_config()["current_profile"] == "Akun Test"

    # 5. Delete profile
    cm.delete_profile("Akun Test")
    profiles = cm.get_profiles()
    assert "Akun Test" not in profiles
    assert "Akun Kedua" in profiles


def test_domains_cache_crud(tmp_path, monkeypatch):
    import src.config_manager as cm
    from src.cloudflare.zones import ZoneItem

    fake_cache = tmp_path / "data" / "domains_cache.json"
    monkeypatch.setattr(cm, "get_domains_cache_path", lambda: fake_cache)
    monkeypatch.setattr(cm, "get_data_dir", lambda: tmp_path / "data")

    # 1. Load when empty
    initial = cm.load_cached_domains()
    assert initial["zones"] == []
    assert initial["targets"] == {}

    # 2. Save zones and targets
    z1 = ZoneItem({"id": "z1", "name": "domain1.com", "status": "active"}, account_id="acc1", account_label="Akun 1")
    z2 = {"id": "z2", "name": "domain2.com", "status": "pending", "account_id": "acc2", "account_label": "Akun 2"}
    targets = {"z1": "https://target1.com"}

    saved = cm.save_cached_domains([z1, z2], targets=targets)
    assert saved is True
    assert fake_cache.is_file()

    # 3. Load saved data
    loaded = cm.load_cached_domains()
    assert len(loaded["zones"]) == 2
    assert loaded["zones"][0]["name"] == "domain1.com"
    assert loaded["zones"][0]["account_label"] == "Akun 1"
    assert loaded["zones"][1]["name"] == "domain2.com"
    assert loaded["targets"]["z1"] == "https://target1.com"

    # 4. Update cached target
    cm.update_cached_target("z2", "https://target2.com")
    updated = cm.load_cached_domains()
    assert updated["targets"]["z2"] == "https://target2.com"

    # 5. Delete target
    cm.update_cached_target("z1", "-")
    after_del = cm.load_cached_domains()
    assert "z1" not in after_del["targets"]
    assert after_del["targets"]["z2"] == "https://target2.com"

    # 6. Clear cache
    cm.clear_cached_domains()
    assert not fake_cache.is_file()
    cleared = cm.load_cached_domains()
    assert cleared["zones"] == []


def test_cached_redirect_checks_persistence(tmp_path, monkeypatch):
    import src.config_manager as cm

    fake_cache = tmp_path / "data" / "domains_cache.json"
    monkeypatch.setattr(cm, "get_domains_cache_path", lambda: fake_cache)
    monkeypatch.setattr(cm, "get_data_dir", lambda: tmp_path / "data")

    # Initially empty
    assert cm.load_cached_redirect_checks() == {}

    # Save multiple check results
    checks = {
        "domain1.com": {"status_code": 301, "target_url": "https://dest1.com", "hops": 1, "is_multiple": False},
        "domain2.com": {"status_code": 302, "target_url": "https://dest2.com", "hops": 2, "is_multiple": True},
    }
    cm.save_cached_redirect_checks(checks)

    # Load and verify
    loaded = cm.load_cached_redirect_checks()
    assert len(loaded) == 2
    assert loaded["domain1.com"]["hops"] == 1
    assert loaded["domain2.com"]["is_multiple"] is True

    # Update single check
    cm.update_cached_redirect_check("domain3.com", {"status_code": 200, "hops": 0, "is_multiple": False})
    updated = cm.load_cached_redirect_checks()
    assert len(updated) == 3
    assert "domain3.com" in updated


def test_prune_orphan_cached_domains(tmp_path, monkeypatch):
    import src.config_manager as cm

    fake_cache = tmp_path / "data" / "domains_cache.json"
    monkeypatch.setattr(cm, "get_domains_cache_path", lambda: fake_cache)
    monkeypatch.setattr(cm, "get_data_dir", lambda: tmp_path / "data")

    zones = [
        {"id": "z1", "name": "keep1.com", "account_label": "Aktif 1"},
        {"id": "z2", "name": "keep2.com", "account_label": "Aktif 2"},
        {"id": "z3", "name": "orphan.com", "account_label": "OldDeletedAccount"},
    ]
    targets = {"z1": "https://dest1.com", "z3": "https://dest3.com"}
    checks = {"keep1.com": {"hops": 1}, "orphan.com": {"hops": 2}}

    cm.save_cached_domains(zones, targets=targets, redirect_checks=checks)

    # Prune orphan accounts, keeping only Aktif 1 and Aktif 2
    pruned = cm.prune_orphan_cached_domains(valid_account_labels=["Aktif 1", "Aktif 2"])
    assert pruned == 1

    loaded = cm.load_cached_domains()
    assert len(loaded["zones"]) == 2
    assert {z["name"] for z in loaded["zones"]} == {"keep1.com", "keep2.com"}
    assert "z3" not in loaded["targets"]
    assert "orphan.com" not in loaded["redirect_checks"]
    assert "keep1.com" in loaded["redirect_checks"]


def test_merge_cached_zones_for_account(tmp_path, monkeypatch):
    import src.config_manager as cm

    fake_cache = tmp_path / "data" / "domains_cache.json"
    monkeypatch.setattr(cm, "get_domains_cache_path", lambda: fake_cache)
    monkeypatch.setattr(cm, "get_data_dir", lambda: tmp_path / "data")

    # Initial state with Account A
    cm.save_cached_domains([
        {"id": "za1", "name": "a1.com", "account_label": "Account A"},
        {"id": "za2", "name": "a2.com", "account_label": "Account A"},
    ])

    # Merge Account B
    total = cm.merge_cached_zones_for_account([
        {"id": "zb1", "name": "b1.com", "account_label": "Account B"},
    ], account_label="Account B")

    assert total == 3
    loaded = cm.load_cached_domains()
    assert len(loaded["zones"]) == 3
    labels = {z["account_label"] for z in loaded["zones"]}
    assert labels == {"Account A", "Account B"}

    # Update Account A with new zones (should replace A's old zones, keeping B)
    total_updated = cm.merge_cached_zones_for_account([
        {"id": "za_new", "name": "a_new.com", "account_label": "Account A"},
    ], account_label="Account A")

    assert total_updated == 2
    loaded = cm.load_cached_domains()
    names = {z["name"] for z in loaded["zones"]}
    assert names == {"a_new.com", "b1.com"}





