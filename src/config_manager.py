"""Local Configuration & Credentials Manager (Persistent Profiles).
Securely persists Cloudflare API profiles locally so users don't need to re-type
tokens/keys on every application restart.

SECURITY GUARANTEES:
- The target 'config.json' file is explicitly ignored in .gitignore (never pushed to GitHub).
- Zero secret hardcoding.
- Safe fallback if file is corrupted or missing.
"""

import json
import sys
import copy
from pathlib import Path
from typing import Dict, Any, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    "api_profiles": {},
    "current_profile": "",
    "batch_size": 10,
    "theme": "dark",
}


def get_default_config() -> Dict[str, Any]:
    """Returns a fresh deep copy of the default configuration."""
    return copy.deepcopy(DEFAULT_CONFIG)


def get_config_path() -> Path:
    """Resolves the absolute path to config.json.
    Works seamlessly in both local Python runtime and PyInstaller frozen executable.
    """
    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        # If running from inside dist/ and root has config.json, prefer root
        if (exe_dir / "config.json").exists():
            return exe_dir / "config.json"
        if (exe_dir.parent / "config.json").exists():
            return exe_dir.parent / "config.json"
        if exe_dir.name.lower() == "dist":
            return exe_dir.parent / "config.json"
        return exe_dir / "config.json"

    # Running from Python source (src/ is one level below project root)
    root_dir = Path(__file__).resolve().parent.parent
    return root_dir / "config.json"


def load_config() -> Dict[str, Any]:
    """Loads configuration from local config.json.
    Creates default config if file does not exist.
    """
    config_path = get_config_path()
    if not config_path.is_file():
        return get_default_config()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return get_default_config()

            merged = get_default_config()
            merged.update(data)
            if not isinstance(merged.get("api_profiles"), dict):
                merged["api_profiles"] = {}
            else:
                merged["api_profiles"] = dict(merged["api_profiles"])
            return merged
    except Exception as exc:
        # Fallback to defaults on parse/read error
        return get_default_config()


def save_config(config: Dict[str, Any]) -> bool:
    """Saves configuration dict to config.json."""
    config_path = get_config_path()
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        return True
    except Exception:
        return False


def get_profiles() -> Dict[str, Dict[str, Any]]:
    """Returns all saved API profiles from config."""
    cfg = load_config()
    return cfg.get("api_profiles", {})


def save_profile(name: str, profile_data: Dict[str, Any], set_as_current: bool = True) -> bool:
    """Adds or updates an account profile in config.json."""
    cfg = load_config()
    profiles = cfg.get("api_profiles", {})
    clean_name = name.strip() if name and name.strip() else f"Akun CF #{len(profiles) + 1}"
    profiles[clean_name] = profile_data
    cfg["api_profiles"] = profiles

    if set_as_current or not cfg.get("current_profile"):
        cfg["current_profile"] = clean_name

    return save_config(cfg)


def delete_profile(name: str) -> bool:
    """Deletes an account profile from config.json."""
    cfg = load_config()
    profiles = cfg.get("api_profiles", {})
    target_key = None
    if name in profiles:
        target_key = name
    else:
        for k in profiles:
            if k.lower() == name.lower():
                target_key = k
                break

    if target_key:
        del profiles[target_key]
        cfg["api_profiles"] = profiles

        if cfg.get("current_profile", "").lower() == target_key.lower():
            cfg["current_profile"] = next(iter(profiles.keys()), "")

        saved = save_config(cfg)
        if saved:
            prune_orphan_cached_domains(list(profiles.keys()))
        return saved
    return False


def set_current_profile(name: str) -> bool:
    """Updates the active profile name in config.json."""
    cfg = load_config()
    profiles = cfg.get("api_profiles", {})
    target_key = None
    if name in profiles:
        target_key = name
    else:
        for k in profiles:
            if k.lower() == name.lower():
                target_key = k
                break

    if target_key:
        cfg["current_profile"] = target_key
        return save_config(cfg)
    return False


def clear_all_profiles() -> bool:
    """Removes all profiles from config.json and clears local domain caches."""
    cfg = load_config()
    cfg["api_profiles"] = {}
    cfg["current_profile"] = ""
    saved = save_config(cfg)
    clear_cached_domains()
    return saved


def get_data_dir() -> Path:
    """Resolves and ensures local data directory exists."""
    cfg_path = get_config_path()
    data_dir = cfg_path.parent / "data"
    data_dir.mkdir(parents=True, exist_ok=True)
    return data_dir


def get_domains_cache_path() -> Path:
    """Resolves the path to data/domains_cache.json."""
    return get_data_dir() / "domains_cache.json"


def load_cached_domains() -> Dict[str, Any]:
    """Loads cached Cloudflare zones and redirect targets from local data/domains_cache.json.
    Returns:
        dict: {"zones": [...], "targets": {...}, "redirect_checks": {...}, "last_updated": "..."} or empty dict on error.
    """
    cache_path = get_domains_cache_path()
    if not cache_path.is_file():
        return {"zones": [], "targets": {}, "redirect_checks": {}, "last_updated": ""}

    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return {"zones": [], "targets": {}, "redirect_checks": {}, "last_updated": ""}
            if "zones" not in data or not isinstance(data["zones"], list):
                data["zones"] = []
            if "targets" not in data or not isinstance(data["targets"], dict):
                data["targets"] = {}
            if "redirect_checks" not in data or not isinstance(data["redirect_checks"], dict):
                data["redirect_checks"] = {}
            return data
    except Exception:
        return {"zones": [], "targets": {}, "redirect_checks": {}, "last_updated": ""}


def save_cached_domains(
    zones: List[Any],
    targets: Optional[Dict[str, str]] = None,
    redirect_checks: Optional[Dict[str, Any]] = None,
) -> bool:
    """Saves zones and redirect target mappings to local data/domains_cache.json.
    Accepts List of ZoneItem instances or dictionaries.
    """
    cache_path = get_domains_cache_path()
    try:
        from datetime import datetime

        # Preserve existing targets & redirect_checks if not passed explicitly
        target_map: Dict[str, str] = {}
        checks_map: Dict[str, Any] = {}

        if cache_path.is_file():
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    old_data = json.load(f)
                    if isinstance(old_data, dict):
                        if isinstance(old_data.get("targets"), dict):
                            target_map = old_data["targets"]
                        if isinstance(old_data.get("redirect_checks"), dict):
                            checks_map = old_data["redirect_checks"]
            except Exception:
                pass

        if targets is not None:
            target_map = targets
        if redirect_checks is not None:
            checks_map.update(redirect_checks)

        serialized_zones = []
        for z in zones:
            if hasattr(z, "to_dict"):
                serialized_zones.append(z.to_dict())
            elif isinstance(z, dict):
                serialized_zones.append({
                    "id": z.get("id", ""),
                    "name": z.get("name", ""),
                    "status": z.get("status", "unknown"),
                    "account_id": z.get("account_id", ""),
                    "account_label": z.get("account_label", "Akun Utama"),
                })

        payload = {
            "zones": serialized_zones,
            "targets": target_map,
            "redirect_checks": checks_map,
            "last_updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = cache_path.with_suffix(".tmp")
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4, ensure_ascii=False)
        temp_path.replace(cache_path)
        return True
    except Exception:
        return False


def merge_cached_zones_for_account(new_zones: List[Any], account_label: str) -> int:
    """Merges new zones for a specific account label into domains_cache.json,
    replacing any previous zones for this account while keeping other accounts intact.
    Returns total zones count.
    """
    cache = load_cached_domains()
    existing_zones = cache.get("zones", [])
    targets = cache.get("targets", {})
    redirect_checks = cache.get("redirect_checks", {})

    # Keep all zones from other accounts
    other_zones = [z for z in existing_zones if (z.get("account_label") or "").lower() != account_label.lower()]

    serialized_new = []
    for z in new_zones:
        if hasattr(z, "to_dict"):
            serialized_new.append(z.to_dict())
        elif isinstance(z, dict):
            serialized_new.append({
                "id": z.get("id", ""),
                "name": z.get("name", ""),
                "status": z.get("status", "unknown"),
                "account_id": z.get("account_id", ""),
                "account_label": z.get("account_label", account_label),
            })

    merged = other_zones + serialized_new
    save_cached_domains(merged, targets=targets, redirect_checks=redirect_checks)
    return len(merged)


def load_cached_redirect_checks() -> Dict[str, Dict[str, Any]]:
    """Loads all saved live redirect check results from local cache."""
    cache = load_cached_domains()
    return cache.get("redirect_checks", {})


def save_cached_redirect_checks(checks: Dict[str, Dict[str, Any]]) -> bool:
    """Merges and saves live redirect check results into data/domains_cache.json."""
    cache = load_cached_domains()
    existing_checks = cache.get("redirect_checks", {})
    existing_checks.update(checks)

    cache_path = get_domains_cache_path()
    try:
        cache["redirect_checks"] = existing_checks
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "w", encoding="utf-8") as f:
            json.dump(cache, f, indent=4, ensure_ascii=False)
        return True
    except Exception:
        return False


def update_cached_redirect_check(domain: str, check_data: Dict[str, Any]) -> bool:
    """Updates single domain check result in local cache."""
    return save_cached_redirect_checks({domain.lower(): check_data})


def update_cached_target(zone_id: str, target_url: Optional[str]) -> bool:
    """Updates or removes target redirect for a specific zone in the cache."""
    cache = load_cached_domains()
    targets = cache.get("targets", {})
    if not target_url or target_url.strip() in ("", "-"):
        targets.pop(zone_id, None)
    else:
        targets[zone_id] = target_url.strip()
    return save_cached_domains(cache.get("zones", []), targets)


def clear_cached_domains() -> bool:
    """Deletes local data/domains_cache.json if exists."""
    cache_path = get_domains_cache_path()
    try:
        if cache_path.is_file():
            cache_path.unlink()
        return True
    except Exception:
        return False


def prune_orphan_cached_domains(valid_account_labels: Optional[List[str]] = None) -> int:
    """Removes cached domains, targets, and redirect checks belonging to accounts
    that are no longer in the valid accounts list (e.g. deleted or stale profiles).
    Returns the number of orphan domains removed.
    """
    if valid_account_labels is None:
        cfg = load_config()
        valid_account_labels = list(cfg.get("api_profiles", {}).keys())

    cache_path = get_domains_cache_path()
    if not cache_path.is_file():
        return 0

    try:
        with open(cache_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return 0

        zones = data.get("zones", [])
        if not isinstance(zones, list):
            return 0

        valid_set = {str(lbl).strip().lower() for lbl in valid_account_labels if lbl}
        # If there are no valid profiles connected at all, don't prune automatically
        if not valid_set:
            return 0

        kept_zones = []
        removed_count = 0
        kept_zone_ids = set()
        kept_zone_names = set()

        for z in zones:
            acc_lbl = str(z.get("account_label", "")).strip().lower()
            if acc_lbl in valid_set:
                kept_zones.append(z)
                zid = z.get("id")
                if zid:
                    kept_zone_ids.add(zid)
                zname = z.get("name")
                if zname:
                    kept_zone_names.add(zname.lower())
            else:
                removed_count += 1

        if removed_count > 0:
            targets = data.get("targets", {})
            if isinstance(targets, dict):
                targets = {k: v for k, v in targets.items() if k in kept_zone_ids}
            else:
                targets = {}

            checks = data.get("redirect_checks", {})
            if isinstance(checks, dict):
                checks = {k: v for k, v in checks.items() if k.lower() in kept_zone_names}
            else:
                checks = {}

            data["zones"] = kept_zones
            data["targets"] = targets
            data["redirect_checks"] = checks

            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)

        return removed_count
    except Exception:
        return 0


