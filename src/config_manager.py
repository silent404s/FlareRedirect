"""Local Configuration & Credentials Manager (Persistent Profiles).
Securely persists Cloudflare API profiles locally so users don't need to re-type
tokens/keys on every application restart.

SECURITY GUARANTEES:
- The target 'config.json' file is explicitly ignored in .gitignore (never pushed to GitHub).
- Zero secret hardcoding.
- Safe fallback if file is corrupted or missing.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

DEFAULT_CONFIG: Dict[str, Any] = {
    "api_profiles": {},
    "current_profile": "",
    "batch_size": 10,
    "theme": "dark",
}


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
        return DEFAULT_CONFIG.copy()

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if not isinstance(data, dict):
                return DEFAULT_CONFIG.copy()

            merged = DEFAULT_CONFIG.copy()
            merged.update(data)
            if not isinstance(merged.get("api_profiles"), dict):
                merged["api_profiles"] = {}
            return merged
    except Exception as exc:
        # Fallback to defaults on parse/read error
        return DEFAULT_CONFIG.copy()


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
    profiles[name] = profile_data
    cfg["api_profiles"] = profiles

    if set_as_current or not cfg.get("current_profile"):
        cfg["current_profile"] = name

    return save_config(cfg)


def delete_profile(name: str) -> bool:
    """Deletes an account profile from config.json."""
    cfg = load_config()
    profiles = cfg.get("api_profiles", {})
    if name in profiles:
        del profiles[name]
        cfg["api_profiles"] = profiles

        if cfg.get("current_profile") == name:
            cfg["current_profile"] = next(iter(profiles.keys()), "")

        return save_config(cfg)
    return False


def set_current_profile(name: str) -> bool:
    """Updates the active profile name in config.json."""
    cfg = load_config()
    if name in cfg.get("api_profiles", {}):
        cfg["current_profile"] = name
        return save_config(cfg)
    return False


def clear_all_profiles() -> bool:
    """Removes all profiles from config.json."""
    cfg = load_config()
    cfg["api_profiles"] = {}
    cfg["current_profile"] = ""
    return save_config(cfg)

