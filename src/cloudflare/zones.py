"""Zone management module for Cloudflare API.
Handles listing zones, pagination, status filtering, multi-account aggregation,
and matching hostnames to zones.
"""

from typing import List, Dict, Any, Optional, Tuple
from src.config import settings
from src.cloudflare.client import cf_client
from src.security.session import active_session
from src.security.validation import normalize_hostname, clean_domain_input


class ZoneItem:
    """Minimal zone item representing only essential domain & account routing data."""

    def __init__(self, data: Dict[str, Any], account_id: str = "", account_label: str = ""):
        self.id: str = data.get("id", "")
        self.name: str = data.get("name", "")
        self.status: str = data.get("status", "unknown")
        self.account_id: str = account_id or data.get("account_id", "")
        self.account_label: str = account_label or data.get("account_label", "Akun Utama")
        # Lightweight compatibility fallbacks
        self.plan_name: str = data.get("plan_name") or "Free"
        self.name_servers: List[str] = data.get("name_servers") or []
        self.paused: bool = data.get("paused", False)

    def to_dict(self) -> Dict[str, Any]:
        """Returns minimal representation containing only required fields for domain resolution and redirection."""
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "account_id": self.account_id,
            "account_label": self.account_label,
        }


def _fetch_zones_for_single_account(
    account_id: str,
    account_label: str,
    status_filter: Optional[str] = None,
) -> List[ZoneItem]:
    """Fetches all zones for a specific account session."""
    zones: List[ZoneItem] = []
    page = 1
    per_page = settings.ZONES_PER_PAGE

    while True:
        params: Dict[str, Any] = {
            "page": page,
            "per_page": per_page,
            "order": "name",
            "direction": "asc",
        }
        if status_filter and status_filter.lower() != "all":
            params["status"] = status_filter.lower()

        response = cf_client.request("GET", "zones", params=params, account_id=account_id)
        results = response.get("result", [])
        for item in results:
            zones.append(ZoneItem(item, account_id=account_id, account_label=account_label))

        result_info = response.get("result_info", {})
        total_pages = result_info.get("total_pages", 1)
        if page >= total_pages or len(results) == 0:
            break
        page += 1

    return zones


def fetch_all_zones(
    status_filter: Optional[str] = None,
    account_id: Optional[str] = None,
) -> List[ZoneItem]:
    """Fetches all accessible zones using Cloudflare pagination.
    If account_id is 'all', aggregates zones from all connected accounts.
    If account_id is None, uses active account.
    """
    if account_id == "all":
        all_zones: List[ZoneItem] = []
        for acc in active_session.get_all_accounts():
            try:
                acc_zones = _fetch_zones_for_single_account(acc.account_id, acc.label, status_filter)
                acc.zones = acc_zones
                all_zones.extend(acc_zones)
            except Exception:
                pass
        return all_zones

    target_acc = None
    if account_id:
        target_acc = next((a for a in active_session.get_all_accounts() if a.account_id == account_id), None)
    else:
        target_acc = active_session.active_account

    if not target_acc:
        return []

    zones = _fetch_zones_for_single_account(target_acc.account_id, target_acc.label, status_filter)
    target_acc.zones = zones
    return zones


def find_matching_zone(hostname: str, available_zones: List[ZoneItem]) -> Optional[ZoneItem]:
    """Finds the most specific zone that matches the given hostname."""
    clean_host = normalize_hostname(hostname)
    best_match: Optional[ZoneItem] = None
    longest_match_len = 0

    for zone in available_zones:
        z_name = zone.name.lower()
        if clean_host == z_name or clean_host.endswith("." + z_name):
            if len(z_name) > longest_match_len:
                longest_match_len = len(z_name)
                best_match = zone

    return best_match


def find_matching_zone_for_raw(raw_domain: str, available_zones: List[ZoneItem]) -> Optional[ZoneItem]:
    """Finds zone even if user pasted raw URL, www., or subdomains."""
    try:
        clean = clean_domain_input(raw_domain)
        return find_matching_zone(clean, available_zones)
    except Exception:
        return None


def find_zone_across_accounts(
    domain_string: str,
    cached_zones: Optional[List[ZoneItem]] = None,
) -> Tuple[Optional[str], Optional[str], Optional[ZoneItem], Optional[str]]:
    """Searches across all connected Cloudflare accounts (FlarePilot architecture).
    1. First checks in-memory cache of zones across all connected accounts.
    2. If not found in cache, generates parent domain candidates and queries Cloudflare API
       directly for each connected account.
    Returns:
        (account_id, account_label, zone_item, error_msg)
    """
    try:
        clean = clean_domain_input(domain_string)
    except Exception as exc:
        return None, None, None, f"Format domain tidak valid: {str(exc)}"

    accounts = active_session.get_all_accounts()
    if not accounts:
        return None, None, None, "Belum ada akun Cloudflare yang terhubung dalam sesi."

    # 1. Check in all cached zones
    all_cached: List[ZoneItem] = list(cached_zones or [])
    for acc in accounts:
        for z in acc.zones:
            if not any(cz.id == z.id for cz in all_cached):
                all_cached.append(z)

    match = find_matching_zone(clean, all_cached)
    if match:
        # Check if matching zone belongs to an active connected account
        for acc in accounts:
            if (match.account_id and acc.account_id == match.account_id) or (
                match.account_label and acc.label.lower() == match.account_label.lower()
            ):
                match.account_id = acc.account_id
                match.account_label = acc.label
                return acc.account_id, acc.label, match, None

    # 2. Live API search across all connected accounts
    parts = clean.split(".")
    if len(parts) < 2:
        return None, None, None, f"Nama domain tidak lengkap: '{clean}'"

    candidates = [".".join(parts[i:]) for i in range(len(parts) - 1)]

    for acc in accounts:
        for cand in candidates:
            try:
                res = cf_client.request("GET", f"zones?name={cand}", account_id=acc.account_id)
                results = res.get("result", [])
                if results:
                    raw_zone = results[0]
                    found_zone = ZoneItem(raw_zone, account_id=acc.account_id, account_label=acc.label)
                    # Cache in account for subsequent lookups
                    if not any(z.id == found_zone.id for z in acc.zones):
                        acc.zones.append(found_zone)
                    return acc.account_id, acc.label, found_zone, None
            except Exception:
                continue

    if match and match.account_label:
        return None, match.account_label, match, f"Domain '{clean}' tercatat pada akun '{match.account_label}' yang saat ini tidak terhubung."

    return None, None, None, f"Domain '{clean}' tidak ditemukan pada akun Cloudflare manapun."


def resolve_account_for_zone(zone_id: str, available_zones: List[ZoneItem]) -> Optional[str]:
    """Finds account_id for a zone from the cached zones list or session."""
    for z in available_zones:
        if z.id == zone_id and z.account_id:
            return z.account_id
    return active_session.find_account_id_for_zone(zone_id)


def group_zones_by_target(
    items_with_target: List[Dict[str, Any]]
) -> Dict[str, List[Dict[str, Any]]]:
    """Groups domains/zones by destination_url target.
    Keys are destination_urls (or 'Tanpa Redirect' for empty targets).
    """
    groups: Dict[str, List[Dict[str, Any]]] = {}
    for item in items_with_target:
        target = item.get("destination_url") or "Tanpa Redirect"
        if target not in groups:
            groups[target] = []
        groups[target].append(item)
    return groups

