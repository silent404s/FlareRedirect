"""Zone management module for Cloudflare API.
Handles listing zones, pagination, status filtering, multi-account aggregation,
and matching hostnames to zones.
"""

from typing import List, Dict, Any, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
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


fetch_zones_for_account = _fetch_zones_for_single_account


def fetch_all_zones(
    status_filter: Optional[str] = None,
    account_id: Optional[str] = None,
) -> List[ZoneItem]:
    """Fetches all accessible zones using Cloudflare pagination.
    If account_id is 'all', aggregates zones from all connected accounts in parallel.
    If account_id is None, uses active account.
    """
    if account_id == "all":
        all_zones: List[ZoneItem] = []
        accounts = active_session.get_all_accounts()
        if not accounts:
            return []

        def _fetch_acc(acc):
            try:
                acc_z = _fetch_zones_for_single_account(acc.account_id, acc.label, status_filter)
                acc.zones = acc_z
                return acc_z
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=min(8, len(accounts))) as executor:
            for acc_z in executor.map(_fetch_acc, accounts):
                all_zones.extend(acc_z)

        return all_zones

    target_acc = None
    if account_id:
        target_acc = next(
            (a for a in active_session.get_all_accounts() if a.account_id == account_id or a.label.lower() == account_id.lower()),
            None
        )
    else:
        target_acc = active_session.active_account

    if not target_acc:
        return []

    zones = _fetch_zones_for_single_account(target_acc.account_id, target_acc.label, status_filter)
    target_acc.zones = zones
    return zones


def get_zone_attr(item: Any, attr: str, default: str = "") -> str:
    """Safely extracts attribute from either ZoneItem object or dictionary representation."""
    if hasattr(item, attr):
        val = getattr(item, attr)
        return str(val) if val is not None else default
    if isinstance(item, dict):
        val = item.get(attr)
        return str(val) if val is not None else default
    return default


def find_matching_zone(hostname: str, available_zones: List[Any]) -> Optional[Any]:
    """Finds the most specific zone that matches the given hostname.
    Supports both ZoneItem instances and cached zone dictionaries.
    """
    clean_host = normalize_hostname(hostname)
    best_match: Optional[Any] = None
    longest_match_len = 0

    for zone in available_zones:
        z_name = get_zone_attr(zone, "name").lower()
        if not z_name:
            continue
        if clean_host == z_name or clean_host.endswith("." + z_name):
            if len(z_name) > longest_match_len:
                longest_match_len = len(z_name)
                best_match = zone

    return best_match


def find_matching_zone_for_raw(raw_domain: str, available_zones: List[Any]) -> Optional[Any]:
    """Finds zone even if user pasted raw URL, www., or subdomains."""
    try:
        clean = clean_domain_input(raw_domain)
        return find_matching_zone(clean, available_zones)
    except Exception:
        return None


def find_zone_across_accounts(
    domain_string: str,
    cached_zones: Optional[List[Any]] = None,
) -> Tuple[Optional[str], Optional[str], Optional[Any], Optional[str]]:
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

    # 1. Check in all cached zones safely (handles both objects and dicts)
    all_cached: List[Any] = list(cached_zones or [])
    for acc in accounts:
        for z in acc.zones:
            zid = get_zone_attr(z, "id")
            if not any(get_zone_attr(cz, "id") == zid for cz in all_cached):
                all_cached.append(z)

    match = find_matching_zone(clean, all_cached)
    if match:
        m_account_id = get_zone_attr(match, "account_id")
        m_account_label = get_zone_attr(match, "account_label")
        # Check if matching zone belongs to an active connected account
        for acc in accounts:
            if (m_account_id and acc.account_id == m_account_id) or (
                m_account_label and acc.label.lower() == m_account_label.lower()
            ):
                if hasattr(match, "account_id"):
                    match.account_id = acc.account_id
                    match.account_label = acc.label
                elif isinstance(match, dict):
                    match["account_id"] = acc.account_id
                    match["account_label"] = acc.label
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

    m_label = get_zone_attr(match, "account_label") if match else None
    if match and m_label:
        return None, m_label, match, f"Domain '{clean}' tercatat pada akun '{m_label}' yang saat ini tidak terhubung."

    return None, None, None, f"Domain '{clean}' tidak ditemukan pada akun Cloudflare manapun."


def resolve_account_for_zone(zone_id: str, available_zones: List[Any]) -> Optional[str]:
    """Finds account_id for a zone from the cached zones list or session."""
    for z in available_zones:
        if get_zone_attr(z, "id") == zone_id:
            acc_id = get_zone_attr(z, "account_id")
            if acc_id:
                return acc_id
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

