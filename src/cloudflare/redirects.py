"""Cloudflare Single Redirects (URL Forwarding) Manager.
Uses Cloudflare Rulesets API under the 'http_request_dynamic_redirect' phase.
Supports 301 Permanent Redirects with Apex and WWW coverage,
conflict & anomaly detection, auto-account resolution, and soft-fail resilience.
"""

from typing import List, Dict, Any, Optional, Tuple
import re
from urllib.parse import urlsplit
from src.cloudflare.client import cf_client
from src.security.session import active_session
from src.security.validation import (
    normalize_hostname,
    validate_destination_url,
    build_all_incoming_expression,
    validate_status_code,
)
from src.utils.errors import NotFoundError, ValidationError
from src.utils.audit import session_audit

PHASE_DYNAMIC_REDIRECT = "http_request_dynamic_redirect"


class RedirectRule:
    def __init__(self, data: Dict[str, Any], zone_id: str, ruleset_id: str):
        self.id: str = data.get("id", "")
        self.zone_id: str = zone_id
        self.ruleset_id: str = ruleset_id
        self.description: str = data.get("description", "Single Redirect Rule")
        self.enabled: bool = data.get("enabled", True)
        self.expression: str = data.get("expression", "")

        action_params = data.get("action_parameters", {})
        from_value = action_params.get("from_value", {}) if isinstance(action_params, dict) else {}

        self.status_code: int = from_value.get("status_code", 301)
        self.preserve_query_string: bool = from_value.get("preserve_query_string", False)

        target_url = from_value.get("target_url", {})
        if "value" in target_url:
            self.target_url_raw: str = target_url["value"]
            self.preserve_path: bool = False
            self.destination_url: str = self.target_url_raw
        elif "expression" in target_url:
            self.target_url_raw: str = target_url["expression"]
            self.preserve_path = "http.request.uri.path" in self.target_url_raw
            expr_match = re.search(r'concat\("([^"]+)"', self.target_url_raw)
            self.destination_url = expr_match.group(1) if expr_match else self.target_url_raw
        else:
            self.target_url_raw = ""
            self.preserve_path = False
            self.destination_url = ""

        # Analyze hostname coverage from expression
        expr_clean = self.expression.strip()
        if expr_clean == "true":
            self.coverage = "all"
            self.source_hostname = "*"
            self.source_display = "* (All incoming requests)"
            self.mode = "ALL INCOMING (All requests)"
        else:
            hosts_found = re.findall(r'http\.host\s+(?:eq|==)\s+"([^"]+)"', self.expression)
            if len(hosts_found) >= 2:
                self.coverage = "both"
                apex_cand = next((h for h in hosts_found if not h.startswith("www.")), hosts_found[0])
                self.source_hostname = apex_cand
                self.source_display = f"{apex_cand} (+ www)"
            elif len(hosts_found) == 1:
                h = hosts_found[0]
                if h.startswith("www."):
                    self.coverage = "www"
                    self.source_hostname = h
                    self.source_display = f"{h} (www only)"
                else:
                    self.coverage = "apex"
                    self.source_hostname = h
                    self.source_display = f"{h} (Apex only)"
            else:
                self.source_hostname = self.expression
                self.source_display = self.expression
                self.coverage = "custom"
            self.mode = "ALL INCOMING"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "zone_id": self.zone_id,
            "ruleset_id": self.ruleset_id,
            "description": self.description,
            "enabled": self.enabled,
            "source_hostname": self.source_hostname,
            "source_display": self.source_display,
            "destination_url": self.destination_url,
            "status_code": self.status_code,
            "mode": self.mode,
            "coverage": self.coverage,
            "preserve_path": self.preserve_path,
            "preserve_query_string": self.preserve_query_string,
            "expression": self.expression,
        }


def get_zone_redirect_ruleset(
    zone_id: str,
    account_id: Optional[str] = None,
) -> Tuple[Optional[str], List[RedirectRule]]:
    """Fetches the Single Redirect ruleset and its rules for a given zone.
    Auto-resolves account_id from session cache if omitted.
    Returns:
        (ruleset_id: Optional[str], rules: List[RedirectRule])
    """
    if not account_id:
        account_id = active_session.find_account_id_for_zone(zone_id)

    endpoint = f"zones/{zone_id}/rulesets/phases/{PHASE_DYNAMIC_REDIRECT}/entrypoint"
    try:
        response = cf_client.request("GET", endpoint, account_id=account_id)
        result = response.get("result", {})
        ruleset_id = result.get("id")
        raw_rules = result.get("rules", [])
        rules = [
            RedirectRule(r, zone_id=zone_id, ruleset_id=ruleset_id)
            for r in raw_rules
            if r.get("action") == "redirect"
        ]
        return ruleset_id, rules
    except NotFoundError:
        # Phase entrypoint has not been created yet
        return None, []


def is_file_or_endpoint_path(path: str) -> bool:
    """Checks if a URL path points to an explicit file (e.g. .html, .php, .htm, .aspx, etc.)
    where appending incoming URI path is invalid.
    """
    clean_path = path.rstrip("/")
    if not clean_path:
        return False
    last_segment = clean_path.split("/")[-1]
    return "." in last_segment and not last_segment.startswith(".")


def build_all_incoming_payload(
    source_domain: str,
    destination_url: str,
    coverage: str = "both",
    status_code: int = 301,
    preserve_path: bool = False,
    preserve_query_string: bool = False,
    enabled: bool = True,
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Constructs a Cloudflare Single Redirect rule payload for ALL INCOMING mode (301 Permanent)."""
    norm_source = normalize_hostname(source_domain)
    norm_dest, _ = validate_destination_url(destination_url, source_host=norm_source)
    valid_status = validate_status_code(status_code)  # Enforces 301 strictly

    expression, _ = build_all_incoming_expression(norm_source, coverage=coverage)

    # Standardize rule naming strictly to: Redirect > {domain_tujuan}
    parsed = urlsplit(norm_dest)
    dest_path = parsed.path.rstrip("/") if parsed.path not in ("/", "") else ""
    target_display = f"{parsed.netloc}{dest_path}" if dest_path else parsed.netloc
    rule_desc = description or f"Redirect > {target_display}"

    # Wajib mematikan Query String pada target redirect (preserve_query_string: false)
    forced_preserve_query = False

    is_file_target = is_file_or_endpoint_path(parsed.path) or bool(parsed.query)

    if preserve_path and not is_file_target:
        base_dest = f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/")
        target_expression = f'concat("{base_dest}", http.request.uri.path)'
        from_value = {
            "status_code": valid_status,
            "preserve_query_string": forced_preserve_query,
            "target_url": {
                "expression": target_expression,
            },
        }
    else:
        from_value = {
            "status_code": valid_status,
            "preserve_query_string": forced_preserve_query,
            "target_url": {
                "value": norm_dest,
            },
        }

    return {
        "action": "redirect",
        "description": rule_desc,
        "enabled": enabled,
        "expression": expression,
        "action_parameters": {
            "from_value": from_value,
        },
    }


def build_rule_payload(
    source_hostname: str,
    destination_url: str,
    status_code: int = 301,
    mode: str = "Root",
    description: Optional[str] = None,
) -> Dict[str, Any]:
    """Compatibility helper defaulting to 301."""
    preserve_path = (mode == "Preserve Path")
    return build_all_incoming_payload(
        source_domain=source_hostname,
        destination_url=destination_url,
        coverage="both",
        status_code=301,
        preserve_path=preserve_path,
        preserve_query_string=False,
        description=description,
    )


def is_rule_matching_source(r: RedirectRule, norm_source: str) -> bool:
    """Checks if a RedirectRule specifically targets the given source domain.
    Prevents false positive conflicts and deletions from loose substring matching
    (e.g. preventing 'site.com' from accidentally matching 'mysite.com').
    """
    r_src = r.source_hostname.lower()
    if r_src in ("*", norm_source, f"www.{norm_source}"):
        return True
    if norm_source.startswith("www.") and r_src == norm_source[4:]:
        return True

    clean_expr = r.expression.lower()
    quoted_apex = f'"{norm_source}"'
    quoted_www = f'"www.{norm_source}"'
    return quoted_apex in clean_expr or quoted_www in clean_expr


def detect_redirect_conflicts(
    zone_id: str,
    source_domain: str,
    target_url: str,
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Checks existing Cloudflare dynamic redirect rules for conflicts, duplicates, and anomalies:
    - DUPLICATE: Existing rule already has the same destination URL.
    - REDFLAG_ANOMALY: Multiple (>1) redirect rules exist for this source host or similar target.
    - OVERWRITE: Exactly 1 redirect rule exists with a different destination.
    - CLEAR: No existing redirect rule found for this domain.
    """
    if not account_id:
        account_id = active_session.find_account_id_for_zone(zone_id)

    norm_source = normalize_hostname(source_domain)
    norm_dest, _ = validate_destination_url(target_url, source_host=norm_source)
    ruleset_id, existing_rules = get_zone_redirect_ruleset(zone_id, account_id=account_id)

    matching_rules: List[RedirectRule] = [
        r for r in existing_rules if is_rule_matching_source(r, norm_source)
    ]

    if len(matching_rules) > 1:
        return {
            "status": "REDFLAG_ANOMALY",
            "is_conflict": True,
            "ruleset_id": ruleset_id,
            "count": len(matching_rules),
            "matching_rules": matching_rules,
            "message": f"Ditemukan {len(matching_rules)} rules ganda di Cloudflare! (Redflag Anomali)",
        }

    if len(matching_rules) == 1:
        existing = matching_rules[0]
        if existing.destination_url.rstrip("/") == norm_dest.rstrip("/"):
            return {
                "status": "DUPLICATE",
                "is_conflict": True,
                "ruleset_id": ruleset_id,
                "count": 1,
                "matching_rules": matching_rules,
                "message": f"Rule redirect ke '{norm_dest}' sudah aktif (Rule ID: {existing.id}). Duplikasi dicegah.",
            }
        else:
            return {
                "status": "OVERWRITE",
                "is_conflict": False,
                "ruleset_id": ruleset_id,
                "count": 1,
                "matching_rules": matching_rules,
                "message": f"Rule lama terdeteksi (Target: {existing.destination_url}). Siap diperbarui.",
            }

    return {
        "status": "CLEAR",
        "is_conflict": False,
        "ruleset_id": ruleset_id,
        "count": 0,
        "matching_rules": [],
        "message": "Tidak ada konflik. Zona bersih untuk membuat rule baru.",
    }


def create_redirect_rule(
    zone_id: str,
    source_hostname: str,
    destination_url: str,
    status_code: int = 301,
    mode: str = "Root",
    coverage: str = "both",
    preserve_path: bool = False,
    preserve_query_string: bool = False,
    enabled: bool = True,
    description: Optional[str] = None,
    dry_run: bool = False,
    account_id: Optional[str] = None,
    clean_conflicts: bool = True,
) -> Dict[str, Any]:
    """Creates a new Single Redirect rule in Cloudflare (301 Permanent only).
    Automatically resolves account_id, avoids duplicates, and handles soft-fail validation.
    """
    if not account_id:
        account_id = active_session.find_account_id_for_zone(zone_id)

    payload = build_all_incoming_payload(
        source_domain=source_hostname,
        destination_url=destination_url,
        coverage=coverage,
        status_code=301,
        preserve_path=preserve_path,
        preserve_query_string=False,
        enabled=enabled,
        description=description,
    )

    if dry_run:
        return {"dry_run": True, "payload": payload}

    conflict_info = detect_redirect_conflicts(
        zone_id=zone_id,
        source_domain=source_hostname,
        target_url=destination_url,
        account_id=account_id,
    )

    norm_source = normalize_hostname(source_hostname)
    ruleset_id = conflict_info.get("ruleset_id")
    matching_rules = conflict_info.get("matching_rules", [])

    if conflict_info["status"] == "DUPLICATE":
        return {
            "success": True,
            "status": "DUPLICATE_SKIPPED",
            "message": conflict_info["message"],
            "rule_id": matching_rules[0].id if matching_rules else None,
        }

    # Clean prior matching rules / anomalies if requested
    if clean_conflicts and matching_rules and ruleset_id:
        for old_rule in matching_rules:
            try:
                delete_redirect_rule(
                    zone_id=zone_id,
                    ruleset_id=ruleset_id,
                    rule_id=old_rule.id,
                    account_id=account_id,
                )
            except Exception:
                pass

    if not ruleset_id:
        ruleset_id, _ = get_zone_redirect_ruleset(zone_id, account_id=account_id)

    try:
        if ruleset_id:
            endpoint = f"zones/{zone_id}/rulesets/{ruleset_id}/rules"
            response = cf_client.request("POST", endpoint, json_data=payload, account_id=account_id)
        else:
            endpoint = f"zones/{zone_id}/rulesets"
            ruleset_payload = {
                "name": "default",
                "kind": "zone",
                "phase": PHASE_DYNAMIC_REDIRECT,
                "rules": [payload],
            }
            response = cf_client.request("POST", endpoint, json_data=ruleset_payload, account_id=account_id)

        session_audit.record(
            "CREATE_REDIRECT",
            norm_source,
            "SUCCESS",
            f"Mode: ALL INCOMING ({coverage}), Target: {destination_url}"
        )
        return response
    except Exception as exc:
        # Soft-Fail Verification (e.g. cases where Cloudflare API returns non-blocking notice/warning):
        try:
            _, verified_rules = get_zone_redirect_ruleset(zone_id, account_id=account_id)
            for vr in verified_rules:
                if vr.destination_url.rstrip("/") == destination_url.rstrip("/"):
                    session_audit.record(
                        "CREATE_REDIRECT_SOFT_FAIL",
                        norm_source,
                        "SUCCESS",
                        f"Rule verified active on Cloudflare: {str(exc)}"
                    )
                    return {
                        "success": True,
                        "soft_fail": True,
                        "message": f"Rule berhasil aktif di Cloudflare (Notice: {str(exc)})",
                        "rule_id": vr.id,
                    }
        except Exception:
            pass
        raise


def update_redirect_rule(
    zone_id: str,
    ruleset_id: str,
    rule_id: str,
    source_hostname: str,
    destination_url: str,
    coverage: str = "both",
    status_code: int = 301,
    preserve_path: bool = False,
    preserve_query_string: bool = False,
    enabled: bool = True,
    description: Optional[str] = None,
    dry_run: bool = False,
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Updates an existing Single Redirect rule using PATCH (301 only)."""
    if not zone_id or not ruleset_id or not rule_id:
        raise ValidationError("Zone ID, Ruleset ID, dan Rule ID wajib diisi untuk pembaruan.")

    if not account_id:
        account_id = active_session.find_account_id_for_zone(zone_id)

    payload = build_all_incoming_payload(
        source_domain=source_hostname,
        destination_url=destination_url,
        coverage=coverage,
        status_code=301,
        preserve_path=preserve_path,
        preserve_query_string=False,
        enabled=enabled,
        description=description,
    )

    if dry_run:
        return {"dry_run": True, "rule_id": rule_id, "payload": payload}

    _, rules = get_zone_redirect_ruleset(zone_id, account_id=account_id)
    target_rule = next((r for r in rules if r.id == rule_id), None)
    if not target_rule:
        raise NotFoundError(f"Aturan dengan ID {rule_id} tidak ditemukan pada zona {zone_id}.")

    endpoint = f"zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
    response = cf_client.request("PATCH", endpoint, json_data=payload, account_id=account_id)
    session_audit.record(
        "UPDATE_REDIRECT",
        source_hostname,
        "SUCCESS",
        f"Rule ID: {rule_id}, Target: {destination_url}",
        rule_id=rule_id,
    )
    return response


def toggle_redirect_rule_status(
    zone_id: str,
    ruleset_id: str,
    rule_id: str,
    enabled: bool,
    dry_run: bool = False,
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Enables or disables a redirect rule without changing its parameters."""
    if not zone_id or not ruleset_id or not rule_id:
        raise ValidationError("Zone ID, Ruleset ID, dan Rule ID wajib diisi.")

    if not account_id:
        account_id = active_session.find_account_id_for_zone(zone_id)

    if dry_run:
        return {"dry_run": True, "rule_id": rule_id, "enabled": enabled}

    endpoint = f"zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
    payload = {"enabled": enabled}
    response = cf_client.request("PATCH", endpoint, json_data=payload, account_id=account_id)
    status_str = "ENABLED" if enabled else "DISABLED"
    session_audit.record("TOGGLE_STATUS", rule_id, "SUCCESS", f"Rule {rule_id} -> {status_str}", rule_id=rule_id)
    return response


def delete_redirect_rule(
    zone_id: str,
    ruleset_id: str,
    rule_id: str,
    dry_run: bool = False,
    account_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Deletes a single redirect rule safely by its Rule ID."""
    if not zone_id or not ruleset_id or not rule_id:
        raise ValidationError("Zone ID, Ruleset ID, dan Rule ID wajib diisi untuk penghapusan.")

    if not account_id:
        account_id = active_session.find_account_id_for_zone(zone_id)

    if dry_run:
        return {"dry_run": True, "zone_id": zone_id, "rule_id": rule_id}

    # Verify rule still exists before deletion
    _, rules = get_zone_redirect_ruleset(zone_id, account_id=account_id)
    target_rule = next((r for r in rules if r.id == rule_id), None)
    if not target_rule:
        raise NotFoundError(f"Aturan dengan ID {rule_id} tidak ditemukan lagi pada zona {zone_id}. Mungkin sudah dihapus.")

    endpoint = f"zones/{zone_id}/rulesets/{ruleset_id}/rules/{rule_id}"
    response = cf_client.request("DELETE", endpoint, account_id=account_id)
    session_audit.record("DELETE_REDIRECT", zone_id, "SUCCESS", f"Rule ID: {rule_id}", rule_id=rule_id)
    return response


def delete_matching_redirects_for_domain(
    zone_id: str,
    source_domain: str,
    account_id: Optional[str] = None,
) -> int:
    """Safely finds and deletes any matching, duplicate, or anomaly rules for a domain."""
    if not account_id:
        account_id = active_session.find_account_id_for_zone(zone_id)

    ruleset_id, rules = get_zone_redirect_ruleset(zone_id, account_id=account_id)
    if not ruleset_id or not rules:
        return 0

    norm_source = normalize_hostname(source_domain)
    deleted_count = 0
    for r in rules:
        if is_rule_matching_source(r, norm_source):
            try:
                delete_redirect_rule(zone_id=zone_id, ruleset_id=ruleset_id, rule_id=r.id, account_id=account_id)
                deleted_count += 1
            except Exception:
                pass

    return deleted_count
