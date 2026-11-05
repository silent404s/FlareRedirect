"""PySide6 Background Workers for non-blocking Cloudflare API operations.
Ensures GUI remains responsive at all times and threads do not access UI widgets directly.
"""

from typing import List, Dict, Any, Optional
from PySide6.QtCore import QThread, Signal
from src.cloudflare.client import cf_client
from src.cloudflare.zones import fetch_all_zones, find_zone_across_accounts
from src.cloudflare.redirects import (
    get_zone_redirect_ruleset,
    create_redirect_rule,
    update_redirect_rule,
    toggle_redirect_rule_status,
    delete_redirect_rule,
    detect_redirect_conflicts,
    delete_matching_redirects_for_domain,
)
from src.security.session import active_session
from src.security.validation import (
    check_live_http_redirect,
    check_domain_public_ip,
    is_cloudflare_ip,
)
from src.utils.errors import sanitize_message
from src.utils.audit import session_audit


class ConnectWorker(QThread):
    """Verifies token and adds account to multi-account session."""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, token: str, label: str = "", parent=None):
        super().__init__(parent)
        self.token = token
        self.label = label

    def run(self):
        try:
            # Verify token directly first
            verify_res = cf_client.verify_token(token=self.token)
            status = verify_res.get("status", "active")
            
            # Add to in-memory multi-account session
            account_id = active_session.add_account(label=self.label, token=self.token)
            zones = fetch_all_zones(account_id=account_id)
            
            acc_obj = active_session.active_account
            final_label = acc_obj.label if acc_obj else self.label
            session_audit.record("CONNECT_ACCOUNT", final_label, "SUCCESS", f"Zones count: {len(zones)}")
            
            self.finished.emit({
                "status": status,
                "zones": zones,
                "account_id": account_id,
                "label": final_label,
                "message": f"Akun '{final_label}' berhasil terhubung ke Cloudflare API."
            })
        except Exception as exc:
            err_msg = sanitize_message(str(exc))
            session_audit.record("CONNECT_ACCOUNT", self.label or "New Account", "FAILED", err_msg)
            self.error.emit(err_msg)
        finally:
            self.token = ""


class FetchZonesWorker(QThread):
    """Fetches accessible zones for specific account or all accounts in background."""
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, status_filter: Optional[str] = None, account_id: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.status_filter = status_filter
        self.account_id = account_id

    def run(self):
        try:
            zones = fetch_all_zones(self.status_filter, account_id=self.account_id)
            self.finished.emit(zones)
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class FetchRedirectsWorker(QThread):
    """Fetches rules for a zone in background."""
    finished = Signal(str, list)  # ruleset_id, rules
    error = Signal(str)

    def __init__(self, zone_id: str, parent=None):
        super().__init__(parent)
        self.zone_id = zone_id

    def run(self):
        try:
            ruleset_id, rules = get_zone_redirect_ruleset(self.zone_id)
            self.finished.emit(ruleset_id or "", rules)
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class CreateRedirectWorker(QThread):
    """Creates a redirect rule in background."""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(
        self,
        zone_id: str,
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
        parent=None,
    ):
        super().__init__(parent)
        self.zone_id = zone_id
        self.source_hostname = source_hostname
        self.destination_url = destination_url
        self.coverage = coverage
        self.status_code = 301
        self.preserve_path = preserve_path
        self.preserve_query_string = False
        self.enabled = enabled
        self.description = description
        self.dry_run = dry_run
        self.account_id = account_id

    def run(self):
        try:
            res = create_redirect_rule(
                zone_id=self.zone_id,
                source_hostname=self.source_hostname,
                destination_url=self.destination_url,
                coverage=self.coverage,
                status_code=301,
                preserve_path=self.preserve_path,
                preserve_query_string=False,
                enabled=self.enabled,
                description=self.description,
                dry_run=self.dry_run,
                account_id=self.account_id,
            )
            self.finished.emit(res)
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class UpdateRedirectWorker(QThread):
    """Updates an existing redirect rule in background."""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(
        self,
        zone_id: str,
        ruleset_id: str,
        rule_id: str,
        source_hostname: str,
        destination_url: str,
        coverage: str = "both",
        status_code: int = 302,
        preserve_path: bool = True,
        preserve_query_string: bool = True,
        enabled: bool = True,
        description: Optional[str] = None,
        dry_run: bool = False,
        parent=None,
    ):
        super().__init__(parent)
        self.zone_id = zone_id
        self.ruleset_id = ruleset_id
        self.rule_id = rule_id
        self.source_hostname = source_hostname
        self.destination_url = destination_url
        self.coverage = coverage
        self.status_code = status_code
        self.preserve_path = preserve_path
        self.preserve_query_string = preserve_query_string
        self.enabled = enabled
        self.description = description
        self.dry_run = dry_run

    def run(self):
        try:
            res = update_redirect_rule(
                zone_id=self.zone_id,
                ruleset_id=self.ruleset_id,
                rule_id=self.rule_id,
                source_hostname=self.source_hostname,
                destination_url=self.destination_url,
                coverage=self.coverage,
                status_code=self.status_code,
                preserve_path=self.preserve_path,
                preserve_query_string=self.preserve_query_string,
                enabled=self.enabled,
                description=self.description,
                dry_run=self.dry_run,
            )
            self.finished.emit(res)
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class ToggleRedirectWorker(QThread):
    """Toggles rule enabled/disabled in background."""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, zone_id: str, ruleset_id: str, rule_id: str, enabled: bool, dry_run: bool = False, parent=None):
        super().__init__(parent)
        self.zone_id = zone_id
        self.ruleset_id = ruleset_id
        self.rule_id = rule_id
        self.enabled = enabled
        self.dry_run = dry_run

    def run(self):
        try:
            res = toggle_redirect_rule_status(
                zone_id=self.zone_id,
                ruleset_id=self.ruleset_id,
                rule_id=self.rule_id,
                enabled=self.enabled,
                dry_run=self.dry_run,
            )
            self.finished.emit(res)
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class DeleteRedirectWorker(QThread):
    """Deletes a redirect rule in background."""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, zone_id: str, ruleset_id: str, rule_id: str, dry_run: bool = False, parent=None):
        super().__init__(parent)
        self.zone_id = zone_id
        self.ruleset_id = ruleset_id
        self.rule_id = rule_id
        self.dry_run = dry_run

    def run(self):
        try:
            res = delete_redirect_rule(
                zone_id=self.zone_id,
                ruleset_id=self.ruleset_id,
                rule_id=self.rule_id,
                dry_run=self.dry_run,
            )
            self.finished.emit(res)
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class PreflightValidationWorker(QThread):
    """Asynchronously checks live HTTP redirects, public IP resolution, and auto-discovers
    which Cloudflare account owns the domain across all accounts (FlarePilot architecture).
    """
    progress = Signal(int, int, str)
    finished = Signal(list)
    error = Signal(str)

    def __init__(self, raw_domains: List[str], target_url: str, available_zones: Optional[List[Any]] = None, parent=None):
        super().__init__(parent)
        self.raw_domains = raw_domains
        self.target_url = target_url
        self.available_zones = available_zones or []

    def run(self):
        try:
            total = len(self.raw_domains)
            results = []
            for idx, raw_domain in enumerate(self.raw_domains, start=1):
                clean_name = raw_domain.strip()
                self.progress.emit(idx, total, f"Cek IP & Akun CF: {clean_name}")

                # 1. Resolve Public DNS IP (FlarePilot)
                public_ip = check_domain_public_ip(clean_name)
                is_cf_ip = is_cloudflare_ip(public_ip)

                # 2. Live HTTP Check
                http_check = check_live_http_redirect(clean_name, timeout=2.5)

                # 3. Dynamic Auto-Discovery of Cloudflare Account (FlarePilot)
                acc_id, acc_label, zone, err_msg = find_zone_across_accounts(
                    domain_string=clean_name,
                    cached_zones=self.available_zones,
                )

                # 4. Cloudflare Conflict & Anomaly Check (if zone found)
                if zone and acc_id:
                    try:
                        cf_conflict = detect_redirect_conflicts(
                            zone_id=zone.id,
                            source_domain=clean_name,
                            target_url=self.target_url,
                            account_id=acc_id,
                        )
                    except Exception as exc:
                        cf_conflict = {"status": "ERROR", "is_conflict": False, "message": str(exc), "count": 0}
                else:
                    cf_conflict = {
                        "status": "NO_ZONE",
                        "is_conflict": False,
                        "message": err_msg or "Zona tidak ditemukan di akun Cloudflare manapun.",
                        "count": 0,
                    }

                results.append({
                    "raw_domain": clean_name,
                    "public_ip": public_ip,
                    "is_cf_ip": is_cf_ip,
                    "account_id": acc_id,
                    "account_label": acc_label or "-",
                    "zone": zone,
                    "target_url": self.target_url,
                    "http_check": http_check,
                    "cf_conflict": cf_conflict,
                })

            self.finished.emit(results)
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class SinglePreflightWorker(QThread):
    """Pre-flight check for a single domain redirect with public IP resolution."""
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, domain: str, zone_id: Optional[str] = None, target_url: str = "", account_id: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.domain = domain
        self.zone_id = zone_id
        self.target_url = target_url
        self.account_id = account_id

    def run(self):
        try:
            public_ip = check_domain_public_ip(self.domain)
            http_check = check_live_http_redirect(self.domain, timeout=3.0)
            cf_conflict = None
            if self.zone_id and self.target_url:
                cf_conflict = detect_redirect_conflicts(
                    zone_id=self.zone_id,
                    source_domain=self.domain,
                    target_url=self.target_url,
                    account_id=self.account_id,
                )
            self.finished.emit({
                "public_ip": public_ip,
                "http_check": http_check,
                "cf_conflict": cf_conflict,
            })
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class BulkCreateRedirectsWorker(QThread):
    """Creates multiple redirect rules across zones with progress reporting (301 strictly enforced)."""
    progress = Signal(int, int, str)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, items: List[Dict[str, Any]], parent=None):
        super().__init__(parent)
        self.items = items

    def run(self):
        try:
            total = len(self.items)
            success_count = 0
            failed_count = 0
            errors = []

            for idx, item in enumerate(self.items, start=1):
                zone_id = item["zone_id"]
                account_id = item.get("account_id")
                source = item["source_hostname"]
                dest = item["destination_url"]
                cov = item.get("coverage", "both")
                preserve_p = item.get("preserve_path", False)
                enabled = item.get("enabled", True)

                self.progress.emit(idx, total, f"Memproses: {source}")

                try:
                    create_redirect_rule(
                        zone_id=zone_id,
                        source_hostname=source,
                        destination_url=dest,
                        coverage=cov,
                        status_code=301,
                        preserve_path=preserve_p,
                        preserve_query_string=False,
                        enabled=enabled,
                        account_id=account_id,
                        clean_conflicts=True,
                    )
                    success_count += 1
                except Exception as exc:
                    failed_count += 1
                    err_text = f"{source}: {sanitize_message(str(exc))}"
                    errors.append(err_text)

            self.finished.emit({
                "success": success_count,
                "failed": failed_count,
                "errors": errors,
            })
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class BulkDeleteRedirectsWorker(QThread):
    """Deletes multiple redirect rules safely with progress reporting."""
    progress = Signal(int, int, str)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, items: List[Dict[str, Any]], parent=None):
        super().__init__(parent)
        self.items = items

    def run(self):
        try:
            total = len(self.items)
            success_count = 0
            failed_count = 0
            errors = []

            for idx, item in enumerate(self.items, start=1):
                zone_id = item["zone_id"]
                ruleset_id = item["ruleset_id"]
                rule_id = item["rule_id"]
                source = item.get("source_hostname", rule_id)
                account_id = item.get("account_id")

                self.progress.emit(idx, total, f"Menghapus: {source}")

                if account_id:
                    try:
                        active_session.switch_account(account_id)
                    except Exception:
                        pass

                try:
                    delete_redirect_rule(
                        zone_id=zone_id,
                        ruleset_id=ruleset_id,
                        rule_id=rule_id,
                        account_id=account_id,
                    )
                    success_count += 1
                except Exception as exc:
                    failed_count += 1
                    errors.append(f"{source}: {sanitize_message(str(exc))}")

            self.finished.emit({
                "success": success_count,
                "failed": failed_count,
                "errors": errors,
            })
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class BulkToggleRedirectsWorker(QThread):
    """Toggles enabled status for multiple redirect rules."""
    progress = Signal(int, int, str)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, items: List[Dict[str, Any]], enabled: bool, parent=None):
        super().__init__(parent)
        self.items = items
        self.enabled = enabled

    def run(self):
        try:
            total = len(self.items)
            success_count = 0
            failed_count = 0
            errors = []

            for idx, item in enumerate(self.items, start=1):
                zone_id = item["zone_id"]
                ruleset_id = item["ruleset_id"]
                rule_id = item["rule_id"]
                source = item.get("source_hostname", rule_id)
                account_id = item.get("account_id")

                action_name = "Mengaktifkan" if self.enabled else "Menonaktifkan"
                self.progress.emit(idx, total, f"{action_name}: {source}")

                if account_id:
                    try:
                        active_session.switch_account(account_id)
                    except Exception:
                        pass

                try:
                    toggle_redirect_rule_status(
                        zone_id=zone_id,
                        ruleset_id=ruleset_id,
                        rule_id=rule_id,
                        enabled=self.enabled,
                        account_id=account_id,
                    )
                    success_count += 1
                except Exception as exc:
                    failed_count += 1
                    errors.append(f"{source}: {sanitize_message(str(exc))}")

            self.finished.emit({
                "success": success_count,
                "failed": failed_count,
                "errors": errors,
            })
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


class BulkPurgeRedirectsWorker(QThread):
    """Purges all 301/302 redirect rules across multiple zones."""
    progress = Signal(int, int, str)
    finished = Signal(dict)
    error = Signal(str)

    def __init__(self, zone_items: List[Dict[str, Any]], status_filter: int = 0, parent=None):
        super().__init__(parent)
        self.zone_items = zone_items  # list of {"zone_id": ..., "account_id": ..., "zone_name": ...}
        self.status_filter = status_filter  # 0: all, 301: 301 only, 302: 302 only

    def run(self):
        try:
            total_zones = len(self.zone_items)
            deleted_count = 0
            errors = []

            for idx, z in enumerate(self.zone_items, start=1):
                zid = z["zone_id"]
                zname = z.get("zone_name", zid)
                aid = z.get("account_id")

                self.progress.emit(idx, total_zones, f"Memeriksa zona: {zname}")
                if aid:
                    try:
                        active_session.switch_account(aid)
                    except Exception:
                        pass

                try:
                    ruleset_id, rules = get_zone_redirect_ruleset(zid)
                    if not ruleset_id or not rules:
                        continue

                    matching_rules = []
                    for r in rules:
                        if self.status_filter == 301 and r.status_code == 301:
                            matching_rules.append(r)
                        elif self.status_filter == 302 and r.status_code == 302:
                            matching_rules.append(r)
                        elif self.status_filter == 0:
                            matching_rules.append(r)

                    for r in matching_rules:
                        try:
                            delete_redirect_rule(zid, ruleset_id, r.id)
                            deleted_count += 1
                        except Exception as e:
                            errors.append(f"{zname} ({r.id}): {sanitize_message(str(e))}")
                except Exception as exc:
                    errors.append(f"{zname}: {sanitize_message(str(exc))}")

            self.finished.emit({
                "success": deleted_count,
                "errors": errors,
            })
        except Exception as exc:
            self.error.emit(sanitize_message(str(exc)))


