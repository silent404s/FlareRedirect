"""FlareRedirect Local Web Dashboard Server.
Zero-dependency, high-performance local HTTP server bridging the browser UI
with the Cloudflare API Engine, local profiles, and cache.
"""

import os
import sys
import json
import time
import uuid
import threading
from pathlib import Path
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import webbrowser

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from src import config_manager
from src.security.session import active_session
from src.security.validation import check_live_redirect, validate_destination_url
from src.cloudflare.zones import (
    fetch_all_zones,
    _fetch_zones_for_single_account,
    find_zone_across_accounts,
    get_zone_attr,
    ZoneItem,
)
from src.cloudflare.redirects import (
    create_redirect_rule,
    get_zone_redirect_ruleset,
    delete_matching_redirects_for_domain,
    delete_redirect_rule,
)

# Background tasks tracking with auto-eviction to prevent memory leaks
TASKS: Dict[str, Dict[str, Any]] = {}
TASKS_LOCK = threading.Lock()
MAX_TASKS_CAPACITY = 8


def register_background_task(task_id: str, task_dict: Dict[str, Any]) -> None:
    """Registers task and evicts oldest finished tasks to prevent heap bloat."""
    with TASKS_LOCK:
        completed_keys = [
            k for k, v in TASKS.items()
            if v.get("status") in ("completed", "error", "cancelled")
        ]
        while len(TASKS) >= MAX_TASKS_CAPACITY and completed_keys:
            oldest = completed_keys.pop(0)
            TASKS.pop(oldest, None)
        TASKS[task_id] = task_dict


def init_session_from_config():
    """Initializes active_session accounts from local config.json on server start."""
    cfg = config_manager.load_config()
    profiles = cfg.get("api_profiles", {})
    curr_prof = cfg.get("current_profile", "")

    # Auto prune orphan domains from deleted accounts
    config_manager.prune_orphan_cached_domains(list(profiles.keys()))

    for name, prof in profiles.items():
        if not isinstance(prof, dict):
            continue
        auth_method = prof.get("auth_method", "token")
        api_token = prof.get("api_token", "")
        global_api_key = prof.get("global_api_key", "")
        email = prof.get("email", "")

        try:
            if auth_method == "key" and global_api_key and email:
                active_session.add_account(
                    label=name,
                    auth_method="key",
                    global_api_key=global_api_key,
                    email=email,
                )
            elif auth_method == "token" and api_token:
                active_session.add_account(
                    label=name,
                    token=api_token,
                    auth_method="token",
                )
        except Exception:
            pass

    if curr_prof:
        for acc in active_session.get_all_accounts():
            if acc.label.lower() == curr_prof.lower():
                active_session.switch_account(acc.account_id)
                break


class FlareWebHandler(SimpleHTTPRequestHandler):
    """Custom HTTP handler serving web static files and JSON REST endpoints."""

    def __init__(self, *args, **kwargs):
        # Serve static assets from 'web' directory
        web_dir = Path(__file__).resolve().parent
        super().__init__(*args, directory=str(web_dir), **kwargs)

    def end_headers(self):
        # Force browser to never cache local assets (avoids stale JS/CSS)
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        # Security Headers (Clickjacking, MIME Sniffing, and CSP protection)
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self' 'unsafe-inline'; connect-src 'self' http://127.0.0.1:* http://localhost:* ws://127.0.0.1:* ws://localhost:* https://cloudflare-dns.com https://dns.google; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline';"
        )
        super().end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy standard request logging
        pass

    def _is_safe_origin(self) -> bool:
        """Validates that API requests originate strictly from trusted loopback origins (Anti-CSRF)."""
        origin = self.headers.get("Origin")
        referer = self.headers.get("Referer")

        if origin:
            try:
                parsed = urlparse(origin)
                host = (parsed.hostname or "").lower()
                if host not in ("127.0.0.1", "localhost", "::1"):
                    return False
            except Exception:
                return False

        if referer:
            try:
                parsed = urlparse(referer)
                host = (parsed.hostname or "").lower()
                if host not in ("127.0.0.1", "localhost", "::1"):
                    return False
            except Exception:
                return False

        # Direct local non-browser requests (e.g. tests, curl) must come from loopback client IP
        if not origin and not referer:
            client_ip = self.client_address[0] if self.client_address else ""
            if client_ip not in ("127.0.0.1", "::1", "localhost"):
                return False

        return True

    def _send_cors_headers(self) -> None:
        """Emits restrictive CORS headers only for trusted loopback origins."""
        origin = self.headers.get("Origin")
        if origin:
            try:
                parsed = urlparse(origin)
                host = (parsed.hostname or "").lower()
                if host in ("127.0.0.1", "localhost", "::1"):
                    self.send_header("Access-Control-Allow-Origin", origin)
                    self.send_header("Vary", "Origin")
            except Exception:
                pass
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")

    def _send_json(self, status_code: int, data: Dict[str, Any]) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > 0:
                raw = self.rfile.read(length).decode("utf-8")
                return json.loads(raw)
            return {}
        except Exception:
            return {}

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path.startswith("/api/"):
            if not self._is_safe_origin():
                self._send_json(403, {"error": "Akses ditolak: Permintaan lintas origin tidak diizinkan."})
                return
            self._handle_api_get(path, query)
        else:
            # Static file fallback
            super().do_GET()

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        body = self._read_json_body()

        if path.startswith("/api/"):
            if not self._is_safe_origin():
                self._send_json(403, {"error": "Akses ditolak: Permintaan lintas origin tidak diizinkan."})
                return
            self._handle_api_post(path, body)
        else:
            self._send_json(404, {"error": "Not Found"})

    def _handle_api_get(self, path: str, query: Dict[str, List[str]]) -> None:
        if path == "/api/status":
            cfg = config_manager.load_config()
            cache = config_manager.load_cached_domains()
            zones = cache.get("zones", [])

            accounts_data = []
            for acc in active_session.get_all_accounts():
                acc_zones = sum(1 for z in zones if (z.get("account_label") or "").lower() == acc.label.lower())
                accounts_data.append({
                    "id": acc.account_id,
                    "label": acc.label,
                    "auth_method": acc.auth_method,
                    "is_connected": True,
                    "is_active": acc.account_id == active_session.active_id,
                    "domain_count": acc_zones,
                })

            active_acc = active_session.active_account
            self._send_json(200, {
                "connected": active_session.is_connected,
                "active_account": {
                    "id": active_acc.account_id if active_acc else "",
                    "label": active_acc.label if active_acc else "",
                } if active_acc else None,
                "accounts": accounts_data,
                "total_domains": len(zones),
                "last_updated": cache.get("last_updated", ""),
            })

        elif path == "/api/domains":
            # Returns all cached domains, targets, and redirect check records
            cache = config_manager.load_cached_domains()
            zones = cache.get("zones", [])
            targets = cache.get("targets", {})
            checks = cache.get("redirect_checks", {})

            # Attach active account status
            connected_labels = {a.label.lower(): a.account_id for a in active_session.get_all_accounts()}
            for z in zones:
                z_lbl = (z.get("account_label") or "").lower()
                z["is_connected"] = z_lbl in connected_labels
                if z_lbl in connected_labels:
                    z["account_id"] = connected_labels[z_lbl]

            self._send_json(200, {
                "zones": zones,
                "targets": targets,
                "redirect_checks": checks,
                "total": len(zones),
            })

        elif path == "/api/accounts":
            cfg = config_manager.load_config()
            profiles = cfg.get("api_profiles", {})
            cache = config_manager.load_cached_domains()
            zones = cache.get("zones", [])

            acc_list = []
            for name, prof in profiles.items():
                acc_obj = active_session.get_account_by_label(name)
                d_count = sum(1 for z in zones if (z.get("account_label") or "").lower() == name.lower())
                acc_list.append({
                    "label": name,
                    "id": acc_obj.account_id if acc_obj else "",
                    "auth_method": prof.get("auth_method", "token"),
                    "is_connected": acc_obj is not None,
                    "is_active": (acc_obj and acc_obj.account_id == active_session.active_id),
                    "domain_count": d_count,
                    "email": prof.get("email", ""),
                })

            self._send_json(200, {"accounts": acc_list})

        elif path == "/api/redirect/check-live/status":
            task_id = query.get("task_id", [""])[0]
            with TASKS_LOCK:
                task = TASKS.get(task_id)

            if not task:
                self._send_json(404, {"error": "Task tidak ditemukan"})
                return

            self._send_json(200, task)

        else:
            self._send_json(404, {"error": f"Endpoint GET {path} tidak ditemukan"})

    def _handle_api_post(self, path: str, body: Dict[str, Any]) -> None:
        if path == "/api/accounts/switch":
            label = body.get("label", "").strip()
            acc_id = body.get("account_id", "").strip()

            target_acc = None
            if acc_id:
                target_acc = active_session.get_account(acc_id)
            if not target_acc and label:
                target_acc = active_session.get_account_by_label(label)

            if target_acc:
                active_session.switch_account(target_acc.account_id)
                config_manager.set_current_profile(target_acc.label)
                self._send_json(200, {"success": True, "label": target_acc.label, "id": target_acc.account_id})
            else:
                self._send_json(400, {"error": "Akun tidak ditemukan dalam sesi"})

        elif path == "/api/accounts/add":
            label = body.get("label", "").strip()
            auth_method = body.get("auth_method", "token")
            token = body.get("token", "").strip()
            global_key = body.get("global_api_key", "").strip()
            email = body.get("email", "").strip()

            if not label:
                label = f"Akun CF #{active_session.account_count + 1}"

            aid = None
            try:
                if auth_method == "key":
                    aid = active_session.add_account(label=label, auth_method="key", global_api_key=global_key, email=email)
                    prof_data = {"auth_method": "key", "api_token": "", "global_api_key": global_key, "email": email}
                else:
                    aid = active_session.add_account(label=label, auth_method="token", token=token)
                    prof_data = {"auth_method": "token", "api_token": token, "global_api_key": "", "email": ""}

                # Immediately validate credentials and fetch zones from Cloudflare API
                zones = _fetch_zones_for_single_account(account_id=aid, account_label=label)

                # Persist profile only after successful verification
                config_manager.save_profile(label, prof_data, set_as_current=True)
                active_session.switch_account(aid)

                # Merge newly fetched domains into local cache
                total_zones = config_manager.merge_cached_zones_for_account(zones, account_label=label)

                self._send_json(200, {
                    "success": True,
                    "label": label,
                    "id": aid,
                    "zones_count": len(zones),
                    "total_domains": total_zones,
                })
            except Exception as exc:
                if aid and active_session.get_account(aid):
                    active_session.remove_account(aid)
                self._send_json(400, {"error": f"Gagal menghubungkan akun / memuat domain: {str(exc)}"})

        elif path == "/api/accounts/sync":
            label = body.get("label", "").strip()
            acc_id = body.get("account_id", "").strip()

            target_acc = None
            if acc_id:
                target_acc = active_session.get_account(acc_id)
            if not target_acc and label:
                target_acc = active_session.get_account_by_label(label)

            if not target_acc:
                self._send_json(400, {"error": "Akun tidak ditemukan dalam sesi"})
                return

            try:
                zones = _fetch_zones_for_single_account(account_id=target_acc.account_id, account_label=target_acc.label)
                total_zones = config_manager.merge_cached_zones_for_account(zones, account_label=target_acc.label)
                self._send_json(200, {
                    "success": True,
                    "label": target_acc.label,
                    "zones_count": len(zones),
                    "total_domains": total_zones,
                })
            except Exception as exc:
                self._send_json(500, {"error": f"Gagal sinkronisasi domain akun '{target_acc.label}': {str(exc)}"})

        elif path == "/api/accounts/delete":
            label = body.get("label", "").strip()
            if not label:
                self._send_json(400, {"error": "Nama label akun wajib diisi"})
                return

            acc_obj = active_session.get_account_by_label(label)
            if acc_obj:
                active_session.remove_account(acc_obj.account_id)
            config_manager.delete_profile(label)
            # Prune orphan domains from this account
            pruned = config_manager.prune_orphan_cached_domains()
            self._send_json(200, {"success": True, "pruned_domains": pruned})

        elif path == "/api/domains/clean-cache":
            pruned = config_manager.prune_orphan_cached_domains()
            cache = config_manager.load_cached_domains()
            self._send_json(200, {"success": True, "pruned_count": pruned, "remaining_count": len(cache.get("zones", []))})

        elif path == "/api/domains/refresh":
            # Fetch zones from Cloudflare directly (supports single account or all accounts)
            account_id = body.get("account_id", "all")
            try:
                if account_id and account_id != "all":
                    target_acc = active_session.get_account(account_id) or active_session.get_account_by_label(account_id)
                    if not target_acc:
                        self._send_json(400, {"error": f"Akun '{account_id}' tidak ditemukan dalam sesi"})
                        return
                    zones = _fetch_zones_for_single_account(account_id=target_acc.account_id, account_label=target_acc.label)
                    total_count = config_manager.merge_cached_zones_for_account(zones, account_label=target_acc.label)
                    self._send_json(200, {"success": True, "count": total_count, "account_zones": len(zones), "label": target_acc.label})
                else:
                    zones = fetch_all_zones(status_filter="all", account_id="all")
                    cache = config_manager.load_cached_domains()
                    targets = cache.get("targets", {})
                    checks = cache.get("redirect_checks", {})
                    config_manager.save_cached_domains(zones, targets=targets, redirect_checks=checks)
                    self._send_json(200, {"success": True, "count": len(zones)})
            except Exception as exc:
                self._send_json(500, {"error": str(exc)})

        elif path == "/api/system/restart":
            self._send_json(200, {"success": True, "message": "Server sedang memuat ulang..."})
            def _delayed_restart():
                time.sleep(0.5)
                try:
                    os.execv(sys.executable, [sys.executable] + sys.argv)
                except Exception as ex:
                    print(f"[RESTART ERROR] {ex}")
            threading.Thread(target=_delayed_restart, daemon=True).start()

        elif path == "/api/redirect/trace-single":
            domain = body.get("domain", "").strip()
            if not domain:
                self._send_json(400, {"error": "Domain tidak boleh kosong"})
                return

            try:
                res = check_live_redirect(domain)
            except Exception as exc:
                res = {
                    "domain": domain,
                    "status_code": None,
                    "target_url": "",
                    "final_url": "",
                    "hops": 0,
                    "is_multiple": False,
                    "has_redirect": False,
                    "chain": [],
                    "checked_at": "",
                    "error": str(exc),
                    "bypassed_nawala": False,
                }

            config_manager.update_cached_redirect_check(domain, res)
            self._send_json(200, res)

        elif path == "/api/redirect/check-live/cancel":
            task_id = body.get("task_id", "").strip()
            with TASKS_LOCK:
                if task_id in TASKS:
                    TASKS[task_id]["status"] = "cancelled"
                    TASKS[task_id]["cancelled"] = True
                    self._send_json(200, {"success": True, "message": "Pengecekan live berhasil dibatalkan."})
                else:
                    self._send_json(404, {"error": "Task ID tidak ditemukan"})

        elif path == "/api/redirect/check-live":
            domains = body.get("domains", [])
            if not domains:
                self._send_json(400, {"error": "Daftar domain kosong"})
                return

            task_id = str(uuid.uuid4())
            register_background_task(task_id, {
                "status": "running",
                "current": 0,
                "total": len(domains),
                "current_domain": "",
                "results": {},
                "error": None,
                "cancelled": False,
            })

            # Launch background worker thread
            def run_scan(tid: str, doms: list):
                results = {}
                worker_check = check_live_redirect

                try:
                    with ThreadPoolExecutor(max_workers=15) as executor:
                        future_to_dom = {executor.submit(worker_check, d): d for d in doms}
                        idx = 0
                        for future in as_completed(future_to_dom):
                            with TASKS_LOCK:
                                if TASKS.get(tid, {}).get("cancelled"):
                                    for f in future_to_dom:
                                        f.cancel()
                                    break

                            d = future_to_dom[future]
                            idx += 1
                            try:
                                res = future.result()
                            except Exception as e:
                                res = {"domain": d, "has_redirect": False, "hops": 0, "is_multiple": False, "error": str(e)}

                            results[d.lower()] = res
                            with TASKS_LOCK:
                                if tid in TASKS and not TASKS[tid].get("cancelled"):
                                    TASKS[tid]["current"] = idx
                                    TASKS[tid]["current_domain"] = d
                                    TASKS[tid]["results"][d.lower()] = res

                            # Batch save every 25 domains
                            if idx % 25 == 0 or idx == len(doms):
                                config_manager.save_cached_redirect_checks(results)

                    with TASKS_LOCK:
                        if tid in TASKS and not TASKS[tid].get("cancelled"):
                            TASKS[tid]["status"] = "completed"
                            TASKS[tid]["results"] = results
                except Exception as exc:
                    with TASKS_LOCK:
                        if tid in TASKS and not TASKS[tid].get("cancelled"):
                            TASKS[tid]["status"] = "error"
                            TASKS[tid]["error"] = str(exc)

            threading.Thread(target=run_scan, args=(task_id, domains), daemon=True).start()
            self._send_json(200, {"task_id": task_id, "total": len(domains)})

        elif path == "/api/redirect/single":
            zone_id = body.get("zone_id", "").strip()
            source = body.get("source_hostname", "").strip()
            dest = body.get("destination_url", "").strip()
            is_delete = body.get("delete") is True or str(body.get("delete", "")).lower() == "true"
            account_id = body.get("account_id")

            if not zone_id or not source:
                self._send_json(400, {"error": "Data zona atau nama domain tidak lengkap"})
                return

            try:
                if is_delete:
                    count = delete_matching_redirects_for_domain(zone_id, source, account_id=account_id)
                    config_manager.update_cached_target(zone_id, None)
                    config_manager.save_cached_redirect_checks({
                        source.lower(): {
                            "domain": source,
                            "status_code": 200,
                            "target_url": "",
                            "hops": 0,
                            "has_redirect": False,
                            "is_multiple": False,
                            "chain": [],
                            "bypassed_nawala": False,
                        }
                    })
                    self._send_json(200, {"success": True, "message": f"{count} aturan redirect dihapus."})
                else:
                    if not dest or dest in ("", "-"):
                        self._send_json(400, {"error": "Masukkan URL tujuan redirect yang valid"})
                        return
                    norm_target, _ = validate_destination_url(dest, source_host=source)
                    create_redirect_rule(
                        zone_id=zone_id,
                        source_hostname=source,
                        destination_url=norm_target,
                        status_code=301,
                        account_id=account_id,
                        clean_conflicts=True,
                    )
                    config_manager.update_cached_target(zone_id, norm_target)
                    config_manager.save_cached_redirect_checks({
                        source.lower(): {
                            "domain": source,
                            "status_code": 301,
                            "target_url": norm_target,
                            "hops": 1,
                            "has_redirect": True,
                            "is_multiple": False,
                            "chain": [norm_target],
                            "bypassed_nawala": False,
                        }
                    })
                    self._send_json(200, {"success": True, "target": norm_target})
            except Exception as exc:
                self._send_json(400, {"error": str(exc)})

        elif path == "/api/redirect/bulk":
            items = body.get("items", [])
            preserve_path = body.get("preserve_path", False)
            if not items:
                self._send_json(400, {"error": "Daftar item redirect kosong"})
                return

            success = 0
            failed = 0
            errors = []
            applied = {}

            for item in items:
                zid = item.get("zone_id")
                source = item.get("source")
                dest = item.get("target")
                acc_id = item.get("account_id")
                acc_label = item.get("account_label")

                # Auto-resolve zone from source domain if zone_id was not provided
                if (not zid or not acc_id) and source:
                    cache = config_manager.load_cached_domains()
                    cached_zones = cache.get("zones", [])
                    found_acc, _, found_z, _ = find_zone_across_accounts(source, cached_zones=cached_zones)
                    if found_z:
                        zid = zid or get_zone_attr(found_z, "id")
                        acc_id = acc_id or found_acc

                try:
                    norm_dest, _ = validate_destination_url(dest, source_host=source)
                    create_redirect_rule(
                        zone_id=zid,
                        source_hostname=source,
                        destination_url=norm_dest,
                        status_code=301,
                        preserve_path=preserve_path,
                        account_id=acc_id,
                        clean_conflicts=True,
                    )
                    success += 1
                    applied[zid] = norm_dest
                except Exception as exc:
                    failed += 1
                    errors.append(f"{source}: {str(exc)}")

            # Update cache with applied targets and optimistic redirect checks
            if applied:
                cache = config_manager.load_cached_domains()
                zones = cache.get("zones", [])
                targets = cache.get("targets", {})
                targets.update(applied)

                checks_update = {}
                for item in items:
                    zid = item.get("zone_id")
                    s = item.get("source")
                    if zid in applied and s:
                        norm_target = applied[zid]
                        checks_update[s.lower()] = {
                            "domain": s,
                            "target_url": norm_target,
                            "status_code": 301,
                            "hops": 1,
                            "has_redirect": True,
                            "is_multiple": False,
                            "chain": [norm_target],
                            "bypassed_nawala": False,
                        }
                        # Also update corresponding zone name if different from source
                        for z in zones:
                            if get_zone_attr(z, "id") == zid:
                                z_name = get_zone_attr(z, "name")
                                if z_name and z_name.lower() != s.lower():
                                    checks_update[z_name.lower()] = {
                                        "domain": z_name,
                                        "target_url": norm_target,
                                        "status_code": 301,
                                        "hops": 1,
                                        "has_redirect": True,
                                        "is_multiple": False,
                                        "chain": [norm_target],
                                        "bypassed_nawala": False,
                                    }
                                break

                config_manager.save_cached_domains(zones, targets=targets, redirect_checks=checks_update)

            self._send_json(200, {
                "success": success,
                "failed": failed,
                "errors": errors,
            })

        elif path == "/api/redirect/delete-bulk":
            zones_to_del = body.get("zones", [])
            if not zones_to_del:
                self._send_json(400, {"error": "Daftar zona kosong"})
                return

            total_deleted = 0
            checks_update = {}
            for z in zones_to_del:
                zid = z.get("id")
                zname = z.get("name")
                acc_id = z.get("account_id")
                try:
                    cnt = delete_matching_redirects_for_domain(zid, zname, account_id=acc_id)
                    total_deleted += cnt
                    config_manager.update_cached_target(zid, None)
                    if zname:
                        checks_update[zname.lower()] = {
                            "domain": zname,
                            "status_code": 200,
                            "target_url": "",
                            "hops": 0,
                            "has_redirect": False,
                            "is_multiple": False,
                            "chain": [],
                            "bypassed_nawala": False,
                        }
                except Exception:
                    pass

            if checks_update:
                config_manager.save_cached_redirect_checks(checks_update)

            self._send_json(200, {"success": True, "deleted_rules": total_deleted})

        else:
            self._send_json(404, {"error": f"Endpoint POST {path} tidak ditemukan"})


def run_server(port: int = 5050, open_browser: bool = True):
    """Starts local server on 127.0.0.1:port."""
    init_session_from_config()
    server_address = ("127.0.0.1", port)

    try:
        httpd = ThreadingHTTPServer(server_address, FlareWebHandler)
    except OSError as e:
        # Fallback to alternate port if 5050 is in use
        if port == 5050:
            return run_server(port=5051, open_browser=open_browser)
        raise e

    url = f"http://localhost:{port}"
    print("=" * 66)
    print("  ⚡ FLAREREDIRECT LOCAL WEB DASHBOARD (HTML5 + FAST ENGINE)")
    print("=" * 66)
    print(f"  URL Dashboard Lokal : {url}")
    print(f"  Penyimpanan Data   : {config_manager.get_domains_cache_path()}")
    print("  Tekan Ctrl + C di terminal ini untuk mematikan server.")
    print("=" * 66)

    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[INFO] Server dimatikan oleh pengguna.")
        httpd.server_close()


if __name__ == "__main__":
    # Check if port specified
    port = 5050
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    run_server(port=port)

