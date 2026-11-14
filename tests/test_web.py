"""Unit and integration tests for FlareRedirect Local Web Server.
Tests all static file serving and JSON REST API endpoints.
"""

import json
import socket
import threading
import urllib.request
import urllib.error
import pytest
from http.server import ThreadingHTTPServer

from web.server import FlareWebHandler, init_session_from_config
from src import config_manager
from src.security.session import active_session


@pytest.fixture(scope="module")
def web_server():
    """Starts FlareWebHandler on a random free localhost port for tests."""
    init_session_from_config()

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()

    server = ThreadingHTTPServer(("127.0.0.1", port), FlareWebHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    yield base_url

    server.shutdown()
    server.server_close()


def http_get(url: str):
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.getcode(), response.read().decode("utf-8"), response.headers


def http_post(url: str, data: dict):
    body = json.dumps(data).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.getcode(), json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read().decode("utf-8"))


# --- STATIC ASSET TESTS ---

def test_static_index_html(web_server):
    code, body, headers = http_get(f"{web_server}/")
    assert code == 200
    assert "text/html" in headers.get("Content-Type", "")
    assert "FlareRedirect Web" in body


def test_static_css(web_server):
    code, body, headers = http_get(f"{web_server}/css/style.css")
    assert code == 200
    assert "text/css" in headers.get("Content-Type", "")
    assert "--ground" in body


def test_static_js(web_server):
    code, body, headers = http_get(f"{web_server}/js/main.js")
    assert code == 200
    assert "FlareRedirect Web" in body


# --- API GET TESTS ---

def test_api_status(web_server):
    code, body, _ = http_get(f"{web_server}/api/status")
    assert code == 200
    data = json.loads(body)
    assert "connected" in data
    assert "accounts" in data
    assert "total_domains" in data
    assert isinstance(data["accounts"], list)


def test_api_domains(web_server):
    code, body, _ = http_get(f"{web_server}/api/domains")
    assert code == 200
    data = json.loads(body)
    assert "zones" in data
    assert "targets" in data
    assert "redirect_checks" in data
    assert "total" in data
    assert isinstance(data["zones"], list)


def test_api_accounts(web_server):
    code, body, _ = http_get(f"{web_server}/api/accounts")
    assert code == 200
    data = json.loads(body)
    assert "accounts" in data
    assert isinstance(data["accounts"], list)


def test_api_get_404(web_server):
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        http_get(f"{web_server}/api/non_existent_route")
    assert exc_info.value.code == 404


# --- API POST TESTS ---

def test_api_trace_single_empty(web_server):
    code, data = http_post(f"{web_server}/api/redirect/trace-single", {"domain": ""})
    assert code == 400
    assert "error" in data


def test_api_check_live_batch_empty(web_server):
    code, data = http_post(f"{web_server}/api/redirect/check-live", {"domains": []})
    assert code == 400
    assert "error" in data


def test_api_clean_cache(web_server):
    code, data = http_post(f"{web_server}/api/domains/clean-cache", {})
    assert code == 200
    assert data.get("success") is True
    assert "pruned_count" in data
    assert "remaining_count" in data


def test_api_single_redirect_missing_params(web_server):
    code, data = http_post(f"{web_server}/api/redirect/single", {"zone_id": ""})
    assert code == 400
    assert "error" in data

    # Test missing destination when delete is False
    code2, data2 = http_post(
        f"{web_server}/api/redirect/single",
        {"zone_id": "dummy_zone", "source_hostname": "test.com", "destination_url": "", "delete": False}
    )
    assert code2 == 400
    assert "URL tujuan" in data2.get("error", "")


def test_api_bulk_redirect_empty(web_server):
    code, data = http_post(f"{web_server}/api/redirect/bulk", {"items": []})
    assert code == 400
    assert "error" in data


def test_api_delete_bulk_empty(web_server):
    code, data = http_post(f"{web_server}/api/redirect/delete-bulk", {"zones": []})
    assert code == 400
    assert "error" in data


def test_api_accounts_switch_not_found(web_server):
    code, data = http_post(f"{web_server}/api/accounts/switch", {"label": "NON_EXISTENT_LABEL_XYZ"})
    assert code == 400
    assert "error" in data


def test_api_accounts_sync_not_found(web_server):
    code, data = http_post(f"{web_server}/api/accounts/sync", {"label": "NON_EXISTENT_LABEL_XYZ"})
    assert code == 400
    assert "error" in data


def test_api_accounts_add_invalid_token(web_server):
    code, data = http_post(f"{web_server}/api/accounts/add", {
        "label": "InvalidAccountTest",
        "auth_method": "token",
        "token": "invalid_fake_token_12345"
    })
    # Must fail verification against Cloudflare API
    assert code == 400
    assert "error" in data


# --- SECURITY AUDIT REMEDIATION TESTS ---

def test_security_headers_present(web_server):
    code, _, headers = http_get(f"{web_server}/")
    assert code == 200
    assert headers.get("X-Frame-Options") == "DENY"
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "Content-Security-Policy" in headers


def test_csrf_untrusted_origin_rejected(web_server):
    # Cross-origin request from malicious external website must be blocked with 403 Forbidden
    body = json.dumps({"zones": []}).encode("utf-8")
    req = urllib.request.Request(
        f"{web_server}/api/redirect/delete-bulk",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Origin": "https://malicious-attacker-site.com"
        },
        method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    assert exc_info.value.code == 403


def test_cors_trusted_origin_accepted(web_server):
    # Request from valid local origin must be accepted and receive CORS headers
    body = json.dumps({"zones": []}).encode("utf-8")
    req = urllib.request.Request(
        f"{web_server}/api/redirect/delete-bulk",
        data=body,
        headers={
            "Content-Type": "application/json",
            "Origin": "http://127.0.0.1:5050"
        },
        method="POST"
    )
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req, timeout=5)
    # Expected 400 (empty zones) but NOT 403 (origin is trusted)
    assert exc_info.value.code == 400
    assert exc_info.value.headers.get("Access-Control-Allow-Origin") == "http://127.0.0.1:5050"


def test_api_check_live_cancel(web_server):
    code, data = http_post(f"{web_server}/api/redirect/check-live/cancel", {"task_id": "non_existent_tid"})
    assert code == 404
    assert "error" in data


def test_api_bulk_redirect_optimistic_cache_update(web_server, monkeypatch):
    import web.server
    monkeypatch.setattr(web.server, "create_redirect_rule", lambda **kwargs: True)

    payload = {
        "items": [
            {
                "zone_id": "test_z123",
                "source": "mytestdomain.com",
                "target": "https://brandnewtarget.com",
                "account_id": "acc_1",
                "account_label": "Akun 1"
            }
        ]
    }
    code, data = http_post(f"{web_server}/api/redirect/bulk", payload)
    assert code == 200
    assert data.get("success") == 1

    # Verify that cache now immediately contains the new target in both targets and redirect_checks
    code, dom_data = http_post(f"{web_server}/api/status", {}) # or check /api/domains
    req = urllib.request.Request(f"{web_server}/api/domains")
    with urllib.request.urlopen(req, timeout=5) as resp:
        domains_resp = json.loads(resp.read().decode("utf-8"))

    assert domains_resp["targets"].get("test_z123") == "https://brandnewtarget.com/"
    check = domains_resp["redirect_checks"].get("mytestdomain.com")
    assert check is not None
    assert check.get("target_url") == "https://brandnewtarget.com/"
    assert check.get("status_code") == 301
    assert check.get("has_redirect") is True


def test_api_single_redirect_optimistic_cache_update(web_server, monkeypatch):
    import web.server
    monkeypatch.setattr(web.server, "create_redirect_rule", lambda **kwargs: True)
    monkeypatch.setattr(web.server, "delete_matching_redirects_for_domain", lambda *args, **kwargs: 1)

    payload = {
        "zone_id": "test_z999",
        "source_hostname": "singletest.com",
        "destination_url": "https://dest999.com",
        "delete": False
    }
    code, data = http_post(f"{web_server}/api/redirect/single", payload)
    assert code == 200
    assert data.get("success") is True
    assert data.get("target") == "https://dest999.com/"

    req = urllib.request.Request(f"{web_server}/api/domains")
    with urllib.request.urlopen(req, timeout=5) as resp:
        domains_resp = json.loads(resp.read().decode("utf-8"))

    assert domains_resp["targets"].get("test_z999") == "https://dest999.com/"
    check = domains_resp["redirect_checks"].get("singletest.com")
    assert check is not None
    assert check.get("target_url") == "https://dest999.com/"
    assert check.get("status_code") == 301

    # Now test deletion
    payload_del = {
        "zone_id": "test_z999",
        "source_hostname": "singletest.com",
        "delete": True
    }
    code_del, data_del = http_post(f"{web_server}/api/redirect/single", payload_del)
    assert code_del == 200
    assert data_del.get("success") is True

    with urllib.request.urlopen(req, timeout=5) as resp:
        domains_resp2 = json.loads(resp.read().decode("utf-8"))

    assert "test_z999" not in domains_resp2["targets"]
    check_del = domains_resp2["redirect_checks"].get("singletest.com")
    assert check_del is not None
    assert check_del.get("status_code") == 200
    assert check_del.get("has_redirect") is False





