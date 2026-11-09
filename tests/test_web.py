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
