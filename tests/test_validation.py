"""Unit tests for domain and URL validation, IDNA conversion, loop detection, and escaping.
"""

import pytest
from src.security.validation import (
    normalize_hostname,
    clean_domain_input,
    validate_destination_url,
    build_cloudflare_expression,
    validate_status_code,
    escape_cloudflare_string,
    check_domain_public_ip,
    is_cloudflare_ip,
)
from src.utils.errors import ValidationError


def test_normalize_hostname_valid():
    assert normalize_hostname("example.com") == "example.com"
    assert normalize_hostname("SUB.EXAMPLE.COM") == "sub.example.com"
    assert normalize_hostname("  blog.domain.co.id  ") == "blog.domain.co.id"


def test_normalize_hostname_idna():
    # münchen.de -> xn--mnchen-3ya.de
    punycode = normalize_hostname("münchen.de")
    assert punycode == "xn--mnchen-3ya.de"


def test_normalize_hostname_invalid():
    with pytest.raises(ValidationError):
        normalize_hostname("")

    with pytest.raises(ValidationError):
        normalize_hostname("   ")

    with pytest.raises(ValidationError):
        normalize_hostname("-invalid.com")

    with pytest.raises(ValidationError):
        normalize_hostname("domain with space.com")

    with pytest.raises(ValidationError):
        normalize_hostname("domain\nnewline.com")


def test_validate_destination_url_valid():
    url, is_sub = validate_destination_url("https://target.com/page", source_host="example.com")
    assert url == "https://target.com/page"
    assert not is_sub

    # Automatically prepends https:// if missing
    url2, _ = validate_destination_url("destination.org")
    assert url2 == "https://destination.org/"


def test_validate_destination_url_subdomain_warning():
    _, is_sub = validate_destination_url("https://sub.example.com", source_host="example.com")
    assert is_sub is True


def test_validate_destination_url_loop_rejection():
    # Exact same host and root path must raise ValidationError
    with pytest.raises(ValidationError, match="Loop redirect terdeteksi"):
        validate_destination_url("https://example.com/", source_host="example.com")


def test_validate_destination_url_scheme_restriction():
    with pytest.raises(ValidationError, match="Skema 'ftp' tidak diizinkan"):
        validate_destination_url("ftp://files.example.com/file.zip")

    with pytest.raises(ValidationError, match="Skema 'javascript' tidak diizinkan"):
        validate_destination_url("javascript:alert(1)")


def test_validate_destination_url_credentials_rejection():
    with pytest.raises(ValidationError, match="kredensial pengguna"):
        validate_destination_url("https://user:password@target.com")


def test_validate_destination_url_control_characters():
    with pytest.raises(ValidationError, match="karakter kontrol"):
        validate_destination_url("https://target.com/\x00malicious")


def test_escape_cloudflare_string():
    raw = 'test"domain\\name'
    escaped = escape_cloudflare_string(raw)
    assert escaped == 'test\\"domain\\\\name'


def test_build_cloudflare_expression():
    expr = build_cloudflare_expression("old.example.com")
    assert expr == 'http.host eq "old.example.com"'

    expr_idna = build_cloudflare_expression("münchen.de")
    assert expr_idna == 'http.host eq "xn--mnchen-3ya.de"'


def test_validate_status_code():
    assert validate_status_code(301) == 301

    with pytest.raises(ValidationError, match="301"):
        validate_status_code(302)

    with pytest.raises(ValidationError):
        validate_status_code(200)

    with pytest.raises(ValidationError):
        validate_status_code(404)


def test_clean_domain_input():
    assert clean_domain_input("example.com") == "example.com"
    assert clean_domain_input("www.example.com") == "example.com"
    assert clean_domain_input("https://www.example.com/some/path?q=1") == "example.com"
    assert clean_domain_input("http://sub.example.com:8080/") == "sub.example.com"
    assert clean_domain_input("  www.münchen.de  ") == "xn--mnchen-3ya.de"

    with pytest.raises(ValidationError):
        clean_domain_input("")


def test_check_domain_public_ip(monkeypatch):
    monkeypatch.setattr("socket.gethostbyname", lambda host: "104.21.48.12")
    ip = check_domain_public_ip("example.com")
    assert ip == "104.21.48.12"

    monkeypatch.setattr("socket.gethostbyname", lambda host: (_ for _ in ()).throw(Exception("DNS Fail")))
    ip_fail = check_domain_public_ip("invalid-domain-xyz.com")
    assert ip_fail == "Gagal Resolusi IP"


def test_is_cloudflare_ip():
    assert is_cloudflare_ip("104.21.48.12") is True
    assert is_cloudflare_ip("172.67.180.2") is True
    assert is_cloudflare_ip("188.114.96.1") is True
    assert is_cloudflare_ip("1.1.1.1") is False
    assert is_cloudflare_ip("8.8.8.8") is False
    assert is_cloudflare_ip("Gagal Resolusi IP") is False


def test_check_live_redirect_single_301(monkeypatch):
    import httpx
    from src.security.validation import check_live_redirect

    class MockResponse:
        def __init__(self, url, status_code, history=None):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.history = history or []

    class MockHistoryItem:
        def __init__(self, url, status_code, location):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.headers = {"Location": location}

    def fake_get(url, *args, **kwargs):
        hist = [MockHistoryItem("https://mysite.com", 301, "https://destination.com/landing")]
        return MockResponse("https://destination.com/landing", 200, history=hist)

    monkeypatch.setattr("httpx.Client.get", fake_get)

    res = check_live_redirect("mysite.com")
    assert res["domain"] == "mysite.com"
    assert res["status_code"] == 301
    assert res["target_url"] == "https://destination.com/landing"
    assert res["hops"] == 1
    assert res["is_multiple"] is False
    assert res["has_redirect"] is True


def test_check_live_redirect_multiple_hops(monkeypatch):
    import httpx
    from src.security.validation import check_live_redirect

    class MockResponse:
        def __init__(self, url, status_code, history=None):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.history = history or []

    class MockHistoryItem:
        def __init__(self, url, status_code, location):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.headers = {"Location": location}

    def fake_get(url, *args, **kwargs):
        hist = [
            MockHistoryItem("https://mysite.com", 301, "https://intermediate.com"),
            MockHistoryItem("https://intermediate.com", 302, "https://finaltarget.com"),
        ]
        return MockResponse("https://finaltarget.com", 200, history=hist)

    monkeypatch.setattr("httpx.Client.get", fake_get)

    res = check_live_redirect("mysite.com")
    assert res["hops"] == 2
    assert res["is_multiple"] is True  # Alert trigger!
    assert res["status_code"] == 301
    assert "https://finaltarget.com" in res["target_url"]


def test_check_live_redirect_no_redirect(monkeypatch):
    import httpx
    from src.security.validation import check_live_redirect

    class MockResponse:
        def __init__(self, url, status_code):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.history = []

    def fake_get(url, *args, **kwargs):
        return MockResponse("https://directsite.com", 200)

    monkeypatch.setattr("httpx.Client.get", fake_get)

    res = check_live_redirect("directsite.com")
    assert res["hops"] == 0
    assert res["is_multiple"] is False
    assert res["has_redirect"] is False
    assert res["status_code"] == 200
    assert res["target_url"] == ""


def test_check_live_redirect_apex_to_www_is_200_ok(monkeypatch):
    """Verifies that apex to www (or www to apex) redirect is treated as 200 OK (no external redirect)."""
    import httpx
    from src.security.validation import check_live_redirect

    class MockResponse:
        def __init__(self, url, status_code, history=None):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.history = history or []

    class MockHistoryItem:
        def __init__(self, url, status_code, location):
            self.url = httpx.URL(url)
            self.status_code = status_code
            self.headers = {"Location": location}

    def fake_get(url, *args, **kwargs):
        # http://mybrand.com -> https://www.mybrand.com/ (canonical apex to www)
        hist = [MockHistoryItem("http://mybrand.com", 301, "https://www.mybrand.com/")]
        return MockResponse("https://www.mybrand.com/", 200, history=hist)

    monkeypatch.setattr("httpx.Client.get", fake_get)

    res = check_live_redirect("mybrand.com")
    assert res["domain"] == "mybrand.com"
    assert res["status_code"] == 200
    assert res["target_url"] == ""
    assert res["hops"] == 0
    assert res["has_redirect"] is False
    assert res["is_multiple"] is False


def test_check_live_redirect_nawala_bypass(monkeypatch):
    """Verifies that when ISP intercepts or drops connection, DoH fallback resolves real redirect."""
    import httpx
    from src.security.validation import check_live_redirect

    # Simulate standard connection failing with ConnectTimeout (typical Nawala behavior)
    def fake_get_fail(*args, **kwargs):
        raise httpx.ConnectTimeout("Connection timed out (Nawala block)")

    monkeypatch.setattr("httpx.Client.get", fake_get_fail)

    # Mock DoH resolver returning Cloudflare IP
    monkeypatch.setattr("src.security.validation.resolve_doh_ips", lambda d, timeout=3.0: ["104.21.1.1"])

    # Mock trace_doh_chain finding 301 redirect
    def fake_doh_chain(domain, timeout=4.0):
        return {
            "domain": domain,
            "status_code": 301,
            "target_url": "https://realdestination.com/target",
            "final_url": "https://realdestination.com/target",
            "hops": 1,
            "is_multiple": False,
            "has_redirect": True,
            "chain": ["https://realdestination.com/target"],
            "bypassed_nawala": True,
            "error": None,
        }

    monkeypatch.setattr("src.security.validation.trace_doh_chain", fake_doh_chain)

    res = check_live_redirect("blockedgamblingsite.com")
    assert res["status_code"] == 301
    assert res["target_url"] == "https://realdestination.com/target"
    assert res["hops"] == 1
    assert res["bypassed_nawala"] is True
    assert res["error"] is None


