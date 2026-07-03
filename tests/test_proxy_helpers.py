from prevent_visit.config import AppConfig
from prevent_visit.proxy import ProxyServer


def test_intercepts_known_search_hosts() -> None:
    server = ProxyServer(AppConfig())
    assert server.should_intercept("www.google.com", 443) is True
    assert server.should_intercept("www.google.co.in", 443) is True
    assert server.should_intercept("mail.google.com", 443) is False
    assert server.should_intercept("docs.python.org", 443) is False


def test_intercepts_google_images_subdomains() -> None:
    """Google images subdomain should be intercepted for HTTPS."""
    server = ProxyServer(AppConfig())
    assert server.should_intercept("images.google.com", 443) is True
    assert server.should_intercept("www.google.com", 443) is True
    assert server.should_intercept("www.google.com", 80) is False  # Only HTTPS (443)


def test_intercepts_google_search_mobile() -> None:
    """Mobile search subdomains should be intercepted."""
    server = ProxyServer(AppConfig())
    assert server.should_intercept("www.google.com", 443) is True


def test_intercepts_all_configured_search_engines() -> None:
    """All configured search engines should be intercepted."""
    server = ProxyServer(AppConfig())
    # Google variants
    assert server.should_intercept("www.google.com", 443) is True
    assert server.should_intercept("www.google.co.in", 443) is True
    # Bing
    assert server.should_intercept("www.bing.com", 443) is True
    # DuckDuckGo
    assert server.should_intercept("www.duckduckgo.com", 443) is True
    # Yahoo
    assert server.should_intercept("search.yahoo.com", 443) is True
    # Brave
    assert server.should_intercept("search.brave.com", 443) is True
    # Startpage
    assert server.should_intercept("www.startpage.com", 443) is True
    # Yandex
    assert server.should_intercept("www.yandex.com", 443) is True
    # Ecosia
    assert server.should_intercept("www.ecosia.org", 443) is True


def test_does_not_intercept_non_search_domains() -> None:
    """Non-search domains should NOT be intercepted."""
    server = ProxyServer(AppConfig())
    assert server.should_intercept("mail.google.com", 443) is False
    assert server.should_intercept("drive.google.com", 443) is False
    assert server.should_intercept("docs.google.com", 443) is False
    assert server.should_intercept("calendar.google.com", 443) is False
    assert server.should_intercept("github.com", 443) is False
    assert server.should_intercept("stackoverflow.com", 443) is False
    assert server.should_intercept("youtube.com", 443) is False
    assert server.should_intercept("twitter.com", 443) is False
    assert server.should_intercept("facebook.com", 443) is False


def test_does_not_intercept_http_port_80() -> None:
    """Only HTTPS port 443 should be intercepted."""
    server = ProxyServer(AppConfig())
    assert server.should_intercept("www.google.com", 80) is False
    assert server.should_intercept("www.bing.com", 80) is False
    assert server.should_intercept("www.google.com", 8080) is False
    assert server.should_intercept("www.google.com", 8443) is False


def test_split_head_body() -> None:
    head, body = ProxyServer.split_head_body(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\npayload"
    )
    assert head.endswith(b"\r\n\r\n")
    assert body == b"payload"
