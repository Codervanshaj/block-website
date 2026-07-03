from prevent_visit.config import AppConfig
from prevent_visit.proxy import ProxyServer


def test_intercepts_known_search_hosts() -> None:
    server = ProxyServer(AppConfig())
    assert server.should_intercept("www.google.com", 443) is True
    assert server.should_intercept("www.google.co.in", 443) is True
    assert server.should_intercept("mail.google.com", 443) is False
    assert server.should_intercept("docs.python.org", 443) is False


def test_split_head_body() -> None:
    head, body = ProxyServer.split_head_body(
        b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\npayload"
    )
    assert head.endswith(b"\r\n\r\n")
    assert body == b"payload"
