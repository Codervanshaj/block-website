from __future__ import annotations

import json
import select
import socket
import socketserver
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from .certs import CertificateManager
from .config import AppConfig
from .rules import Decision, RuleSet


BUFFER_SIZE = 65536
SOCKET_TIMEOUT = 20


@dataclass(slots=True)
class BlockEvent:
    timestamp_utc: str
    client: str
    method: str
    target: str
    reason: str
    matched_value: str | None


class BlockLogger:
    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: BlockEvent) -> None:
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(asdict(event)) + "\n")


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], handler_class, proxy_server: "ProxyServer") -> None:
        self.proxy_server = proxy_server
        super().__init__(server_address, handler_class)

    def server_bind(self) -> None:
        if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        super().server_bind()


class ProxyRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(SOCKET_TIMEOUT)
        proxy_server: ProxyServer = self.server.proxy_server
        client = self.client_address[0] if self.client_address else "unknown"

        try:
            request_data = self._recv_until_headers(self.request)
        except OSError:
            return

        if not request_data:
            return

        header_text, body = proxy_server.split_head_body(request_data)
        lines = header_text.decode("iso-8859-1", errors="replace").split("\r\n")
        if not lines or not lines[0]:
            return

        parts = lines[0].split()
        if len(parts) < 3:
            return

        method, target, _ = parts
        headers = proxy_server.parse_headers(lines[1:])

        if method.upper() == "CONNECT":
            self._handle_connect(proxy_server, client, target)
            return

        self._handle_http(proxy_server, client, method, target, headers, header_text, body)

    def _handle_http(
        self,
        proxy_server: "ProxyServer",
        client: str,
        method: str,
        target: str,
        headers: dict[str, str],
        header_text: bytes,
        body: bytes,
    ) -> None:
        host = headers.get("host", "")
        url = target if "://" in target else f"http://{host}{target}"
        decision = proxy_server.rules.match_url(url, host_hint=host, body=body, headers=headers)
        if decision.blocked:
            proxy_server.write_decision_response(self.request, decision, client, method, url)
            return

        parsed = urlsplit(url)
        port = parsed.port or 80
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        rewritten_head = proxy_server.rewrite_request_head(
            header_text.decode("iso-8859-1", errors="replace"),
            method,
            path,
        ).encode("iso-8859-1")
        outbound = rewritten_head + body

        with socket.create_connection((parsed.hostname, port), timeout=SOCKET_TIMEOUT) as upstream:
            upstream.settimeout(SOCKET_TIMEOUT)
            upstream.sendall(outbound)
            self._bridge(self.request, upstream)

    def _handle_connect(self, proxy_server: "ProxyServer", client: str, target: str) -> None:
        host, _, port_text = target.partition(":")
        port = int(port_text or "443")
        decision = proxy_server.rules.match_host(host)
        if decision.blocked:
            proxy_server.write_decision_response(self.request, decision, client, "CONNECT", target)
            return

        if proxy_server.should_intercept(host, port):
            self._handle_intercept_connect(proxy_server, client, host, port)
            return

        with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as upstream:
            upstream.settimeout(SOCKET_TIMEOUT)
            self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            self._bridge(self.request, upstream)

    def _handle_intercept_connect(
        self,
        proxy_server: "ProxyServer",
        client: str,
        host: str,
        port: int,
    ) -> None:
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        cert_path = proxy_server.certificate_manager.get_or_create_leaf_cert(host)
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_context.load_cert_chain(
            certfile=str(cert_path),
            keyfile=str(proxy_server.certificate_manager.leaf_key_path),
        )

        tls_client = client_context.wrap_socket(self.request, server_side=True)
        try:
            request_data = self._recv_until_headers(tls_client)
            if not request_data:
                return

            header_text, body = proxy_server.split_head_body(request_data)
            lines = header_text.decode("iso-8859-1", errors="replace").split("\r\n")
            parts = lines[0].split()
            if len(parts) < 3:
                return

            headers = proxy_server.parse_headers(lines[1:])
            method, target, _ = parts
            full_url = f"https://{host}{target}"
            decision = proxy_server.rules.match_url(full_url, host_hint=host, body=body, headers=headers)
            if decision.blocked:
                proxy_server.write_decision_response(tls_client, decision, client, method, full_url)
                return

            rewritten_head = proxy_server.rewrite_request_head(
                header_text.decode("iso-8859-1", errors="replace"),
                method,
                target,
            ).encode("iso-8859-1")
            outbound = rewritten_head + body

            upstream_context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=SOCKET_TIMEOUT) as upstream_socket:
                with upstream_context.wrap_socket(upstream_socket, server_hostname=host) as tls_upstream:
                    tls_upstream.settimeout(SOCKET_TIMEOUT)
                    tls_upstream.sendall(outbound)
                    self._bridge(tls_client, tls_upstream)
        finally:
            try:
                tls_client.close()
            except OSError:
                pass

    def _recv_until_headers(self, conn: socket.socket | ssl.SSLSocket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(BUFFER_SIZE)
            if not chunk:
                break
            data += chunk
            if len(data) > 1024 * 1024:
                break
        return data

    def _bridge(self, left: socket.socket | ssl.SSLSocket, right: socket.socket | ssl.SSLSocket) -> None:
        sockets = [left, right]
        while True:
            readable, _, exceptional = select.select(sockets, [], sockets, SOCKET_TIMEOUT)
            if exceptional:
                break
            if not readable:
                break
            for source in readable:
                target = right if source is left else left
                try:
                    chunk = source.recv(BUFFER_SIZE)
                except OSError:
                    return
                if not chunk:
                    return
                try:
                    target.sendall(chunk)
                except OSError:
                    return


class ProxyServer:
    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.rules = RuleSet(config)
        self.logger = BlockLogger(config.log_path)
        self.certificate_manager = CertificateManager(config)
        self.server: ThreadedTCPServer | None = None
        self.intercept_hosts = {item.lower() for item in config.intercept_search_hosts}

    def run(self) -> None:
        self.certificate_manager.ensure_root_ca()
        try:
            self.server = ThreadedTCPServer(
                (self.config.proxy_host, self.config.proxy_port),
                ProxyRequestHandler,
                self,
            )
        except OSError as exc:
            host = self.config.proxy_host
            port = self.config.proxy_port
            raise RuntimeError(
                f"Prevent Visit could not start because {host}:{port} is already in use."
            ) from exc
        self.server.serve_forever()

    def should_intercept(self, host: str, port: int) -> bool:
        lowered = host.lower()
        return port == 443 and lowered in self.intercept_hosts

    def write_decision_response(
        self,
        conn: socket.socket | ssl.SSLSocket,
        decision: Decision,
        client: str,
        method: str,
        target: str,
    ) -> None:
        self.logger.write(
            BlockEvent(
                timestamp_utc=datetime.now(timezone.utc).isoformat(),
                client=client,
                method=method,
                target=target,
                reason=decision.reason,
                matched_value=decision.matched_value,
            )
        )
        if decision.reason in {"blocked-keyword", "blocked-search-query"}:
            body = self._build_empty_results_page()
            status_line = "HTTP/1.1 200 OK"
        else:
            body = self._build_block_page(decision)
            status_line = "HTTP/1.1 403 Forbidden"

        payload = (
            f"{status_line}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body.encode('utf-8'))}\r\n"
            "Connection: close\r\n\r\n"
            f"{body}"
        )
        conn.sendall(payload.encode("utf-8"))
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()

    @staticmethod
    def split_head_body(raw_request: bytes) -> tuple[bytes, bytes]:
        if b"\r\n\r\n" not in raw_request:
            return raw_request, b""
        head, body = raw_request.split(b"\r\n\r\n", 1)
        return head + b"\r\n\r\n", body

    def _build_empty_results_page(self) -> str:
        return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>No results</title>
  <style>
    body {
      margin: 0;
      background: #f8fafc;
      color: #0f172a;
      font-family: "Segoe UI", sans-serif;
      display: grid;
      place-items: center;
      min-height: 100vh;
    }
    .shell {
      width: min(760px, calc(100vw - 32px));
      background: #ffffff;
      border: 1px solid #dbe3ef;
      border-radius: 18px;
      padding: 40px;
      box-shadow: 0 20px 50px rgba(15, 23, 42, 0.08);
    }
    h1 { margin: 0 0 12px; font-size: 2rem; }
    p { margin: 0; line-height: 1.7; color: #475569; }
  </style>
</head>
<body>
  <div class="shell">
    <h1>No results found</h1>
    <p>Your local protection rules filtered this search request, so no matching results were returned.</p>
  </div>
</body>
</html>"""

    def _build_block_page(self, decision: Decision) -> str:
        matched = decision.matched_value or "adult-content rule"
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{self.config.block_page_title}</title>
  <style>
    body {{
      margin: 0;
      font-family: "Segoe UI", sans-serif;
      background: linear-gradient(135deg, #111827, #1f2937);
      color: #f9fafb;
      display: grid;
      place-items: center;
      min-height: 100vh;
    }}
    .card {{
      width: min(640px, calc(100vw - 32px));
      background: rgba(17, 24, 39, 0.92);
      border: 1px solid rgba(255, 255, 255, 0.08);
      border-radius: 20px;
      padding: 32px;
      box-shadow: 0 30px 70px rgba(0, 0, 0, 0.45);
    }}
    h1 {{ margin-top: 0; font-size: 2rem; }}
    p {{ line-height: 1.65; color: #d1d5db; }}
    code {{
      background: rgba(255, 255, 255, 0.08);
      border-radius: 8px;
      padding: 2px 8px;
      color: #fef3c7;
    }}
  </style>
</head>
<body>
  <div class="card">
    <h1>{self.config.block_page_title}</h1>
    <p>{self.config.block_page_message}</p>
    <p>Matched rule: <code>{decision.reason}</code></p>
    <p>Matched value: <code>{matched}</code></p>
  </div>
</body>
</html>"""

    @staticmethod
    def parse_headers(lines: list[str]) -> dict[str, str]:
        headers: dict[str, str] = {}
        for line in lines:
            if not line or ":" not in line:
                continue
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()
        return headers

    @staticmethod
    def rewrite_request_head(request_head: str, method: str, path: str) -> str:
        lines = request_head.split("\r\n")
        if not lines:
            return request_head
        parts = lines[0].split()
        if len(parts) == 3:
            lines[0] = f"{method} {path} {parts[2]}"

        filtered: list[str] = []
        saw_connection = False
        for line in lines[1:]:
            if not line:
                continue
            if line.lower().startswith("proxy-connection:"):
                continue
            if line.lower().startswith("connection:"):
                filtered.append("Connection: close")
                saw_connection = True
                continue
            filtered.append(line)
        if not saw_connection:
            filtered.append("Connection: close")
        return "\r\n".join([lines[0], *filtered, "", ""])
