"""One-request direct HTTPS transport, with live operations behind an explicit injected seam.

Importing this module or constructing its synthetic test transport performs no network activity.
The system backend is usable only when a later owner authorization explicitly constructs it.
"""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import socket
import ssl
from typing import Any, Protocol

COMPONENT_ID = "vault-next-direct-https-transport"
COMPONENT_VERSION = "0.1.0"
REAL_COMPONENT_VERSION = "0.2.0"
FIXED_URL = "https://www.rfc-editor.org/rfc/rfc2606.txt"
RECIPIENT = "www.rfc-editor.org"
_HEADER_LIMIT = 8_192
_BODY_LIMIT = 65_536


class DirectHttpsTransportError(RuntimeError):
    """The one-request direct transport policy denied the synthetic attempt."""


class SyntheticDirectHttpsBackend(Protocol):
    """Test-only byte source; it must not perform DNS, sockets, or HTTP."""

    def fetch_fixed(self) -> Any: ...


@dataclass(frozen=True)
class SyntheticTransportEnvironment:
    """Explicit hostile fixture input, never an inspection of process environment state."""

    proxy_configured: bool = False
    cookies_available: bool = False
    credentials_available: bool = False
    browser_state_available: bool = False
    connector_available: bool = False
    model_api_available: bool = False


class SyntheticDirectHttpsTransport:
    """Enforce future direct-transport controls while remaining incapable of networking."""

    def __init__(
        self,
        backend: SyntheticDirectHttpsBackend,
        environment: SyntheticTransportEnvironment = SyntheticTransportEnvironment(),
    ) -> None:
        self.backend = backend
        self.environment = environment
        self.calls = 0

    def get_exact(self, url: str) -> Any:
        if url != FIXED_URL:
            raise DirectHttpsTransportError("exact fixed URL is required")
        if any(vars(self.environment).values()):
            raise DirectHttpsTransportError("inherited host, proxy, credential, or model state is denied")
        if self.calls:
            raise DirectHttpsTransportError("one-request transport budget is exhausted")
        self.calls += 1
        response = self.backend.fetch_fixed()
        if response.final_url != FIXED_URL or response.redirect_chain:
            raise DirectHttpsTransportError("redirect or final URL mismatch is denied")
        if response.used_proxy or response.sent_cookie or response.used_credentials:
            raise DirectHttpsTransportError("transport disclosure is denied")
        if not response.tls_hostname_valid or not response.tls_certificate_valid:
            raise DirectHttpsTransportError("TLS hostname/certificate validation failed")
        if response.resolved_address_class != "global_unicast":
            raise DirectHttpsTransportError("resolved address class is denied")
        if not response.response_framing_valid or response.authentication_challenge:
            raise DirectHttpsTransportError("response framing/authentication challenge is denied")
        return response

    @staticmethod
    def capability_report() -> dict[str, object]:
        return {
            "component_id": COMPONENT_ID,
            "component_version": COMPONENT_VERSION,
            "synthetic_backend_only": True,
            "live_https": False,
            "dns": False,
            "socket": False,
            "browser": False,
            "connector_plugin": False,
            "proxy": False,
            "model_api": False,
            "recipient": RECIPIENT,
        }


@dataclass(frozen=True)
class ResolvedAddress:
    """One normalized resolver result; its address value is never persisted by the caller."""

    family: int
    socktype: int
    protocol: int
    sockaddr: tuple[Any, ...]
    address_class: str


class DirectTlsStream(Protocol):
    """The minimum connection surface used by the exact HTTP/1.1 request."""

    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


class DirectHttpsNetwork(Protocol):
    """Network operations that tests replace with an in-memory hostile double."""

    def resolve_exact(self, host: str, port: int) -> tuple[ResolvedAddress, ...]: ...

    def connect_tls_exact(self, address: ResolvedAddress, server_hostname: str) -> DirectTlsStream: ...


class SystemDirectHttpsNetwork:
    """System resolver/socket/TLS implementation. Never construct it in synthetic-only work."""

    def resolve_exact(self, host: str, port: int) -> tuple[ResolvedAddress, ...]:
        results = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        addresses: list[ResolvedAddress] = []
        for family, socktype, protocol, _canonname, sockaddr in results:
            value = str(sockaddr[0])
            parsed = ipaddress.ip_address(value)
            address_class = "global_unicast" if parsed.is_global else "denied"
            addresses.append(ResolvedAddress(family, socktype, protocol, sockaddr, address_class))
        return tuple(sorted(addresses, key=lambda item: (item.family, item.sockaddr)))

    def connect_tls_exact(self, address: ResolvedAddress, server_hostname: str) -> DirectTlsStream:
        raw = socket.socket(address.family, address.socktype, address.protocol)
        raw.settimeout(10.0)
        try:
            raw.connect(address.sockaddr)
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            return context.wrap_socket(raw, server_hostname=server_hostname)
        except Exception:
            raw.close()
            raise


class RealDirectHttpsTransport:
    """Strict, non-retrying one-request backend; tests must inject ``DirectHttpsNetwork``."""

    def __init__(self, network: DirectHttpsNetwork) -> None:
        self.network = network
        self.calls = 0

    def get_exact(self, url: str) -> Any:
        if url != FIXED_URL:
            raise DirectHttpsTransportError("exact fixed URL is required")
        if self.calls:
            raise DirectHttpsTransportError("one-request transport budget is exhausted")
        self.calls += 1
        addresses = self.network.resolve_exact(RECIPIENT, 443)
        selected = next((item for item in addresses if item.address_class == "global_unicast"), None)
        if selected is None:
            raise DirectHttpsTransportError("resolver returned no permitted address")
        stream = self.network.connect_tls_exact(selected, RECIPIENT)
        try:
            stream.sendall(
                b"GET /rfc/rfc2606.txt HTTP/1.1\r\n"
                b"Host: www.rfc-editor.org\r\n"
                b"Accept: text/plain\r\n"
                b"Connection: close\r\n\r\n"
            )
            return self._read_response(stream)
        finally:
            stream.close()

    @staticmethod
    def _read_response(stream: DirectTlsStream) -> Any:
        from vault_next.public_research import SyntheticResponse

        raw = b""
        while b"\r\n\r\n" not in raw:
            chunk = stream.recv(min(1024, _HEADER_LIMIT + 1 - len(raw)))
            if not chunk:
                raise DirectHttpsTransportError("response headers are incomplete")
            raw += chunk
            if len(raw) > _HEADER_LIMIT:
                raise DirectHttpsTransportError("response headers are invalid or too large")
        header_bytes, body = raw.split(b"\r\n\r\n", maxsplit=1)
        try:
            lines = header_bytes.decode("iso-8859-1").split("\r\n")
            version, status, _reason = lines[0].split(" ", maxsplit=2)
            if version not in {"HTTP/1.0", "HTTP/1.1"}:
                raise ValueError
            headers: dict[str, str] = {}
            for line in lines[1:]:
                name, value = line.split(":", maxsplit=1)
                normalized = name.strip().lower()
                if not normalized or normalized in headers:
                    raise ValueError
                headers[normalized] = value.strip()
            if "transfer-encoding" in headers or "content-length" not in headers:
                raise ValueError
            status_code = int(status)
            length = int(headers["content-length"])
            if length < 0 or length > _BODY_LIMIT:
                raise ValueError
        except (ValueError, IndexError):
            raise DirectHttpsTransportError("response framing is invalid") from None
        while len(body) < length:
            chunk = stream.recv(min(4096, length - len(body)))
            if not chunk:
                raise DirectHttpsTransportError("response body is truncated")
            body += chunk
        if len(body) != length:
            raise DirectHttpsTransportError("response body framing is invalid")
        content_type = headers.get("content-type", "").split(";", maxsplit=1)[0].strip().lower()
        return SyntheticResponse(
            status_code,
            content_type,
            body,
            FIXED_URL,
            resolved_address_class="global_unicast",
        )

    @staticmethod
    def capability_report() -> dict[str, object]:
        return {
            "component_id": COMPONENT_ID,
            "component_version": REAL_COMPONENT_VERSION,
            "requires_explicit_network_injection": True,
            "live_https": "not_constructed_in_synthetic_mode",
            "dns": "not_called_in_synthetic_mode",
            "socket": "not_called_in_synthetic_mode",
            "browser": False,
            "connector_plugin": False,
            "proxy": False,
            "model_api": False,
            "recipient": RECIPIENT,
        }
