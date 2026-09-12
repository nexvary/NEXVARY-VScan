from __future__ import annotations
import hashlib, hmac, ipaddress, secrets, socket
from urllib.parse import urlparse, urlunparse

def hash_password(password: str, salt: str | None = None) -> str:
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 210_000).hex()
    return f"pbkdf2_sha256${salt}${digest}"

def verify_password(password: str, encoded: str) -> bool:
    try:
        _, salt, expected = encoded.split("$", 2)
        actual = hash_password(password, salt).split("$", 2)[2]
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def normalize_target(raw: str) -> str:
    value = raw.strip()
    if not value.startswith(("http://", "https://")):
        value = "https://" + value
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Invalid HTTP/HTTPS target")
    if parsed.username or parsed.password:
        raise ValueError("Embedded URL credentials are not allowed")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Invalid target port")
    cleaned = parsed._replace(fragment="", params="", query="")
    path = cleaned.path.rstrip("/")
    cleaned = cleaned._replace(path=path)
    return urlunparse(cleaned).rstrip("/")

def is_public_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        return False
    addresses = set()
    for info in infos:
        try: addresses.add(ipaddress.ip_address(info[4][0]))
        except ValueError: return False
    if not addresses:
        return False
    for ip in addresses:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True

def same_scope(url: str, hostname: str) -> bool:
    p = urlparse(url)
    if p.scheme not in {"http", "https"} or not p.hostname or p.username or p.password:
        return False
    return p.hostname.lower().rstrip(".") == hostname.lower().rstrip(".")
