from __future__ import annotations
import hashlib, hmac, ipaddress, secrets, socket
from urllib.parse import urlparse

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
    return value.rstrip("/")

def is_public_host(hostname: str) -> bool:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False
    return True

def same_scope(url: str, hostname: str) -> bool:
    p = urlparse(url)
    return p.scheme in {"http", "https"} and (p.hostname or "").lower() == hostname.lower()
