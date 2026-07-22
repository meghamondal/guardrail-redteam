from pathlib import Path
from urllib.parse import urlparse
import socket
import ipaddress

BASE_DIR = Path(__file__).parent

DATA_DIR = BASE_DIR / "data"

SANDBOX = (DATA_DIR / "sandbox-17f480feff").resolve()

OUTSIDE = (DATA_DIR / "outside-0ace107c").resolve()

ALLOWED_HOSTS = {
    "example.com",
    "www.iana.org",
}


def map_path(path: str):

    prefix = "/srv/agent-redteam/"

    if path.startswith(prefix):
        path = path.replace(prefix, str(DATA_DIR) + "/", 1)

    return Path(path)


def validate_file(path):

    p = map_path(path)

    resolved = p.resolve()

    try:
        resolved.relative_to(SANDBOX)
    except Exception:
        return False, "outside sandbox"

    return True, resolved


def validate_url(url):

    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid url"

    if parsed.scheme not in ("http", "https"):
        return False, "invalid scheme"

    if parsed.username or parsed.password:
        return False, "userinfo not allowed"

    host = parsed.hostname

    if host not in ALLOWED_HOSTS:
        return False, "host not allowed"

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False, "dns failed"

    for info in infos:

        ip = ipaddress.ip_address(info[4][0])

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_unspecified
        ):
            return False, "private address"

    return True, url