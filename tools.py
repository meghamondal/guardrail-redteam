from pathlib import Path
import requests


def read_file(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def fetch_url(url):
    r = requests.get(
        url,
        timeout=3,
        allow_redirects=False,
    )
    return r.text