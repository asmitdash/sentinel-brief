from __future__ import annotations

import httpx
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

DEFAULT_TIMEOUT = httpx.Timeout(connect=10.0, read=60.0, write=30.0, pool=10.0)
USER_AGENT = "sentinel-brief/0.1 (+https://github.com/asmitdash/sentinel-brief)"


def make_client(headers: dict[str, str] | None = None) -> httpx.Client:
    base_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        base_headers.update(headers)
    return httpx.Client(headers=base_headers, timeout=DEFAULT_TIMEOUT, follow_redirects=True)


@retry(
    stop=stop_after_attempt(4),
    wait=wait_exponential(multiplier=1.5, min=2, max=30),
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
    reraise=True,
)
def get_json(client: httpx.Client, url: str, params: dict | None = None) -> dict:
    r = client.get(url, params=params)
    if r.status_code == 429 or r.status_code >= 500:
        r.raise_for_status()
    r.raise_for_status()
    return r.json()


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1.5, min=2, max=20),
    retry=retry_if_exception_type((httpx.HTTPStatusError, httpx.TransportError)),
    reraise=True,
)
def get_text(client: httpx.Client, url: str, params: dict | None = None) -> str:
    r = client.get(url, params=params)
    r.raise_for_status()
    return r.text
