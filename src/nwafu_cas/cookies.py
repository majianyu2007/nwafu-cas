"""Cookie jar (de)serialisation, so a login can be reused across runs."""

from __future__ import annotations

import time
from http.cookiejar import Cookie

import httpx


def to_json(jar: httpx.Cookies) -> list[dict]:
    now = time.time()
    return [
        {
            "name": c.name,
            "value": c.value,
            "domain": c.domain,
            "domain_specified": c.domain_specified,
            "path": c.path,
            "expires": c.expires,
            "secure": c.secure,
        }
        for c in jar.jar
        if not c.is_expired(now)
    ]


def from_json(items: list[dict] | None) -> httpx.Cookies:
    jar = httpx.Cookies()
    now = time.time()
    for it in items or []:
        if it.get("expires") and it["expires"] < now:
            continue
        domain = it.get("domain") or ""
        # Legacy state files omitted `domain_specified`; RFC 6265 domain cookies
        # start with a leading dot while host-only cookies (e.g. CASTGC) do not.
        domain_specified = bool(it["domain_specified"]) if "domain_specified" in it else domain.startswith(".")
        jar.jar.set_cookie(Cookie(
            version=0, name=it["name"], value=it["value"], port=None, port_specified=False,
            domain=domain, domain_specified=domain_specified, domain_initial_dot=domain.startswith("."),
            path=it.get("path") or "/", path_specified=True, secure=bool(it.get("secure")),
            expires=it.get("expires"), discard=False, comment=None, comment_url=None, rest={},
        ))
    return jar


def has(jar: httpx.Cookies, name: str, domain: str | None = None) -> bool:
    now = time.time()
    want_domain = domain.lstrip(".").lower() if domain else None
    for c in jar.jar:
        if c.name != name or not c.value or c.is_expired(now):
            continue
        if want_domain and c.domain and c.domain.lstrip(".").lower() != want_domain:
            continue
        return True
    return False
