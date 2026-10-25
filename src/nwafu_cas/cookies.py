"""Cookie jar (de)serialisation, so a login can be reused across runs."""

from __future__ import annotations

import time
from http.cookiejar import Cookie

import httpx


def to_json(jar: httpx.Cookies) -> list[dict]:
    return [
        {"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "expires": c.expires, "secure": c.secure}
        for c in jar.jar
    ]


def from_json(items: list[dict] | None) -> httpx.Cookies:
    jar = httpx.Cookies()
    now = time.time()
    for it in items or []:
        if it.get("expires") and it["expires"] < now:
            continue
        domain = it.get("domain") or ""
        jar.jar.set_cookie(Cookie(
            version=0, name=it["name"], value=it["value"], port=None, port_specified=False,
            domain=domain, domain_specified=bool(domain), domain_initial_dot=domain.startswith("."),
            path=it.get("path") or "/", path_specified=True, secure=bool(it.get("secure")),
            expires=it.get("expires"), discard=False, comment=None, comment_url=None, rest={},
        ))
    return jar


def has(jar: httpx.Cookies, name: str) -> bool:
    return any(c.name == name for c in jar.jar)
