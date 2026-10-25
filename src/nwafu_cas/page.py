"""Reading the authserver pages.

Nothing here hard-codes the list of form fields: every ``<input>`` of a form
is collected, so a hidden field the school adds later is submitted as well.
Only the names the browser fills in itself (username, password, …) are
overwritten by the client.
"""

from __future__ import annotations

import html as _html
import json
import re
from dataclasses import dataclass, field
from urllib.parse import urljoin

_FORM_RE = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.S | re.I)
_INPUT_RE = re.compile(r"<input\b([^>]*)>", re.S | re.I)
_ATTR_RE = re.compile(r"""([\w:-]+)\s*=\s*("([^"]*)"|'([^']*)')""", re.S)
_VAR_RE = re.compile(r"""\bvar\s+(\w+)\s*=\s*["']([^"']*)["']""")
_THEME_RE = re.compile(r"/authserver/(\w+)/static/[^\"'?]+\?v=([\w.]+)")


def attrs(tag: str) -> dict[str, str]:
    out = {}
    for m in _ATTR_RE.finditer(tag):
        out[m.group(1).lower()] = _html.unescape(m.group(3) if m.group(3) is not None else m.group(4))
    return out


@dataclass
class Form:
    id: str
    action: str
    fields: dict[str, str]  # name -> default value, in page order
    ids: dict[str, str]  # input id -> value (also for inputs without a name, e.g. pwdEncryptSalt)

    @property
    def cllt(self) -> str:
        return self.fields.get("cllt", "")


def parse_forms(html: str) -> list[Form]:
    forms = []
    for m in _FORM_RE.finditer(html):
        a = attrs(m.group(1))
        fields: dict[str, str] = {}
        ids: dict[str, str] = {}
        for inp in _INPUT_RE.finditer(m.group(2)):
            ia = attrs(inp.group(1))
            if ia.get("type") in ("checkbox", "radio") and "checked" not in inp.group(1):
                continue
            if ia.get("name"):
                fields.setdefault(ia["name"], ia.get("value", ""))
            if ia.get("id"):
                ids.setdefault(ia["id"], ia.get("value", ""))
        forms.append(Form(a.get("id", ""), a.get("action", ""), fields, ids))
    return forms


def script_vars(html: str) -> dict[str, str]:
    """``var x = "…"`` assignments of the inline scripts (feature switches)."""
    out: dict[str, str] = {}
    for s in re.findall(r"<script\b[^>]*>(.*?)</script>", html, re.S | re.I):
        for k, v in _VAR_RE.findall(s):
            out.setdefault(k, v)
    return out


def theme(html: str) -> tuple[str, str]:
    """(theme directory, asset version), e.g. ("nwafuTheme", "20260922.133736")."""
    m = _THEME_RE.search(html)
    return (m.group(1), m.group(2)) if m else ("", "")


def scripts(html: str, base: str) -> list[str]:
    return [urljoin(base, s) for s in re.findall(r"<script\b[^>]*\bsrc=[\"']([^\"']+)[\"']", html, re.I)]


# ---------------------------------------------------------------- login page
@dataclass
class LoginPage:
    url: str
    html: str
    forms: list[Form]
    vars: dict[str, str]
    theme_dir: str
    theme_version: str

    def form(self, cllt: str) -> Form | None:
        return next((f for f in self.forms if f.cllt == cllt), None)

    @property
    def salt(self) -> str:
        for f in self.forms:
            if f.ids.get("pwdEncryptSalt"):
                return f.ids["pwdEncryptSalt"]
        m = re.search(r"id=[\"']pwdEncryptSalt[\"'][^>]*value=[\"']([^\"']*)", self.html)
        return m.group(1) if m else ""

    @property
    def methods(self) -> dict[str, bool]:
        """First-factor login methods the page offers."""
        v = self.vars
        return {
            "password": v.get("is_userNameLogin", "true") == "true" and self.form("userNameLogin") is not None,
            "sms": v.get("is_dynamicLogin") == "true" and self.form("dynamicLogin") is not None,
            "qr": v.get("isQrLoginEnabled") == "true" and self.form("qrLogin") is not None,
            "fido2": v.get("_fidoEnabled") == "true" and self.form("fidoLogin") is not None,
        }

    @property
    def captcha_switch(self) -> str:
        """"1" = picture captcha, "2" = slider (when a captcha is needed)."""
        return self.vars.get("captchaSwitch", "")


def parse_login_page(html: str, url: str) -> LoginPage:
    td, tv = theme(html)
    return LoginPage(url, html, parse_forms(html), script_vars(html), td, tv)


def error_text(html: str) -> str:
    for pat in (
        r"id=[\"']showErrorTip[\"'][^>]*>\s*(?:<span[^>]*>)?([^<]+)<",
        r"id=[\"']formErrorTip[\"'][^>]*>.*?<span[^>]*>([^<]+)</span>",
        r"class=[\"'][^\"']*auth_error[^\"']*[\"'][^>]*>([^<]+)<",
    ):
        m = re.search(pat, html, re.S)
        if m and m.group(1).strip():
            return _html.unescape(m.group(1).strip())
    return ""


# ---------------------------------------------------------------- second factor page
@dataclass
class ReauthPage:
    url: str
    html: str
    params: dict  # reAuthParams of the page
    offered: list[tuple[str, str]]  # (type, name) as listed on the page, in order
    vars: dict[str, str]
    plugin_id: str = ""
    theme_dir: str = ""
    theme_version: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def current(self) -> str:
        return str(self.params.get("reAuthType") or "")

    @property
    def service(self) -> str:
        return str(self.params.get("service") or "")

    @property
    def user_id(self) -> str:
        return str(self.params.get("reAuthUserId") or "")

    @property
    def salt(self) -> str:
        return str(self.params.get("pwdEncryptSalt") or "")

    @property
    def is_multifactor(self) -> str:
        return str(self.params.get("isMultifactor") or "true")

    @property
    def asks_trust(self) -> bool:
        """The page shows the 信任此设备 dialog (``isSleepAccount === '0'``)."""
        return str(self.params.get("isSleepAccount", "0")) == "0"


def _js_object(src: str, name: str) -> dict:
    m = re.search(rf"\b{name}\s*=\s*\{{", src)
    if not m:
        return {}
    i, depth, in_str, esc, quote = m.end() - 1, 0, False, False, ""
    for j in range(i, len(src)):
        ch = src[j]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                in_str = False
        elif ch in "\"'":
            in_str, quote = True, ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                text = src[i : j + 1]
                try:
                    return json.loads(text)
                except ValueError:
                    # tolerate JS-only syntax: fall back to "key": "value" pairs
                    return {k: v for k, v in re.findall(r"[\"'](\w+)[\"']\s*:\s*[\"']([^\"']*)[\"']", text)}
    return {}


def parse_reauth_page(html: str, url: str) -> ReauthPage:
    params = _js_object(html, "reAuthParams")
    offered: list[tuple[str, str]] = []
    for m in re.finditer(r"<[a-z]+\b[^>]*\b(?:reauth-tab-item|reauth-tab-more-item|changeReAuthTypes)\b[^>]*>", html, re.I):
        a = attrs(m.group(0))
        t = a.get("data-type") or a.get("id", "")
        t = t.removeprefix("tab_")
        if not t or t in {x for x, _ in offered}:
            continue
        name = a.get("data-name") or a.get("title") or ""
        if not name:
            tail = re.match(r"\s*(?:<[^>]+>\s*)*([^<]+)", html[m.end() : m.end() + 300])
            name = tail.group(1).strip() if tail else ""
        offered.append((t, name))
    plugin = re.search(r"id=[\"']pluginId[\"'][^>]*value=[\"']([^\"']*)", html)
    td, tv = theme(html)
    return ReauthPage(url, html, params, offered, script_vars(html), plugin.group(1) if plugin else "", td, tv)
