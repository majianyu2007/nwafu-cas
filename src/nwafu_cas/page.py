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
from urllib.parse import parse_qs, unquote, urljoin, urlparse

from .constants import CAMPUS_HOST_SUFFIXES

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
        r"id=[\"']formErrorTip[\"'][^>]*>(?:(?!</div>).)*?<span[^>]*>([^<]+)</span>",
        r"class=[\"'][^\"']*auth_error[^\"']*[\"'][^>]*>([^<]+)<",
        r"class=[\"'][^\"']*no-access-or-registered-tip[^\"']*[\"'][^>]*>([^<]+)<",
    ):
        for m in re.finditer(pat, html, re.S):
            text = _html.unescape(m.group(1)).strip()
            if text:
                return text
    return ""


def _normalize_service(raw: object) -> str:
    """Normalize a CAS service URL extracted from HTML/JS, rejecting corrupt escapes."""
    if raw is None:
        return ""
    s = _html.unescape(str(raw).strip())
    if not s:
        return ""
    if re.match(r"^https?%3A%2F%2F", s, re.I):
        s = unquote(s)
    if "\\" in s:
        return ""
    u = urlparse(s)
    if u.scheme not in ("http", "https") or not u.hostname:
        return ""
    if not u.hostname.lower().endswith(CAMPUS_HOST_SUFFIXES):
        return ""
    return s


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
        from_params = _normalize_service(self.params.get("service"))
        if from_params:
            return from_params
        q_service = parse_qs(urlparse(self.url).query).get("service", [""])[0]
        return _normalize_service(q_service)

    @property
    def user_id(self) -> str:
        return str(self.params.get("reAuthUserId") or "")

    @property
    def salt(self) -> str:
        return str(self.params.get("pwdEncryptSalt") or "")

    @property
    def is_multifactor(self) -> str:
        val = self.params.get("isMultifactor")
        if val is None or val == "":
            return "true"
        if isinstance(val, bool):
            return "true" if val else "false"
        return str(val)

    @property
    def asks_trust(self) -> bool:
        """The page shows the 信任此设备 dialog (``isSleepAccount === '0'``)."""
        val = self.params.get("isSleepAccount")
        if val is None or val == "":
            return True
        return str(val) == "0"


def _scan_js_string_end(src: str, start: int) -> int:
    quote = src[start]
    i = start + 1
    n = len(src)
    while i < n:
        ch = src[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        i += 1
    return n


def _skip_js_space_and_comments(src: str, i: int) -> int:
    n = len(src)
    while i < n:
        if src[i].isspace() or src[i] == "\ufeff":
            i += 1
            continue
        if src[i] == "/" and i + 1 < n:
            if src[i + 1] == "/":
                nl = src.find("\n", i + 2)
                i = n if nl < 0 else nl + 1
                continue
            if src[i + 1] == "*":
                end = src.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
        break
    return i


def _scan_js_balanced_end(src: str, start: int, open_ch: str, close_ch: str) -> int:
    depth, i, n = 0, start, len(src)
    while i < n:
        ch = src[i]
        if ch in "\"'":
            i = _scan_js_string_end(src, i)
            continue
        if ch == "/" and i + 1 < n:
            if src[i + 1] == "/":
                nl = src.find("\n", i + 2)
                i = n if nl < 0 else nl + 1
                continue
            if src[i + 1] == "*":
                end = src.find("*/", i + 2)
                i = n if end < 0 else end + 2
                continue
        if ch == open_ch:
            depth += 1
        elif ch == close_ch:
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


_JS_SIMPLE_ESCAPES = {"/": "/", "\\": "\\", '"': '"', "'": "'", "n": "\n", "r": "\r", "t": "\t", "b": "\b", "f": "\f", "v": "\v", "0": "\x00"}


def _unescape_js_string(raw: str) -> str:
    if "\\" not in raw:
        return raw
    out: list[str] = []
    i, n = 0, len(raw)
    while i < n:
        ch = raw[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        i += 1
        nxt = raw[i]
        if nxt in _JS_SIMPLE_ESCAPES:
            out.append(_JS_SIMPLE_ESCAPES[nxt])
            i += 1
        elif nxt == "\r":
            i += 2 if i + 1 < n and raw[i + 1] == "\n" else 1
        elif nxt == "\n":
            i += 1
        elif nxt == "u":
            if i + 1 < n and raw[i + 1] == "{":
                close = raw.find("}", i + 2)
                if close > i + 2:
                    try:
                        out.append(chr(int(raw[i + 2 : close], 16)))
                        i = close + 1
                        continue
                    except ValueError:
                        pass
            elif i + 4 < n:
                try:
                    code = int(raw[i + 1 : i + 5], 16)
                    # Combine UTF-16 surrogate pair if followed by a low surrogate.
                    if 0xD800 <= code <= 0xDBFF and i + 10 < n and raw[i + 5 : i + 7] == "\\u":
                        low = int(raw[i + 7 : i + 11], 16)
                        if 0xDC00 <= low <= 0xDFFF:
                            out.append(chr(0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)))
                            i += 11
                            continue
                    out.append(chr(code))
                    i += 5
                    continue
                except ValueError:
                    pass
            out.append("u")
            i += 1
        elif nxt == "x" and i + 2 < n:
            try:
                out.append(chr(int(raw[i + 1 : i + 3], 16)))
                i += 3
                continue
            except ValueError:
                out.append("x")
                i += 1
        else:
            out.append(nxt)
            i += 1
    return "".join(out)


def _parse_js_object_literal(block: str) -> dict:
    """Parse top-level key/value pairs of a JS object literal with full JS string unescaping."""
    out: dict = {}
    n = len(block)
    i = _skip_js_space_and_comments(block, 0)
    if i >= n or block[i] != "{":
        return out
    i += 1
    while i < n:
        i = _skip_js_space_and_comments(block, i)
        if i >= n or block[i] == "}":
            break
        if block[i] == ",":
            i += 1
            continue
        if block[i] in "\"'":
            quote = block[i]
            end = _scan_js_string_end(block, i)
            if end <= i + 1 or block[end - 1] != quote:
                break
            key = _unescape_js_string(block[i + 1 : end - 1])
            i = end
        else:
            start = i
            while i < n and (block[i].isalnum() or block[i] in "_$"):
                i += 1
            if i == start:
                i += 1
                continue
            key = block[start:i]
        i = _skip_js_space_and_comments(block, i)
        if i >= n or block[i] != ":":
            while i < n and block[i] not in ",}":
                i += 1
            continue
        i = _skip_js_space_and_comments(block, i + 1)
        if i >= n:
            break
        ch = block[i]
        if ch in "\"'":
            end = _scan_js_string_end(block, i)
            if end > i + 1 and block[end - 1] == ch:
                out[key] = _unescape_js_string(block[i + 1 : end - 1])
            i = end
        elif ch == "{":
            i = _scan_js_balanced_end(block, i, "{", "}")
        elif ch == "[":
            i = _scan_js_balanced_end(block, i, "[", "]")
        else:
            start = i
            while i < n and block[i] not in ",}":
                if block[i] in "\"'":
                    i = _scan_js_string_end(block, i)
                    continue
                if block[i] == "/" and i + 1 < n and block[i + 1] in "/*":
                    break
                i += 1
            tok = block[start:i].strip()
            if tok == "true":
                out[key] = True
            elif tok == "false":
                out[key] = False
            elif tok in ("null", "undefined"):
                out[key] = None
            else:
                try:
                    out[key] = int(tok) if re.fullmatch(r"-?\d+", tok) else float(tok)
                except ValueError:
                    pass
    return out


def _js_object(src: str, name: str) -> dict:
    m = re.search(rf"\b{re.escape(name)}\s*=\s*\{{", src)
    if not m:
        return {}
    start = m.end() - 1
    end = _scan_js_balanced_end(src, start, "{", "}")
    if end <= start or src[end - 1] != "}":
        return {}
    text = src[start:end]
    try:
        v = json.loads(text)
        return v if isinstance(v, dict) else {}
    except ValueError:
        return _parse_js_object_literal(text)


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
