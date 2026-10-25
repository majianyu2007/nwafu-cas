"""The client: first-factor login, second factor, and reaching campus services.

Typical use::

    cas = CasClient.load("~/.config/nwafu-cas/state.json")   # or CasClient()
    if not cas.is_logged_in():
        result = cas.login("2025000000", password)
        if not result.done:                     # 学校要求二次认证
            mfa = result.mfa
            print([m.name for m in mfa.methods])
            mfa.select("3"); mfa.send_code()
            result = mfa.submit(code=input("短信验证码: "))
    page = cas.open_service("https://ehall.nwafu.edu.cn/login")
    cas.save("~/.config/nwafu-cas/state.json")

:func:`nwafu_cas.interactive.complete` does the second-factor dialogue for you.
"""

from __future__ import annotations

import json
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urljoin, urlparse

import httpx

from . import cookies as _cookies
from . import mfa as _mfa
from . import page as _page
from . import qr as _qr
from .constants import BASE, CAMPUS_HOST_SUFFIXES, DEFAULT_SERVICE, TGC_COOKIE, TRUSTED_DEVICE_COOKIE, UA
from .crypto import DEFAULT_PARAMS, CipherParams, encrypt_password, params_from_script
from .errors import (
    AccountLocked,
    CaptchaRequired,
    CasError,
    InvalidCredentials,
    LoginRequired,
    Maintenance,
    MfaError,
    NetworkError,
    SiteChanged,
    Unsupported,
)

_REAUTH = "/authserver/reAuthCheck/reAuthLoginView.do"


@dataclass
class LoginResult:
    """Outcome of a login step: either finished, or a second factor is due."""

    response: httpx.Response
    mfa: MfaChallenge | None = None

    @property
    def done(self) -> bool:
        return self.mfa is None


def _is_redirect(r: httpx.Response) -> bool:
    return r.status_code in (301, 302, 303, 307, 308) and bool(r.headers.get("location"))


def _campus(url: str) -> bool:
    u = urlparse(url)
    return u.scheme in ("http", "https") and (u.hostname or "").endswith(CAMPUS_HOST_SUFFIXES)


class CasClient:
    """One login identity (a cookie jar) against authserver.nwafu.edu.cn.

    Args:
        cookies: cookies to start from (e.g. restored with :meth:`load`).
        http: an existing ``httpx.Client`` to use instead of creating one. It
            must not follow redirects by itself.
        fingerprint: the browser fingerprint registered for 信任此设备; keep
            it stable per installation (it is saved by :meth:`save`).
        guard: optional :class:`~nwafu_cas.guard.LoginGuard` consulted before
            every real login attempt.
        adaptive: read cipher parameters and second-factor code types from
            the live scripts (once per site version) instead of only using
            the built-in values.
    """

    #: called once the authserver has accepted the first factor
    on_first_factor_ok: Callable[[], None] | None = None

    def __init__(self, cookies: httpx.Cookies | None = None, *, http: httpx.Client | None = None,
                 fingerprint: str | None = None, guard=None, adaptive: bool = True, timeout: float = 30.0):
        self.http = http or httpx.Client(cookies=cookies, headers={"User-Agent": UA},
                                         timeout=httpx.Timeout(timeout, connect=12.0), follow_redirects=False)
        self.fingerprint = fingerprint or secrets.token_hex(16)
        self.guard = guard
        self.adaptive = adaptive
        self.cipher: CipherParams = DEFAULT_PARAMS
        self.site_version = ""
        self._adapted: set[str] = set()

    # ------------------------------------------------------------ persistence
    def state(self) -> dict:
        return {"cookies": _cookies.to_json(self.http.cookies), "fingerprint": self.fingerprint}

    @classmethod
    def from_state(cls, state: dict | None, **kw) -> CasClient:
        state = state or {}
        return cls(_cookies.from_json(state.get("cookies")), fingerprint=state.get("fingerprint"), **kw)

    def save(self, path: str | os.PathLike) -> None:
        """Write cookies + fingerprint, readable only by the current user."""
        p = Path(path).expanduser()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(p.suffix + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(self.state(), f)
        os.replace(tmp, p)

    @classmethod
    def load(cls, path: str | os.PathLike, **kw) -> CasClient:
        p = Path(path).expanduser()
        try:
            state = json.loads(p.read_text("utf-8"))
        except (OSError, ValueError):
            state = None
        return cls.from_state(state, **kw)

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> CasClient:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ------------------------------------------------------------ navigation
    @staticmethod
    def login_url(service: str | None = DEFAULT_SERVICE) -> str:
        return f"{BASE}/login" + (f"?service={quote(service, safe='')}" if service else "")

    def _get(self, url: str, **kw) -> httpx.Response:
        try:
            return self.http.get(url, **kw)
        except httpx.HTTPError as e:
            raise NetworkError("连接学校服务器失败", f"{urlparse(url).hostname}: {str(e)[:60]}") from e

    def _post(self, url: str, **kw) -> httpx.Response:
        try:
            return self.http.post(url, **kw)
        except httpx.HTTPError as e:
            raise NetworkError("连接学校服务器失败", f"{urlparse(url).hostname}: {str(e)[:60]}") from e

    def follow(self, url: str, max_hops: int = 20) -> httpx.Response:
        """GET ``url`` and follow redirects by hand, staying on campus hosts."""
        current = url
        for _ in range(max_hops):
            if not _campus(current):
                raise CasError("跳转到了学校以外的地址，已停止", current[:80], kind="redirect")
            r = self._get(current)
            if not _is_redirect(r):
                return r
            current = urljoin(str(r.url), r.headers["location"])
        raise CasError("重定向次数过多", url[:80], kind="redirect")

    def has_tgc(self) -> bool:
        return _cookies.has(self.http.cookies, TGC_COOKIE)

    def trusted(self) -> bool:
        """This installation is registered as a device (信任此设备 may apply)."""
        return _cookies.has(self.http.cookies, TRUSTED_DEVICE_COOKIE)

    def is_logged_in(self, service: str = DEFAULT_SERVICE) -> bool:
        """True when CASTGC is valid: the login page redirects straight on."""
        r = self._get(self.login_url(service))
        if not _is_redirect(r):
            return False
        # a pending second factor also redirects, but to reAuthLoginView
        path = urlparse(urljoin(str(r.url), r.headers["location"])).path
        return not (path.rstrip("/").endswith("/authserver/login") or "/reAuthCheck/" in path)

    def get(self, url: str) -> httpx.Response:
        """Open any campus URL, following its redirects (CAS, Vouch/OIDC, …).

        Raises :class:`LoginRequired` (with ``login_url``) if the chain ends
        on the authserver login page; log in with that URL and the result
        lands back on the target.
        """
        last = self.follow(url)
        final = str(last.url)
        if _REAUTH in final:
            raise LoginRequired("学校要求二次认证", "", login_url=final, kind="mfa")
        if urlparse(final).path.rstrip("/").endswith("/authserver/login"):
            raise LoginRequired("统一身份认证未登录或已失效", "", login_url=final)
        return last

    def open_service(self, service: str = DEFAULT_SERVICE) -> httpx.Response:
        """Reach a CAS ``service`` with the current login (ticket handled)."""
        return self.get(self.login_url(service))

    # ------------------------------------------------------------ site adaptation
    def _adapt(self, theme_dir: str, version: str) -> None:
        """Re-read the cipher and code-type tables when the site version is new."""
        if version:
            self.site_version = version
        if not (self.adaptive and theme_dir) or (theme_dir, version) in self._adapted:
            return
        self._adapted.add((theme_dir, version))
        root = f"{BASE}/{theme_dir}/static"
        try:
            js = self._get(f"{root}/common/encrypt.js", params={"v": version}).text
            self.cipher = params_from_script(js) or DEFAULT_PARAMS
            _mfa.learn(self._get(f"{root}/custom/js/reAuth.js", params={"v": version}).text)
        except CasError:
            pass  # built-in values still apply

    def ensure_fingerprint(self) -> None:
        """Register this installation's browser fingerprint (``/bfp/info``).

        The login page does the same from JavaScript; 信任此设备 is stored
        against this value, so it has to exist before a second factor.
        """
        if self.trusted():
            return
        try:
            self.http.get(f"{BASE}/bfp/info", params={"bfp": self.fingerprint, "_": int(time.time() * 1000)})
        except httpx.HTTPError:
            pass

    # ------------------------------------------------------------ first factor
    def login_page(self, service: str | None = DEFAULT_SERVICE, login_url: str | None = None) -> _page.LoginPage | LoginResult:
        """The parsed login page, or a finished result if already logged in."""
        url = login_url or self.login_url(service)
        r = self._get(url)
        if _is_redirect(r):
            return self._after(r)
        if r.status_code >= 500:
            raise Maintenance("统一身份认证暂时不可用", f"HTTP {r.status_code}")
        p = _page.parse_login_page(r.text, str(r.url))
        if not p.forms:
            raise SiteChanged("统一身份认证登录页无法识别", "运行 nwafu-cas doctor 检查页面是否改版")
        self._adapt(p.theme_dir, p.theme_version)
        return p

    def login(self, username: str, password: str, *, service: str | None = DEFAULT_SERVICE,
              login_url: str | None = None) -> LoginResult:
        """Log in with 学号/工号 and password (账号登录)."""
        p = self.login_page(service, login_url)
        if isinstance(p, LoginResult):
            return p
        form = p.form("userNameLogin")
        if form is None or not p.salt:
            raise SiteChanged("登录页没有账号密码登录表单或加密参数", "运行 nwafu-cas doctor 检查页面是否改版")
        self._check_captcha(username, p)
        if self.guard:
            self.guard.before_attempt()
        data = {k: v for k, v in form.fields.items() if k != "passwordText"}  # the browser disables the clear-text field
        data.update(username=username, password=encrypt_password(password, p.salt, self.cipher), rememberMe="true")
        data.setdefault("captcha", "")
        return self._guarded(lambda: self._submit_login(p.url, data))

    def login_qr(self, *, service: str | None = DEFAULT_SERVICE, login_url: str | None = None) -> _qr.QrChallenge | LoginResult:
        """扫码登录 with the university app; ``wait()`` returns a :class:`LoginResult`."""
        p = self.login_page(service, login_url)
        if isinstance(p, LoginResult):
            return p
        form = p.form("qrLogin")
        if form is None or not p.methods["qr"]:
            raise Unsupported("登录页当前没有开放扫码登录")
        if self.guard:
            self.guard.before_attempt()
        return _qr.school_qr(self, p.url, form.fields)

    def login_fido2(self, credential, *, service: str | None = DEFAULT_SERVICE, login_url: str | None = None) -> LoginResult:
        """Passkey login with a software credential (see :mod:`nwafu_cas.fido2`)."""
        from . import fido2

        p = self.login_page(service, login_url)
        if isinstance(p, LoginResult):
            return p
        form = p.form("fidoLogin")
        if form is None:
            raise Unsupported("登录页当前没有开放 FIDO 登录")
        if self.guard:
            self.guard.before_attempt()
        data = fido2.login_form(self, credential, form.fields)
        return self._guarded(lambda: self._submit_login(p.url, data))

    def _check_captcha(self, username: str, p) -> None:
        try:
            j = self._get(f"{BASE}/checkNeedCaptcha.htl", params={"username": username, "_": int(time.time() * 1000)}).json()
        except (ValueError, CasError):
            return
        if isinstance(j, dict) and j.get("isNeed"):
            kind = "滑块验证" if p.captcha_switch == "2" else "图形验证码"
            raise CaptchaRequired(f"学校要求{kind}", "失败次数较多时会出现；请先在浏览器里成功登录一次，或过一段时间再试")

    def _guarded(self, fn: Callable[[], LoginResult]) -> LoginResult:
        if not self.guard:
            return fn()
        try:
            res = fn()
        except CasError as e:
            self.guard.record_failure(e.kind)
            raise
        self.guard.record_success()
        return res

    def _submit_login(self, url: str, data: dict) -> LoginResult:
        r = self._post(url, data=data)
        if not _is_redirect(r):
            raise classify_failure(r.text)
        return self._after(r)

    def _after(self, r: httpx.Response) -> LoginResult:
        last = self.follow(urljoin(str(r.url), r.headers["location"])) if _is_redirect(r) else r
        final = str(last.url)
        on_login = urlparse(final).path.rstrip("/").endswith("/authserver/login")
        if not on_login and self.on_first_factor_ok:
            self.on_first_factor_ok()
        if _REAUTH in final:
            rp = _page.parse_reauth_page(last.text, final)
            if not rp.params and not rp.offered:
                raise SiteChanged("二次认证页面无法识别", "运行 nwafu-cas doctor 检查页面是否改版")
            self._adapt(rp.theme_dir, rp.theme_version)
            return LoginResult(last, MfaChallenge(self, rp))
        if on_login:
            raise classify_failure(last.text)
        return LoginResult(last)

    def logout(self) -> None:
        try:
            self.http.get(f"{BASE}/logout")
        except httpx.HTTPError:
            pass


def classify_failure(html: str) -> CasError:
    tip = _page.error_text(html)
    if any(w in tip for w in ("锁定", "冻结")):
        return AccountLocked(tip, "到统一身份认证页面按提示解锁，或联系网络中心")
    if "验证码" in tip or "频繁" in tip:
        return CaptchaRequired(tip, "请先在浏览器里成功登录一次，或过一段时间再试")
    if any(w in tip for w in ("密码", "用户名", "账号", "不存在")):
        return InvalidCredentials(tip, "检查学号/工号和统一身份认证密码")
    if "维护" in tip:
        return Maintenance(tip)
    if not tip and "<form" not in html:
        return SiteChanged("登录后的页面无法识别", "运行 nwafu-cas doctor 检查页面是否改版")
    return CasError(tip or "统一身份认证登录失败")


class MfaChallenge:
    """The second-factor step (``reAuthLoginView.do``) of one login."""

    def __init__(self, cas: CasClient, page: _page.ReauthPage):
        self.cas = cas
        self.page = page
        self.current = page.current
        self.service = page.service
        offered = page.offered or ([(page.current, "")] if page.current else [])
        self.methods: list[_mfa.MfaMethod] = [_mfa.method(t, n) for t, n in offered]

    def method(self, type_: str | None = None) -> _mfa.MfaMethod:
        t = str(type_ or self.current)
        return next((m for m in self.methods if m.type == t), _mfa.method(t))

    @property
    def supported(self) -> list[_mfa.MfaMethod]:
        return [m for m in self.methods if m.supported]

    def select(self, type_: str) -> dict:
        """Switch to a method (what clicking its tab does). Returns the server data."""
        r = self.cas._post(f"{BASE}/reAuthCheck/changeReAuthType.do",
                           data={"isMultifactor": self.page.is_multifactor, "reAuthType": str(type_), "service": self.service})
        j = _json(r)
        if str(j.get("code")) != "1":
            raise MfaError(j.get("message") or "无法切换到这种验证方式")
        data = j.get("data") or {}
        self.current = str(data.get("reAuthType") or type_)
        if self.current == "10" and data.get("otpIsBind") is False:
            raise Unsupported("这个账号还没有绑定安全令牌 OTP", "请先在浏览器的二次认证页面扫码绑定“数盾OTP”")
        return data

    def send_code(self) -> str:
        """Send the code for the current ``code`` method; returns the server's message."""
        m = self.method()
        if m.kind != "code" or not m.send_type:
            raise MfaError(f"“{m.name}”不需要发送验证码")
        r = self.cas._post(f"{BASE}/dynamicCode/getDynamicCodeByReauth.do",
                           data={"userName": self.page.user_id, "authCodeTypeName": m.send_type})
        j = _json(r)
        res = str(j.get("res", ""))
        msg = f"{j.get('returnMessage') or ''}{j.get('mobile') or ''}".strip()
        if res in ("success", "wechat_success", "cpdaily_success", "other_success"):
            return msg or f"{m.name}已发送"
        raise MfaError(msg or "验证码发送失败", "稍后再试" if res == "code_time_fail" else "")

    def submit(self, *, code: str | None = None, password: str | None = None, uuid: str | None = None,
               trust_device: bool = True) -> LoginResult:
        """Complete the current method. ``trust_device`` = 信任此设备."""
        m = self.method()
        params = {"service": self.service, "reAuthType": self.current, "isMultifactor": self.page.is_multifactor,
                  "password": "", "dynamicCode": "", "uuid": "", "answer1": "", "answer2": "", "otpCode": ""}
        if m.kind == "password":
            if not password:
                raise MfaError("需要输入密码")
            params["reAuthType"] = "2"
            params["password"] = encrypt_password(password, self.page.salt, self.cas.cipher)
        elif m.kind == "code":
            params["dynamicCode"] = (code or "").strip()
        elif m.kind == "otp":
            params["otpCode"] = (code or "").strip()
            if len(params["otpCode"]) != 6:
                raise MfaError("安全令牌需要 6 位数字")
        elif m.kind in ("qr", "face"):
            params["uuid"] = uuid or ""
        else:
            raise Unsupported(f"“{m.name}”只能在浏览器里完成")
        if self.page.asks_trust:
            params["skipTmpReAuth"] = "true" if trust_device else "false"
        self.cas.ensure_fingerprint()
        j = _json(self.cas._post(f"{BASE}/reAuthCheck/reAuthSubmit.do", data=params))
        if j.get("code") in ("reAuth_failed", "reAuth_unauthorized"):
            raise MfaError(j.get("msg") or "二次认证失败", "检查后重试")
        return self.cas._after(self.cas._get(self.cas.login_url(self.service or None)))

    def submit_totp(self, secret: str, trust_device: bool = True) -> LoginResult:
        import pyotp

        if self.current != "10":
            self.select("10")
        return self.submit(code=pyotp.TOTP(secret.replace(" ", "").upper()).now(), trust_device=trust_device)

    def start_qr(self, trust_device: bool = True) -> _qr.QrChallenge:
        """For ``qr``/``face``/``wechat`` methods: the code to scan; ``wait()`` finishes."""
        m = self.method()
        self.cas.ensure_fingerprint()
        submit = lambda **kw: self.submit(trust_device=trust_device, **kw)  # noqa: E731
        if m.kind == "qr":
            return _qr.mfa_qr(self.cas, submit)
        if m.kind == "face":
            plugin = self.current if self.current.upper().startswith("REAL_PERSON_PLUGIN_") else self.page.plugin_id
            app = "微信" if self.current == "18" or "WECHAT" in plugin.upper() else "支付宝"
            return _qr.face_qr(self.cas, plugin, app, submit)
        if m.kind == "wechat":
            reauth = "2" if self.page.is_multifactor == "true" else "1"
            return _qr.wechat_qr(self.cas, self.service, reauth, trust_device if self.page.asks_trust else None)
        raise MfaError(f"“{m.name}”不是扫码方式")


def _json(r: httpx.Response) -> dict:
    try:
        v = r.json()
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}
