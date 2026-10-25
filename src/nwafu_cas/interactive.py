"""A complete login dialogue on top of :class:`CasClient`.

The caller provides a small UI object (terminal, GUI dialog, chat bot, …);
this module decides what to ask. Secrets typed by the user go straight to
the authserver and are never stored here.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

import httpx

from .client import CasClient, LoginResult
from .errors import MfaError, QrExpired
from .mfa import MfaMethod
from .qr import CONFIRMED, SCANNED, QrChallenge

STATUS_TEXT = {SCANNED: "已扫码，请在手机上确认", CONFIRMED: "已确认"}


class Ui(Protocol):
    def choose(self, message: str, options: Sequence[str]) -> int: ...
    def ask(self, message: str, secret: bool = False) -> str: ...
    def info(self, message: str) -> None: ...
    def show_qr(self, qr: QrChallenge) -> None: ...


def complete(result: LoginResult, ui: Ui, *, totp_secret: str | None = None, trust_device: bool = True,
             prefer: Sequence[str] = (), attempts: int = 3, qr_timeout: float = 180) -> httpx.Response:
    """Finish ``result`` (asking for a second factor if needed); returns the final page.

    ``prefer`` lists method types to use without asking when offered
    (e.g. ``("10",)`` for OTP). With ``totp_secret`` OTP is done silently.
    """
    tries = 0
    while not result.done:
        mfa = result.mfa
        assert mfa is not None
        offered = mfa.supported
        if not offered:
            names = "、".join(m.name for m in mfa.methods) or "未知"
            raise MfaError(f"学校提供的二次认证方式（{names}）都只能在浏览器里完成")
        try:
            if totp_secret and any(m.type == "10" for m in offered):
                result = mfa.submit_totp(totp_secret, trust_device)
                continue
            m = next((m for t in prefer for m in offered if m.type == t), None)
            if m is None:
                m = offered[0] if len(offered) == 1 else offered[ui.choose(
                    "学校要求二次认证，请选择方式" + ("（完成后本机将被信任一段时间）" if trust_device else ""),
                    [m.name for m in offered])]
            result = _one(mfa, m, ui, trust_device, qr_timeout)
        except (MfaError, QrExpired) as e:
            tries += 1
            if tries >= attempts:
                raise
            ui.info(f"{e}，请重试")
            prefer = ()
    return result.response


def _one(mfa, m: MfaMethod, ui: Ui, trust: bool, qr_timeout: float) -> LoginResult:
    if mfa.current != m.type:
        mfa.select(m.type)
    if m.kind == "code":
        ui.info(mfa.send_code())
        return mfa.submit(code=ui.ask(f"请输入{m.name}"), trust_device=trust)
    if m.kind == "otp":
        return mfa.submit(code=ui.ask("请输入安全令牌（6 位）"), trust_device=trust)
    if m.kind == "password":
        return mfa.submit(password=ui.ask("请再次输入统一身份认证密码", secret=True), trust_device=trust)
    qr = mfa.start_qr(trust)
    ui.show_qr(qr)
    return qr.wait(timeout=qr_timeout, on_status=lambda s: s in STATUS_TEXT and ui.info(STATUS_TEXT[s]))


def login(cas: CasClient, username: str, password: str, ui: Ui, *, service: str | None = None,
          login_url: str | None = None, **kw) -> httpx.Response:
    """Password login plus whatever second factor the school asks for."""
    from .constants import DEFAULT_SERVICE

    res = cas.login(username, password, service=service or DEFAULT_SERVICE, login_url=login_url)
    return complete(res, ui, **kw)


def login_qr(cas: CasClient, ui: Ui, *, service: str | None = None, qr_timeout: float = 180, **kw) -> httpx.Response:
    """扫码登录 (university app) plus any second factor."""
    from .constants import DEFAULT_SERVICE

    q = cas.login_qr(service=service or DEFAULT_SERVICE)
    if isinstance(q, LoginResult):
        return complete(q, ui, **kw)
    ui.show_qr(q)
    res = q.wait(timeout=qr_timeout, on_status=lambda s: s in STATUS_TEXT and ui.info(STATUS_TEXT[s]))
    return complete(res, ui, qr_timeout=qr_timeout, **kw)
