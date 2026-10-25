"""Second-factor (二次认证) methods of the authserver.

Each method has a *kind* that decides how it is completed:

=========  ==============================================================
code       a code is sent (SMS, 企业微信, 今日校园, e-mail, …) and typed in
otp        a 6-digit TOTP from the 数盾 OTP mini program or any TOTP app
password   the account password again (also what 安全问题 now falls back to)
qr         a QR code shown here, scanned in 钉钉/企业微信/WeLink
face       a QR code scanned in 支付宝/微信, then a face check on the phone
wechat     微信扫码 through WeChat's web login (open.weixin.qq.com)
none       not possible outside a browser (QQ 扫码, CA UKey)
=========  ==============================================================

The table below was read from ``reAuth.js`` (2026-10). At run time
:func:`learn` re-reads the code types from the live script, so a new
"verification code" channel works without a new release.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class MfaMethod:
    type: str
    name: str
    kind: str
    send_type: str | None = None  # authCodeTypeName for kind == "code"

    @property
    def supported(self) -> bool:
        return self.kind != "none"


BUILTIN: dict[str, MfaMethod] = {m.type: m for m in [
    MfaMethod("2", "认证密码", "password"),
    MfaMethod("3", "短信验证码", "code", "reAuthDynamicCodeType"),
    MfaMethod("4", "企业微信验证码", "code", "reAuthWChatDynamicCodeType"),
    MfaMethod("5", "今日校园验证码", "code", "reAuthCpdailyDynamicCodeType"),
    MfaMethod("6", "实人认证（支付宝扫码刷脸）", "face"),
    MfaMethod("7", "安全问题", "password"),  # the page now completes this with the password
    MfaMethod("8", "微信扫码", "wechat"),
    MfaMethod("9", "QQ 扫码", "none"),
    MfaMethod("10", "安全令牌 OTP", "otp"),
    MfaMethod("11", "邮箱验证码", "code", "reAuthEmailDynamicCodeType"),
    MfaMethod("12", "钉钉验证码", "code", "reAuthDingTalkDynamicCodeType"),
    MfaMethod("13", "WeLink 验证码", "code", "reAuthWeLinkDynamicCodeType"),
    MfaMethod("14", "钉钉/企业微信/WeLink 扫码", "qr"),
    MfaMethod("15", "公众号验证码", "code", "reAuthWeChatServiceDynamicCodeType"),
    MfaMethod("18", "腾讯云人脸核身（微信扫码刷脸）", "face"),
    MfaMethod("20", "实人认证", "face"),
    MfaMethod("UKey", "CA UKey", "none"),
]}

_learned: dict[str, str] = {}  # type -> authCodeTypeName from the live reAuth.js


def learn(script: str) -> dict[str, str]:
    """Pick up ``reAuthType == 'N' … authCodeTypeName = "X"`` pairs."""
    found = dict(re.findall(
        r"reAuthType\s*==\s*['\"](\w+)['\"]\s*\)\s*\{\s*authCodeTypeName\s*=\s*['\"](\w+)['\"]", script))
    _learned.update(found)
    return found


def method(type_: str, page_name: str = "") -> MfaMethod:
    """The method for ``type_``, using the page's own label when it has one."""
    t = str(type_)
    if t.upper().startswith("REAL_PERSON_PLUGIN_"):
        return MfaMethod(t, page_name or "实人认证", "face")
    base = BUILTIN.get(t)
    if t in _learned:
        return MfaMethod(t, page_name or (base.name if base else f"验证码（类型 {t}）"), "code", _learned[t])
    if base:
        return MfaMethod(t, page_name or base.name, base.kind, base.send_type)
    return MfaMethod(t, page_name or f"未知方式 {t}", "none")
