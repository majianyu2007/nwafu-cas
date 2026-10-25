"""Check that the live authserver still matches what this library expects.

Only public pages are read (the login page and its scripts); no account is
needed. The result says, item by item, which endpoint or field is missing, so
a site update can be fixed quickly. The weekly ``site-watch`` workflow runs
this and opens an issue when something changed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from . import page as _page
from .constants import BASE, DEFAULT_SERVICE, UA, VERIFIED_THEME
from .crypto import DEFAULT_PARAMS, params_from_script

# script (relative to /authserver/<theme>/static/) -> things it must contain
SCRIPT_MARKERS: dict[str, list[str]] = {
    "common/encrypt.js": ["function encryptPassword", "randomString(64)", "randomString(16)", "CryptoJS.mode.CBC"],
    "common/common-header.js": ["/bfp/info"],
    "web/js/login.js": ["/checkNeedCaptcha.htl", "#saltPassword", "pwdEncryptSalt", "userNameLogin"],
    "custom/js/qrcode.js": ["/qrCode/getToken", "/qrCode/getCode", "/qrCode/getStatus.htl"],
    "web/js/fido.js": ["/startAssertion", "responseJson", "requestId"],
    "custom/js/reAuth.js": ["/reAuthCheck/reAuthSubmit.do", "/reAuthCheck/changeReAuthType.do",
                            "/dynamicCode/getDynamicCodeByReauth.do", "otpCode", "skipTmpReAuth",
                            "authCodeTypeName", "combinedLogin.do"],
    "custom/js/qrcodeMfa.js": ["/reAuthCheck/getToken", "/reAuthCheck/getCode", "/reAuthCheck/getStatus.htl"],
    "custom/js/faceAuth.js": ["/faceAuthWithPlugins/getQrCodeById", "/faceAuthWithPlugins/getQrCodeByFace",
                              "/faceAuthWithPlugins/getStatus"],
}


@dataclass
class Report:
    status: str = "ok"  # ok | changed | unreachable
    site_version: str = ""
    verified_version: str = VERIFIED_THEME
    login_methods: dict = field(default_factory=dict)
    checks: list[tuple[str, bool, str]] = field(default_factory=list)  # (item, ok, detail)

    @property
    def problems(self) -> list[tuple[str, str]]:
        return [(i, d) for i, ok, d in self.checks if not ok]

    def add(self, item: str, ok: bool, detail: str = "") -> None:
        self.checks.append((item, ok, detail))

    def text(self) -> str:
        head = {"ok": "页面与本版本一致", "changed": "页面有变化，可能需要更新 nwafu-cas", "unreachable": "无法访问统一身份认证"}[self.status]
        lines = [f"{head}（站点版本 {self.site_version or '未知'}，本版本核对于 {self.verified_version}）"]
        if self.login_methods:
            lines.append("首页登录方式：" + "、".join(k for k, v in self.login_methods.items() if v))
        for item, ok, detail in self.checks:
            lines.append(f"  {'✓' if ok else '✗'} {item}" + (f"：{detail}" if detail else ""))
        return "\n".join(lines)


def run(http: httpx.Client | None = None, service: str = DEFAULT_SERVICE) -> Report:
    own = http is None
    http = http or httpx.Client(headers={"User-Agent": UA}, timeout=20, follow_redirects=False)
    rep = Report()
    try:
        try:
            r = http.get(f"{BASE}/login", params={"service": service})
        except httpx.HTTPError as e:
            rep.status = "unreachable"
            rep.add("打开登录页", False, str(e)[:80])
            return rep
        if r.status_code != 200:
            rep.status = "unreachable" if r.status_code >= 500 else "changed"
            rep.add("打开登录页", False, f"HTTP {r.status_code}")
            return rep
        p = _page.parse_login_page(r.text, str(r.url))
        rep.site_version = p.theme_version
        rep.login_methods = p.methods
        form = p.form("userNameLogin")
        rep.add("账号密码登录表单", form is not None)
        if form:
            for name in ("username", "password", "execution", "_eventId", "cllt", "dllt", "lt"):
                rep.add(f"表单字段 {name}", name in form.fields)
        rep.add("密码加密盐 pwdEncryptSalt", len(p.salt) == 16, f"长度 {len(p.salt)}")
        rep.add("页面开关 captchaSwitch", bool(p.captcha_switch), p.captcha_switch)
        rep.add("资源主题目录", bool(p.theme_dir), p.theme_dir)
        root = f"{BASE}/{p.theme_dir or 'nwafuTheme'}/static/"
        for rel, markers in SCRIPT_MARKERS.items():
            try:
                js = http.get(root + rel, params={"v": p.theme_version}).text
            except httpx.HTTPError as e:
                rep.add(rel, False, f"无法下载：{str(e)[:60]}")
                continue
            missing = [m for m in markers if m not in js]
            rep.add(rel, not missing, ("缺少 " + "、".join(missing)) if missing else "")
            if rel == "common/encrypt.js":
                cp = params_from_script(js)
                rep.add("密码加密参数", cp is not None, "与内置一致" if cp == DEFAULT_PARAMS else f"{cp}")
            if rel == "custom/js/reAuth.js":
                codes = dict(re.findall(r"reAuthType\s*==\s*['\"](\w+)['\"]\s*\)\s*\{\s*authCodeTypeName\s*=\s*['\"](\w+)['\"]", js))
                rep.add("验证码类二次认证类型", bool(codes), "、".join(sorted(codes, key=lambda x: int(x) if x.isdigit() else 99)))
        if any(not ok for _, ok, _ in rep.checks):
            rep.status = "changed"
        return rep
    finally:
        if own:
            http.close()
