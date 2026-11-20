"""QR-code steps: the user scans a code with a phone app, we poll until done.

Four variants share one interface (:class:`QrChallenge`):

* ``school``  首页“扫码登录”：the code holds an authserver URL
              (``/qrCode/qrCodeLogin.do?uuid=``); scanned with 微信/企业微信,
              it is confirmed on a phone that is logged in to 统一身份认证.
* ``mfa``     二次认证“钉钉/企业微信/WeLink 扫码”(type 14).
* ``face``    二次认证“实人认证”：scan in 支付宝/微信, then a face check.
* ``wechat``  二次认证“微信扫码”：WeChat's own web login (open.weixin.qq.com),
              which redirects back to the authserver with a code.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING
from urllib.parse import parse_qs, urlparse

import httpx

from .constants import BASE
from .errors import MfaError, NetworkError, QrExpired

if TYPE_CHECKING:
    from .client import CasClient, LoginResult

WAITING, SCANNED, CONFIRMED, EXPIRED = "waiting", "scanned", "confirmed", "expired"


@dataclass
class QrChallenge:
    kind: str
    image: bytes  # PNG/JPEG as served
    hint: str  # which app to scan with, in Chinese
    content: str | None = None  # text inside the code when known (to draw it in a terminal)
    uuid: str = ""
    _poll: Callable[[], str] = field(default=lambda: WAITING, repr=False)
    _finish: Callable[[], LoginResult] = field(default=None, repr=False)  # type: ignore[assignment]
    status: str = WAITING

    @property
    def image_type(self) -> str:
        return "png" if self.image[:8] == b"\x89PNG\r\n\x1a\n" else "jpg"

    def poll(self) -> str:
        self.status = self._poll()
        return self.status

    def wait(self, timeout: float = 180, interval: float = 1.5, on_status: Callable[[str], None] | None = None) -> LoginResult:
        """Poll until the scan is confirmed, then finish the login step."""
        deadline = time.monotonic() + timeout
        last = None
        while time.monotonic() < deadline:
            st = self.poll()
            if st != last and on_status:
                on_status(st)
            last = st
            if st == CONFIRMED:
                return self._finish()
            if st == EXPIRED:
                raise QrExpired("二维码已失效", "重新开始登录即可获取新的二维码")
            if self.kind != "wechat":  # WeChat's own poll already blocks ~25 s
                time.sleep(interval)
        raise QrExpired("等待扫码超时", "重新开始登录即可获取新的二维码")


def _get(http: httpx.Client, url: str, **params) -> httpx.Response:
    try:
        return http.get(url, params=params or None)
    except httpx.HTTPError as e:
        raise NetworkError("连接统一身份认证失败", str(e)[:80]) from e


def _ts() -> int:
    return int(time.time() * 1000)


# ---------------------------------------------------------------- school app (first factor)
def school_qr(cas: CasClient, login_url: str, form: dict[str, str]) -> QrChallenge:
    uuid = _get(cas.http, f"{BASE}/qrCode/getToken", ts=_ts(), uuid="").text.strip()
    if not uuid or "<" in uuid:
        raise MfaError("无法获取登录二维码", "学校可能关闭了扫码登录")
    img = _get(cas.http, f"{BASE}/qrCode/getCode", uuid=uuid).content

    def poll() -> str:
        v = _get(cas.http, f"{BASE}/qrCode/getStatus.htl", ts=_ts(), uuid=uuid).text.strip()
        return {"1": CONFIRMED, "2": SCANNED, "3": EXPIRED}.get(v, WAITING)

    def finish() -> LoginResult:
        data = {**form, "uuid": uuid}
        sep = "&" if "?" in login_url else "?"
        return cas._submit_login(login_url + sep + "display=qrLogin", data)

    return QrChallenge("school", img, "用微信或企业微信扫码，并在手机上确认登录（手机上需已登录统一身份认证）", uuid=uuid, _poll=poll, _finish=finish)


# ---------------------------------------------------------------- 钉钉/企业微信/WeLink (type 14)
def mfa_qr(cas: CasClient, submit: Callable[..., LoginResult]) -> QrChallenge:
    j = _json(_get(cas.http, f"{BASE}/reAuthCheck/getToken", ts=_ts(), uuid=""))
    if str(j.get("errCode")) != "1" or not j.get("uuid"):
        raise MfaError(j.get("errMsg") or "无法获取二次认证二维码")
    uuid = j["uuid"]
    img = _get(cas.http, f"{BASE}/reAuthCheck/getCode", uuid=uuid).content

    def poll() -> str:
        v = _get(cas.http, f"{BASE}/reAuthCheck/getStatus.htl", ts=_ts(), uuid=uuid).text.strip()
        return {"1": CONFIRMED, "2": SCANNED, "3": EXPIRED}.get(v, WAITING)

    return QrChallenge("mfa", img, "用钉钉、企业微信或 WeLink 扫码并确认", uuid=uuid, _poll=poll,
                       _finish=lambda: submit(uuid=uuid))


# ---------------------------------------------------------------- 实人认证 (6 / 18 / 20 / plugins)
def face_qr(cas: CasClient, plugin_id: str, app: str, submit: Callable[..., LoginResult]) -> QrChallenge:
    j = _json(_get(cas.http, f"{BASE}/faceAuthWithPlugins/getQrCodeById", ts=_ts(), pluginId=plugin_id, uuid=""))
    if str(j.get("errCode")) != "1" or not j.get("uuid"):
        raise MfaError(j.get("errMsg") or "无法获取实人认证二维码")
    uuid = j["uuid"]
    img = _get(cas.http, f"{BASE}/faceAuthWithPlugins/getQrCodeByFace", pluginId=plugin_id, uuid=uuid).content

    def poll() -> str:
        st = str(_json(_get(cas.http, f"{BASE}/faceAuthWithPlugins/getStatus", ts=_ts(), pluginId=plugin_id, uuid=uuid)).get("state", ""))
        return {"1": CONFIRMED, "2": SCANNED, "4": EXPIRED}.get(st, WAITING)

    return QrChallenge("face", img, f"用{app}扫码，并在手机上完成刷脸", uuid=uuid, _poll=poll,
                       _finish=lambda: submit(uuid=uuid))


# ---------------------------------------------------------------- 微信扫码 (type 8)
_WX_HOSTS = {"open.weixin.qq.com", "lp.open.weixin.qq.com"}


def wechat_qr(cas: CasClient, service: str, reauth: str, trust: bool | None) -> QrChallenge:
    params = {"type": "weixin", "reAuth": reauth}
    if service:
        params["success"] = service
    if trust is not None:
        params["skipTmpReAuth"] = "true" if trust else "false"
    r = _get(cas.http, f"{BASE}/combinedLogin.do", **params)
    auth_url = r.headers.get("location", "")
    u = urlparse(auth_url)
    if u.hostname not in _WX_HOSTS:
        raise MfaError("学校没有跳转到微信扫码页面", auth_url[:80])
    q = parse_qs(u.query)
    redirect_uri, state = q.get("redirect_uri", [""])[0], q.get("state", [""])[0]
    page = _get(cas.http, auth_url).text
    m = re.search(r"/connect/qrcode/([\w-]+)", page) or re.search(r"uuid\s*[=:]\s*['\"]([\w-]+)['\"]", page)
    if not m or not redirect_uri:
        raise MfaError("无法读取微信扫码页面")
    uuid = m.group(1)
    img = _get(cas.http, f"https://open.weixin.qq.com/connect/qrcode/{uuid}").content
    box = {"code": "", "last": ""}

    def poll() -> str:
        params = {"uuid": uuid, "_": str(_ts())}
        if box["last"]:
            params["last"] = box["last"]
        try:
            text = cas.http.get("https://lp.open.weixin.qq.com/connect/l/qrconnect", params=params,
                                timeout=httpx.Timeout(40.0, connect=10.0)).text
        except httpx.TimeoutException:
            return WAITING
        except httpx.HTTPError as e:
            raise NetworkError("连接微信失败", str(e)[:80]) from e
        err = re.search(r"wx_errcode\s*=\s*(\d+)", text)
        code = re.search(r"wx_code\s*=\s*['\"]([^'\"]*)", text)
        e = err.group(1) if err else "408"
        if e == "405" and code and code.group(1):
            box["code"] = code.group(1)
            return CONFIRMED
        if e == "404":
            box["last"] = "404"
            return SCANNED
        if e in ("402", "403", "500"):
            return EXPIRED
        return WAITING

    def finish() -> LoginResult:
        sep = "&" if "?" in redirect_uri else "?"
        return cas._after(cas._get(f"{redirect_uri}{sep}code={box['code']}&state={state}"), fallback_service=service or None)

    return QrChallenge("wechat", img, "用微信扫码并在手机上确认", content=f"https://open.weixin.qq.com/connect/confirm?uuid={uuid}",
                       uuid=uuid, _poll=poll, _finish=finish)


def _json(r: httpx.Response) -> dict:
    try:
        v = r.json()
        return v if isinstance(v, dict) else {}
    except ValueError:
        return {}
