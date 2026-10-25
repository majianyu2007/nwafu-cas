"""A fake authserver.nwafu.edu.cn for offline tests.

The pages are minimal synthetic copies of the real structure (2026-10): same
form ids, field names, script variables, second-factor tabs and endpoints.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, quote

import httpx
import pyotp
import pytest

from nwafu_cas import CasClient
from nwafu_cas.crypto import decrypt_password

AS = "https://authserver.nwafu.edu.cn"
SERVICE = "https://ehall.nwafu.edu.cn/login"
SALT = "At1wiiLSvmQU7Nkf"
REAUTH_SALT = "Bq2xjjMTwnRV8Olg"
V = "20260922.133736"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"
PNG = b"\x89PNG\r\n\x1a\n" + b"\0" * 16

LOGIN_HTML = f"""<html><head>
<script src="/authserver/nwafuTheme/static/common/encrypt.js?v={V}"></script>
<script>var service = ["{SERVICE}"];var qrCodeLoginType = "1";</script>
<script>var isQrLoginEnabled = "true"
var captchaSwitch = "2";
var _fidoEnabled = "true";
var is_dynamicLogin = "true";
var is_userNameLogin = "true";</script></head><body>
<form method="post" id="qrLoginForm" action="/authserver/login"><input type="hidden" name="lt" id="lt" value="" />
<input type="hidden" name="uuid" id="uuid" value=""/><input type="hidden" name="cllt" value="qrLogin"/>
<input type="hidden" id="dllt" name="dllt" value="generalLogin"><input type="hidden" name="execution" value="e1s1"/>
<input type="hidden" name="_eventId" value="submit"/><input type="hidden" name="rmShown" value="1"></form>
<form class="loginFromClass" method="post" id="loginFromId" action="/authserver/login">
<input type="hidden" id="username-fido" name="username" value=""><input type="hidden" id="responseJson-fido" name="responseJson" value="">
<input type="hidden" id="cllt" name="cllt" value="fidoLogin"><input type="hidden" id="dllt" name="dllt" value="generalLogin">
<input type="hidden" id="execution" name="execution" value="e1s1" /></form>
<form class="loginFromClass" method="post" id="pwdFromId" action="/authserver/login">
<input id="username" name="username" type="text" value=""><input id="password" name="passwordText" type="password">
<input id="saltPassword" name="password" type="hidden"><input type="text" id="captcha" name="captcha">
<input type="checkbox" name="rememberMe" id="rememberMe" value="true" /><input type="hidden" id="_eventId" name="_eventId" value="submit" />
<input type="hidden" id="cllt" name="cllt" value="userNameLogin"><input type="hidden" id="dllt" name="dllt" value="generalLogin">
<input type="hidden" id="lt" name="lt" value="" /><input type="hidden" id="pwdEncryptSalt" value="{SALT}" />
<input type="hidden" id="execution" name="execution" value="e1s1" /><input type="hidden" name="newField" value="x1" /></form>
</body></html>"""

ERROR_HTML = LOGIN_HTML.replace("<body>", '<body><span id="showErrorTip"><span>您提供的用户名或者密码有误</span></span>')


def reauth_html(offered=(("8", "微信扫码"), ("3", "短信验证码")), more=(("10", "安全令牌OTP"), ("4", "企业微信验证码"), ("14", "钉钉/企微/WeLink扫码"), ("6", "实人认证"), ("2", "认证密码"))):
    tabs = "".join(f'<div class="reauth-tab-item" id="tab_{t}" onclick="handlePcTabClick(this)" data-type="{t}" data-name="{n}"><span>{n}</span></div>' for t, n in offered)
    items = "".join(f'<a class="reauth-tab-more-item" href="javascript:;" id="{t}" title="{n}" data-name="{n}">{n}</a>' for t, n in more)
    params = {"isSleepAccount": "0", "reAuthType": offered[0][0], "isMultifactor": "true", "ipAnomaly": "0",
              "service": SERVICE, "reAuthUserId": "2025000001", "pwdEncryptSalt": REAUTH_SALT, "noneAuthType": None}
    return f"""<html><head><script src="/authserver/nwafuTheme/static/custom/js/reAuth.js?v={V}"></script>
<script>var contextPath = "\\/authserver";
	var reAuthParams = {json.dumps(params)};</script></head><body>
<div class="reauth-tab-list">{tabs}<div class="reauth-tab-more-wrapper">{items}</div></div>
<input type="hidden" name="pluginId" id="pluginId" value="REAL_PERSON_PLUGIN_ALI_PAY"/></body></html>"""


ENCRYPT_JS = ('function getAesString(n,f,c){return 1}function encryptAES(n,f){return f?getAesString(randomString(64)+n,f,randomString(16)):n}'
              'function encryptPassword(n,f){try{return encryptAES(n,f)}catch(c){}return n}'
              'var $aes_chars="ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678",aes_chars_len=$aes_chars.length;mode:CryptoJS.mode.CBC')
REAUTH_JS = """function sendDynamicCodeByPhone(that) {
	if(reAuthParams.reAuthType == '3'){
		authCodeTypeName = "reAuthDynamicCodeType";
	}else if(reAuthParams.reAuthType == '4'){
		authCodeTypeName = "reAuthWChatDynamicCodeType";
	}else if(reAuthParams.reAuthType == '21'){
		authCodeTypeName = "reAuthNewChannelCodeType";
	}
 url: contextPath+"/reAuthCheck/reAuthSubmit.do" "/reAuthCheck/changeReAuthType.do" "/dynamicCode/getDynamicCodeByReauth.do" otpCode skipTmpReAuth combinedLogin.do"""


class FakeAuthServer:
    def __init__(self):
        self.password = "correct horse"
        self.need_mfa = True
        self.need_captcha = False
        self.reauth = reauth_html()
        self.logged_in = False
        self.mfa_pending = False
        self.calls: list[tuple[str, str, dict]] = []
        self.sent: list[str] = []
        self.submits: list[dict] = []
        self.logins: list[dict] = []
        self.status_seq = {"mfa": ["0", "2", "1"], "face": ["0", "2", "1"], "school": ["2", "1"], "wx": ["408", "404", "405"]}
        self.ticket_hits = 0

    def handler(self, req: httpx.Request) -> httpx.Response:
        u = req.url
        q = {k: v[0] for k, v in parse_qs(u.query.decode()).items()}
        form = {k: v[0] for k, v in parse_qs(req.content.decode(), keep_blank_values=True).items()} if req.method == "POST" and req.content and b"{" not in req.content[:1] else {}
        self.calls.append((req.method, f"{u.host}{u.path}", {**q, **form}))
        host, path = u.host, u.path
        if host == "ehall.nwafu.edu.cn":
            if "ticket" in q:
                self.ticket_hits += 1
                return httpx.Response(302, headers={"Location": SERVICE.replace("/login", "/new/index.html")})
            return httpx.Response(200, text="portal")
        if host == "open.weixin.qq.com":
            if path == "/connect/qrconnect":
                return httpx.Response(200, text='<img class="web_qrcode_img" src="/connect/qrcode/WXUUID"/>')
            return httpx.Response(200, content=PNG)
        if host == "lp.open.weixin.qq.com":
            code = self.status_seq["wx"].pop(0)
            return httpx.Response(200, text=f"window.wx_errcode={code};window.wx_code='{'WXCODE' if code == '405' else ''}';")
        assert host == "authserver.nwafu.edu.cn", host
        if path.endswith("/encrypt.js"):
            return httpx.Response(200, text=ENCRYPT_JS)
        if path.endswith("/reAuth.js"):
            return httpx.Response(200, text=REAUTH_JS)
        if path == "/authserver/login":
            if req.method == "GET":
                if self.logged_in and not self.mfa_pending:
                    return httpx.Response(302, headers={"Location": f"{q['service']}?ticket=ST-1"} if "service" in q else {"Location": "/authserver/index.do"})
                if self.mfa_pending:
                    return httpx.Response(302, headers={"Location": f"/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service={quote(q.get('service', ''), safe='')}"})
                return httpx.Response(200, text=LOGIN_HTML)
            self.logins.append(form)
            ok = False
            if form.get("cllt") == "userNameLogin":
                ok = decrypt_password(form["password"], SALT) == self.password and "passwordText" not in form
            elif form.get("cllt") == "qrLogin":
                ok = form.get("uuid") == "SCHOOLUUID" and q.get("display") == "qrLogin"
            elif form.get("cllt") == "fidoLogin":
                ok = json.loads(form["responseJson"])["requestId"] == "REQ1"
            if not ok:
                return httpx.Response(200, text=ERROR_HTML)
            self.logged_in = True
            self.mfa_pending = self.need_mfa and not any(c.name == "MULTIFACTOR_TRUSTED" for c in [])
            resp = httpx.Response(302, headers={"Location": f"{AS}/authserver/login?service={quote(q['service'], safe='')}"})
            resp.headers["Set-Cookie"] = "CASTGC=TGT-1; Path=/authserver; Secure"
            return resp
        if path == "/authserver/checkNeedCaptcha.htl":
            return httpx.Response(200, json={"isNeed": self.need_captcha})
        if path == "/authserver/bfp/info":
            return httpx.Response(200, json={}, headers={"Set-Cookie": f"MULTIFACTOR_BROWSER_FINGERPRINT={q['bfp']}; Path=/authserver"})
        if path == "/authserver/reAuthCheck/reAuthLoginView.do":
            return httpx.Response(200, text=self.reauth)
        if path == "/authserver/reAuthCheck/changeReAuthType.do":
            return httpx.Response(200, json={"code": 1, "data": {"reAuthType": form["reAuthType"], "otpIsBind": True}})
        if path == "/authserver/dynamicCode/getDynamicCodeByReauth.do":
            self.sent.append(form["authCodeTypeName"])
            return httpx.Response(200, json={"res": "success", "returnMessage": "验证码已发送至", "mobile": "138****0000", "codeTime": 120})
        if path == "/authserver/reAuthCheck/reAuthSubmit.do":
            self.submits.append(form)
            t = form["reAuthType"]
            ok = {
                "3": form.get("dynamicCode") == "123456",
                "4": form.get("dynamicCode") == "654321",
                "10": form.get("otpCode") == pyotp.TOTP(TOTP_SECRET).now() and form.get("dynamicCode") == "",
                "2": form.get("password") and decrypt_password(form["password"], REAUTH_SALT) == self.password,
                "14": form.get("uuid") == "U14",
                "6": form.get("uuid") == "UFACE",
            }.get(t, False)
            if not ok:
                return httpx.Response(200, json={"code": "reAuth_failed", "msg": "验证码错误"})
            self.mfa_pending = False
            return httpx.Response(200, json={"code": "reAuth_success"})
        if path == "/authserver/reAuthCheck/getToken":
            return httpx.Response(200, json={"errCode": "1", "uuid": "U14"})
        if path in ("/authserver/reAuthCheck/getCode", "/authserver/qrCode/getCode", "/authserver/faceAuthWithPlugins/getQrCodeByFace"):
            return httpx.Response(200, content=PNG)
        if path == "/authserver/reAuthCheck/getStatus.htl":
            return httpx.Response(200, text=self.status_seq["mfa"].pop(0))
        if path == "/authserver/faceAuthWithPlugins/getQrCodeById":
            assert q["pluginId"] == "REAL_PERSON_PLUGIN_ALI_PAY"
            return httpx.Response(200, json={"errCode": "1", "uuid": "UFACE"})
        if path == "/authserver/faceAuthWithPlugins/getStatus":
            return httpx.Response(200, json={"state": self.status_seq["face"].pop(0)})
        if path == "/authserver/qrCode/getToken":
            return httpx.Response(200, text="SCHOOLUUID")
        if path == "/authserver/qrCode/getStatus.htl":
            return httpx.Response(200, text=self.status_seq["school"].pop(0))
        if path == "/authserver/combinedLogin.do":
            assert q["type"] == "weixin"
            redirect = quote(f"{AS}/authserver/callback", safe="")
            return httpx.Response(302, headers={"Location": f"https://open.weixin.qq.com/connect/qrconnect?appid=wx1&redirect_uri={redirect}&response_type=code&scope=snsapi_login&state=ST8"})
        if path == "/authserver/callback":
            assert q == {"code": "WXCODE", "state": "ST8"}
            self.mfa_pending = False
            return httpx.Response(302, headers={"Location": f"{AS}/authserver/login?service={quote(SERVICE, safe='')}"})
        if path == "/authserver/startAssertion":
            body = json.loads(req.content)
            assert body["userId"] and "id" in body
            return httpx.Response(200, json={"result": {"success": True, "request": {"requestId": "REQ1", "sessionToken": "S1",
                                     "publicKeyCredentialRequestOptions": {"challenge": "Y2hhbGxlbmdl", "rpId": "authserver.nwafu.edu.cn"}}}})
        if path == "/authserver/logout":
            self.logged_in = False
            return httpx.Response(200, text="bye")
        return httpx.Response(404, text=f"no route {path}")


@pytest.fixture
def site():
    return FakeAuthServer()


@pytest.fixture
def cas(site):
    http = httpx.Client(transport=httpx.MockTransport(site.handler), follow_redirects=False)
    c = CasClient(http=http)
    yield c
    c.close()
