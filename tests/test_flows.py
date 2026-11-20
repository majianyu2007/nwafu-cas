import pyotp
import pytest
from conftest import PNG, SERVICE, TOTP_SECRET, reauth_html

from nwafu_cas import CaptchaRequired, CasClient, InvalidCredentials, LoginRequired, MfaError, Unsupported, interactive, mfa
from nwafu_cas.crypto import decrypt_password, encrypt_password
from nwafu_cas.page import parse_login_page


def test_cipher_roundtrip_matches_server_side_decryption():
    for pw in ("abc", "密码Pa$$w0rd!", "x" * 40):
        assert decrypt_password(encrypt_password(pw, "At1wiiLSvmQU7Nkf"), "At1wiiLSvmQU7Nkf") == pw
    assert encrypt_password("plain", "") == "plain"


def test_login_page_parsing_collects_every_field():
    from conftest import LOGIN_HTML

    p = parse_login_page(LOGIN_HTML, "u")
    assert p.methods == {"password": True, "sms": False, "qr": True, "fido2": True}
    assert p.salt == "At1wiiLSvmQU7Nkf" and p.captcha_switch == "2" and p.theme_version == "20260922.133736"
    f = p.form("userNameLogin")
    assert f.fields["newField"] == "x1" and "rememberMe" not in f.fields  # unchecked checkbox


def test_password_login_without_second_factor(cas, site):
    site.need_mfa = False
    res = cas.login("2025000001", "correct horse", service=SERVICE)
    assert res.done and res.response.text == "portal"
    sent = site.logins[-1]
    assert sent["newField"] == "x1" and sent["rememberMe"] == "true" and "passwordText" not in sent
    assert cas.has_tgc() and cas.is_logged_in()
    assert cas.open_service(SERVICE).text == "portal"


def test_wrong_password_and_captcha(cas, site):
    with pytest.raises(InvalidCredentials, match="用户名或者密码有误"):
        cas.login("2025000001", "wrong")
    site.need_captcha = True
    with pytest.raises(CaptchaRequired, match="滑块"):
        cas.login("2025000001", "correct horse")


def test_adapts_code_types_from_live_script(cas, site):
    res = cas.login("2025000001", "correct horse")
    assert not res.done
    assert cas.has_tgc() and not cas.is_logged_in()  # second factor still pending
    assert mfa.method("21").kind == "code" and mfa.method("21").send_type == "reAuthNewChannelCodeType"


def test_sms_second_factor_with_trust(cas, site):
    res = cas.login("2025000001", "correct horse")
    m = res.mfa
    assert [x.type for x in m.methods] == ["8", "3", "10", "4", "14", "6", "2"]
    assert m.method("3").name == "短信验证码" and m.current == "8"
    m.select("3")
    assert "138****0000" in m.send_code()
    with pytest.raises(MfaError, match="验证码错误"):
        m.submit(code="000000")
    res = m.submit(code="123456")
    assert res.done and res.response.text == "portal"
    sub = site.submits[-1]
    assert sub["skipTmpReAuth"] == "true" and sub["reAuthType"] == "3" and sub["otpCode"] == ""
    assert site.sent == ["reAuthDynamicCodeType"]
    assert cas.trusted()  # fingerprint registered before submitting


def test_otp_is_sent_as_otpCode(cas, site):
    res = cas.login("2025000001", "correct horse").mfa.submit_totp(TOTP_SECRET)
    assert res.done and site.submits[-1]["otpCode"] == pyotp.TOTP(TOTP_SECRET).now()


def test_password_reauth_uses_page_salt(cas, site):
    m = cas.login("2025000001", "correct horse").mfa
    m.select("2")
    assert m.submit(password="correct horse").done


@pytest.mark.parametrize("type_, kind", [("14", "mfa"), ("6", "face"), ("8", "wechat")])
def test_qr_second_factors(cas, site, type_, kind):
    m = cas.login("2025000001", "correct horse").mfa
    m.select(type_)
    q = m.start_qr()
    assert q.kind == kind and q.image == PNG and q.image_type == "png"
    seen = []
    res = q.wait(interval=0, on_status=seen.append)
    assert res.done and res.response.text == "portal"
    assert seen[-2:] == ["scanned", "confirmed"]
    if kind == "wechat":
        assert q.content.endswith("uuid=WXUUID")


def test_school_app_qr_login(cas, site):
    site.need_mfa = False
    q = cas.login_qr(service=SERVICE)
    assert q.kind == "school"
    assert q.wait(interval=0).done
    assert site.logins[-1]["cllt"] == "qrLogin" and site.logins[-1]["execution"] == "e1s1"


def test_fido2_login(cas, site):
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from nwafu_cas.fido2 import Fido2Credential

    key = ec.generate_private_key(ec.SECP256R1())
    der = key.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    import base64

    cred = Fido2Credential(credential_id="0a0b0c", key_value=base64.b64encode(der).decode(), username="2025000001")
    site.need_mfa = False
    assert cas.login_fido2(cred).done
    import json

    body = json.loads(site.logins[-1]["responseJson"])
    assert body["sessionToken"] == "S1" and body["credential"]["type"] == "public-key"


def test_interactive_completion_with_preference(cas, site):
    class Ui:
        asked = []

        def choose(self, message, options):
            return options.index("企业微信验证码")

        def ask(self, message, secret=False):
            self.asked.append(message)
            return "654321"

        def info(self, message):
            pass

        def show_qr(self, qr):
            raise AssertionError

    r = interactive.login(cas, "2025000001", "correct horse", Ui())
    assert r.text == "portal" and site.sent == ["reAuthWChatDynamicCodeType"]
    assert Ui.asked == ["请输入企业微信验证码"]


def test_interactive_uses_totp_secret_silently(cas, site):
    r = interactive.login(cas, "2025000001", "correct horse", ui=None, totp_secret=TOTP_SECRET)
    assert r.text == "portal"


def test_unbound_otp_and_browser_only_methods(cas, site):
    site.reauth = reauth_html(offered=(("9", "QQ扫码"),), more=())
    m = cas.login("2025000001", "correct horse").mfa
    assert m.supported == []
    with pytest.raises(MfaError, match="浏览器"):
        interactive.complete(cas.login("2025000001", "correct horse"), ui=None)
    with pytest.raises(Unsupported):
        m.submit(code="1")


def test_get_reports_where_to_log_in(cas, site):
    with pytest.raises(LoginRequired) as e:
        cas.get("https://authserver.nwafu.edu.cn/authserver/login?service=https%3A%2F%2Fehall.nwafu.edu.cn%2Flogin")
    assert e.value.login_url.startswith("https://authserver.nwafu.edu.cn/authserver/login")


def test_foreign_redirects_are_not_followed(cas):
    from nwafu_cas import CasError

    with pytest.raises(CasError, match="学校以外"):
        cas.follow("https://example.com/")


def test_state_roundtrip(cas, site, tmp_path):
    site.need_mfa = False
    cas.login("2025000001", "correct horse")
    cas.ensure_fingerprint()
    p = tmp_path / "s.json"
    cas.save(p)
    again = CasClient.load(p)
    assert again.fingerprint == cas.fingerprint and again.has_tgc() and again.trusted()
    import os
    import stat

    if os.name != "nt":
        assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_reauth_params_with_thymeleaf_js_escapes_and_non_json_syntax(cas, site):
    # Thymeleaf th:inline="javascript" escapes `/` as `\/`, `&` as `\u0026`, and `'` as `\'`.
    # The `\'` inside reAuthDec3 forces _js_object out of json.loads into the JS-literal parser.
    site.reauth = """<html><head><script>
        var other = {"service": "https:\\/\\/wrong.invalid\\/bad"};
        var reAuthParams = {
            // comment with } brace
            "reAuthDec3": "Don\\'t share <span class=\\'tip\\'>验证码</span>",
            isSleepAccount: 0,
            reAuthType: '3',
            isMultifactor: true,
            service: "https:\\/\\/ehall.nwafu.edu.cn\\/login",
            reAuthUserId: "2025000001",
            pwdEncryptSalt: "Bq2xjjMTwnRV8Olg",
        };
    </script></head><body>
        <div class="reauth-tab-item" id="tab_3" data-type="3" data-name="短信验证码">短信验证码</div>
    </body></html>"""
    m = cas.login("2025000001", "correct horse").mfa
    assert m.service == SERVICE
    assert m.page.is_multifactor == "true"
    assert m.page.asks_trust is True
    assert "138****0000" in m.send_code()
    res = m.submit(code="123456")
    assert res.done and res.response.text == "portal"
    assert site.submits[-1]["service"] == SERVICE


def test_reauth_service_normalizes_encoded_and_falls_back_to_url():
    from nwafu_cas.page import parse_reauth_page

    # 1. Whole-URL-encoded service in reAuthParams
    html_encoded = """<script>
        var reAuthParams = {
            "service": "https%3A%2F%2Fehall.nwafu.edu.cn%2Fjwapp%2Fsys%2Fwdkbby%2F*default%2Findex.do",
            "reAuthType": "3", "reAuthUserId": "2025000001"
        };
    </script>"""
    p1 = parse_reauth_page(html_encoded, "https://authserver.nwafu.edu.cn/authserver/reAuthCheck/reAuthLoginView.do")
    assert p1.service == "https://ehall.nwafu.edu.cn/jwapp/sys/wdkbby/*default/index.do"

    # 2. Missing service in reAuthParams falls back to query string of reAuthLoginView.do
    html_missing = '<script>var reAuthParams = {"reAuthType": "3", "reAuthUserId": "2025000001"};</script>'
    p2 = parse_reauth_page(
        html_missing,
        "https://authserver.nwafu.edu.cn/authserver/reAuthCheck/reAuthLoginView.do?isMultifactor=true&service=https%3A%2F%2Fehall.nwafu.edu.cn%2Flogin",
    )
    assert p2.service == SERVICE

    # 3. Query params escaped with \u0026 inside non-JSON reAuthParams
    html_amp = """<script>
        var reAuthParams = {
            note: 'a\\'b',
            service: "https:\\/\\/ehall.nwafu.edu.cn\\/jwapp\\/sys\\/wdkbby\\/*default\\/index.do?a=1\\u0026b=2",
        };
    </script>"""
    p3 = parse_reauth_page(html_amp, "https://authserver.nwafu.edu.cn/authserver/reAuthCheck/reAuthLoginView.do")
    assert p3.service == "https://ehall.nwafu.edu.cn/jwapp/sys/wdkbby/*default/index.do?a=1&b=2"


def test_unregistered_app_error_is_extracted_and_surfaced():
    from conftest import UNREGISTERED_HTML

    from nwafu_cas import CasError
    from nwafu_cas.client import classify_failure
    from nwafu_cas.page import error_text

    assert error_text(UNREGISTERED_HTML) == "应用未注册"
    err = classify_failure(UNREGISTERED_HTML)
    assert isinstance(err, CasError) and "应用未注册" in str(err)


def test_mfa_submit_rejects_expired_redirect_and_unregistered_msg(cas, site):
    import httpx

    m = cas.login("2025000001", "correct horse").mfa
    m.select("3")
    orig = site.handler

    def redirect_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/authserver/reAuthCheck/reAuthSubmit.do":
            return httpx.Response(302, headers={"Location": "/authserver/login"})
        return orig(req)

    cas.http._transport = httpx.MockTransport(redirect_handler)
    with pytest.raises(MfaError, match="已过期"):
        m.submit(code="123456")

    def unreg_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/authserver/reAuthCheck/reAuthSubmit.do":
            return httpx.Response(200, json={"code": "reAuth_failed", "msg": "应用未注册"})
        return orig(req)

    cas.http._transport = httpx.MockTransport(unreg_handler)
    with pytest.raises(MfaError, match="应用未注册"):
        m.submit(code="123456")

    def empty_code_handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/authserver/reAuthCheck/reAuthSubmit.do":
            return httpx.Response(200, json={"msg": "验证状态异常"})
        return orig(req)

    cas.http._transport = httpx.MockTransport(empty_code_handler)
    with pytest.raises(MfaError, match="验证状态异常"):
        m.submit(code="123456")


def test_error_text_does_not_escape_empty_form_error_tip_div():
    from nwafu_cas.page import error_text

    clean_login = """<html><body>
        <div id="formErrorTip" class="form-errorTip">
            <span id="showErrorTip" class="form-error"></span>
            <span id="showWarnTip" class="form-warn"></span>
        </div>
        <div class="remember-me"><span>7天免登录</span></div>
    </body></html>"""
    assert error_text(clean_login) == ""

    second_tab_error = clean_login + '<div id="formErrorTip"><span class="form-error">动态码已失效</span></div>'
    assert error_text(second_tab_error) == "动态码已失效"


def test_normalize_service_rejects_non_campus_host_and_falls_back():
    from nwafu_cas.page import parse_reauth_page

    html = '<script>var reAuthParams = {"service": "https:\\/\\/evil.example.com\\/steal", "reAuthType": "3"};</script>'
    p = parse_reauth_page(
        html,
        "https://authserver.nwafu.edu.cn/authserver/reAuthCheck/reAuthLoginView.do?service=https%3A%2F%2Fehall.nwafu.edu.cn%2Flogin",
    )
    assert p.service == SERVICE


def test_cookies_preserve_host_only_scope_and_ignore_expired_and_cross_host_302(tmp_path):
    import time
    from http.cookiejar import Cookie

    import httpx

    from nwafu_cas import cookies as C

    seen_headers: dict[str, str] = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen_headers[f"{req.url.host}{req.url.path}"] = req.headers.get("cookie", "")
        if req.url.host == "authserver.nwafu.edu.cn" and req.url.path == "/authserver/set":
            return httpx.Response(200, headers={"Set-Cookie": "CASTGC=TGT-LIVE; Path=/authserver/; Secure; HttpOnly"})
        if req.url.host == "booking-lib.nwafu.edu.cn" and req.url.path == "/api/cas/cas":
            return httpx.Response(
                302,
                headers={
                    "Set-Cookie": "PHPSESSID=php-123; path=/",
                    "Location": "https://authserver.nwafu.edu.cn/authserver/login?service=https%3A%2F%2Fbooking-lib.nwafu.edu.cn%2Fapi%2Fcas%2Fcas",
                },
            )
        return httpx.Response(200, text="ok")

    c1 = CasClient(http=httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False))
    c1._get("https://authserver.nwafu.edu.cn/authserver/set")
    p = tmp_path / "state.json"
    c1.save(p)
    c1.close()

    # Reload into a fresh client (simulating cold start)
    loaded = CasClient.load(p)
    loaded.http._transport = httpx.MockTransport(handler)
    try:
        # Host-only CASTGC keeps domain_specified=False and does not leak to sibling campus hosts
        castgc = next(c for c in loaded.http.cookies.jar if c.name == "CASTGC")
        assert castgc.domain_specified is False and castgc.domain_initial_dot is False
        loaded._get("https://ehall.nwafu.edu.cn/authserver/login")
        assert "CASTGC" not in seen_headers["ehall.nwafu.edu.cn/authserver/login"]

        # Cross-host 302 from booking-lib with Set-Cookie: PHPSESSID must NOT pollute or wipe authserver cookies
        loaded.follow("https://booking-lib.nwafu.edu.cn/api/cas/cas")
        assert "CASTGC=TGT-LIVE" in seen_headers["authserver.nwafu.edu.cn/authserver/login"]
        assert "PHPSESSID" not in seen_headers["authserver.nwafu.edu.cn/authserver/login"]
        assert loaded.has_tgc()

        # Expired CASTGC must not report has_tgc() == True
        loaded.http.cookies.jar.set_cookie(Cookie(
            version=0, name="CASTGC", value="TGT-OLD", port=None, port_specified=False,
            domain="authserver.nwafu.edu.cn", domain_specified=False, domain_initial_dot=False,
            path="/authserver/", path_specified=True, secure=True,
            expires=int(time.time()) - 60, discard=False, comment=None, comment_url=None, rest={},
        ))
        assert not C.has(loaded.http.cookies, "CASTGC", "authserver.nwafu.edu.cn")
        assert not loaded.has_tgc()
    finally:
        loaded.close()


def test_get_mfa_login_url_can_be_passed_directly_to_login(cas, site):
    # First login leaves MFA pending
    res1 = cas.login("2025000001", "correct horse", service=SERVICE)
    assert not res1.done

    # Subsequent cas.get() raises LoginRequired(kind="mfa", login_url=reAuthLoginView...)
    with pytest.raises(LoginRequired) as exc:
        cas.get(cas.login_url(SERVICE))
    assert exc.value.kind == "mfa"
    assert "/reAuthCheck/reAuthLoginView.do" in (exc.value.login_url or "")

    # Passing e.login_url back to cas.login() returns the MfaChallenge cleanly instead of SiteChanged
    res2 = cas.login("2025000001", "correct horse", login_url=exc.value.login_url)
    assert not res2.done and res2.mfa is not None
    res2.mfa.select("3")
    done = res2.mfa.submit(code="123456")
    assert done.done and done.response.text == "portal"
