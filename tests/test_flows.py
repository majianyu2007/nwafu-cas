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
