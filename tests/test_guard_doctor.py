import time

import httpx
import pytest
from conftest import ENCRYPT_JS, LOGIN_HTML, REAUTH_JS

from nwafu_cas import GuardPolicy, LoginGuard, Throttled, doctor


def test_guard_interval_backoff_and_hold(tmp_path):
    g = LoginGuard(GuardPolicy(min_interval=0, max_per_hour=100, backoff_base=0.05, backoff_max=0.1, hold_after_lock=60), tmp_path / "g.json")
    g.before_attempt()
    g.record_failure("password")
    with pytest.raises(Throttled):
        g.before_attempt()
    time.sleep(0.15)
    g.before_attempt()
    g.record_failure("network")  # not escalated
    g.before_attempt()
    g.record_failure("locked")
    again = LoginGuard(g.policy, tmp_path / "g.json")  # persisted
    with pytest.raises(Throttled) as e:
        again.before_attempt()
    assert e.value.retry_after > 50
    again.reset()
    again.before_attempt()


def test_guard_rate_limits():
    g = LoginGuard(GuardPolicy(min_interval=0, max_per_hour=2))
    g.before_attempt()
    g.before_attempt()
    with pytest.raises(Throttled, match="次数过多"):
        g.before_attempt()


def _site(js_override=None):
    js = {"common/encrypt.js": ENCRYPT_JS, "custom/js/reAuth.js": REAUTH_JS}
    js.update(js_override or {})

    def handler(req):
        p = req.url.path
        if p == "/authserver/login":
            return httpx.Response(200, text=LOGIN_HTML)
        rel = p.split("/static/", 1)[-1]
        if rel in js:
            return httpx.Response(200, text=js[rel])
        from nwafu_cas.doctor import SCRIPT_MARKERS

        return httpx.Response(200, text=" ".join(SCRIPT_MARKERS.get(rel, [])))

    return httpx.Client(transport=httpx.MockTransport(handler))


def test_doctor_ok_and_changed():
    rep = doctor.run(_site())
    assert rep.status == "ok", rep.text()
    assert "21" in dict((i, d) for i, _, d in rep.checks)["验证码类二次认证类型"]
    rep = doctor.run(_site({"custom/js/reAuth.js": REAUTH_JS.replace("otpCode", "otpValue")}))
    assert rep.status == "changed" and any("otpCode" in d for _, d in rep.problems)


def test_doctor_unreachable():
    def boom(req):
        raise httpx.ConnectError("down")

    assert doctor.run(httpx.Client(transport=httpx.MockTransport(boom))).status == "unreachable"
