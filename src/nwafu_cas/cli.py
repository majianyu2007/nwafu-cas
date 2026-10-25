"""``nwafu-cas`` command line: log in once, reuse the session, check the site.

    nwafu-cas login [-u 学号] [--qr] [--totp-secret-env VAR]
    nwafu-cas status
    nwafu-cas open <URL>          # print the final URL reached with the login
    nwafu-cas doctor [--json]
    nwafu-cas logout

The session (cookies + device fingerprint) is stored in the user's config
directory with owner-only permissions; passwords are never stored.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path

from . import __version__, doctor
from .client import CasClient
from .errors import CasError
from .interactive import login as i_login
from .interactive import login_qr as i_login_qr
from .qr import QrChallenge


def default_state_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "nwafu-cas" / "state.json"


class TerminalUi:
    def choose(self, message: str, options: Sequence[str]) -> int:
        print(message, file=sys.stderr)
        for i, o in enumerate(options, 1):
            print(f"  {i}. {o}", file=sys.stderr)
        while True:
            v = input("选择序号: ").strip()
            if v.isdigit() and 1 <= int(v) <= len(options):
                return int(v) - 1

    def ask(self, message: str, secret: bool = False) -> str:
        return getpass.getpass(f"{message}: ") if secret else input(f"{message}: ").strip()

    def info(self, message: str) -> None:
        print(message, file=sys.stderr)

    def show_qr(self, qr: QrChallenge) -> None:
        print(f"请{qr.hint}。", file=sys.stderr)
        if qr.content:
            _draw(qr.content)
        path = Path(tempfile.gettempdir()) / f"nwafu-cas-qr.{qr.image_type}"
        path.write_bytes(qr.image)
        print(f"二维码图片：{path}", file=sys.stderr)
        open_file(path)


def _draw(text: str) -> bool:
    try:
        import segno
    except ImportError:
        return False
    segno.make(text, error="l").terminal(compact=True)
    return True


def open_file(path: Path) -> None:
    try:
        if sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        elif os.name == "nt":
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
            subprocess.Popen(["xdg-open", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except OSError:
        pass


def main(argv: list[str] | None = None) -> int:
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    ap = argparse.ArgumentParser(prog="nwafu-cas", description="西北农林科技大学统一身份认证（authserver.nwafu.edu.cn）命令行")
    ap.add_argument("--version", action="version", version=f"nwafu-cas {__version__}")
    ap.add_argument("--state", type=Path, default=None, help=f"会话文件（默认 {default_state_path()}）")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("login", help="登录（账号密码或扫码），自动处理二次认证")
    p.add_argument("-u", "--username", help="学号/工号")
    p.add_argument("--qr", action="store_true", help="用学校 App 扫码登录")
    p.add_argument("--service", help="登录后要进入的服务地址")
    p.add_argument("--totp-secret-env", metavar="VAR", help="从环境变量读取安全令牌 OTP 的密钥，自动完成二次认证")
    p.add_argument("--no-trust", action="store_true", help="不勾选“信任此设备”")
    sub.add_parser("status", help="当前会话是否有效")
    p = sub.add_parser("open", help="用当前会话打开一个校内地址，输出最终到达的地址")
    p.add_argument("url")
    p = sub.add_parser("doctor", help="检查统一身份认证页面是否改版（不需要登录）")
    p.add_argument("--json", action="store_true")
    sub.add_parser("logout", help="退出登录并删除本机会话")
    a = ap.parse_args(argv)
    state = (a.state or default_state_path()).expanduser()

    if a.cmd == "doctor":
        rep = doctor.run()
        if a.json:
            print(json.dumps({"status": rep.status, "site_version": rep.site_version, "verified_version": rep.verified_version,
                              "login_methods": rep.login_methods, "problems": rep.problems}, ensure_ascii=False, indent=1))
        else:
            print(rep.text())
        return {"ok": 0, "changed": 1, "unreachable": 2}[rep.status]

    cas = CasClient.load(state)
    try:
        if a.cmd == "status":
            ok = cas.has_tgc() and cas.is_logged_in()
            print("已登录" if ok else "未登录或已失效", "；本机已登记为可信设备" if cas.trusted() else "")
            return 0 if ok else 1
        if a.cmd == "open":
            r = cas.get(a.url)
            cas.save(state)
            print(r.url)
            return 0
        if a.cmd == "logout":
            cas.logout()
            state.unlink(missing_ok=True)
            print("已退出")
            return 0
        ui = TerminalUi()
        kw = {"trust_device": not a.no_trust}
        if a.totp_secret_env:
            kw["totp_secret"] = os.environ.get(a.totp_secret_env, "")
        if a.qr:
            r = i_login_qr(cas, ui, service=a.service, **kw)
        else:
            user = a.username or input("学号/工号: ").strip()
            r = i_login(cas, user, getpass.getpass("统一身份认证密码: "), ui, service=a.service, **kw)
        cas.save(state)
        print(f"登录成功：{r.url}")
        return 0
    except CasError as e:
        print(f"错误：{e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("已取消", file=sys.stderr)
        return 130
    finally:
        cas.close()


if __name__ == "__main__":
    sys.exit(main())
