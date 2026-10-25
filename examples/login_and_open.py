"""Log in once (asking for a second factor if the school wants one), then reuse the session."""

import getpass

from nwafu_cas import CasClient
from nwafu_cas.cli import TerminalUi
from nwafu_cas.interactive import login

STATE = "state.json"

cas = CasClient.load(STATE)
if not cas.is_logged_in():
    login(cas, input("学号/工号: "), getpass.getpass("密码: "), TerminalUi())
    cas.save(STATE)
print(cas.open_service("https://ehall.nwafu.edu.cn/login").url)
