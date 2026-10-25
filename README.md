# nwafu-cas

[![CI](https://github.com/majianyu2007/nwafu-cas/actions/workflows/ci.yml/badge.svg)](https://github.com/majianyu2007/nwafu-cas/actions/workflows/ci.yml)
[![Site watch](https://github.com/majianyu2007/nwafu-cas/actions/workflows/site-watch.yml/badge.svg)](https://github.com/majianyu2007/nwafu-cas/actions/workflows/site-watch.yml)
[![PyPI](https://img.shields.io/pypi/v/nwafu-cas)](https://pypi.org/project/nwafu-cas/)
![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

西北农林科技大学统一身份认证（[authserver.nwafu.edu.cn](https://authserver.nwafu.edu.cn)）的 Python 客户端与命令行。用于给自己的脚本、工具接入学校的单点登录：

- **首页登录方式**：账号密码、扫码登录（微信或企业微信扫码，在已登录统一身份认证的手机上确认）、FIDO 通行密钥（软件凭据）。
- **二次认证**：学校页面提供的方式都能完成：
  - 短信、企业微信、今日校园、邮箱、钉钉、WeLink、公众号验证码；
  - 安全令牌 OTP（可用密钥自动生成）；
  - 认证密码；
  - 微信扫码、钉钉/企业微信/WeLink 扫码、实人认证（支付宝/微信扫码刷脸）；
  - 支持“信任此设备”。
- **会话复用**：Cookie 和设备指纹可保存到本地文件（仅本人可读）。下次直接复用 CASTGC，不必重复登录。
- **进入任意校内服务**：自动处理 CAS ticket；对 Vouch / OIDC 等多跳跳转，也能登录后回到原地址。
- **自适应页面改版**：详见下文“学校页面改版怎么办”。

> 原名 `wisedu_cas`（通用金智 CAS 客户端）。1.0 起专为西农设计，接口不兼容旧版，见 [CHANGELOG](CHANGELOG.md)。

## 安装

```bash
pip install nwafu-cas
# 可选：FIDO 通行密钥登录 / 终端里直接显示二维码
pip install "nwafu-cas[fido2,qr]"
# 校园网内访问 PyPI 慢时可用镜像，例如：pip install -i https://pypi.tuna.tsinghua.edu.cn/simple nwafu-cas
```

需要 Python 3.10+。依赖只有 httpx、pycryptodome、pyotp。

## 命令行

```bash
nwafu-cas login -u 2025xxxxxx     # 输入密码；需要二次认证时列出可用方式让你选
nwafu-cas login --qr              # 用微信或企业微信扫码登录
nwafu-cas status                  # 会话是否还有效
nwafu-cas open https://ehall.nwafu.edu.cn/new/index.html
nwafu-cas doctor                  # 检查学校页面是否改版（不需要登录）
nwafu-cas logout
```

会话保存在 macOS `~/Library/Application Support/nwafu-cas/state.json`、Linux `~/.config/nwafu-cas/state.json`、Windows `%APPDATA%\nwafu-cas\state.json`，只含 Cookie 和设备指纹，不含密码。

## 作为库使用

最简单的方式是交给 `interactive`，它会在需要时询问二次认证：

```python
from nwafu_cas import CasClient
from nwafu_cas.cli import TerminalUi
from nwafu_cas.interactive import login

cas = CasClient.load("state.json")
if not cas.is_logged_in():
    login(cas, "2025xxxxxx", password, TerminalUi())   # 也可传 totp_secret=... 自动完成 OTP
page = cas.open_service("https://ehall.nwafu.edu.cn/login")
cas.save("state.json")
```

自己控制每一步：

```python
res = cas.login("2025xxxxxx", password)
if not res.done:                               # 学校要求二次认证
    mfa = res.mfa
    for m in mfa.methods:                      # 这个账号可用的方式，例如
        print(m.type, m.name, m.kind)          # 3 短信验证码 code / 10 安全令牌OTP otp / 8 微信扫码 wechat
    mfa.select("3")
    print(mfa.send_code())                     # “验证码已发送至 138****0000”
    res = mfa.submit(code=input("验证码: "), trust_device=True)

    # 扫码类（微信扫码 / 钉钉等扫码 / 实人认证）：
    # mfa.select("8"); qr = mfa.start_qr(); 保存或显示 qr.image; res = qr.wait()
```

需要登录的地址不是 CAS `service` 形式时（如前面有 Vouch Proxy），用 `cas.get(url)`。它抛出的 `LoginRequired` 带有 `login_url`，用 `cas.login(..., login_url=e.login_url)` 登录后即回到原地址。

二次认证方式的 `kind` 决定怎么完成：

| kind | 方式 | 怎么完成 |
|---|---|---|
| `code` | 短信、企业微信、今日校园、邮箱、钉钉、WeLink、公众号验证码 | `send_code()` 后 `submit(code=…)` |
| `otp` | 安全令牌 OTP | `submit(code=…)` 或 `submit_totp(密钥)` |
| `password` | 认证密码（安全问题现在也走这一项） | `submit(password=…)` |
| `qr` / `face` / `wechat` | 钉钉/企微/WeLink 扫码、实人认证、微信扫码 | `start_qr()` → 显示 `image` → `wait()` |
| `none` | QQ 扫码、CA UKey | 只能在浏览器里完成 |

### 防止频繁登录

给机器人、长期运行的服务用：`CasClient(guard=LoginGuard(path="guard.json"))`。

- 每次真正登录前都会检查最小间隔和每小时次数上限；
- 连续失败会指数退避；
- 账号被锁定或学校要求验证码后，会暂停数小时，不会越试越糟。

### 错误

所有异常都继承 `CasError`，消息是中文，带 `hint`（下一步怎么办）和 `kind`。主要有：

- `InvalidCredentials`、`CaptchaRequired`、`AccountLocked`；
- `LoginRequired`、`MfaError`、`QrExpired`；
- `SiteChanged`（页面改版）、`NetworkError`、`Throttled`。

## 学校页面改版怎么办

1. **运行时自适应**：
   - 表单的隐藏字段从页面读取并原样提交；
   - 密码加密的字符表和长度从线上 `encrypt.js` 读取；
   - 验证码类二次认证的类型对照，从线上 `reAuth.js` 读取。

   页面新增一个隐藏字段或一种验证码渠道，旧版本照样能用。
2. **`nwafu-cas doctor`**：
   - 逐项核对本库依赖的表单字段、接口和脚本标记；
   - 报告页面版本（`?v=` 资源版本号），并和本版本核对时的版本比较。
3. **每周自动巡检**：GitHub Actions 定期对线上页面运行 doctor（[site-watch](.github/workflows/site-watch.yml)），发现变化就自动开 issue。

本版本核对于站点版本 `20260922.133736`（AuthServer 3.8.2）。

## 开发

```bash
uv venv && uv pip install -e ".[dev,qr]"
.venv/bin/pytest          # 离线测试：模拟的 authserver，覆盖全部登录与二次认证流程
.venv/bin/ruff check src tests
```

## 免责声明

本项目是个人开发的工具，与西北农林科技大学及金智教育无关联，也未获背书：

- 只模拟浏览器里本人可以完成的登录操作，请求频率应与正常使用相当；
- 请遵守学校的信息化管理规定，不要用于他人账号或批量访问；
- 密码只会发送给学校的统一身份认证服务器，不会写入本库保存的任何文件。

## 许可

[MIT](LICENSE)
