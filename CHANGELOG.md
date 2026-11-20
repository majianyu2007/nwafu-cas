# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.3] — 2026-11-20

### 修正
- 修复 `page.error_text` 中 `formErrorTip` 正则跨出 `</div>` 导致在正常登录页误匹配 `<span>7天免登录</span>` 的问题，并改为遍历全部匹配项以跳过前置空提示节点。
- 修复 `cookies.to_json` / `from_json` 重载会话时将 host-only Cookie（如 `CASTGC`）的 `domain_specified` 误置为 `True` 的问题，并过滤已过期 Cookie；同时 `cookies.has` 忽略已过期或空值 Cookie 并按 `authserver.nwafu.edu.cn` 域名校验。
- 修复 `CasClient.get()` 因触发二次认证抛出 `LoginRequired(kind="mfa", login_url=...)` 后，将该 `login_url` 传给 `CasClient.login` / `login_page` / `interactive.login` 时直接报 `SiteChanged` 的问题，现在可直接衔接返回 `MfaChallenge`。
- 加强 `MfaChallenge.submit` 对缺失 `code` 响应的拦截、`page._normalize_service` 对非校内域名的过滤，以及微信扫码回调的 `fallback_service` 传递。

## [1.0.2] — 2026-11-20

### 修正
- 修复 `reAuthParams` 包含非严格 JSON 语法（如 Thymeleaf 转义的 `\'`、无引号键、注释、尾随逗号等）触发回退解析时，未反转义 `\/`、`\u0026` 等 JS 转义序列，导致二次认证提交 `service` 触发「应用未注册」的问题。
- 为 `ReauthPage.service` 增加 HTML 实体与重复 URL 编码纠偏，并在缺失或异常时依次回退至 `reAuthLoginView.do` 查询参数及原登录请求的 `service`。
- 修正 `ReauthPage.is_multifactor` 在收到布尔值时的序列化（`true`/`false`）；补充 `no-access-or-registered-tip`（「应用未注册」）页面错误提取。
- 加固 `MfaChallenge.submit`：明确拦截 302 会话过期、非 JSON 响应及其他非 `reAuth_success` 错误码，不再静默忽略。

## [1.0.1] — 2026-10-25

### 修正
- 扫码登录的说明：二维码用微信或企业微信扫，在已登录统一身份认证的手机上确认（不是“学校 App”）。

### 新增
- 发布到 PyPI（GitHub Actions 可信发布）。

## [1.0.0] — 2026-10-25

更名为 **nwafu-cas**（原 `wisedu_cas`），专为西北农林科技大学统一身份认证设计。与 0.x 不兼容。

### 新增
- 二次认证覆盖学校页面提供的全部方式：
  - 验证码类：短信、企业微信、今日校园、邮箱、钉钉、WeLink、公众号；
  - 安全令牌 OTP（按新接口以 `otpCode` 提交）、认证密码；
  - 扫码类：微信扫码、钉钉/企微/WeLink 扫码、实人认证（支付宝/微信刷脸）；
  - 支持“信任此设备”。
- 首页扫码登录（微信/企业微信扫码）；FIDO 登录改用页面返回的 `sessionToken`。
- 分步 API：`LoginResult` / `MfaChallenge` / `QrChallenge`；`nwafu_cas.interactive` 提供完整对话流程。
- `CasClient.get(url)`：任意校内地址的多跳跳转（含 Vouch/OIDC），未登录时给出 `login_url`。
- 页面自适应：
  - 表单字段从页面读取；
  - 加密参数从 `encrypt.js` 读取；
  - 验证码类型从 `reAuth.js` 读取。
- `nwafu-cas doctor` 页面核对，以及每周自动巡检工作流（发现变化自动开 issue）。
- 命令行 `nwafu-cas`：`login`、`status`、`open`、`doctor`、`logout`。
- `LoginGuard`：最小间隔、每小时上限、失败退避、锁定/验证码后暂停，状态可持久化。

### 变更
- 同步 API（httpx.Client）取代 0.x 的 async `AuthClient`；异步程序可用 `asyncio.to_thread` 调用。
- 不再硬编码 Vouch Proxy 回调路径，改为通用的跳转跟随。
- 包改为 src 布局，构建后端改为 hatchling。

### 移除
- `AuthClient`、`AuthSession`、`AuthState` 状态机和旧的 `retry` 模块（由 `LoginGuard` 取代）。

## [0.2.1] — 2026-05-13

### Changed
- Hardened `AuthClient` configuration validation: unsupported `auth_method` now fails fast.
- Unified TOTP code normalization/validation across provider, generated, and manual submit paths.
- Implemented manual TOTP waiting flow with bounded timeout and clearer error messaging.
- Added targeted unit tests for auth method validation, manual TOTP flow, and provider format errors.

## [0.2.0] — 2026-05-13

### Added
- FIDO2/WebAuthn passkey authentication (`wisedu_cas/fido2.py`).
- `auth_method` parameter on `AuthClient`: `"password"`, `"fido2"`, `"auto"`.
- `Fido2Credential` data model for pre-extracted ECDSA P-256 credentials.
- `Fido2Authenticator` orchestrator: startAssertion, assertion building, submission.
- `Fido2AssertionError` and `Fido2NotConfiguredError` exceptions.
- `auto` auth mode: try FIDO2 first, transparent fallback to password+TOTP.
- All protection layers (rate limit, backoff, circuit breaker, single-flight)
  apply to FIDO2 and auto paths identically.
- `examples/with_fido2.py` and `examples/auto_auth_method.py`.
- 16 new pytest tests covering FIDO2 credential model, assertion building,
  startAssertion, full authenticator flow, AuthClient FIDO2 integration,
  auto fallback, and circuit breaker interaction.

### Not yet supported
- FIDO2 credentials from OS keychain or hardware security keys (requires
  pre-extracted credential file from browser passkey export).
- FIDO2 + TOTP combined flows (if 2FA is required after passkey login).
- WebAuthn registration / credential creation on-device.

## [0.1.0] — 2026-05-13

### Added
- Initial pre-release.

- `AuthClient` — primary entry point for Wisedu CAS authentication.
- `AuthSession` — session representation with `cookies_dict()`, `cookie_header()`, `auth_headers()`, `validate()`, `save()`, `load()`.
- `AuthState` — state machine: `OK`, `SUSPECT`, `EXPIRED`, `LOGIN_BACKOFF`, `CIRCUIT_OPEN`.
- Complete exception hierarchy: `AuthError`, `NetworkError`, `InvalidCredentialsError`, `CaptchaRequiredError`, `TotpRequiredError`, `AccountLockedError`, `LoginBackoffError`, `CircuitOpenError`, `SessionExpiredError`, `ParseError`.
- AES-CBC password encryption matching Wisedu frontend `encrypt.js`.
- CAS login form HTML parsing (execution, salt, error text extraction).
- Login protection layers: rate limiter, exponential backoff with jitter, circuit breaker, single-flight lock.
- TOTP 2FA auto-generation via `pyotp` with window alignment and retry-on-rejection.
- Pluggable TOTP provider (`totp_provider` callable).
- Optional file-based state persistence (rate limit, circuit breaker) and cookie persistence.
- Full type hints and public API docstrings.
- `examples/` directory with basic_login, with_totp, and custom_retry_policy scripts.
- `tests/` directory with pytest suite covering parser, state machine, retry/circuit, session validation, client flows.
- Bilingual (ZH/EN) README with comprehensive documentation.
