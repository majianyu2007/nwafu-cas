# Changelog

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 与 [语义化版本](https://semver.org/lang/zh-CN/)。

## [1.0.0] — 2026-10-25

更名为 **nwafu-cas**（原 `wisedu_cas`），专为西北农林科技大学统一身份认证设计。与 0.x 不兼容。

### 新增
- 二次认证覆盖学校页面提供的全部方式：
  - 验证码类：短信、企业微信、今日校园、邮箱、钉钉、WeLink、公众号；
  - 安全令牌 OTP（按新接口以 `otpCode` 提交）、认证密码；
  - 扫码类：微信扫码、钉钉/企微/WeLink 扫码、实人认证（支付宝/微信刷脸）；
  - 支持“信任此设备”。
- 首页扫码登录（学校 App）；FIDO 登录改用页面返回的 `sessionToken`。
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
