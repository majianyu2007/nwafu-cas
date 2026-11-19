"""西北农林科技大学统一身份认证（authserver.nwafu.edu.cn）的 Python 客户端。"""

from .client import CasClient, LoginResult, MfaChallenge, classify_failure
from .constants import AUTH_SERVER, DEFAULT_SERVICE, VERIFIED_THEME
from .crypto import encrypt_password
from .errors import (
    AccountLocked,
    CaptchaRequired,
    CasError,
    Fido2Error,
    InvalidCredentials,
    LoginRequired,
    Maintenance,
    MfaError,
    NetworkError,
    QrExpired,
    SiteChanged,
    Throttled,
    Unsupported,
)
from .guard import GuardPolicy, LoginGuard
from .mfa import MfaMethod
from .qr import QrChallenge

__version__ = "1.0.2"

__all__ = [
    "AUTH_SERVER", "DEFAULT_SERVICE", "VERIFIED_THEME",
    "CasClient", "LoginResult", "MfaChallenge", "MfaMethod", "QrChallenge", "classify_failure",
    "LoginGuard", "GuardPolicy", "encrypt_password",
    "CasError", "NetworkError", "InvalidCredentials", "CaptchaRequired", "AccountLocked", "Maintenance",
    "SiteChanged", "LoginRequired", "MfaError", "QrExpired", "Unsupported", "Fido2Error", "Throttled",
]
