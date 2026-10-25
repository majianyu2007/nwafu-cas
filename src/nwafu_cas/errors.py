"""Exceptions. Messages are Chinese and meant for end users; ``kind`` is for code."""

from __future__ import annotations


class CasError(Exception):
    kind = "auth"

    def __init__(self, message: str, hint: str = "", *, kind: str | None = None):
        super().__init__(message)
        self.message = message
        self.hint = hint
        if kind:
            self.kind = kind

    def __str__(self) -> str:
        return f"{self.message}（{self.hint}）" if self.hint else self.message


class NetworkError(CasError):
    kind = "network"


class InvalidCredentials(CasError):
    kind = "password"


class CaptchaRequired(CasError):
    kind = "captcha"


class AccountLocked(CasError):
    kind = "locked"


class Maintenance(CasError):
    kind = "maintenance"


class SiteChanged(CasError):
    """The page no longer looks like what this version understands."""

    kind = "schema"


class LoginRequired(CasError):
    """No valid login (CASTGC) for this request.

    ``login_url`` is the authserver page the request ended on; pass it to
    :meth:`CasClient.login` to log in and come back to the same target.
    """

    kind = "expired"

    def __init__(self, message: str, hint: str = "", *, login_url: str | None = None, kind: str | None = None):
        super().__init__(message, hint, kind=kind)
        self.login_url = login_url


class MfaError(CasError):
    kind = "mfa"


class QrExpired(MfaError):
    kind = "qr_expired"


class Unsupported(CasError):
    kind = "unsupported"


class Fido2Error(CasError):
    kind = "fido2"


class Throttled(CasError):
    """Refused by :class:`LoginGuard` before contacting the server."""

    kind = "throttled"

    def __init__(self, message: str, hint: str = "", *, retry_after: float = 0.0):
        super().__init__(message, hint)
        self.retry_after = retry_after
