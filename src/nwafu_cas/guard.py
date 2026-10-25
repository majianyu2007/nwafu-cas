"""Protection against login storms (for bots and long-running services).

A :class:`LoginGuard` sits in front of real login attempts:

* a minimum interval between attempts and an hourly cap;
* exponential backoff (with jitter) after consecutive failures;
* a "circuit" that stays open for a long time after the account was locked
  or a captcha was demanded, so a broken script cannot make things worse.

State can be persisted to a JSON file so restarts do not reset it.
"""

from __future__ import annotations

import json
import os
import random
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .errors import Throttled


@dataclass
class GuardPolicy:
    min_interval: float = 30.0  # seconds between two attempts
    max_per_hour: int = 6
    backoff_base: float = 60.0  # first wait after a failure
    backoff_max: float = 3600.0
    hold_after_lock: float = 6 * 3600.0  # locked / captcha → stop for this long
    hold_kinds: tuple[str, ...] = ("locked", "captcha")


@dataclass
class _State:
    attempts: list[float] = field(default_factory=list)
    failures: int = 0
    blocked_until: float = 0.0
    reason: str = ""


class LoginGuard:
    def __init__(self, policy: GuardPolicy | None = None, path: str | os.PathLike | None = None):
        self.policy = policy or GuardPolicy()
        self.path = Path(path).expanduser() if path else None
        self._lock = threading.Lock()
        self._s = _State()
        if self.path and self.path.exists():
            try:
                self._s = _State(**json.loads(self.path.read_text("utf-8")))
            except (ValueError, TypeError, OSError):
                pass

    def _save(self) -> None:
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(asdict(self._s)), "utf-8")

    def before_attempt(self) -> None:
        """Raise :class:`Throttled` if an attempt now is not allowed; else record it."""
        now = time.time()
        with self._lock:
            s, p = self._s, self.policy
            s.attempts = [t for t in s.attempts if now - t < 3600]
            wait = 0.0
            why = ""
            if s.blocked_until > now:
                wait, why = s.blocked_until - now, s.reason or "上次登录失败"
            elif s.attempts and now - s.attempts[-1] < p.min_interval:
                wait, why = p.min_interval - (now - s.attempts[-1]), "两次登录间隔太短"
            elif len(s.attempts) >= p.max_per_hour:
                wait, why = 3600 - (now - s.attempts[0]), "一小时内登录次数过多"
            if wait > 0:
                raise Throttled(f"暂不尝试登录：{why}", f"约 {int(wait // 60) + 1} 分钟后再试", retry_after=wait)
            s.attempts.append(now)
            self._save()

    def record_success(self) -> None:
        with self._lock:
            self._s.failures, self._s.blocked_until, self._s.reason = 0, 0.0, ""
            self._save()

    def record_failure(self, kind: str = "auth") -> None:
        with self._lock:
            s, p = self._s, self.policy
            if kind in ("network", "maintenance", "throttled"):
                return  # not the account's fault; don't escalate
            s.failures += 1
            if kind in p.hold_kinds:
                s.blocked_until, s.reason = time.time() + p.hold_after_lock, "账号被锁定或要求验证码"
            else:
                delay = min(p.backoff_max, p.backoff_base * 2 ** (s.failures - 1))
                s.blocked_until, s.reason = time.time() + delay * random.uniform(0.8, 1.2), "上次登录失败"
            self._save()

    def reset(self) -> None:
        with self._lock:
            self._s = _State()
            self._save()
