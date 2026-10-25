"""Password cipher of ``encrypt.js``.

base64(AES-128-CBC(key = salt, iv = random 16 chars, PKCS#7,
plaintext = random 64 chars + password)). The random characters come from a
fixed alphabet. All three numbers are read from the live ``encrypt.js`` when
possible (see :func:`params_from_script`), so a change there is picked up
without a new release.
"""

from __future__ import annotations

import base64
import re
import secrets
from dataclasses import dataclass

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


@dataclass(frozen=True)
class CipherParams:
    alphabet: str = "ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678"
    prefix_len: int = 64
    iv_len: int = 16


DEFAULT_PARAMS = CipherParams()


def params_from_script(js: str) -> CipherParams | None:
    """Read the alphabet and lengths from ``encrypt.js``; None if not found."""
    a = re.search(r"\$aes_chars\s*=\s*[\"']([^\"']+)[\"']", js)
    m = re.search(r"getAesString\(\s*randomString\((\d+)\)\s*\+\s*\w+\s*,\s*\w+\s*,\s*randomString\((\d+)\)", js)
    if not (a and m):
        return None
    return CipherParams(a.group(1), int(m.group(1)), int(m.group(2)))


def _rand(n: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


def encrypt_password(password: str, salt: str, params: CipherParams = DEFAULT_PARAMS) -> str:
    key = (salt or "").strip()
    if not key:
        return password  # what encrypt.js does without a salt
    iv = _rand(params.iv_len, params.alphabet)
    plain = (_rand(params.prefix_len, params.alphabet) + password).encode("utf-8")
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv.encode("utf-8"))
    return base64.b64encode(cipher.encrypt(pad(plain, 16))).decode("ascii")


def decrypt_password(token: str, salt: str, params: CipherParams = DEFAULT_PARAMS) -> str:
    """What the server does: any IV works, because only the random prefix
    (the first CBC block lies inside it) is affected. Used by the tests."""
    cipher = AES.new(salt.encode("utf-8"), AES.MODE_CBC, b"\0" * 16)
    return unpad(cipher.decrypt(base64.b64decode(token)), 16)[params.prefix_len:].decode("utf-8")
