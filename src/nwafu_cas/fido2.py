"""FIDO2 / passkey login with a *software* credential.

Browsers keep passkeys inside the OS; a command-line tool cannot use them.
This module signs the WebAuthn assertion itself from an exported credential
(ECDSA P-256 private key + credential id, e.g. from a password manager that
stores passkeys). Requires ``pip install "nwafu-cas[fido2]"``.

Flow (``fido.js``): POST ``/startAssertion`` {userId, id} → challenge →
sign → submit the login form with ``cllt=fidoLogin`` and ``responseJson``.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import TYPE_CHECKING

from .constants import AUTH_SERVER, BASE
from .errors import Fido2Error

if TYPE_CHECKING:
    from .client import CasClient


@dataclass
class Fido2Credential:
    """An exported passkey.

    Attributes:
        credential_id: hex (dashes allowed) or base64url credential id.
        key_value: base64 / base64url DER (PKCS#8) ECDSA P-256 private key.
        username: 学号/工号.
        rp_id: relying party, normally ``authserver.nwafu.edu.cn``.
        user_handle: optional user handle to echo back.
        device_binding_id: the ``anonbiometricsd`` value the site stored when
            the passkey was bound (sent as ``id`` to ``startAssertion``).
        user_id: the ``anonbiometricsu`` value; defaults to base64(username).
    """

    credential_id: str
    key_value: str
    username: str
    rp_id: str = "authserver.nwafu.edu.cn"
    user_handle: str = ""
    device_binding_id: str = ""
    user_id: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> Fido2Credential:
        return cls(
            credential_id=d.get("credentialId", ""), key_value=d.get("keyValue", ""), username=d.get("username", ""),
            rp_id=d.get("rpId", d.get("rpID", "authserver.nwafu.edu.cn")), user_handle=d.get("userHandle", ""),
            device_binding_id=d.get("deviceBindingId", ""), user_id=d.get("userId", ""),
        )

    @property
    def site_user_id(self) -> str:
        return self.user_id or base64.b64encode(self.username.encode()).decode()


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    s = s.strip()
    return base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_") + "=" * (-len(s) % 4))


def _credential_id(raw: str) -> bytes:
    h = raw.replace("-", "")
    try:
        return bytes.fromhex(h)
    except ValueError:
        return _unb64(raw)


def assertion(credential: Fido2Credential, challenge: str, origin: str = AUTH_SERVER) -> dict:
    """A signed assertion in the shape ``fido.js`` submits (``responseToObject``)."""
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
    except ImportError as e:
        raise Fido2Error("需要安装 FIDO2 支持", 'pip install "nwafu-cas[fido2]"') from e
    try:
        key = serialization.load_der_private_key(_unb64(credential.key_value), password=None)
    except Exception as e:  # noqa: BLE001
        raise Fido2Error("无法读取 FIDO2 私钥", str(e)[:80]) from e
    client_data = json.dumps({"type": "webauthn.get", "challenge": challenge, "origin": origin, "crossOrigin": False},
                             separators=(",", ":")).encode()
    # flags 0x1D = user present | user verified | backup eligible | backed up (a synced passkey)
    auth_data = hashlib.sha256(credential.rp_id.encode()).digest() + bytes([0x1D]) + struct.pack(">I", 0)
    signature = key.sign(auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
    out = {
        "id": b64url(_credential_id(credential.credential_id)),
        "type": "public-key",
        "response": {"authenticatorData": b64url(auth_data), "clientDataJSON": b64url(client_data), "signature": b64url(signature)},
        "clientExtensionResults": {},
    }
    if credential.user_handle:
        out["response"]["userHandle"] = credential.user_handle
    out["rawId"] = out["id"]
    return out


def login_form(cas: CasClient, credential: Fido2Credential, fields: dict[str, str]) -> dict:
    """Run ``startAssertion`` and return the login form to POST."""
    r = cas._post(f"{BASE}/startAssertion", content=json.dumps({"userId": credential.site_user_id, "id": credential.device_binding_id}),
                  headers={"Content-Type": "application/json;charset=utf-8"})
    try:
        res = (r.json() or {}).get("result") or {}
    except ValueError as e:
        raise Fido2Error("startAssertion 返回的不是 JSON") from e
    req = res.get("request") or {}
    opts = req.get("publicKeyCredentialRequestOptions") or {}
    if not opts.get("challenge"):
        raise Fido2Error(res.get("message") or "学校没有返回 FIDO2 挑战", "这个账号可能没有绑定通行密钥")
    body = {"requestId": req.get("requestId"), "credential": assertion(credential, opts["challenge"]),
            "sessionToken": req.get("sessionToken")}
    return {**fields, "username": credential.site_user_id, "responseJson": json.dumps(body, separators=(",", ":")),
            "rememberMe": "true"}
