"""
agent_verifier.py — Standalone, Zero-Dependency Ed25519 & SHA-256 Verifier (RFC 8032)
Works in any standard Python 3.6+ environment without external C-extensions or pip packages.
"""

import hashlib
import base64
from typing import Dict, Any, Optional

_b = 256
_q = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493

def _expmod(base, exp, mod):
    return pow(base, exp, mod)

def _inv(x):
    return _expmod(x, _q - 2, _q)

_d = -121665 * _inv(121666)
_I = _expmod(2, (_q - 1) // 4, _q)

def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = _expmod(xx, (_q + 3) // 8, _q)
    if (x * x - xx) % _q != 0:
        x = (x * _I) % _q
    if x % 2 != 0:
        x = _q - x
    return x

_By = 4 * _inv(5)
_Bx = _xrecover(_By)
_B = [_Bx % _q, _By % _q]

def _edwards(P, Q):
    x1, y1 = P[0], P[1]
    x2, y2 = Q[0], Q[1]
    x3 = (x1 * y2 + x2 * y1) * _inv(1 + _d * x1 * x2 * y1 * y2)
    y3 = (y1 * y2 + x1 * x2) * _inv(1 - _d * x1 * x2 * y1 * y2)
    return [x3 % _q, y3 % _q]

def _scalarmult(P, e):
    if e == 0:
        return [0, 1]
    Q = _scalarmult(P, e // 2)
    Q = _edwards(Q, Q)
    if e & 1:
        Q = _edwards(Q, P)
    return Q

def _decodeint(s):
    return int.from_bytes(s, "little")

def _decodepoint(s):
    y = int.from_bytes(s, "little") & ((1 << 255) - 1)
    x = _xrecover(y)
    if (x & 1) != ((s[31] >> 7) & 1):
        x = _q - x
    return [x, y]

def _Hint(m):
    return int.from_bytes(hashlib.sha512(m).digest(), "little")

def verify_ed25519_pure(msg: bytes, sig: bytes, pubkey: bytes) -> bool:
    """Verifies Ed25519 signature in pure Python with zero external libraries."""
    if len(sig) != 64 or len(pubkey) != 32:
        return False
    Rraw = sig[:32]
    Sraw = sig[32:]
    S = _decodeint(Sraw)
    if S >= _l:
        return False
    try:
        A = _decodepoint(pubkey)
        R = _decodepoint(Rraw)
        h = _Hint(Rraw + pubkey + msg)
        ra = _edwards(R, _scalarmult(A, h))
        sb = _scalarmult(_B, S)
        return ra == sb
    except Exception:
        return False

def verify_manifest(agent_bytes: bytes, manifest: Dict[str, Any], pubkey_hex: Optional[str] = None) -> bool:
    """
    Validates agent artifact against an update manifest:
    1. Size match
    2. SHA-256 match
    3. Ed25519 digital signature
    """
    if not manifest:
        return False

    expected_sha = manifest.get("sha256", "").strip().lower()
    actual_sha = hashlib.sha256(agent_bytes).hexdigest().lower()

    # Robust line ending check: if CRLF/LF platform checkout differs, test canonical LF
    if expected_sha and actual_sha != expected_sha:
        lf_bytes = agent_bytes.replace(b"\r\n", b"\n")
        if hashlib.sha256(lf_bytes).hexdigest().lower() == expected_sha:
            agent_bytes = lf_bytes
            actual_sha = expected_sha
        else:
            return False

    # 1. Size check
    expected_size = manifest.get("size")
    if expected_size and len(agent_bytes) != expected_size:
        return False

    # 2. SHA-256 Digest check
    if expected_sha and actual_sha != expected_sha:
        return False

    # 3. Ed25519 Signature check
    sig_b64 = manifest.get("signature", "")
    key_hex = pubkey_hex or manifest.get("public_key")
    if not sig_b64 or not key_hex:
        return False

    try:
        sig_bytes = base64.b64decode(sig_b64)
        pub_bytes = bytes.fromhex(key_hex)
        return verify_ed25519_pure(agent_bytes, sig_bytes, pub_bytes)
    except Exception:
        return False
