"""WireGuard keys, generated locally.

WireGuard uses Curve25519 key pairs, written as 32 bytes in standard base64 (the
same format ``wg genkey`` / ``wg pubkey`` / ``wg genpsk`` print). Device private
keys are made on the device that will use them and never sent anywhere; the
server's private key is made on the server and never leaves it.
"""

from __future__ import annotations

import base64
import binascii
import os

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat


class KeyError_(ValueError):
    """A string is not a valid WireGuard key."""


def _decode(key: str) -> bytes:
    try:
        raw = base64.b64decode(key.strip(), validate=True)
    except (binascii.Error, ValueError, AttributeError) as exc:
        raise KeyError_("not a WireGuard key (expected 44 characters of base64)") from exc
    if len(raw) != 32:
        raise KeyError_("not a WireGuard key (expected 32 bytes)")
    return raw


def is_key(key: str) -> bool:
    try:
        _decode(key)
    except KeyError_:
        return False
    return True


def _clamp(raw: bytes) -> bytes:
    # Same clamping as `wg genkey`, so a key made here is byte-identical in form.
    b = bytearray(raw)
    b[0] &= 248
    b[31] = (b[31] & 127) | 64
    return bytes(b)


def generate_private_key() -> str:
    raw = X25519PrivateKey.generate().private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    return base64.b64encode(_clamp(raw)).decode()


def public_key(private_key: str) -> str:
    priv = X25519PrivateKey.from_private_bytes(_decode(private_key))
    return base64.b64encode(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def generate_preshared_key() -> str:
    """A 256-bit symmetric key mixed into the handshake (post-quantum hedge)."""
    return base64.b64encode(os.urandom(32)).decode()


def fingerprint(key: str) -> str:
    """A short, readable form of a public key for display (first 8 characters)."""
    _decode(key)
    return key[:8] + "…"
