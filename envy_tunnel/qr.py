"""QR codes for phones: the official WireGuard iOS/Android apps can scan a config.

The QR code contains the device's private key, so it is only ever drawn on this
screen or saved where you ask; it is never uploaded anywhere.
"""

from __future__ import annotations

import io

import segno


def make(config: str):
    return segno.make(config, error="m", micro=False)


def terminal_text(config: str) -> str:
    buf = io.StringIO()
    make(config).terminal(out=buf, compact=True, border=2)
    return buf.getvalue()


def png_bytes(config: str, scale: int = 6) -> bytes:
    buf = io.BytesIO()
    make(config).save(buf, kind="png", scale=scale, border=3, dark="#050713", light="#ffffff")
    return buf.getvalue()


def save(config: str, path: str, scale: int = 8) -> None:
    make(config).save(path, scale=scale, border=3, dark="#050713", light="#ffffff")
