"""Petits outils pour timestamp et nonce."""

import secrets
import time

from .protocol import sign_message


def now_ts():
    """Retourner le timestamp Unix courant (en secondes)."""
    return int(time.time())


def generate_nonce():
    """Generer un nonce aleatoire pour l anti-rejeu."""
    return secrets.token_hex(8)


def make_message(seq, payload, secret, nonce=None, ts=None):
    """Construire et signer un dict message."""
    if ts is None:
        ts = now_ts()
    if nonce is None:
        nonce = generate_nonce()

    fields = {
        "seq": int(seq),
        "ts": int(ts),
        "nonce": str(nonce),
        "payload": str(payload),
    }
    return sign_message(fields, secret)
