"""Detecteur d anomalies type MITM: ordre, rejeu, integrite."""

import time
from collections import deque

from .protocol import verify_message


class MITMDetector:
    """
    Garder un etat minimal pour detecter modification, rejeu et ordre.

    Exemple pedagogique, uniquement pour des demos localhost.
    """

    def __init__(self, secret, allowed_time_skew_seconds=30, max_nonces=1000):
        self.secret = secret
        self.allowed_time_skew_seconds = allowed_time_skew_seconds
        self.max_nonces = max_nonces

        # Etat pour l ordre et la detection de rejeu.
        self.last_seq = -1
        self.seen_nonces = set()
        self._nonce_order = deque()

    def _remember_nonce(self, nonce):
        """Memoriser un nonce et evincer les plus anciens si besoin."""
        self.seen_nonces.add(nonce)
        self._nonce_order.append(nonce)

        while len(self._nonce_order) > self.max_nonces:
            old = self._nonce_order.popleft()
            self.seen_nonces.discard(old)

    def check(self, message):
        """
        Valider un message et renvoyer (ok, reason).

        Raisons possibles : INVALID_MAC, SEQ_OUT_OF_ORDER, REPLAY_NONCE, TS_TOO_OLD.
        """
        ok, reason = verify_message(message, self.secret)
        if not ok:
            return False, reason

        # Lire les champs apres le MAC pour ne pas faire confiance aux donnees.
        seq = message.get("seq")
        ts = message.get("ts")
        nonce = message.get("nonce")

        # La sequence doit augmenter strictement.
        if not isinstance(seq, int):
            try:
                seq = int(seq)
            except (TypeError, ValueError):
                return False, "INVALID_MAC (bad seq)"

        if seq <= self.last_seq:
            return False, "SEQ_OUT_OF_ORDER"

        # Le nonce ne doit jamais se repeter.
        if nonce in self.seen_nonces:
            return False, "REPLAY_NONCE"

        # Le timestamp ne doit pas etre trop ancien.
        if not isinstance(ts, int):
            try:
                ts = int(ts)
            except (TypeError, ValueError):
                return False, "INVALID_MAC (bad ts)"

        now = int(time.time())
        if now - ts > self.allowed_time_skew_seconds:
            return False, "TS_TOO_OLD"

        # Mettre a jour l etat seulement si tout est OK.
        self.last_seq = seq
        self._remember_nonce(nonce)
        return True, "OK"
