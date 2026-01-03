"""Outils de protocole pour une demo TCP integrite + anti-rejeu."""

import hashlib
import hmac
import json
import struct

# Champs proteges par le MAC, dans un ordre fixe.
SIGNED_FIELDS = ("seq", "ts", "nonce", "payload")


def _canonical_bytes(fields):
    """Construire une chaine d octets deterministe pour le MAC."""
    # On signe uniquement les champs attendus pour eviter l ambiguite.
    payload = {key: fields[key] for key in SIGNED_FIELDS}
    # Cles triees + separateurs compacts pour un JSON stable.
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _compute_mac(fields, secret):
    """Calculer le HMAC-SHA256 pour les champs du message."""
    data = _canonical_bytes(fields)
    key = secret.encode("utf-8")
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def sign_message(fields, secret):
    """
    Ajouter un MAC au message.

    Le dict d entree doit contenir : seq, ts, nonce, payload.
    Renvoie un NOUVEAU dict avec le champ 'mac'.
    """
    for key in SIGNED_FIELDS:
        if key not in fields:
            raise ValueError("Missing required field: %s" % key)

    message = dict(fields)
    message["mac"] = _compute_mac(message, secret)
    return message


def verify_message(message, secret):
    """
    Verifier le MAC d un message.

    Renvoie (ok, reason). reason vaut 'OK' ou commence par 'INVALID_MAC'.
    """
    for key in SIGNED_FIELDS + ("mac",):
        if key not in message:
            return False, "INVALID_MAC (missing field)"

    expected = _compute_mac(message, secret)
    if not hmac.compare_digest(expected, str(message["mac"])):
        return False, "INVALID_MAC"

    return True, "OK"


def pack_message(message):
    """Serialiser un message en JSON avec longueur prefixee."""
    data = json.dumps(message, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    length = struct.pack("!I", len(data))
    return length + data


def send_message(sock, message):
    """Envoyer un message frame sur un socket TCP."""
    sock.sendall(pack_message(message))


def _recv_exact(sock, size):
    """Recevoir exactement size octets ou None si fin de flux."""
    chunks = []
    received = 0
    while received < size:
        chunk = sock.recv(size - received)
        if not chunk:
            return None
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


def recv_message(sock):
    """Recevoir un message JSON frame. Renvoie dict ou None si deconnexion."""
    header = _recv_exact(sock, 4)
    if header is None:
        return None

    length = struct.unpack("!I", header)[0]
    data = _recv_exact(sock, length)
    if data is None:
        return None

    text = data.decode("utf-8")
    return json.loads(text)
