"""Client TCP simple pour la demo de detection MITM (localhost uniquement)."""

import socket

from .protocol import send_message
from .utils import make_message


def _send_with_simulation(sock, message, simulate):
    """Envoyer un message, avec option de modification ou rejeu."""
    if simulate == "tamper":
        # Modifier le payload APRES le MAC pour forcer un echec d integrite.
        message["payload"] = message["payload"] + " [TAMPERED]"

    send_message(sock, message)

    if simulate == "replay":
        # Envoyer exactement le meme paquet signe deux fois.
        send_message(sock, message)


def _auto_send(sock, secret, count, simulate):
    """Envoyer un petit lot de messages automatiquement."""
    if simulate == "reorder":
        # Envoyer seq 1 puis seq 0 pour declencher l ordre anormal.
        first = make_message(0, "message 0", secret)
        second = make_message(1, "message 1", secret)
        send_message(sock, second)
        send_message(sock, first)

        seq = 2
        while seq < count:
            message = make_message(seq, f"message {seq}", secret)
            send_message(sock, message)
            seq += 1
        return

    seq = 0
    while seq < count:
        message = make_message(seq, f"message {seq}", secret)
        _send_with_simulation(sock, message, simulate)
        seq += 1


def _interactive_send(sock, secret, simulate):
    """Mode interactif : l utilisateur tape dans le terminal."""
    if simulate == "reorder":
        print("La simulation reorder n est pas supportee en mode interactif.")
        print("Utilise --count 2 avec --simulate reorder.")
        return

    if simulate != "normal":
        print("Simulation active:", simulate)

    seq = 0
    while True:
        try:
            line = input("message> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nClient termine.")
            break

        if not line:
            continue

        message = make_message(seq, line, secret)
        _send_with_simulation(sock, message, simulate)
        seq += 1


def run_client(host, port, secret, count=None, simulate="normal"):
    """Se connecter au serveur et envoyer des messages."""
    with socket.create_connection((host, port)) as sock:
        if count is None:
            _interactive_send(sock, secret, simulate)
        else:
            _auto_send(sock, secret, int(count), simulate)


if __name__ == "__main__":
    # Execution directe pour un test rapide.
    run_client("127.0.0.1", 9000, "demo-secret", count=3)
