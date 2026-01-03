"""Serveur TCP simple qui detecte des anomalies type MITM."""

import socket

from .detector import MITMDetector
from .protocol import recv_message


def _handle_client(conn, addr, secret):
    """Recevoir les messages d un seul client."""
    detector = MITMDetector(secret)
    print("Client connected:", addr)

    try:
        while True:
            message = recv_message(conn)
            if message is None:
                break

            ok, reason = detector.check(message)
            if ok:
                print("ACCEPTED:", message.get("payload"))
            else:
                print("ALERT:", reason)
    except KeyboardInterrupt:
        pass
    finally:
        print("Client disconnected:", addr)


def run_server(host, port, secret):
    """Lancer un serveur bloquant sur localhost pour la demo."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(1)
        print(f"Server listening on {host}:{port}")

        try:
            while True:
                conn, addr = sock.accept()
                with conn:
                    _handle_client(conn, addr, secret)
        except KeyboardInterrupt:
            print("Server shutting down.")


if __name__ == "__main__":
    # Execution directe pour un test rapide.
    run_server("127.0.0.1", 9000, "demo-secret")
