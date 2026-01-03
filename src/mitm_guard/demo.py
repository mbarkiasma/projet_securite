"""Lancer une demo de bout en bout: normal, tamper, replay."""

import time
from multiprocessing import Process

from .client import run_client
from .server import run_server


def run_demo(host, port, secret):
    """Demarrer le serveur et lancer les scenarios automatiquement."""
    server_process = Process(target=run_server, args=(host, port, secret), daemon=True)
    server_process.start()

    # Laisser un petit delai au serveur pour demarrer.
    time.sleep(0.5)

    print("=== SCENARIO NORMAL ===")
    run_client(host, port, secret, count=3, simulate="normal")
    time.sleep(0.5)

    print("=== SCENARIO TAMPER ===")
    run_client(host, port, secret, count=1, simulate="tamper")
    time.sleep(0.5)

    print("=== SCENARIO REPLAY ===")
    run_client(host, port, secret, count=1, simulate="replay")
    time.sleep(0.5)

    server_process.terminate()
    server_process.join()
    print("Demo terminee.")


if __name__ == "__main__":
    run_demo("127.0.0.1", 9000, "demo-secret")
