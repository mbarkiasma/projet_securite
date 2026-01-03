"""Point d entree CLI pour le mini-projet de detection MITM."""

import argparse

from .client import run_client
from .demo import run_demo
from .server import run_server


def _build_parser():
    """Creer le parser principal."""
    parser = argparse.ArgumentParser(
        description="P2C1 - TCP MITM detection demo (localhost only)."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    server_parser = subparsers.add_parser("server", help="Run the TCP server")
    server_parser.add_argument("--host", default="127.0.0.1", help="Server host")
    server_parser.add_argument("--port", type=int, default=9000, help="Server port")
    server_parser.add_argument(
        "--secret", default="demo-secret", help="Shared secret for HMAC"
    )

    client_parser = subparsers.add_parser("client", help="Run the TCP client")
    client_parser.add_argument("--host", default="127.0.0.1", help="Server host")
    client_parser.add_argument("--port", type=int, default=9000, help="Server port")
    client_parser.add_argument(
        "--secret", default="demo-secret", help="Shared secret for HMAC"
    )
    client_parser.add_argument(
        "--count",
        type=int,
        default=None,
        help="Number of messages to send (omit for interactive mode)",
    )
    client_parser.add_argument(
        "--simulate",
        choices=["normal", "tamper", "replay", "reorder"],
        default="normal",
        help="Controlled simulation of anomalies",
    )

    demo_parser = subparsers.add_parser("demo", help="Run the full demo")
    demo_parser.add_argument("--host", default="127.0.0.1", help="Server host")
    demo_parser.add_argument("--port", type=int, default=9000, help="Server port")
    demo_parser.add_argument(
        "--secret", default="demo-secret", help="Shared secret for HMAC"
    )

    return parser


def main():
    """Point d entree principal de la CLI."""
    parser = _build_parser()
    args = parser.parse_args()

    if args.command == "server":
        run_server(args.host, args.port, args.secret)
        return 0

    if args.command == "client":
        run_client(args.host, args.port, args.secret, count=args.count, simulate=args.simulate)
        return 0

    if args.command == "demo":
        run_demo(args.host, args.port, args.secret)
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())

