"""Tests simples pour le mini-projet P2C1 detection MITM."""

import os
import sys

# Assurer que src/ est importable depuis P2C1_mitm_detection/.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from mitm_guard.detector import MITMDetector
from mitm_guard.protocol import verify_message
from mitm_guard.utils import make_message


def _assert_true(condition, message):
    if not condition:
        raise AssertionError(message)


def test_normal_message_ok():
    """Un message signe normal doit etre valide."""
    secret = "test-secret"
    message = make_message(0, "hello", secret)
    ok, reason = verify_message(message, secret)
    _assert_true(ok, f"expected ok, got {reason}")


def test_tamper_invalid_mac():
    """Un payload modifie doit echouer la verification MAC."""
    secret = "test-secret"
    message = make_message(0, "hello", secret)
    message["payload"] = "HELLO"  # Modifier apres calcul du MAC.

    ok, reason = verify_message(message, secret)
    _assert_true(not ok, "tampered message should be rejected")
    _assert_true("INVALID_MAC" in reason, f"unexpected reason: {reason}")


def test_replay_detected():
    """Rejouer le meme message doit etre detecte."""
    secret = "test-secret"
    detector = MITMDetector(secret)

    message = make_message(0, "hello", secret)
    ok, reason = detector.check(message)
    _assert_true(ok, f"first message should pass, got {reason}")

    ok, reason = detector.check(message)
    _assert_true(not ok, "replayed message should be rejected")
    _assert_true(
        reason in ("REPLAY_NONCE", "SEQ_OUT_OF_ORDER"),
        f"unexpected reason: {reason}",
    )


def run_all_tests():
    """Lancer tous les tests et afficher un petit rapport."""
    tests = [
        test_normal_message_ok,
        test_tamper_invalid_mac,
        test_replay_detected,
    ]

    failures = 0
    for test in tests:
        try:
            test()
            print("PASS:", test.__name__)
        except Exception as exc:
            failures += 1
            print("FAIL:", test.__name__, "->", exc)

    if failures:
        print("\n", failures, "test(s) failed.")
        return 1

    print("\nAll tests passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_all_tests())
