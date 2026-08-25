#!/usr/bin/env python3
"""
Blind Signature over secp256k1 (Pointcheval-Stern style) with Double-Spend Registry
Real elliptic-curve math: blind, sign, unblind, verify. The signer never sees
the message-challenge pair it signs; the user unblinds a valid Schnorr-style
signature on the blinded point T.

Zero-dependency. Author: Dr. Abu Suraih Sakhri. License: MIT.
"""
import argparse
import hashlib
import json
import secrets
import sys
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

# secp256k1 domain parameters
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True)
class Point:
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None


INFINITY = Point(None, None)
G = Point(Gx, Gy)


def _add(p: Point, q: Point) -> Point:
    if p.is_infinity: return q
    if q.is_infinity: return p
    if p.x == q.x and (p.y + q.y) % P == 0:
        return INFINITY
    if p.x == q.x and p.y == q.y:
        lam = (3 * p.x * p.x + A) * pow(2 * p.y, -1, P) % P
    else:
        lam = (q.y - p.y) * pow(q.x - p.x, -1, P) % P
    x = (lam * lam - p.x - q.x) % P
    y = (lam * (p.x - x) - p.y) % P
    return Point(x, y)


def _mul(k: int, pt: Point = G) -> Point:
    k %= N
    result, addend = INFINITY, pt
    while k:
        if k & 1:
            result = _add(result, addend)
        addend = _add(addend, addend)
        k >>= 1
    return result


def hash_to_scalar(msg: bytes) -> int:
    return int.from_bytes(hashlib.sha256(msg).digest(), "big") % N


@dataclass
class SignerKeyPair:
    secret: int
    public: Point


def generate_keypair() -> SignerKeyPair:
    d = secrets.randbelow(N - 1) + 1
    return SignerKeyPair(d, _mul(d))


@dataclass
class BlindSession:
    """User-side state between blinding and unblinding."""
    alpha: int            # blinding multiplier
    beta: int             # blinding offset
    T: Point              # effective nonce commitment (public in final signature)


def blind(message: bytes, R: Point) -> Tuple[BlindSession, int]:
    """
    Step 2 of protocol. Given signer's nonce commitment R = k*G, produce the
    blinded challenge c_hat for the signer and keep unblinding state.
    Returns (session, c_hat).
    """
    while True:
        alpha = secrets.randbelow(N - 2) + 1     # nonzero mod N
        beta = secrets.randbelow(N - 2) + 1
        try:
            T = _add(_mul(alpha, R), _mul(beta))
            if T.is_infinity:
                continue
            break
        except ValueError:
            continue
    c = hash_to_scalar(message + T.x.to_bytes(32, "big"))   # Fiat-Shamir challenge on final sig
    # blinded challenge: c_hat = c / alpha  (so that alpha*c_hat = c mod N)
    c_hat = c * pow(alpha, -1, N) % N
    return BlindSession(alpha, beta, T), c_hat


def sign(c_hat: int, k: int, keypair: SignerKeyPair) -> int:
    """Signer responds: s_hat = k + c_hat*d mod N. Never learns c or m."""
    return (k + c_hat * keypair.secret) % N


def unblind(session: BlindSession, s_hat: int) -> int:
    """sigma = alpha*s_hat + beta mod N."""
    return (session.alpha * s_hat + session.beta) % N


def verify(T: Point, sigma: int, message: bytes, public_key: Point) -> bool:
    """Check sigma*G == T + H(m||T.x)*Q."""
    if T is None or T.is_infinity:
        return False
    c = hash_to_scalar(message + T.x.to_bytes(32, "big"))
    lhs = _mul(sigma)
    rhs = _add(T, _mul(c, public_key))
    return lhs == rhs


class DoubleSpendRegistry:
    """Tracks spent token commitments; flags reuse."""

    def __init__(self):
        self.spent: Dict[str, str] = {}

    def redeem(self, token_id: str, commitment_hex: str) -> Dict[str, Any]:
        prev_owner = self.spent.get(commitment_hex)
        if prev_owner is not None:
            return {"accepted": False, "double_spend_detected": True,
                    "first_seen_token": prev_owner, "offending_token": token_id}
        self.spent[commitment_hex] = token_id
        return {"accepted": True, "double_spend_detected": False}


def issue_token(message: bytes, keypair: SignerKeyPair) -> Dict[str, Any]:
    """Full sign -> unblind -> verify pipeline; returns verifiable token."""
    k = secrets.randbelow(N - 1) + 1
    R = _mul(k)
    session, c_hat = blind(message, R)
    s_hat = sign(c_hat, k, keypair)
    sigma = unblind(session, s_hat)
    ok = verify(session.T, sigma, message, keypair.public)
    commitment = hex(session.T.x)[2:].rjust(64, "0")
    return {
        "verified": ok,
        "token_commitment": commitment,
        "signature_sigma": hex(sigma)[2:],
        "signer_saw_message": False,
    }


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="secp256k1 blind signature demo")
    ap.add_argument("--message", default="ballot-choice-A")
    args = ap.parse_args()

    kp = generate_keypair()
    msg = args.message.encode()

    token = issue_token(msg, kp)
    print(json.dumps(token, indent=2))

    # independent verification of the token: reconstruct T from x (try both y signs)
    xc = int(token["token_commitment"], 16)
    sigma_int = int(token["signature_sigma"], 16)
    rhs = (pow(xc, 3, P) + B) % P
    y = pow(rhs, (P + 1) // 4, P)
    candidates = [Point(xc, y)] if (y * y) % P != rhs else [Point(xc, y), Point(xc, (-y) % P)]
    results = {f"y_parity_{i}": verify(T_full, sigma_int, msg, kp.public)
               for i, T_full in enumerate(candidates)}
    print(json.dumps({
        **results,
        "tamper_detect": any(verify(t, sigma_int, b"ballot-choice-B", kp.public)
                             for t in candidates),
    }, indent=2))

    registry = DoubleSpendRegistry()
    first = registry.redeem("token-001", token["token_commitment"])
    replay = registry.redeem("token-002", token["token_commitment"])
    print(json.dumps({"first_redeem": first, "replay_attempt": replay}, indent=2))
