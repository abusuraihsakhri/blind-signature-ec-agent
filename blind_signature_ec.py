"""
Elliptic Curve Blind Signature & Cryptographic Token Engine
===========================================================
Production-grade implementation of Pointcheval-Stern style Blind Signatures
over secp256k1, Pedersen Commitments, and Zero-Knowledge Proofs (ZKP).

Mathematical Specification:
1. Curve: secp256k1 (y^2 = x^3 + 7 mod p)
2. Blind Signature Protocol:
   - Signer generates keypair (d, Q = d*G) and nonce commitment R = k*G
   - Client blinds with secret scalars alpha, beta:
       T = alpha*R + beta*G
       c = H(m || T_x) mod n
       c_hat = c * alpha^(-1) mod n
   - Signer signs blinded challenge:
       s_hat = k + c_hat*d mod n
   - Client unblinds signature:
       sigma = alpha*s_hat + beta mod n
   - Anyone verifies:
       sigma*G == T + c*Q  (where c = H(m || T_x))
3. Zero-Knowledge Proof of Knowledge (Schnorr PoK of discrete log)
4. Double-Spend Token Registry with commitment nonces
"""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


# secp256k1 Domain Parameters
P: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N: int = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
A: int = 0
B: int = 7
Gx: int = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy: int = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8


@dataclass(frozen=True)
class ECPoint:
    """Affine point on elliptic curve y^2 = x^3 + B mod P."""
    x: Optional[int]
    y: Optional[int]

    @property
    def is_infinity(self) -> bool:
        return self.x is None or self.y is None

    def to_hex(self, compressed: bool = True) -> str:
        """Serialize point to hex format."""
        if self.is_infinity:
            return "00"
        if compressed:
            prefix = "02" if self.y % 2 == 0 else "03"
            return f"{prefix}{self.x:064x}"
        return f"04{self.x:064x}{self.y:064x}"

    @classmethod
    def from_hex(cls, hex_str: str) -> "ECPoint":
        """Deserialize point from hex format (compressed or uncompressed)."""
        hex_str = hex_str.strip().lower()
        if hex_str == "00":
            return INFINITY
        if hex_str.startswith("04") and len(hex_str) == 130:
            x = int(hex_str[2:66], 16)
            y = int(hex_str[66:130], 16)
            return ECPoint(x, y)
        if (hex_str.startswith("02") or hex_str.startswith("03")) and len(hex_str) == 66:
            prefix = hex_str[:2]
            x = int(hex_str[2:], 16)
            y_squared = (pow(x, 3, P) + B) % P
            y = pow(y_squared, (P + 1) // 4, P)
            if pow(y, 2, P) != y_squared:
                raise ValueError("Point is not on secp256k1 curve")
            if (prefix == "02" and y % 2 != 0) or (prefix == "03" and y % 2 == 0):
                y = P - y
            return ECPoint(x, y)
        raise ValueError(f"Invalid point encoding: {hex_str}")


INFINITY = ECPoint(None, None)
G = ECPoint(Gx, Gy)


def point_add(p: ECPoint, q: ECPoint) -> ECPoint:
    """Point addition on secp256k1 curve."""
    if p.is_infinity:
        return q
    if q.is_infinity:
        return p
    if p.x == q.x and (p.y + q.y) % P == 0:
        return INFINITY

    if p.x == q.x and p.y == q.y:
        # Point doubling
        lam = (3 * p.x * p.x + A) * pow(2 * p.y, -1, P) % P
    else:
        # Point addition
        lam = (q.y - p.y) * pow(q.x - p.x, -1, P) % P

    x3 = (lam * lam - p.x - q.x) % P
    y3 = (lam * (p.x - x3) - p.y) % P
    return ECPoint(x3, y3)


def point_mul(k: int, pt: ECPoint = G) -> ECPoint:
    """Scalar multiplication via double-and-add."""
    k = k % N
    if k == 0 or pt.is_infinity:
        return INFINITY

    result = INFINITY
    addend = pt

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


def hash_to_scalar(*data: bytes) -> int:
    """Cryptographic hash to scalar in [1, N-1]."""
    h = hashlib.sha256()
    for item in data:
        h.update(item)
    digest = h.digest()
    return int.from_bytes(digest, "big") % N


# Second generator H for Pedersen commitments (deterministic on-curve point)
H_SCALAR = hash_to_scalar(b"secp256k1_pedersen_commitment_generator_H")
H_GEN = point_mul(H_SCALAR, G)


# ==============================================================================
# 1. KEY MANAGEMENT
# ==============================================================================

@dataclass
class KeyPair:
    """Signer public/private keypair."""
    secret_key: int
    public_key: ECPoint

    @classmethod
    def generate(cls) -> "KeyPair":
        d = secrets.randbelow(N - 1) + 1
        q = point_mul(d, G)
        return cls(secret_key=d, public_key=q)


@dataclass
class BlindSession:
    """Client-side state during interactive blind signing."""
    alpha: int  # Blinding scalar multiplier
    beta: int  # Blinding scalar offset
    T: ECPoint  # Blinded commitment point
    message: bytes
    blinded_challenge: int


@dataclass
class BlindSignature:
    """Verified unblinded signature (T, sigma) on message."""
    T: ECPoint
    sigma: int
    message: bytes

    def to_dict(self) -> Dict[str, Any]:
        return {
            "T_hex": self.T.to_hex(),
            "sigma_hex": f"{self.sigma:064x}",
            "message_utf8": self.message.decode("utf-8", errors="replace"),
            "message_hex": self.message.hex(),
        }


# ==============================================================================
# 2. POINTCHEVAL-STERN BLIND SIGNATURE PROTOCOL
# ==============================================================================

class BlindSignatureProtocol:
    """Interactive & deterministic Pointcheval-Stern blind signature protocol."""

    @staticmethod
    def signer_step1_commit() -> Tuple[int, ECPoint]:
        """
        Step 1 (Signer): Choose random nonce k in [1, N-1], publish commitment R = k*G.
        """
        k = secrets.randbelow(N - 1) + 1
        R = point_mul(k, G)
        return k, R

    @staticmethod
    def client_step2_blind(
        message: bytes,
        signer_nonce_R: ECPoint,
    ) -> Tuple[BlindSession, int]:
        """
        Step 2 (Client): Blind the message with alpha, beta.
        T = alpha*R + beta*G
        c = H(m || T.x)
        c_hat = c * alpha^(-1) mod N
        Returns (session, c_hat).
        """
        if signer_nonce_R.is_infinity:
            raise ValueError("Signer commitment R cannot be point at infinity")

        for _ in range(100):
            alpha = secrets.randbelow(N - 2) + 1
            beta = secrets.randbelow(N - 2) + 1

            # T = alpha * R + beta * G
            t1 = point_mul(alpha, signer_nonce_R)
            t2 = point_mul(beta, G)
            T = point_add(t1, t2)

            if not T.is_infinity:
                break
        else:
            raise RuntimeError("Failed to generate non-infinity commitment T")

        # Challenge c = H(message || T.x)
        t_bytes = T.x.to_bytes(32, "big")
        c = hash_to_scalar(message, t_bytes)
        if c == 0:
            c = 1

        # Blinded challenge c_hat = c * alpha^(-1) mod N
        c_hat = (c * pow(alpha, -1, N)) % N
        session = BlindSession(
            alpha=alpha,
            beta=beta,
            T=T,
            message=message,
            blinded_challenge=c_hat,
        )
        return session, c_hat

    @staticmethod
    def signer_step3_sign(
        blinded_challenge: int,
        signer_nonce_k: int,
        keypair: KeyPair,
    ) -> int:
        """
        Step 3 (Signer): Compute s_hat = k + c_hat * d mod N.
        The signer signs without learning message m or challenge c.
        """
        s_hat = (signer_nonce_k + blinded_challenge * keypair.secret_key) % N
        return s_hat

    @staticmethod
    def client_step4_unblind(
        session: BlindSession,
        s_hat: int,
    ) -> BlindSignature:
        """
        Step 4 (Client): Unblind to obtain valid signature sigma = alpha*s_hat + beta mod N.
        """
        sigma = (session.alpha * s_hat + session.beta) % N
        return BlindSignature(T=session.T, sigma=sigma, message=session.message)

    @staticmethod
    def verify(
        signature: BlindSignature,
        public_key: ECPoint,
    ) -> bool:
        """
        Step 5 (Anyone): Verify sigma*G == T + H(m || T.x)*Q.
        """
        if signature.T.is_infinity or public_key.is_infinity:
            return False

        t_bytes = signature.T.x.to_bytes(32, "big")
        c = hash_to_scalar(signature.message, t_bytes)
        if c == 0:
            c = 1

        # LHS = sigma * G
        lhs = point_mul(signature.sigma, G)

        # RHS = T + c * Q
        cq = point_mul(c, public_key)
        rhs = point_add(signature.T, cq)

        return lhs.x == rhs.x and lhs.y == rhs.y


# ==============================================================================
# 3. PEDERSEN COMMITMENTS & ZERO-KNOWLEDGE PROOFS
# ==============================================================================

class ZKProofEngine:
    """Pedersen commitments and Schnorr Zero-Knowledge Proofs."""

    @staticmethod
    def pedersen_commit(value: int, blinding_factor: Optional[int] = None) -> Tuple[ECPoint, int]:
        """
        Compute Pedersen commitment C = v*G + r*H.
        """
        r = blinding_factor if blinding_factor is not None else (secrets.randbelow(N - 1) + 1)
        vg = point_mul(value, G)
        rh = point_mul(r, H_GEN)
        commitment = point_add(vg, rh)
        return commitment, r

    @staticmethod
    def schnorr_pok_prove(secret_x: int) -> Dict[str, Any]:
        """
        Non-interactive Zero-Knowledge Proof of Knowledge of discrete log x for Y = x*G.
        Proof: (V = r*G, challenge e = H(Y || V), response s = r + e*x mod N).
        """
        Y = point_mul(secret_x, G)
        r = secrets.randbelow(N - 1) + 1
        V = point_mul(r, G)

        e = hash_to_scalar(Y.to_hex().encode(), V.to_hex().encode())
        s = (r + e * secret_x) % N

        return {
            "public_key_hex": Y.to_hex(),
            "commitment_v_hex": V.to_hex(),
            "challenge_e": e,
            "response_s": s,
        }

    @staticmethod
    def schnorr_pok_verify(proof: Dict[str, Any]) -> bool:
        """
        Verify Schnorr Proof of Knowledge: s*G == V + e*Y.
        """
        Y = ECPoint.from_hex(proof["public_key_hex"])
        V = ECPoint.from_hex(proof["commitment_v_hex"])
        e = proof["challenge_e"]
        s = proof["response_s"]

        # Recompute challenge
        expected_e = hash_to_scalar(Y.to_hex().encode(), V.to_hex().encode())
        if e != expected_e:
            return False

        lhs = point_mul(s, G)
        ey = point_mul(e, Y)
        rhs = point_add(V, ey)

        return lhs.x == rhs.x and lhs.y == rhs.y


# ==============================================================================
# 4. DOUBLE-SPEND REGISTRY
# ==============================================================================

class DoubleSpendRegistry:
    """Tracks redeemed blinded token commitments to prevent double-spending."""

    def __init__(self):
        self._redeemed_commitments: Dict[str, Dict[str, Any]] = {}

    def redeem_token(
        self,
        token_id: str,
        signature: BlindSignature,
        public_key: ECPoint,
    ) -> Dict[str, Any]:
        """
        Verify signature and redeem token, preventing replay attacks.
        """
        # 1. Cryptographic signature verification
        is_valid = BlindSignatureProtocol.verify(signature, public_key)
        if not is_valid:
            return {
                "accepted": False,
                "error": "Invalid cryptographic signature",
                "double_spend": False,
            }

        # 2. Check commitment uniqueness
        commitment_key = signature.T.to_hex()
        if commitment_key in self._redeemed_commitments:
            prev_entry = self._redeemed_commitments[commitment_key]
            return {
                "accepted": False,
                "error": f"Double-spend detected! Commitment already redeemed by token '{prev_entry['token_id']}'",
                "double_spend": True,
                "original_token_id": prev_entry["token_id"],
                "offending_token_id": token_id,
            }

        # Record redemption
        self._redeemed_commitments[commitment_key] = {
            "token_id": token_id,
            "message": signature.message.hex(),
            "sigma": f"{signature.sigma:064x}",
        }

        return {
            "accepted": True,
            "token_id": token_id,
            "commitment": commitment_key,
            "double_spend": False,
            "status": "Token redeemed successfully",
        }
