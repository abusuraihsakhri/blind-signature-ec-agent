"""ECDSA Blind Signature Protocol: Pedersen commitment scheme with zero-knowledge proofs."""
from typing import Dict, Any, Tuple, Optional
from dataclasses import dataclass
import hashlib
import secrets


@dataclass
class CurveParams:
    p: int
    a: int
    b: int
    G: Tuple[int, int]
    n: int


SECP256K1 = CurveParams(
    p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a=0, b=7,
    G=(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
       0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8),
    n=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
)


class ECDSAUtils:
    """Elliptic curve operations for blind signature protocol."""

    def __init__(self, curve: Optional[CurveParams] = None):
        self.curve = curve or SECP256K1

    def point_add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        """Point addition on the curve."""
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        if P[0] == Q[0] and P[1] != Q[1]:
            return (0, 0)
        if P == Q:
            lam = (3 * P[0] * P[0] + self.curve.a) * pow(2 * P[1], -1, self.curve.p) % self.curve.p
        else:
            lam = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, self.curve.p) % self.curve.p
        x = (lam * lam - P[0] - Q[0]) % self.curve.p
        y = (lam * (P[0] - x) - P[1]) % self.curve.p
        return (x, y)

    def point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        """Scalar multiplication."""
        R = (0, 0)
        Q = P
        while k > 0:
            if k & 1:
                R = self.point_add(R, Q)
            Q = self.point_add(Q, Q)
            k >>= 1
        return R

    def hash_to_int(self, data: bytes) -> int:
        h = hashlib.sha256(data).digest()
        return int.from_bytes(h, "big") % self.curve.n

    def generate_keypair(self) -> Dict[str, Any]:
        private_key = secrets.randbelow(self.curve.n - 1) + 1
        public_key = self.point_mul(private_key, self.curve.G)
        return {"private_key": private_key, "public_key": public_key}

    def sign(self, private_key: int, message: bytes) -> Dict[str, int]:
        z = self.hash_to_int(message)
        k = secrets.randbelow(self.curve.n - 1) + 1
        R = self.point_mul(k, self.curve.G)
        r = R[0] % self.curve.n
        s = (pow(k, -1, self.curve.n) * (z + r * private_key)) % self.curve.n
        return {"r": r, "s": s, "z": z}

    def verify(self, public_key: Tuple[int, int], message: bytes, sig: Dict[str, int]) -> bool:
        z = self.hash_to_int(message)
        w = pow(sig["s"], -1, self.curve.n)
        u1 = (z * w) % self.curve.n
        u2 = (sig["r"] * w) % self.curve.n
        R = self.point_add(self.point_mul(u1, self.curve.G), self.point_mul(u2, public_key))
        return R[0] % self.curve.n == sig["r"]


class BlindSignatureProtocol:
    """Pedersen blind signature with blinding factor."""

    def __init__(self):
        self.ecdsa = ECDSAUtils()

    def blind(self, message: bytes, signer_public_key: Tuple[int, int]) -> Dict[str, Any]:
        """Client blinds a message for signing."""
        msg_int = self.ecdsa.hash_to_int(message)
        blinding_factor = secrets.randbelow(self.ecdsa.curve.n - 1) + 1
        blinded_msg = (msg_int + blinding_factor) % self.ecdsa.curve.n
        return {
            "blinded_msg": blinded_msg,
            "blinding_factor": blinding_factor,
            "original_hash": msg_int,
        }

    def partial_sign(self, signer_private_key: int, blinded_msg: int) -> Dict[str, int]:
        """Signer produces partial blind signature."""
        k = secrets.randbelow(self.ecdsa.curve.n - 1) + 1
        R = self.ecdsa.point_mul(k, self.ecdsa.curve.G)
        r = R[0] % self.ecdsa.curve.n
        s = (pow(k, -1, self.ecdsa.curve.n) * (blinded_msg + r * signer_private_key)) % self.ecdsa.curve.n
        return {"r": r, "s": s}

    def unblind(self, blind_sig: Dict[str, int], blinding_factor: int, signer_public_key: Tuple[int, int]) -> Dict[str, Any]:
        """Client unblinds the signature."""
        s_unblinded = (blind_sig["s"] - blinding_factor) % self.ecdsa.curve.n
        return {"r": blind_sig["r"], "s": s_unblinded}

    def verify_blind_signature(
        self, public_key: Tuple[int, int], message: bytes, signature: Dict[str, int]
    ) -> Dict[str, Any]:
        """Verify an unblinded blind signature."""
        z = self.ecdsa.hash_to_int(message)
        valid = self.ecdsa.verify(public_key, message, signature)
        return {"valid": valid, "message_hash": z, "r": signature["r"], "s": signature["s"]}
