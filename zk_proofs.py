"""Zero-Knowledge Proofs: Schnorr identification protocol and hash-based commitments."""
from typing import Dict, Any, Tuple, Optional
import hashlib
import secrets


class ZKProofSystem:
    """Zero-knowledge proof primitives for blind signature verification."""

    def __init__(self, p: int, q: int, g: int):
        self.p = p
        self.q = q
        self.g = g

    def schnorr_prove(self, private_key: int) -> Dict[str, Any]:
        """Prover generates commitment and challenge."""
        k = secrets.randbelow(self.q - 1) + 1
        commitment = pow(self.g, k, self.p)
        return {"commitment": commitment, "k": k, "g": self.g, "p": self.p, "q": self.q}

    def schnorr_challenge(self, commitment: int) -> int:
        """Verifier generates random challenge."""
        return secrets.randbelow(self.q - 1) + 1

    def schnorr_respond(self, private_key: int, k: int, challenge: int) -> int:
        """Prover computes response."""
        return (k - challenge * private_key) % self.q

    def schnorr_verify(self, public_key: int, commitment: int, challenge: int, response: int) -> Dict[str, Any]:
        """Verifier checks the proof."""
        lhs = pow(self.g, response, self.p) * pow(public_key, challenge, self.p) % self.p
        valid = lhs == commitment
        return {"valid": valid, "lhs": lhs, "commitment": commitment}

    def hash_commitment(self, data: bytes) -> Tuple[int, bytes]:
        """Pedersen-style hash commitment."""
        r = secrets.token_bytes(32)
        h = hashlib.sha256(data + r).digest()
        commitment_val = int.from_bytes(h, "big") % self.p
        return commitment_val, r

    def verify_commitment(self, data: bytes, salt: bytes, expected_commitment: int) -> bool:
        """Verify a hash commitment."""
        h = hashlib.sha256(data + salt).digest()
        actual = int.from_bytes(h, "big") % self.p
        return actual == expected_commitment

    def hash_chain_commitment(self, messages: list) -> Dict[str, Any]:
        """Commit to a sequence of messages using hash chaining."""
        chain = []
        current = b""
        salts = []
        for msg in messages:
            msg_bytes = msg.encode() if isinstance(msg, str) else msg
            salt = secrets.token_bytes(16)
            salts.append(salt)
            h = hashlib.sha256(current + msg_bytes + salt).digest()
            current = h
            chain.append(int.from_bytes(h, "big") % self.p)

        return {
            "final_hash": chain[-1] if chain else 0,
            "chain": chain,
            "salts": [s.hex() for s in salts],
            "num_messages": len(messages),
        }

    def verify_hash_chain(self, messages: list, chain: list, salts: list) -> bool:
        """Verify a hash chain commitment."""
        current = b""
        for msg, expected, salt in zip(messages, chain, salts):
            msg_bytes = msg.encode() if isinstance(msg, str) else msg
            salt_bytes = bytes.fromhex(salt) if isinstance(salt, str) else salt
            h = hashlib.sha256(current + msg_bytes + salt_bytes).digest()
            actual = int.from_bytes(h, "big") % self.p
            if actual != expected:
                return False
            current = h
        return True
