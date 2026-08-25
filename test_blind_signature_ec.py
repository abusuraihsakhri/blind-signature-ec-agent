"""
Unit Test Suite for Elliptic Curve Blind Signature & Token Engine
==================================================================
Comprehensive test suite verifying:
  - secp256k1 point arithmetic, doubling, scalar multiplication, point compression
  - Pointcheval-Stern blind signature protocol issuance, unblinding, and verification
  - Mathematical blindness (signer never sees message or unblinded challenge)
  - Security against signature tampering, key substitution, and corrupted commitments
  - Schnorr Zero-Knowledge Proofs of Knowledge (ZKP)
  - Pedersen commitment homomorphic properties
  - Double-spend token registry and replay detection
  - CLI command execution and JSON serialization
"""

import io
import json
import unittest
from contextlib import redirect_stdout

from blind_signature_ec import (
    G,
    H_GEN,
    INFINITY,
    N,
    P,
    BlindSignature,
    BlindSignatureProtocol,
    DoubleSpendRegistry,
    ECPoint,
    KeyPair,
    ZKProofEngine,
    hash_to_scalar,
    point_add,
    point_mul,
)
from cli import main


class TestEllipticCurveArithmetic(unittest.TestCase):
    """Test fundamental secp256k1 group and finite field arithmetic."""

    def test_generator_on_curve(self):
        self.assertFalse(G.is_infinity)
        y2 = (pow(G.x, 3, P) + 7) % P
        self.assertEqual(pow(G.y, 2, P), y2)

    def test_point_add_identity(self):
        self.assertEqual(point_add(G, INFINITY), G)
        self.assertEqual(point_add(INFINITY, G), G)
        self.assertEqual(point_add(INFINITY, INFINITY), INFINITY)

    def test_point_inverse_addition(self):
        g_inv = ECPoint(G.x, P - G.y)
        self.assertEqual(point_add(G, g_inv), INFINITY)

    def test_scalar_multiplication_properties(self):
        # 1 * G = G
        self.assertEqual(point_mul(1, G), G)
        # 0 * G = INFINITY
        self.assertEqual(point_mul(0, G), INFINITY)
        # N * G = INFINITY (order of base point)
        self.assertEqual(point_mul(N, G), INFINITY)

    def test_distributive_scalar_multiplication(self):
        # 3*G + 5*G == 8*G
        p1 = point_mul(3, G)
        p2 = point_mul(5, G)
        p_sum = point_add(p1, p2)
        p_direct = point_mul(8, G)
        self.assertEqual(p_sum, p_direct)

    def test_point_hex_compression_roundtrip(self):
        comp_hex = G.to_hex(compressed=True)
        self.assertTrue(comp_hex.startswith("02") or comp_hex.startswith("03"))
        g_recovered = ECPoint.from_hex(comp_hex)
        self.assertEqual(g_recovered, G)

    def test_point_hex_uncompressed_roundtrip(self):
        uncomp_hex = G.to_hex(compressed=False)
        self.assertTrue(uncomp_hex.startswith("04"))
        g_recovered = ECPoint.from_hex(uncomp_hex)
        self.assertEqual(g_recovered, G)

    def test_invalid_hex_point_deserialization(self):
        with self.assertRaises(ValueError):
            ECPoint.from_hex("invalid_hex_string")

    def test_off_curve_point_deserialization(self):
        # x = 5 is a quadratic non-residue on secp256k1 (5^3 + 7 = 132 is not a square mod P)
        off_curve_hex = "02" + "00" * 31 + "05"
        with self.assertRaises(ValueError):
            ECPoint.from_hex(off_curve_hex)


class TestBlindSignatureProtocol(unittest.TestCase):
    """Test interactive blind signature issuance, unblinding, and verification."""

    def setUp(self):
        self.keypair = KeyPair.generate()
        self.message = b"confidential_ballot_vote:Candidate_Alpha"

    def test_full_blind_signature_workflow(self):
        # 1. Signer commit
        k, R = BlindSignatureProtocol.signer_step1_commit()
        self.assertFalse(R.is_infinity)

        # 2. Client blind
        session, c_hat = BlindSignatureProtocol.client_step2_blind(self.message, R)
        self.assertGreater(c_hat, 0)
        self.assertLess(c_hat, N)

        # 3. Signer sign
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, self.keypair)
        self.assertGreater(s_hat, 0)

        # 4. Client unblind
        sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)
        self.assertFalse(sig.T.is_infinity)
        self.assertGreater(sig.sigma, 0)

        # 5. Verification
        is_valid = BlindSignatureProtocol.verify(sig, self.keypair.public_key)
        self.assertTrue(is_valid)

    def test_signer_blindness_guarantee(self):
        """Verify the signer receives c_hat which differs from the true challenge c."""
        k, R = BlindSignatureProtocol.signer_step1_commit()
        session, c_hat = BlindSignatureProtocol.client_step2_blind(self.message, R)

        t_bytes = session.T.x.to_bytes(32, "big")
        true_c = hash_to_scalar(self.message, t_bytes)

        # c_hat must NOT equal true challenge c (unlinkability)
        self.assertNotEqual(c_hat, true_c)

    def test_verification_tampered_message(self):
        k, R = BlindSignatureProtocol.signer_step1_commit()
        session, c_hat = BlindSignatureProtocol.client_step2_blind(self.message, R)
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, self.keypair)
        sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)

        # Tampered message
        tampered_sig = BlindSignature(T=sig.T, sigma=sig.sigma, message=b"tampered_message")
        self.assertFalse(BlindSignatureProtocol.verify(tampered_sig, self.keypair.public_key))

    def test_verification_wrong_signer_public_key(self):
        k, R = BlindSignatureProtocol.signer_step1_commit()
        session, c_hat = BlindSignatureProtocol.client_step2_blind(self.message, R)
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, self.keypair)
        sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)

        # Different signer key
        attacker_kp = KeyPair.generate()
        self.assertFalse(BlindSignatureProtocol.verify(sig, attacker_kp.public_key))

    def test_verification_corrupted_sigma(self):
        k, R = BlindSignatureProtocol.signer_step1_commit()
        session, c_hat = BlindSignatureProtocol.client_step2_blind(self.message, R)
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, self.keypair)
        sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)

        corrupted_sig = BlindSignature(T=sig.T, sigma=(sig.sigma + 1) % N, message=self.message)
        self.assertFalse(BlindSignatureProtocol.verify(corrupted_sig, self.keypair.public_key))


class TestZKProofEngine(unittest.TestCase):
    """Test Zero-Knowledge Proofs and Pedersen commitments."""

    def test_schnorr_pok_valid(self):
        secret_x = 1234567890123456789
        proof = ZKProofEngine.schnorr_pok_prove(secret_x)
        self.assertTrue(ZKProofEngine.schnorr_pok_verify(proof))

    def test_schnorr_pok_corrupted_response(self):
        secret_x = 9876543210987654321
        proof = ZKProofEngine.schnorr_pok_prove(secret_x)
        proof["response_s"] = (proof["response_s"] + 1) % N
        self.assertFalse(ZKProofEngine.schnorr_pok_verify(proof))

    def test_pedersen_commitment_homomorphism(self):
        # Commit(v1, r1) + Commit(v2, r2) == Commit(v1 + v2, r1 + r2)
        v1, r1 = 100, 555
        v2, r2 = 250, 777
        c1, _ = ZKProofEngine.pedersen_commit(v1, r1)
        c2, _ = ZKProofEngine.pedersen_commit(v2, r2)

        c_sum = point_add(c1, c2)
        c_direct, _ = ZKProofEngine.pedersen_commit(v1 + v2, r1 + r2)

        self.assertEqual(c_sum, c_direct)


class TestDoubleSpendRegistry(unittest.TestCase):
    """Test anonymous token redemption and double-spend detection."""

    def setUp(self):
        self.registry = DoubleSpendRegistry()
        self.keypair = KeyPair.generate()

        k, R = BlindSignatureProtocol.signer_step1_commit()
        session, c_hat = BlindSignatureProtocol.client_step2_blind(b"E-Cash-50-USD", R)
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, self.keypair)
        self.valid_sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)

    def test_successful_first_redemption(self):
        res = self.registry.redeem_token("TOKEN-001", self.valid_sig, self.keypair.public_key)
        self.assertTrue(res["accepted"])
        self.assertFalse(res["double_spend"])

    def test_double_spend_rejected(self):
        res1 = self.registry.redeem_token("TOKEN-001", self.valid_sig, self.keypair.public_key)
        self.assertTrue(res1["accepted"])

        # Attempt to redeem second time
        res2 = self.registry.redeem_token("TOKEN-002", self.valid_sig, self.keypair.public_key)
        self.assertFalse(res2["accepted"])
        self.assertTrue(res2["double_spend"])

    def test_invalid_signature_redemption_rejected(self):
        bogus_sig = BlindSignature(T=self.valid_sig.T, sigma=12345, message=b"fake")
        res = self.registry.redeem_token("TOKEN-FAKE", bogus_sig, self.keypair.public_key)
        self.assertFalse(res["accepted"])


class TestCLIExecution(unittest.TestCase):
    """Test CLI commands and JSON output."""

    def test_cli_keygen_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["keygen", "--json"])
        self.assertEqual(ret, 0)
        data = json.loads(buf.getvalue())
        self.assertIn("public_key_compressed", data)
        self.assertEqual(data["curve"], "secp256k1")

    def test_cli_issue_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["issue", "--message", "test_vote_A", "--json"])
        self.assertEqual(ret, 0)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["verified"])
        self.assertTrue(data["signer_privacy_preserved"])

    def test_cli_zk_proof_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["zk-proof", "--json"])
        self.assertEqual(ret, 0)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["verified"])

    def test_cli_double_spend_json(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            ret = main(["double-spend", "--json"])
        self.assertEqual(ret, 0)
        data = json.loads(buf.getvalue())
        self.assertTrue(data["double_spend_prevented"])

    def test_cli_verify_valid_and_invalid(self):
        kp = KeyPair.generate()
        k, R = BlindSignatureProtocol.signer_step1_commit()
        sess, c_hat = BlindSignatureProtocol.client_step2_blind(b"valid_vote", R)
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, kp)
        sig = BlindSignatureProtocol.client_step4_unblind(sess, s_hat)

        # Valid verify
        ret_valid = main([
            "verify",
            "--message", "valid_vote",
            "--public-key", kp.public_key.to_hex(compressed=True),
            "--commitment-t", sig.T.to_hex(compressed=True),
            "--sigma", f"{sig.sigma:064x}",
            "--json",
        ])
        self.assertEqual(ret_valid, 0)

        # Invalid verify (tampered message)
        ret_invalid = main([
            "verify",
            "--message", "tampered_vote",
            "--public-key", kp.public_key.to_hex(compressed=True),
            "--commitment-t", sig.T.to_hex(compressed=True),
            "--sigma", f"{sig.sigma:064x}",
            "--json",
        ])
        self.assertEqual(ret_invalid, 2)


class TestAdditionalCryptoProperties(unittest.TestCase):
    """Test cryptographic invariants and edge cases."""

    def test_keygen_distinct(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        self.assertNotEqual(kp1.secret_key, kp2.secret_key)
        self.assertNotEqual(kp1.public_key, kp2.public_key)

    def test_blind_signature_to_dict(self):
        sig = BlindSignature(T=G, sigma=12345, message=b"hello_world")
        d = sig.to_dict()
        self.assertEqual(d["message_utf8"], "hello_world")
        self.assertEqual(d["message_hex"], b"hello_world".hex())
        self.assertIn("sigma_hex", d)

    def test_zk_proof_mismatched_public_key(self):
        kp1 = KeyPair.generate()
        kp2 = KeyPair.generate()
        proof = ZKProofEngine.schnorr_pok_prove(kp1.secret_key)
        # Replace public key with kp2's pubkey
        proof["public_key_hex"] = kp2.public_key.to_hex()
        self.assertFalse(ZKProofEngine.schnorr_pok_verify(proof))

    def test_empty_message_blind_signing(self):
        kp = KeyPair.generate()
        k, R = BlindSignatureProtocol.signer_step1_commit()
        session, c_hat = BlindSignatureProtocol.client_step2_blind(b"", R)
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, kp)
        sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)
        self.assertTrue(BlindSignatureProtocol.verify(sig, kp.public_key))


if __name__ == "__main__":
    unittest.main()
