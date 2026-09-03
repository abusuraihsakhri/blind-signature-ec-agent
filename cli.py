#!/usr/bin/env python3
"""
Command-Line Interface for Elliptic Curve Blind Signature & Token Engine
========================================================================
Interactive & command-driven interface for:
  - secp256k1 keypair generation
  - Pointcheval-Stern blind signature issuance and unblinding
  - Signature verification
  - Schnorr Zero-Knowledge Proofs of Knowledge (ZKP)
  - Double-spending registry and replay prevention
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from typing import Any, Dict, List, Optional

from blind_signature_ec import (
    G,
    N,
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


def cmd_keygen(args: argparse.Namespace) -> int:
    kp = KeyPair.generate()
    out = {
        "private_key_hex": f"{kp.secret_key:064x}",
        "public_key_compressed": kp.public_key.to_hex(compressed=True),
        "public_key_uncompressed": kp.public_key.to_hex(compressed=False),
        "curve": "secp256k1",
    }
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("=" * 65)
        print("  SECP256K1 KEYPAIR GENERATED")
        print("=" * 65)
        print(f"Private Key (d)      : {out['private_key_hex']}")
        print(f"Public Key (Q, comp) : {out['public_key_compressed']}")
        print(f"Public Key (Q, uncmp): {out['public_key_uncompressed']}")
        print("=" * 65)
    return 0


def cmd_issue(args: argparse.Namespace) -> int:
    msg_bytes = args.message.encode("utf-8")
    kp = KeyPair.generate()

    # Step 1: Signer commits R = k*G
    k, R = BlindSignatureProtocol.signer_step1_commit()

    # Step 2: Client blinds
    session, c_hat = BlindSignatureProtocol.client_step2_blind(msg_bytes, R)

    # Step 3: Signer signs blinded challenge
    s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, kp)

    # Step 4: Client unblinds
    sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)

    # Step 5: Verification
    is_valid = BlindSignatureProtocol.verify(sig, kp.public_key)

    out = {
        "verified": is_valid,
        "message": args.message,
        "public_key": kp.public_key.to_hex(compressed=True),
        "signature": sig.to_dict(),
        "signer_privacy_preserved": True,
    }

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("=" * 70)
        print("  POINTCHEVAL-STERN BLIND SIGNATURE ISSUED")
        print("=" * 70)
        print(f"Message                : {args.message}")
        print(f"Signer Public Key (Q)  : {out['public_key']}")
        print(f"Commitment Point (T)   : {sig.T.to_hex(compressed=True)}")
        print(f"Signature Scalar (σ)   : {sig.sigma:064x}")
        print(f"Cryptographic Validity : {'VALID (Verified)' if is_valid else 'INVALID'}")
        print(f"Signer Saw Message?    : NO (Blind Signature)")
        print("=" * 70)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    try:
        pub_pt = ECPoint.from_hex(args.public_key)
        t_pt = ECPoint.from_hex(args.commitment_t)
        sigma = int(args.sigma, 16)
        msg_bytes = args.message.encode("utf-8")
    except Exception as e:
        print(f"Error parsing arguments: {e}", file=sys.stderr)
        return 1

    sig = BlindSignature(T=t_pt, sigma=sigma, message=msg_bytes)
    is_valid = BlindSignatureProtocol.verify(sig, pub_pt)

    out = {
        "valid": is_valid,
        "message": args.message,
        "public_key": args.public_key,
        "commitment_t": args.commitment_t,
        "sigma": args.sigma,
    }

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("=" * 60)
        print("  BLIND SIGNATURE VERIFICATION")
        print("=" * 60)
        print(f"Verification Result    : {'VALID SIGNATURE' if is_valid else 'INVALID SIGNATURE'}")
        print(f"Message                : {args.message}")
        print(f"Public Key             : {args.public_key}")
        print("=" * 60)
    return 0 if is_valid else 2


def cmd_zk_proof(args: argparse.Namespace) -> int:
    kp = KeyPair.generate()
    proof = ZKProofEngine.schnorr_pok_prove(kp.secret_key)
    verified = ZKProofEngine.schnorr_pok_verify(proof)

    out = {
        "proof": {
            "public_key_hex": proof["public_key_hex"],
            "commitment_v_hex": proof["commitment_v_hex"],
            "challenge_e_hex": f"{proof['challenge_e']:064x}",
            "response_s_hex": f"{proof['response_s']:064x}",
        },
        "verified": verified,
    }

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("=" * 70)
        print("  SCHNORR ZERO-KNOWLEDGE PROOF OF KNOWLEDGE (ZKP)")
        print("=" * 70)
        print(f"Public Key (Y)         : {proof['public_key_hex']}")
        print(f"Commitment (V)         : {proof['commitment_v_hex']}")
        print(f"Challenge (e)          : {proof['challenge_e']:064x}")
        print(f"Response (s)           : {proof['response_s']:064x}")
        print(f"Proof Verification     : {'PASSED (Zero-Knowledge Valid)' if verified else 'FAILED'}")
        print("=" * 70)
    return 0


def cmd_double_spend(args: argparse.Namespace) -> int:
    registry = DoubleSpendRegistry()
    kp = KeyPair.generate()

    # Issue token 1
    k, R = BlindSignatureProtocol.signer_step1_commit()
    sess, c_hat = BlindSignatureProtocol.client_step2_blind(b"Token-Value-100USD", R)
    s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, kp)
    sig = BlindSignatureProtocol.client_step4_unblind(sess, s_hat)

    # First redemption
    res1 = registry.redeem_token("TXN-001", sig, kp.public_key)
    # Second redemption attempt with same blinded commitment (replay)
    res2 = registry.redeem_token("TXN-002", sig, kp.public_key)

    out = {
        "first_redemption": res1,
        "replay_attempt": res2,
        "double_spend_prevented": res2["double_spend"],
    }

    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print("=" * 65)
        print("  DOUBLE-SPEND REGISTRY & REPLAY PREVENTION TEST")
        print("=" * 65)
        print(f"First Redemption (TXN-001) : {'ACCEPTED' if res1['accepted'] else 'REJECTED'}")
        print(f"Replay Attempt   (TXN-002) : {'ACCEPTED' if res2['accepted'] else 'REJECTED (Double-Spend Flagged)'}")
        print(f"Replay Attack Prevented    : {'YES' if res2['double_spend'] else 'NO'}")
        print("=" * 65)
    return 0


def cmd_interactive() -> int:
    print("Elliptic Curve Blind Signature Interactive CLI")
    print("Commands: keygen, issue <msg>, zkproof, exit\n")
    while True:
        try:
            line = input("blind-ec> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break
        if not line:
            continue
        if line.lower() in ("exit", "quit"):
            break
        if line.lower() == "keygen":
            kp = KeyPair.generate()
            print(f"Pubkey: {kp.public_key.to_hex(compressed=True)}")
        elif line.lower().startswith("issue"):
            msg = line[5:].strip() or "anonymous-ballot-vote"
            kp = KeyPair.generate()
            k, R = BlindSignatureProtocol.signer_step1_commit()
            sess, c_hat = BlindSignatureProtocol.client_step2_blind(msg.encode(), R)
            s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, kp)
            sig = BlindSignatureProtocol.client_step4_unblind(sess, s_hat)
            ok = BlindSignatureProtocol.verify(sig, kp.public_key)
            print(f"Issued Blind Signature: valid={ok}, commitment={sig.T.to_hex()}")
        elif line.lower() == "zkproof":
            kp = KeyPair.generate()
            p = ZKProofEngine.schnorr_pok_prove(kp.secret_key)
            ok = ZKProofEngine.schnorr_pok_verify(p)
            print(f"ZKP Verification: {ok}")
        else:
            print(f"Unknown command: {line}")
    return 0


def cmd_batch(args: argparse.Namespace) -> int:
    import csv

    input_path = args.input
    output_path = args.output

    try:
        with open(input_path, mode="r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            fieldnames = list(reader.fieldnames or [])
            rows = list(reader)
    except Exception as e:
        print(f"Error reading input CSV '{input_path}': {e}", file=sys.stderr)
        return 1

    registry = DoubleSpendRegistry()
    out_rows = []
    extra_fields = [
        "message_hash",
        "signer_pubkey",
        "commitment_r",
        "blinded_point_t",
        "blinded_challenge_chat",
        "blinded_sig_shat",
        "unblinded_sigma",
        "verification_result",
        "zk_verification_result",
        "redemption_status",
        "double_spend_flag",
    ]

    for r in rows:
        row_dict = dict(r)
        operation = row_dict.get("operation", "issue_and_verify").strip().lower()
        msg_str = row_dict.get("message", "token-record")
        msg_bytes = msg_str.encode("utf-8")
        msg_hash = hashlib.sha256(msg_bytes).hexdigest()
        row_dict["message_hash"] = msg_hash

        # Check if keys/factors are provided, otherwise generate deterministically or randomly
        priv_hex = row_dict.get("signer_privkey", "").strip()
        if priv_hex:
            d = int(priv_hex, 16) % N
            kp = KeyPair(secret_key=d, public_key=point_mul(d, G))
        else:
            kp = KeyPair.generate()

        row_dict["signer_pubkey"] = kp.public_key.to_hex(compressed=True)

        k_hex = row_dict.get("signer_nonce_k", "").strip()
        if k_hex:
            k = int(k_hex, 16) % N
            R = point_mul(k, G)
        else:
            k, R = BlindSignatureProtocol.signer_step1_commit()
        row_dict["commitment_r"] = R.to_hex(compressed=True)

        # Blinding factors alpha, beta
        alpha_hex = row_dict.get("alpha_factor", "").strip()
        beta_hex = row_dict.get("beta_factor", "").strip()

        if alpha_hex and beta_hex:
            alpha = int(alpha_hex, 16) % N
            beta = int(beta_hex, 16) % N
            t1 = point_mul(alpha, R)
            t2 = point_mul(beta, G)
            T = point_add(t1, t2)
            t_bytes = T.x.to_bytes(32, "big")
            c = hash_to_scalar(msg_bytes, t_bytes)
            if c == 0:
                c = 1
            c_hat = (c * pow(alpha, -1, N)) % N
            from blind_signature_ec import BlindSession
            sess = BlindSession(alpha=alpha, beta=beta, T=T, message=msg_bytes, blinded_challenge=c_hat)
        else:
            sess, c_hat = BlindSignatureProtocol.client_step2_blind(msg_bytes, R)

        row_dict["blinded_point_t"] = sess.T.to_hex(compressed=True)
        row_dict["blinded_challenge_chat"] = f"{c_hat:064x}"

        # Signer signs blinded challenge
        s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, kp)
        row_dict["blinded_sig_shat"] = f"{s_hat:064x}"

        # Client unblinds signature
        sig = BlindSignatureProtocol.client_step4_unblind(sess, s_hat)
        row_dict["unblinded_sigma"] = f"{sig.sigma:064x}"

        # Verification
        if operation == "tampered_signature":
            # Tamper the signature to test negative verification
            corrupted_sig = BlindSignature(T=sig.T, sigma=(sig.sigma + 1) % N, message=sig.message)
            is_valid = BlindSignatureProtocol.verify(corrupted_sig, kp.public_key)
            sig_to_redeem = corrupted_sig
        elif operation == "tampered_message":
            corrupted_sig = BlindSignature(T=sig.T, sigma=sig.sigma, message=b"tampered-" + sig.message)
            is_valid = BlindSignatureProtocol.verify(corrupted_sig, kp.public_key)
            sig_to_redeem = corrupted_sig
        else:
            is_valid = BlindSignatureProtocol.verify(sig, kp.public_key)
            sig_to_redeem = sig

        row_dict["verification_result"] = "PASS" if is_valid else "FAIL"

        # ZK Proof of Knowledge of signer private key
        zk_proof = ZKProofEngine.schnorr_pok_prove(kp.secret_key)
        zk_valid = ZKProofEngine.schnorr_pok_verify(zk_proof)
        row_dict["zk_verification_result"] = "PASS" if zk_valid else "FAIL"

        # Double spend redemption simulation
        token_id = row_dict.get("token_id", f"TOK-{len(out_rows) + 1:04d}").strip()
        redemption = registry.redeem_token(token_id, sig_to_redeem, kp.public_key)
        row_dict["redemption_status"] = "ACCEPTED" if redemption["accepted"] else "REJECTED"
        row_dict["double_spend_flag"] = "TRUE" if redemption.get("double_spend") else "FALSE"

        out_rows.append(row_dict)

    # Compile all fieldnames ensuring order
    final_fields = list(fieldnames)
    for f_name in extra_fields:
        if f_name not in final_fields:
            final_fields.append(f_name)

    try:
        with open(output_path, mode="w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=final_fields)
            writer.writeheader()
            writer.writerows(out_rows)
        print(f"Batch processed {len(out_rows)} records: '{input_path}' -> '{output_path}'")
    except Exception as e:
        print(f"Error writing output CSV '{output_path}': {e}", file=sys.stderr)
        return 1

    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="blind_signature_ec_cli",
        description="Elliptic Curve Blind Signature & Cryptographic Token Platform",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Subcommand: keygen
    p_key = subparsers.add_parser("keygen", help="Generate secp256k1 keypair")
    p_key.add_argument("--json", action="store_true", help="Output JSON")

    # Subcommand: issue
    p_iss = subparsers.add_parser("issue", help="Execute full blind signature issuance protocol")
    p_iss.add_argument("--message", "-m", type=str, default="ballot-vote-option-A", help="Message to blind sign")
    p_iss.add_argument("--json", action="store_true", help="Output JSON")

    # Subcommand: verify
    p_ver = subparsers.add_parser("verify", help="Verify unblinded signature (T, sigma)")
    p_ver.add_argument("--message", "-m", type=str, required=True, help="Original message string")
    p_ver.add_argument("--public-key", "-k", type=str, required=True, help="Signer public key (hex)")
    p_ver.add_argument("--commitment-t", "-t", type=str, required=True, help="Commitment point T (hex)")
    p_ver.add_argument("--sigma", "-s", type=str, required=True, help="Signature scalar sigma (hex)")
    p_ver.add_argument("--json", action="store_true", help="Output JSON")

    # Subcommand: zk-proof
    p_zk = subparsers.add_parser("zk-proof", help="Generate and verify Schnorr Zero-Knowledge Proof")
    p_zk.add_argument("--json", action="store_true", help="Output JSON")

    # Subcommand: double-spend
    p_ds = subparsers.add_parser("double-spend", help="Test double-spend token redemption registry")
    p_ds.add_argument("--json", action="store_true", help="Output JSON")

    # Subcommand: batch
    p_batch = subparsers.add_parser("batch", help="Batch process cryptographic blind signature operations from CSV")
    p_batch.add_argument("-i", "--input", required=True, help="Input CSV file path")
    p_batch.add_argument("-o", "--output", default="results.csv", help="Output CSV file path")

    # Subcommand: interactive
    subparsers.add_parser("interactive", help="Interactive REPL session")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "keygen":
        return cmd_keygen(args)
    elif args.command == "issue":
        return cmd_issue(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "zk-proof":
        return cmd_zk_proof(args)
    elif args.command == "double-spend":
        return cmd_double_spend(args)
    elif args.command == "batch":
        return cmd_batch(args)
    elif args.command == "interactive":
        return cmd_interactive()
    return 0


if __name__ == "__main__":
    sys.exit(main())
