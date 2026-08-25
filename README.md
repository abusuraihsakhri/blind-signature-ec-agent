# Elliptic Curve Blind Signature Agent

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-brightgreen.svg)](https://python.org)
[![Tests: 29 Passing](https://img.shields.io/badge/Tests-29%20Passing-success.svg)](test_blind_signature_ec.py)
[![Domain: Cryptography & Zero-Knowledge](https://img.shields.io/badge/Domain-Applied%20Cryptography-blueviolet.svg)](#)

A cryptographic engine implementing **Pointcheval-Stern style Blind Signatures** over the `secp256k1` elliptic curve, **Pedersen Commitments**, **Schnorr Zero-Knowledge Proofs of Knowledge (ZKP)**, and **Double-Spend Protection** for anonymous electronic cash, private credentials, and verifiable electronic voting.

---

## Cryptographic Protocol Specification

### 1. Pointcheval-Stern Blind Signature Protocol over `secp256k1`

Let curve $\mathcal{E}(\mathbb{F}_p)$ be defined by $y^2 \equiv x^3 + 7 \pmod p$ with base generator $G$ and prime group order $N$.

1. **Signer Key Generation & Commitment**:
   - Private key $d \in_R [1, N-1]$, public key $Q = d \cdot G$.
   - Choose ephemeral nonce $k \in_R [1, N-1]$, publish commitment $R = k \cdot G$.

2. **Client Blinding**:
   - Choose random blinding scalars $\alpha, \beta \in_R [1, N-1]$.
   - Compute blinded commitment point:
     $$T = \alpha \cdot R + \beta \cdot G$$
   - Compute Fiat-Shamir challenge:
     $$c = H(m \parallel T_x) \pmod N$$
   - Compute blinded challenge:
     $$\hat{c} = c \cdot \alpha^{-1} \pmod N$$
   - Send $\hat{c}$ to Signer (the Signer learns neither message $m$ nor challenge $c$).

3. **Signer Blind Signing**:
   - Compute response scalar:
     $$\hat{s} = k + \hat{c} \cdot d \pmod N$$
   - Return $\hat{s}$ to Client.

4. **Client Unblinding**:
   - Compute unblinded signature:
     $$\sigma = \alpha \cdot \hat{s} + \beta \pmod N$$
   - The public verifiable signature on message $m$ is $(T, \sigma)$.

5. **Universal Verification**:
   - Compute $c = H(m \parallel T_x) \pmod N$.
   - Check the elliptic curve equality:
     $$\sigma \cdot G \stackrel{?}{=} T + c \cdot Q$$
   - *Mathematical Correctness*:
     $$\sigma \cdot G = (\alpha(k + \hat{c} d) + \beta) G = \alpha k G + \alpha \hat{c} d G + \beta G = (\alpha R + \beta G) + c (d G) = T + c \cdot Q$$

---

## Installation

```bash
git clone https://github.com/example/blind-signature-ec-agent.git
cd blind-signature-ec-agent
```

*Requires Python 3.10+ with zero external third-party dependencies (pure standard library).*

---

## Command-Line Interface (CLI)

```bash
# 1. Generate secp256k1 keypair
python cli.py keygen

# 2. Issue a blind signature for a message
python cli.py issue --message "ballot:Candidate_Alpha"

# 3. Verify an unblinded signature (T, sigma)
python cli.py verify --message "ballot:Candidate_Alpha" \
  --public-key "0270306da2291966f2409672514bba517158a89da40f8639fa77f42469d95db266" \
  --commitment-t "03eae89885b38497a143c69a638b32e34734a4f18c4e2be5528d8dce465ffc43cd" \
  --sigma "ae2530d0eb4a5589fc020d39c1debfcd4ea14a66d9a35644f033a9e870ca3980"

# 4. Generate and verify a Schnorr Zero-Knowledge Proof of Knowledge (ZKP)
python cli.py zk-proof

# 5. Test double-spend token redemption registry
python cli.py double-spend
```

---

## Python API Usage

```python
from blind_signature_ec import (
    KeyPair,
    BlindSignatureProtocol,
    ZKProofEngine,
    DoubleSpendRegistry,
)

# 1. Signer setup
signer_keys = KeyPair.generate()

# 2. Protocol execution
# Signer commits
k, R = BlindSignatureProtocol.signer_step1_commit()

# Client blinds message
message = b"anonymous-e-cash-token-100USD"
session, c_hat = BlindSignatureProtocol.client_step2_blind(message, R)

# Signer signs blinded challenge
s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, signer_keys)

# Client unblinds signature
sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)

# 3. Verification & Double-Spend Registry
registry = DoubleSpendRegistry()
redemption = registry.redeem_token("TOKEN-001", sig, signer_keys.public_key)
print("Token Accepted:", redemption["accepted"])

# Replay attempt fails
replay = registry.redeem_token("TOKEN-002", sig, signer_keys.public_key)
print("Double Spend Detected:", replay["double_spend"])
```

---

## Test Suite

Run the unit test suite:

```bash
python -m unittest test_blind_signature_ec.py
```

Tests cover:
- secp256k1 point arithmetic, group laws, and compression roundtrips
- Full interactive blind signature workflow and verification
- Signer privacy and computational blindness invariants
- Tamper detection on message, public key, and signature scalars
- Homomorphic properties of Pedersen commitments
- Schnorr Zero-Knowledge Proofs of Knowledge
- Double-spend token redemption and replay protection

---

## License

MIT License. See `LICENSE` for details.
