# Elliptic Curve Blind Signature Agent (`blind-signature-ec-agent`)

Production-grade, zero-dependency implementation of **Pointcheval–Stern & Chaum-style Blind Signatures** over the **secp256k1** elliptic curve, equipped with **Schnorr Zero-Knowledge Proofs of Knowledge (ZKP)**, **Pedersen Commitments**, and a **Double-Spending Token Registry**.

---

## 1. Theoretical Foundations & Mathematical Formulations

Blind signatures, introduced by **David Chaum (1983)**, allow a client to obtain a valid digital signature on a message $m$ from an authority without disclosing the content of $m$ or the unblinded signature $(T, \sigma)$. In decentralized e-cash, secret-ballot e-voting, and privacy-preserving credential issuance, elliptic-curve variants dramatically reduce bandwidth, verification overhead, and storage requirements compared to RSA-based schemes.

### Curve Domain Parameters: secp256k1
The cryptographic operations occur over the Koblitz curve defined by the Weierstraß equation:
$$E(\mathbb{F}_p): y^2 \equiv x^3 + 7 \pmod p$$
where:
- Prime field modulus:
  $$p = 2^{256} - 2^{32} - 977 = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F}$$
- Group generator point: $G = (G_x, G_y) \in E(\mathbb{F}_p)$
- Prime order of base point $G$:
  $$q = n = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}$$
- Cofactor: $h = 1$

### Key Generation
The signer selects a uniform random private key $d$:
$$d \xleftarrow{\$} \mathbb{Z}_q^*$$
and computes the public key through elliptic curve point multiplication:
$$Q = d \cdot G$$

---

## 2. Pointcheval–Stern Blind Signature Protocol

The protocol executes between **Signer** (holding private key $d$) and **Client** (holding message $m$).

```
       Signer (d, Q = d·G)                               Client (Message m)
       -------------------                               ------------------
Step 1: k <-$ Z_q*
        R = k·G                   ------ R ------>
                                                 Step 2: alpha, beta <-$ Z_q*
                                                         T = alpha·R + beta·G
                                                         c = H(m || T_x) mod q
                                  <---- c_hat ----       c_hat = c · alpha^(-1) mod q
Step 3: s_hat = k + c_hat·d mod q
                                  ---- s_hat ---->
                                                 Step 4: sigma = alpha·s_hat + beta mod q
                                                         Unblinded Signature: (T, sigma)
```

### Protocol Steps

1. **Step 1: Signer Nonce Commitment**
   The signer picks an ephemeral secret nonce $k \xleftarrow{\$} \mathbb{Z}_q^*$ and transmits the commitment point:
   $$R = k \cdot G$$

2. **Step 2: Client Blinding**
   The client samples two secret blinding scalar factors $\alpha, \beta \xleftarrow{\$} \mathbb{Z}_q^*$:
   - Computes blinded commitment point:
     $$T = \alpha \cdot R + \beta \cdot G$$
   - Computes challenge scalar from message $m$ and $T_x$:
     $$c = H(m \parallel T_x) \pmod q$$
   - Blinds challenge:
     $$\hat{c} = c \cdot \alpha^{-1} \pmod q$$
   The client transmits $\hat{c}$ to the signer. Because $\alpha$ is uniformly random, $\hat{c}$ leaks zero information about $m$ or $c$.

3. **Step 3: Signer Blind Signing**
   The signer signs the blinded challenge without learning $m$ or $T$:
   $$\hat{s} = k + \hat{c} \cdot d \pmod q$$
   The signer returns $\hat{s}$ to the client.

4. **Step 4: Client Unblinding**
   The client computes the signature scalar $\sigma$:
   $$\sigma = \alpha \cdot \hat{s} + \beta \pmod q$$
   The resulting unblinded signature is the tuple:
   $$(T, \sigma)$$

5. **Step 5: Public Verification**
   Any party can verify that $(T, \sigma)$ is a valid signature on $m$ under public key $Q$:
   $$\sigma \cdot G \stackrel{?}{=} T + c \cdot Q \quad \text{where } c = H(m \parallel T_x) \pmod q$$

---

## 3. Mathematical Correctness & Unforgeability Guarantees

### Correctness Proof
Expanding the verification equation:
$$\begin{aligned}
\sigma \cdot G &= (\alpha \cdot \hat{s} + \beta) \cdot G \\
&= (\alpha \cdot (k + \hat{c} \cdot d) + \beta) \cdot G \\
&= (\alpha \cdot k + \alpha \cdot (c \cdot \alpha^{-1}) \cdot d + \beta) \cdot G \\
&= (\alpha \cdot k + c \cdot d + \beta) \cdot G \\
&= (\alpha \cdot k \cdot G + \beta \cdot G) + c \cdot (d \cdot G) \\
&= (\alpha \cdot R + \beta \cdot G) + c \cdot Q \\
&= T + c \cdot Q \pmod p
\end{aligned}$$
Thus, verification holds with probability 1 for honestly generated transcripts.

### Unlinkability (Blindness)
For any view $(R, \hat{c}, \hat{s})$ possessed by the signer and any unblinded signature $(T, \sigma)$ on $m$, there exists a unique pair of blinding scalars $(\alpha, \beta) \in (\mathbb{Z}_q^*)^2$ defined by:
$$\alpha = c \cdot \hat{c}^{-1} \pmod q, \quad \beta = \sigma - \alpha \cdot \hat{s} \pmod q$$
Since $\alpha$ and $\beta$ are chosen uniformly and independently at random from $\mathbb{Z}_q^*$, the conditional probability distribution of the signer's view given any signature is uniform. Consequently, the signer cannot link an issued blind signature $(T, \sigma)$ to the session that issued it.

### One-More Unforgeability
Under the discrete logarithm assumption and the Random Oracle Model (ROM), Pointcheval–Stern blind signatures are secure against *one-more forgery attacks*: an adversary requesting $\ell$ blinded signatures cannot construct $\ell + 1$ valid signatures.

---

## 4. Zero-Knowledge Proofs & Double-Spend Registry

- **Schnorr Zero-Knowledge Proof of Knowledge (PoK):** Proves knowledge of the discrete log $d$ such that $Q = d \cdot G$ without revealing $d$:
  - Commitment: $V = r \cdot G$ for $r \xleftarrow{\$} \mathbb{Z}_q^*$
  - Challenge: $e = H(Q \parallel V) \pmod q$
  - Response: $s = r + e \cdot d \pmod q$
  - Verification: $s \cdot G \stackrel{?}{=} V + e \cdot Q$
- **Pedersen Commitments:** Homomorphic commitments $C = v \cdot G + r \cdot H$ where $H$ is a deterministic, verified on-curve generator with unknown discrete log relative to $G$.
- **Double-Spend Token Registry:** Tracks verified commitment points $T$. Any attempt to redeem or spend a token with an already redeemed $T$ is flagged and rejected as a double-spend attempt.

---

## 5. CLI Quickstart & Usage

The application provides a command-line interface `cli.py`:

```bash
# 1. Generate secp256k1 keypair
python cli.py keygen --json

# 2. Issue a Pointcheval-Stern blind signature interactively
python cli.py issue --message "anonymous-ballot-vote" --json

# 3. Verify an unblinded signature
python cli.py verify \
  --message "ballot-vote-option-A" \
  --public-key "02c0ffee..." \
  --commitment-t "03deadbeef..." \
  --sigma "3fa0..."

# 4. Generate & verify Schnorr Zero-Knowledge Proof of discrete log
python cli.py zk-proof --json

# 5. Run Double-Spend redemption test
python cli.py double-spend --json

# 6. Batch process operations from CSV
python cli.py batch -i sample.csv -o results.csv
```

---

## 6. Python API Quickstart

```python
from blind_signature_ec import KeyPair, BlindSignatureProtocol, BlindSignature, ZKProofEngine

# 1. Authority generates public/private keypair
signer_keys = KeyPair.generate()

# 2. Step 1 (Signer): Nonce commitment
k, R = BlindSignatureProtocol.signer_step1_commit()

# 3. Step 2 (Client): Blind the message
message = b"confidential-ballot-option-1"
session, c_hat = BlindSignatureProtocol.client_step2_blind(message, R)

# 4. Step 3 (Signer): Signs blinded challenge (never sees message)
s_hat = BlindSignatureProtocol.signer_step3_sign(c_hat, k, signer_keys)

# 5. Step 4 (Client): Unblinds signature
sig = BlindSignatureProtocol.client_step4_unblind(session, s_hat)

# 6. Step 5 (Anyone): Publicly verifies unblinded signature
assert BlindSignatureProtocol.verify(sig, signer_keys.public_key)
print("Signature verified successfully! Point T:", sig.T.to_hex(compressed=True))

# 7. Schnorr Zero-Knowledge Proof
zk_proof = ZKProofEngine.schnorr_pok_prove(signer_keys.secret_key)
assert ZKProofEngine.schnorr_pok_verify(zk_proof)
print("Zero-Knowledge Proof verified!")
```

---

## 7. Testing & Verification

Run the test suite:
```bash
python -m pytest -p no:zarr -v
```

Execute batch CLI verification:
```bash
python cli.py batch -i sample.csv -o out_smoke.csv
```

---

## 8. License

MIT License. Copyright (c) 2026 Dr. Abu Suraih Sakhri.
