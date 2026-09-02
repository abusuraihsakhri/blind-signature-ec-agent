# Blind Signature Ec Agent

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture  
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

**Blind Signature Ec Agent** is an advanced analytical and computational platform implementing Blind-signature RSA & ECC anonymous token authentication & double-spend interceptor.

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

---

## ⚙️ Key Capabilities & Algorithmic Modules

### 🔬 Core Algorithmic & Evaluation Engines

- **`CurveParams`** — dedicated module for curve params evaluation and state verification.
- **`ECDSAUtils`**: Elliptic curve operations for blind signature protocol.
- **`BlindSignatureProtocol`**: Pedersen blind signature with blinding factor.
- **`ECPoint`**: Affine point on elliptic curve y^2 = x^3 + B mod P.
- **`KeyPair`**: Signer public/private keypair.
- **`BlindSession`**: Client-side state during interactive blind signing.

---

## 📐 Mathematical Formulation & Logic

```text
  return (0, 0)
  return (x, y)
  return (k + c_hat * keypair.secret) % N
  return (session.alpha * s_hat + session.beta) % N
  return (k - challenge * private_key) % self.q
```

---

## 💻 CLI Quickstart & Usage

### 1. Guided Interactive Mode
```bash
python cli.py
```

### 2. Direct Parameterized Evaluation
```bash
python cli.py --json <value> --message <value> --public-key <value> --commitment-t <value>
```

### Parameter Reference
- `--json`: Specifies input measurement or parameter value.
- `--message`: Specifies input measurement or parameter value.
- `--public-key`: Specifies input measurement or parameter value.
- `--commitment-t`: Specifies input measurement or parameter value.
- `--sigma`: Specifies input measurement or parameter value.

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `suite_name` | Parameter / observation metric | Required |
| `system_slug` | Parameter / observation metric | Required |
| `standard_reference` | Parameter / observation metric | Required |
| `test_cases` | Parameter / observation metric | Required |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active AST and regex inspection blocking SSNs, MRNs, phone numbers, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **Active Learning Bayesian Calibration:** Dynamic tracker updating worker reliability weights and monitoring Brier calibration drift.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py --tasks 1000 --concurrency 8
```

---

## 🐳 Container Deployment

```bash
docker build -t blind-signature-ec-agent .
docker run -p 8000:8000 blind-signature-ec-agent
```
