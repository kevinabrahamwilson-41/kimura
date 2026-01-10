# PQC Secure P2P File Transfer Protocol

> **Post-Quantum Secure, Peer-to-Peer File Transfer Protocol**

A fully peer-to-peer file transfer protocol designed to remain secure against classical and quantum adversaries. The protocol combines post-quantum cryptography for authentication and key exchange with high-performance symmetric encryption for data transfer.

---

## 1. Overview

This project implements a **Post-Quantum Secure Peer-to-Peer (P2P) File Transfer Protocol** that enables two peers to securely exchange files over an untrusted network.

Unlike traditional TLS-based systems, this protocol is designed from the ground up using **NIST-selected post-quantum primitives**, making it resistant to both classical and quantum attacks.

The system is **protocol-driven**, not just a secure application: message formats, cryptographic bindings, handshake phases, and failure behavior are explicitly defined.

---

## 2. Design Goals

* Post-quantum secure key exchange
* Post-quantum mutual authentication
* Forward secrecy
* Replay protection
* Fully peer-to-peer (no permanent server)
* Transport-agnostic (currently TCP)
* Modular cryptographic backend
* High-performance encrypted file transfer

---

## 3. Threat Model

### Adversary Capabilities

* Full network visibility (MITM)
* Packet injection and replay
* Passive traffic analysis
* Future quantum adversary

### Security Guarantees

* Confidentiality of transferred files
* Integrity and authenticity of peers
* Session key forward secrecy
* Resistance to replay and downgrade attacks

---

## 4. Cryptographic Primitives

| Purpose              | Algorithm   |
| -------------------- | ----------- |
| Key Exchange         | ML-KEM-512  |
| Authentication       | ML-DSA      |
| Symmetric Encryption | AES-256-GCM |
| Key Derivation       | HKDF-SHA256 |
| Hashing              | SHA-256     |

All cryptographic components are isolated into dedicated modules to allow future algorithm agility.

---

## 5. Protocol Roles

Although the system is peer-to-peer, each session defines temporary roles:

* **Initiator (I)** – Peer that starts the connection
* **Responder (R)** – Peer that accepts the connection

Roles are symmetric and exist only for the duration of the session.

---

## 6. Protocol Flow

```
Initiator                          Responder
   |--------- HELLO --------------->|
   |<------ HELLO_ACK --------------|
   |----- PQC_HANDSHAKE ------------>|
   |<-- PQC_HANDSHAKE_RESP ----------|
   |===== SECURE CHANNEL ESTABLISHED =====|
   |------ FILE_META -------------->|
   |<----- META_ACK ----------------|
   |------ FILE_CHUNKS ------------>|
   |<----- TRANSFER_OK -------------|
```

---

## 7. Handshake Specification

### 7.1 HELLO

Used for protocol negotiation and replay protection.

Fields:

* protocol_version
* peer_id
* supported_algorithms
* nonce_A

---

### 7.2 HELLO_ACK

Responder acknowledgement.

Fields:

* chosen_algorithms
* nonce_B

---

### 7.3 PQC_HANDSHAKE

Initiator authentication and key exchange.

Fields:

* ephemeral_kem_public_key
* long_term_dsa_public_key
* signature over (KEM key || nonce_A || nonce_B)

---

### 7.4 PQC_HANDSHAKE_RESP

Responder authentication and key agreement.

Fields:

* KEM ciphertext
* responder DSA public key
* signature over (ciphertext || nonce_A || nonce_B)

Both peers derive a shared session key using HKDF.

---

## 8. Secure Channel

After handshake completion, all messages are encrypted using AES-256-GCM.

Each encrypted frame contains:

* sequence number
* ciphertext
* authentication tag

Sequence numbers provide replay protection.

---

## 9. File Transfer Layer

### 9.1 FILE_META

Sent before data transfer.

Fields:

* filename
* filesize
* chunk_size
* file_hash (SHA-256)

---

### 9.2 FILE_CHUNK

Encrypted chunked file data.

Fields:

* chunk_index
* encrypted_payload

---

### 9.3 TRANSFER_OK

Indicates successful file reception and verification.

Fields:

* file_hash

---

## 10. Failure Handling

* Invalid signature → connection termination
* Replay detected → connection termination
* Decryption failure → connection termination
* Hash mismatch → file rejected

The protocol follows a **fail-closed** security model.

---

## 11. Implementation Details

* Written in C++ (modern standard)
* CMake-based build system
* Modular cryptographic backend
* Deterministic test vectors
* Benchmark suite for handshake and throughput

---

## 12. Build & Run

```bash
mkdir build && cd build
cmake ..
make
```

Example P2P run:

```bash
# Peer A
./pqc_peer --listen 9000

# Peer B
./pqc_peer --connect <peer-ip>:9000 --send file.bin
```

---

## 13. Folder Structure

```
pqc_secure_file_transfer/
├── protocol/
│   ├── messages.py        # Message formats (HELLO, HANDSHAKE, etc.)
│   ├── state_machine.py   # Protocol states & transitions
│   └── constants.py       # Versions, limits, enums
│
├── crypto/
│   ├── kem.py             # ML-KEM wrapper (liboqs)
│   ├── dsa.py             # ML-DSA wrapper (liboqs)
│   ├── aead.py            # AES-256-GCM (cryptography)
│   ├── kdf.py             # HKDF
│   └── hash.py            # SHA-256
│
├── transport/
│   └── tcp.py             # Async TCP transport
│
├── file_transfer/
│   ├── chunking.py        # File chunk logic
│   └── transfer.py        # Send/receive logic
│
├── peer/
│   ├── initiator.py       # P2P initiator logic
│   ├── responder.py       # P2P responder logic
│   └── peer.py            # Unified peer entry
│
├── benchmarks/
│   ├── handshake.py
│   └── throughput.py
│
├── tests/
│   ├── test_handshake.py
│   ├── test_replay.py
│   └── test_file_integrity.py
│
├── examples/
│   ├── send_file.py
│   └── receive_file.py
│
├── flow.txt               # Protocol flow diagram
├── README.md
├── requirements.txt
└── pyproject.toml
```

---

## 14. Project Status

* [x] Protocol specification
* [x] PQC handshake implementation
* [x] Secure file transfer
* [x] Benchmarks
* [ ] NAT traversal
* [ ] QUIC transport
* [ ] Formal security analysis

---

## 15. License

MIT License

---

## 16. Author

Project Owner and Protocol Designer

---

This project is intended as a **research-grade, protocol-focused implementation** demonstrating post-quantum secure P2P communication.