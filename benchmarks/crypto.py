#!/usr/bin/env python3
import time
from pathlib import Path
import statistics
from kimura.crypto.mlkem import MLKEM
from crypto.signing import (
    ensure_keys_exist,
    load_mldsa_client_keys,
    load_mlkem_client_keys,
    sign_message,
    verify_message,
)
from kimura.crypto.mldsa import MLDSA
KEY_PATH = Path("./keys")
RUNS = 10_000


def measure_mlkem():
    # Ensure keys exist
    ensure_keys_exist(KEY_PATH, "client")
    pub, priv = load_mlkem_client_keys(KEY_PATH)

    encap_times = []
    decap_times = []

    for _ in range(RUNS):
        start = time.perf_counter()
        ct, ss = MLKEM("ML-KEM-768").encaps(pub)
        encap_times.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        MLKEM("ML-KEM-768").decaps(ct, priv)
        decap_times.append((time.perf_counter() - start) * 1000)

    print("\n=== ML-KEM (ML-KEM-768, client keys) ===")
    print(f"Runs       : {RUNS}")
    print(f"Encap mean : {statistics.mean(encap_times):.3f} ms")
    print(f"Encap 90th : {statistics.quantiles(encap_times, n=10)[8]:.3f} ms")
    print(f"Encap 99th : {statistics.quantiles(encap_times, n=100)[98]:.3f} ms")
    print(f"Encap worst: {max(encap_times):.3f} ms")
    print(f"\nDecap mean : {statistics.mean(decap_times):.3f} ms")
    print(f"Decap 90th : {statistics.quantiles(decap_times, n=10)[8]:.3f} ms")
    print(f"Decap 99th : {statistics.quantiles(decap_times, n=100)[98]:.3f} ms")
    print(f"Decap worst: {max(decap_times):.3f} ms")


def measure_signing():
    # Ensure keys exist
    ensure_keys_exist(KEY_PATH, "client")
    pk, sk = load_mldsa_client_keys(KEY_PATH)

    # DEBUG: print what liboqs says ML-DSA-65 secret‑key length should be
    dsa = MLDSA("ML-DSA-65")
    print("DEBUG: ML-DSA-65 secret_key length should be:", dsa.length_secret_key)
    print("DEBUG: loaded sk length =", len(sk))
    print("DEBUG: loaded sk type =", type(sk))
    print("DEBUG: sk bytes (first 32)", sk[:32])

    # Realistic handshake‑like message size (~1–4 KB)
    message = b"handshake_data_" * 1000  # ~16 KB, realistic envelope

    sign_times = []
    verify_times = []

    for _ in range(RUNS):
        start = time.perf_counter()
        sig = sign_message(message, sk)
        sign_times.append((time.perf_counter() - start) * 1000)

        start = time.perf_counter()
        verify_message(message, sig, pk)
        verify_times.append((time.perf_counter() - start) * 1000)

    print("\n=== ML-DSA (ML-DSA-65, client keys) ===")
    print(f"Runs       : {RUNS}")
    print(f"Sign  mean : {statistics.mean(sign_times):.3f} ms")
    print(f"Sign  90th : {statistics.quantiles(sign_times, n=10)[8]:.3f} ms")
    print(f"Sign  99th : {statistics.quantiles(sign_times, n=100)[98]:.3f} ms")
    print(f"Sign  worst: {max(sign_times):.3f} ms")
    print(f"\nVerify mean: {statistics.mean(verify_times):.3f} ms")
    print(f"Verify 90th: {statistics.quantiles(verify_times, n=10)[8]:.3f} ms")
    print(f"Verify 99th: {statistics.quantiles(verify_times, n=100)[98]:.3f} ms")
    print(f"Verify worst: {max(verify_times):.3f} ms")



if __name__ == "__main__":
    measure_mlkem()
    measure_signing()
