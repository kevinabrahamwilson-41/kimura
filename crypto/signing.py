from crypto.mldsa import MLDSA
from crypto.keygen import (
    generate_mlkem_server_keys, generate_mlkem_client_keys,
    generate_mldsa_server_keys, generate_mldsa_client_keys,
    load_mlkem_server_keys, load_mlkem_client_keys,
    load_mldsa_server_keys, load_mldsa_client_keys
)
from pathlib import Path
from typing import Optional, Tuple
import hashlib

def ensure_keys_exist(base_dir: str = "keys", role: str = "server") -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Ensure ML-KEM + ML-DSA keys exist for the given role (server/client).
    Creates folders and generates keys if missing.

    Returns: (kem_pk, kem_sk, dsa_pk, dsa_sk)
    """
    if role not in ("server", "client"):
        raise ValueError("role must be 'server' or 'client'")

    role_dir = Path(base_dir)
    role_dir.mkdir(parents=True, exist_ok=True)

    kem_file = role_dir / "mlkem.pem"
    dsa_file = role_dir / "mldsa.pem"
    missing = []
    if not kem_file.exists():
        missing.append("ML-KEM")
        if role == "server":
            generate_mlkem_server_keys(str(role_dir))
        else:
            generate_mlkem_client_keys(str(role_dir))

    if not dsa_file.exists():
        missing.append("ML-DSA")
        if role == "server":
            generate_mldsa_server_keys(str(role_dir))
        else:
            generate_mldsa_client_keys(str(role_dir))

    if missing:
        print(f"🔑 Generated {', '.join(missing)} keys for {role.upper()}")
    else:
        print(f"✅ All {role.upper()} keys already exist")

    # Load keys
    if role == "server":
        kem_pk, kem_sk = load_mlkem_server_keys(str(role_dir))
        dsa_pk, dsa_sk = load_mldsa_server_keys(str(role_dir))
    else:
        kem_pk, kem_sk = load_mlkem_client_keys(str(role_dir))
        dsa_pk, dsa_sk = load_mldsa_client_keys(str(role_dir))
    return kem_pk, kem_sk, dsa_pk, dsa_sk


def hash_file(file_path: Path) -> bytes:
    """Compute SHA-256 hash of entire file for integrity."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.digest()


def sign_file(file_path: str, secret_key: bytes, key_dir: str = "keys") -> Tuple[bytes, bytes]:
    """
    Sign a FILE (not raw bytes) - hashes file + signs hash.
    
    Returns: (file_hash, signature)
    """
    file_path = Path(file_path)
    if not file_path.exists():
        raise FileNotFoundError(f"File not found: {file_path}")
    
    # 1. Hash entire file (SHA-256)
    file_hash = hash_file(file_path)
    print(f"📁 File hash: {file_hash.hex()}")
    
    # 2. Sign the hash
    signature = sign_message(file_hash, secret_key)
    
    return file_hash, signature


def verify_file(file_path: str, signature: bytes, public_key: bytes, 
                expected_hash: Optional[bytes] = None) -> bool:
    """
    Verify file integrity + signature.
    
    Args:
        file_path: File to verify
        signature: Signature over file hash
        public_key: Signer's public key
        expected_hash: Pre-computed hash (optional, for receiver)
    
    Returns: True if file matches signature
    """
    file_path = Path(file_path)
    
    # 1. Compute current file hash
    current_hash = hash_file(file_path)
    
    # 2. Verify signature matches hash
    is_sig_valid = verify_message(current_hash, signature, public_key)
    
    if expected_hash:
        hash_match = current_hash == expected_hash
        print(f"🔍 Hash match: {hash_match}")
        return is_sig_valid and hash_match
    else:
        print(f"🔍 Current hash: {current_hash.hex()}")
        return is_sig_valid


# Original functions (unchanged for raw message signing)
def sign_message(message: bytes, secret_key: bytes) -> bytes:
    if not secret_key:
        raise ValueError("ML-DSA secret key not provided")
    dsa = MLDSA("ML-DSA-65")
    return dsa.sign(message, secret_key)


def verify_message(message: bytes, signature: bytes, public_key: Optional[bytes] = None) -> bool:
    if not public_key:
        raise ValueError("ML-DSA public key not provided")
    dsa = MLDSA("ML-DSA-65")
    return dsa.verify(message, signature, public_key)


# Usage example for file transfer protocol
def example_file_signing():
    """Demo: Sign + verify a model.bin file."""
    # Ensure keys exist
    ensure_keys_exist("./keys", role="server")
    
    # Client signs file
    file_hash, sig = sign_file("model.bin", load_mldsa_client_keys("./keys")[1])
    
    # Server verifies
    is_valid = verify_file("model.bin", sig, load_mldsa_client_keys("./keys")[0])
    print(f"✅ File signature valid: {is_valid}")


if __name__ == "__main__":
    example_file_signing()
