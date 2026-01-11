from .mlkem import MLKEM
from pathlib import Path

def generate_persistent_keys(key_name: str, role: str = "server"):
    """Generate and STORE ML-KEM keys in ./keys/."""
    kem = MLKEM("ML-KEM-768")
    pk, sk = kem.keygen()

    key_dir = Path("keys")
    key_dir.mkdir(exist_ok=True)
    key_path = key_dir / f"{role}.pem"

    # SAFE binary format: [4-byte pk length][pk][sk]
    with open(key_path, "wb") as f:
        f.write(len(pk).to_bytes(4, "big"))
        f.write(pk)
        f.write(sk)

    print(f"✅ {role.capitalize()} keys stored: {key_path}")
    return pk, sk


def load_persistent_keys(key_path: str, role: str = "server"):
    """Load ML-KEM keys from key_path/."""
    key_dir = Path(key_path)
    key_path_full = key_dir / f"{role}.pem"

    if not key_path_full.exists():
        raise FileNotFoundError(f"Key not found: {key_path_full}")

    with open(key_path_full, "rb") as f:
        pk_len_bytes = f.read(4)
        if len(pk_len_bytes) != 4:
            raise ValueError("Invalid key file (missing length header)")

        pk_len = int.from_bytes(pk_len_bytes, "big")
        pk = f.read(pk_len)
        sk = f.read()

        if not pk or not sk:
            raise ValueError("Invalid key file (truncated keys)")

    print(f"✅ Keys loaded: {key_path_full}")
    return pk, sk
