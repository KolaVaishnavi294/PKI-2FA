import base64
import os
import time
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding


# -----------------------------
#  Decrypt Seed
# -----------------------------
def decrypt_seed(private_key_path: str, encrypted_seed_b64: str) -> str:
    """Decrypt encrypted seed using student's private key."""

    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
        )

    encrypted_bytes = base64.b64decode(encrypted_seed_b64)

    seed = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashlib.sha256()),
            algorithm=hashlib.sha256(),
            label=None,
        ),
    )

    return seed.decode()


# -----------------------------
#  2FA Code Generation (TOTP-like)
# -----------------------------
def generate_2fa_code(seed: str) -> str:
    """Generate a 6-digit TOTP-style code using HMAC-SHA256."""

    timestep = int(time.time() // 30)
    msg = f"{seed}:{timestep}".encode()

    code = hmac.new(seed.encode(), msg, hashlib.sha256).hexdigest()
    return str(int(code[:6], 16)).zfill(6)


# -----------------------------
#  Verify 2FA Code
# -----------------------------
def verify_2fa_code(seed: str, code: str) -> bool:
    """Verify a submitted 2FA code."""

    expected = generate_2fa_code(seed)
    return expected == code
