from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import time
import hmac
import hashlib

PRIVATE_KEY_PATH = "/app/student_private.pem"

def decrypt_seed(encrypted_seed_b64: str) -> str:
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(), password=None
        )

    encrypted_bytes = base64.b64decode(encrypted_seed_b64)

    seed = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return seed.decode()

def generate_2fa_code(seed: str) -> str:
    timestep = int(time.time() // 30)
    msg = f"{seed}:{timestep}".encode()

    code = hmac.new(seed.encode(), msg, hashlib.sha256).hexdigest()
    return str(int(code[:6], 16)).zfill(6)

def verify_2fa_code(seed: str, code: str) -> bool:
    return generate_2fa_code(seed) == code
