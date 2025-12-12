import base64
import time
import hmac
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


# ==========================
#   LOAD RSA KEYS
# ==========================

def load_private_key(path: str):
    """Load a PEM RSA private key from file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )


def load_public_key(path: str):
    """Load a PEM RSA public key from file."""
    with open(path, "rb") as key_file:
        return serialization.load_pem_public_key(key_file.read())


# ==========================
#   RSA OPERATIONS
# ==========================

def sign_message_rsa_pss(private_key, message: str) -> str:
    """Sign message using RSA-PSS + SHA256."""
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(signature).decode()


def encrypt_with_public_key(public_key, message: str) -> str:
    """Encrypt message using RSA-OAEP."""
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()


# ==========================
#   SEED DECRYPTION
# ==========================

def decrypt_seed(private_key_path: str, encrypted_seed_b64: str) -> str:
    """Decrypt encrypted seed using student's private key."""

    private_key = load_private_key(private_key_path)
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
