import sys
import os
import base64
import subprocess

# -------------------------------------------------------
# FIX: Ensure Python finds utils_crypto.py
# -------------------------------------------------------
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(ROOT)

from utils_crypto import (
    load_private_key,
    load_public_key,
    sign_message_rsa_pss,
    encrypt_with_public_key,
)

# -------------------------------------------------------
# CONFIGURATION
# -------------------------------------------------------
STUDENT_PRIVATE_KEY = "app/student_private.pem"
STUDENT_PUBLIC_KEY = "app/student_public.pem"
INSTRUCTOR_PUBLIC_KEY = "app/instructor_public.pem"

# -------------------------------------------------------
# 1. Get latest commit hash
# -------------------------------------------------------
def get_latest_commit_hash():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception as e:
        raise Exception(f"Cannot get commit hash: {e}")

# -------------------------------------------------------
# 2. Create string to sign
# -------------------------------------------------------
def create_proof_message(repo_url: str, commit_hash: str) -> str:
    return f"{repo_url}|{commit_hash}"

# -------------------------------------------------------
# 3. Sign message with student's private key
# -------------------------------------------------------
def sign_commit(message: str) -> str:
    private_key = load_private_key(STUDENT_PRIVATE_KEY)
    signature = sign_message_rsa_pss(private_key, message.encode())
    return base64.b64encode(signature).decode()

# -------------------------------------------------------
# 4. Encrypt signature with instructor key
# -------------------------------------------------------
def encrypt_signature(signature_b64: str) -> str:
    instructor_key = load_public_key(INSTRUCTOR_PUBLIC_KEY)
    encrypted_bytes = encrypt_with_public_key(instructor_key, signature_b64.encode())
    return base64.b64encode(encrypted_bytes).decode()

# -------------------------------------------------------
# MAIN EXECUTION
# -------------------------------------------------------
if __name__ == "__main__":
    print("\n--- PKI 2FA Commit Proof Generator ---\n")

    repo_url = subprocess.check_output(
        ["git", "config", "--get", "remote.origin.url"], text=True
    ).strip()

    commit_hash = get_latest_commit_hash()

    print("Repo URL:", repo_url)
    print("Commit Hash:", commit_hash)

    message = create_proof_message(repo_url, commit_hash)

    signature_b64 = sign_commit(message)
    encrypted_sig = encrypt_signature(signature_b64)

    print("\n================= SUBMIT THESE =================")
    print("Repo URL:", repo_url)
    print("Commit Hash:", commit_hash)
    print("Encrypted Signature:", encrypted_sig)
    print("================================================\n")
