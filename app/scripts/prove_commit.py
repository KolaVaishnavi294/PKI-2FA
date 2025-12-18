import subprocess
from utils_crypto import (
    load_private_key,
    load_public_key,
    sign_message_rsa_pss,
    encrypt_with_public_key,
)

STUDENT_PRIVATE_KEY = "app/student_private.pem"
INSTRUCTOR_PUBLIC_KEY = "app/instructor_public.pem"

def get_commit_hash():
    return subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()

if __name__ == "__main__":
    repo_url = subprocess.check_output(
        ["git", "config", "--get", "remote.origin.url"]
    ).decode().strip()

    commit_hash = get_commit_hash()
    message = f"{repo_url}|{commit_hash}".encode()

    priv = load_private_key(STUDENT_PRIVATE_KEY)
    pub = load_public_key(INSTRUCTOR_PUBLIC_KEY)

    signature_b64 = sign_message_rsa_pss(priv, message)

    seed = input("Enter decrypted seed: ").strip()
    encrypted_seed_b64 = encrypt_with_public_key(pub, seed.encode())

    print("\n--- SUBMIT THESE ---")
    print("Repo URL:", repo_url)
    print("Commit Hash:", commit_hash)
    print("Encrypted Signature:", signature_b64)
    print("Encrypted Seed:", encrypted_seed_b64)
