import base64
import subprocess
from app.utils_crypto import (
    load_private_key,
    load_public_key,
    sign_message_rsa_pss,
    encrypt_with_public_key
)

# ---------------------------------------
# Paths to keys inside your project
# ---------------------------------------
STUDENT_PRIVATE_KEY = "app/student_private.pem"
INSTRUCTOR_PUBLIC_KEY = "app/instructor_public.pem"


# ---------------------------------------
# Get latest Git commit hash
# ---------------------------------------
def get_commit_hash() -> str:
    return (
        subprocess.check_output(["git", "rev-parse", "HEAD"])
        .decode()
        .strip()
    )


# ---------------------------------------
# Sign commit message
# ---------------------------------------
def sign_commit(message: str) -> str:
    """Sign commit using student's private key. Returns base64 signature."""
    private_key = load_private_key(STUDENT_PRIVATE_KEY)

    # message must be bytes
    signature_b64 = sign_message_rsa_pss(private_key, message.encode())

    return signature_b64   # already base64 string


# ---------------------------------------
# Encrypt seed with instructor public key
# ---------------------------------------
def encrypt_seed(seed: str) -> str:
    instructor_pub = load_public_key(INSTRUCTOR_PUBLIC_KEY)

    encrypted_b64 = encrypt_with_public_key(instructor_pub, seed.encode())

    return encrypted_b64   # already base64


# ---------------------------------------
# Main execution
# ---------------------------------------
if __name__ == "__main__":
    print("\n--- PKI 2FA Commit Proof Generator ---\n")

    repo_url = (
        subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"]
        ).decode().strip()
    )

    commit_hash = get_commit_hash()

    print(f"Repo URL: {repo_url}")
    print(f"Commit Hash: {commit_hash}")

    # Message to sign
    message = f"{repo_url}|{commit_hash}"

    # Generate encrypted signature
    signature_b64 = sign_commit(message)

    # Ask student for decrypted seed
    seed = input("Enter decrypted seed: ").strip()

    # Encrypt seed for instructor
    encrypted_seed_b64 = encrypt_seed(seed)

    print("\n--- OUTPUT ---")
    print(f"Repo URL: {repo_url}")
    print(f"Commit Hash: {commit_hash}")
    print(f"Encrypted Signature: {signature_b64}")
    print(f"Encrypted Seed: {encrypted_seed_b64}")

    print("\nSubmit these four values in LMS.\n")
