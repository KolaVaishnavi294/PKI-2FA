import subprocess
from pathlib import Path
import base64

from app.utils_crypto import load_private_key, load_public_key, sign_message_rsa_pss, encrypt_with_public_key

def latest_commit_hash():
    out = subprocess.check_output(["git", "log", "-1", "--format=%H"]).decode().strip()
    return out


def main():
    commit = latest_commit_hash()
    print("Commit:", commit)

    priv = load_private_key("../student_private.pem")
    sig = sign_message_rsa_pss(commit, priv)

    pub = load_public_key("../instructor_public.pem")
    encrypted = encrypt_with_public_key(sig, pub)

    b64 = base64.b64encode(encrypted).decode()
    print("Encrypted Signature (single line):")
    print(b64)


if __name__ == "__main__":
    main()
