import requests
from pathlib import Path

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws/"

STUDENT_ID = "23A91A6126"
GITHUB_REPO_URL = "https://github.com/KolaVaishnavi294/PKI-2FA.git"


def main():
    pubkey = Path("../student_public.pem").read_text()
    payload = {
        "student_id": STUDENT_ID,
        "github_repo_url": GITHUB_REPO_URL,
        "public_key": pubkey
    }

    r = requests.post(API_URL, json=payload)
    j = r.json()

    if j.get("status") != "success":
        print("Error:", j)
        return

    Path("../encrypted_seed.txt").write_text(j["encrypted_seed"])
    print("Saved encrypted_seed.txt")


if __name__ == "__main__":
    main()
