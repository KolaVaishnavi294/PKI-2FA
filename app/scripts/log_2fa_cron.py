import sys
import os
from datetime import datetime

sys.path.append("/app")

from utils_crypto import generate_2fa_code

SEED_FILE = "/data/seed.txt"

def main():
    if not os.path.exists(SEED_FILE):
        return

    with open(SEED_FILE, "r") as f:
        seed = f.read().strip()

    code = generate_2fa_code(seed)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} - 2FA Code: {code}")

if __name__ == "__main__":
    main()
