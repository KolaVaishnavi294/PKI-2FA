from datetime import datetime
from pathlib import Path
from utils_crypto import generate_2fa_code

seed_file = Path("/data/seed.txt")

if seed_file.exists():
    seed = seed_file.read_text().strip()
    code = generate_2fa_code(seed)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} - 2FA Code: {code}")
