from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from pathlib import Path
import time

from app.utils_crypto import load_private_key, decrypt_seed, generate_totp_code, verify_totp_code

DATA_DIR = Path("/data")
SEED_FILE = DATA_DIR / "seed.txt"
PRIVATE_KEY_FILE = Path("/app/student_private.pem")

app = FastAPI()


class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: str


@app.post("/decrypt-seed")
async def decrypt_seed_endpoint(req: DecryptRequest):
    try:
        private_key = load_private_key(PRIVATE_KEY_FILE)
        seed = decrypt_seed(req.encrypted_seed, private_key)
    except Exception as e:
        raise HTTPException(500, f"Decryption failed: {e}")

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SEED_FILE.write_text(seed)

    return {"status": "ok"}


@app.get("/generate-2fa")
async def generate_2fa():
    if not SEED_FILE.exists():
        raise HTTPException(500, "Seed not decrypted yet")

    seed = SEED_FILE.read_text().strip()
    code = generate_totp_code(seed)
    valid_for = 30 - (int(time.time()) % 30)

    return {"code": code, "valid_for": valid_for}


@app.post("/verify-2fa")
async def verify_2fa(req: VerifyRequest):
    if not req.code:
        raise HTTPException(400, "Missing code")
    if not SEED_FILE.exists():
        raise HTTPException(500, "Seed not decrypted yet")

    seed = SEED_FILE.read_text().strip()
    valid = verify_totp_code(seed, req.code, valid_window=1)
    return {"valid": bool(valid)}
