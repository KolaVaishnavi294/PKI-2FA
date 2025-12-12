from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from utils_crypto import (
    load_private_key,
    decrypt_seed,
    generate_totp_code,
    verify_totp_code,
)
from pathlib import Path
import base64

app = FastAPI()

SEED_FILE = Path("/data/seed.txt")
PRIVATE_KEY_FILE = Path("/app/student_private.pem")


class OTPRequest(BaseModel):
    encrypted_seed: str


@app.get("/")
def root():
    return {"message": "PKI 2FA student service running"}


@app.post("/store-seed")
def store_seed(req: OTPRequest):
    """Decrypt seed using student's private key and store it."""
    try:
        encrypted_bytes = base64.b64decode(req.encrypted_seed)

        private_key = load_private_key(PRIVATE_KEY_FILE.read_bytes())

        seed = decrypt_seed(encrypted_bytes, private_key)

        SEED_FILE.write_bytes(seed)

        return {"status": "success", "message": "Seed stored securely"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/generate-otp")
def generate_otp():
    """Generate OTP using stored seed."""
    if not SEED_FILE.exists():
        raise HTTPException(status_code=400, detail="Seed not found. Call /store-seed first.")

    seed = SEED_FILE.read_bytes()

    otp = generate_totp_code(seed)

    return {"otp": otp}


@app.post("/verify-otp")
def verify_otp(otp: str):
    """Verify a provided OTP."""
    if not SEED_FILE.exists():
        raise HTTPException(status_code=400, detail="Seed not found.")

    seed = SEED_FILE.read_bytes()

    valid = verify_totp_code(seed, otp)

    return {"valid": valid}
