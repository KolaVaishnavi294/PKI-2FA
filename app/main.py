from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from utils_crypto import decrypt_seed, generate_2fa_code, verify_2fa_code
from pathlib import Path

app = FastAPI()
SEED_FILE = Path("/data/seed.txt")

class SeedRequest(BaseModel):
    encrypted_seed: str

class VerifyRequest(BaseModel):
    code: str

@app.get("/")
def root():
    return {"message": "PKI 2FA student service running"}

# -----------------------------
# Decrypt seed & persist
# -----------------------------
@app.post("/decrypt-seed")
def decrypt_seed_endpoint(req: SeedRequest):
    try:
        seed = decrypt_seed(req.encrypted_seed)
        SEED_FILE.parent.mkdir(parents=True, exist_ok=True)
        SEED_FILE.write_text(seed)
        return {"status": "seed stored"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

def _load_seed():
    if not SEED_FILE.exists():
        raise HTTPException(status_code=400, detail="Seed not initialized")
    return SEED_FILE.read_text().strip()

# -----------------------------
# Generate 2FA
# -----------------------------
@app.get("/generate-2fa")
def generate():
    seed = _load_seed()
    return {"code": generate_2fa_code(seed)}

# -----------------------------
# Verify 2FA
# -----------------------------
@app.post("/verify-2fa")
def verify(req: VerifyRequest):
    seed = _load_seed()
    return {"valid": verify_2fa_code(seed, req.code)}
