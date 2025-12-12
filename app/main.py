from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from utils_crypto import decrypt_seed, generate_2fa_code, verify_2fa_code

app = FastAPI()

class SeedRequest(BaseModel):
    encrypted_seed: str

class VerifyRequest(BaseModel):
    code: str

@app.get("/")
def root():
    return {"message": "PKI 2FA student service running"}

@app.post("/decrypt-seed")
def decrypt_seed_endpoint(req: SeedRequest):
    try:
        seed = decrypt_seed(req.encrypted_seed)
        return {"seed": seed}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/generate-2fa")
def generate_endpoint():
    try:
        code = generate_2fa_code()
        return {"code": code}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/verify-2fa")
def verify_endpoint(req: VerifyRequest):
    try:
        result = verify_2fa_code(req.code)
        return {"valid": result}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
