from app.utils_crypto import generate_rsa_keypair

generate_rsa_keypair("../student_private.pem", "../student_public.pem")
print("Keys generated.")
