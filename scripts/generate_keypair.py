from api.models import MiddlewareKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

def generate():
    priv = ec.generate_private_key(ec.SECP384R1())
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    MiddlewareKey.objects.create(label="active", private_key_pem=priv_pem, public_key_pem=pub_pem)
    print("[✅] Middleware keypair saved.")
