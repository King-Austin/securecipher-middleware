from rest_framework.decorators import api_view
from rest_framework.response import Response
from api.models import MiddlewareKey
from scripts import generate_keypair 
from crypto_engine.crypto_engine import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def get_or_create_active_key():
    """Get active key or create one if it doesn't exist"""
    try:
        return MiddlewareKey.objects.get(label="active")
    except MiddlewareKey.DoesNotExist:
        generate_keypair.generate()
        return MiddlewareKey.objects.get(label="active")

@api_view(["GET"])
def get_public_key(request):
    key = get_or_create_active_key()
    return Response({"public_key": key.public_key_pem})

@api_view(["POST"])
def secure_gateway(request):
    try:
        payload = request.data
        eph_pem = base64.b64decode(payload["ephemeral_pubkey"])
        ciphertext = base64.b64decode(payload["ciphertext"])
        iv = base64.b64decode(payload["iv"])

        key = get_or_create_active_key()
        private_key = serialization.load_pem_private_key(key.private_key_pem.encode(), password=None)
        eph_pubkey = serialization.load_pem_public_key(eph_pem)
        shared_secret = private_key.exchange(ec.ECDH(), eph_pubkey)
        session_key = derive_session_key(shared_secret)
        decrypted = decrypt_aes_gcm(ciphertext, iv, session_key)
        data = json.loads(decrypted)
        tx = json.dumps(data["tx"]).encode()

        if verify_signature(data["q_p"], tx, data["sig_p"]):
            return Response({"status": "verified"})
        else:
            return Response({"status": "invalid signature"}, status=400)
    except Exception as e:
        return Response({"error": str(e)}, status=500)
