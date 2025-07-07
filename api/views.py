from rest_framework.decorators import api_view
from rest_framework.response import Response
from api.models import MiddlewareKey
from scripts import generate_keypair 
from crypto_engine.crypto_engine import *
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
import base64
import json
import traceback

def get_or_create_active_key():
    """Get active middleware key or create one if it doesn't exist"""
    try:
        return MiddlewareKey.objects.get(label="active")
    except MiddlewareKey.DoesNotExist:
        print("DEBUG: No active middleware key found, generating new one...")
        generate_keypair.generate()
        return MiddlewareKey.objects.get(label="active")

@api_view(["GET"])
def get_public_key(request):
    print("DEBUG: Client requesting server public key...")
    middleware_key = get_or_create_active_key()
    print(f"DEBUG: Server public key retrieved: {middleware_key.public_key_pem[:50]}...")
    return Response({"public_key": middleware_key.public_key_pem})

@api_view(["POST"])
def secure_gateway(request):
    print("DEBUG: SecureCipher gateway called")
    try:
        encrypted_payload = request.data
        print(f"DEBUG: Received encrypted payload keys: {list(encrypted_payload.keys())}")
        
        # Decode the encrypted payload components
        ephemeral_public_key_spki = base64.b64decode(encrypted_payload["ephemeral_pubkey"])
        encrypted_ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        initialization_vector = base64.b64decode(encrypted_payload["iv"])
        
        print(f"DEBUG: Ephemeral public key length: {len(ephemeral_public_key_spki)} bytes")
        print(f"DEBUG: Encrypted ciphertext length: {len(encrypted_ciphertext)} bytes")
        print(f"DEBUG: IV length: {len(initialization_vector)} bytes")

        # Load server's private key for ECDH
        middleware_key = get_or_create_active_key()
        server_private_key = serialization.load_pem_private_key(middleware_key.private_key_pem.encode(), password=None)
        
        # Load client's ephemeral public key
        ephemeral_public_key = serialization.load_der_public_key(ephemeral_public_key_spki)
        print("DEBUG: Ephemeral public key loaded successfully")
        
        # Perform ECDH key exchange to derive shared secret
        shared_secret = server_private_key.exchange(ec.ECDH(), ephemeral_public_key)
        print(f"DEBUG: ECDH shared secret derived, length: {len(shared_secret)} bytes")
        
        # Derive session key from shared secret
        session_key = derive_session_key(shared_secret)
        print(f"DEBUG: Session key derived, length: {len(session_key)} bytes")
        
        # Decrypt the payload
        decrypted_payload_bytes = decrypt_aes_gcm(encrypted_ciphertext, initialization_vector, session_key)
        decrypted_payload = json.loads(decrypted_payload_bytes)
        
        print(f"DEBUG: Decrypted payload: {decrypted_payload}")
        
        # Extract transaction data and signatures
        user_transaction_data = decrypted_payload["tx"]
        client_signature = decrypted_payload["sig_p"]
        client_public_key_pem = decrypted_payload["q_p"]
        
        print(f"DEBUG: User transaction data: {user_transaction_data}")
        print(f"DEBUG: Client signature: {client_signature[:50]}...")
        print(f"DEBUG: Client public key: {client_public_key_pem[:100]}...")
        
        # Recreate EXACTLY the same JSON as frontend for signature verification
        transaction_json_for_verification = json.dumps(user_transaction_data, sort_keys=True, separators=(',', ':'))
        transaction_bytes_for_verification = transaction_json_for_verification.encode('utf-8')
        
        print(f"DEBUG: Transaction JSON for verification: {transaction_json_for_verification}")
        print(f"DEBUG: Transaction bytes for verification: {list(transaction_bytes_for_verification)}")

        # Verify client's signature
        signature_is_valid = verify_signature(client_public_key_pem, transaction_bytes_for_verification, client_signature)
        
        if signature_is_valid:
            print("DEBUG: ✅ Client signature verification SUCCESS")
            return Response({
                "status": "verified", 
                "message": "Transaction processed successfully",
                "transaction_id": f"tx_{hash(str(user_transaction_data))}"
            })
        else:
            print("DEBUG: ❌ Client signature verification FAILED")
            return Response({"status": "invalid signature", "error": "Client signature verification failed"}, status=400)
            
    except Exception as error:
        print(f"DEBUG: SecureCipher gateway exception: {error}")
        traceback.print_exc()
        return Response({"error": str(error)}, status=500)