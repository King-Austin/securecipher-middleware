from rest_framework.decorators import api_view
from rest_framework.response import Response
from api.models import MiddlewareKey
from scripts import generate_keypair 
from .crypto_utils import CryptoHandler, TransactionHandler
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
        
        # Load server's private key
        middleware_key = get_or_create_active_key()
        server_private_key = CryptoHandler.load_private_key(middleware_key.private_key_pem)
        
        # Decrypt the payload and get session key
        decrypted_payload, session_key = CryptoHandler.decrypt_payload(encrypted_payload, server_private_key)
        print(f"DEBUG: Decrypted payload: {decrypted_payload}")
        
        # Extract transaction components
        transaction_components = TransactionHandler.extract_transaction_components(decrypted_payload)
        
        # Verify client's signature
        signature_is_valid = TransactionHandler.verify_transaction_signature(
            transaction_components['transaction_data'],
            transaction_components['client_signature'], 
            transaction_components['client_public_key']
        )
        
        if signature_is_valid:
            print("DEBUG: ✅ Client signature verification SUCCESS")
            
            # Create success response
            response_data = TransactionHandler.create_success_response(
                transaction_components['transaction_data']
            )
            
            # Encrypt the response using the same session key
            encrypted_response = CryptoHandler.encrypt_response(response_data, session_key)
            
            return Response(encrypted_response)
        else:
            print("DEBUG: ❌ Client signature verification FAILED")
            
            # Create error response and encrypt it
            error_response = TransactionHandler.create_error_response(
                "Client signature verification failed"
            )
            encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
            
            return Response(encrypted_response, status=400)
            
    except Exception as error:
        print(f"DEBUG: SecureCipher gateway exception: {error}")
        traceback.print_exc()
        return Response({"error": str(error)}, status=500)