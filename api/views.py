from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.conf import settings
from api.models import MiddlewareKey, UsedNonce

from scripts import generate_keypair 
from .crypto_utils import CryptoHandler, TransactionProcessor
from .downstream_handler import DownstreamServiceManager
import traceback
import time

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
    session_key = None # Initialize session_key to None
    try:
        encrypted_payload = request.data
        
        # Load server's private key
        middleware_key = get_or_create_active_key()
        server_private_key_pem = middleware_key.private_key_pem
        server_private_key = CryptoHandler.load_private_key(server_private_key_pem)
        
        # Decrypt the payload and get session key
        decrypted_payload, session_key = CryptoHandler.decrypt_payload(encrypted_payload, server_private_key)
        print(decrypted_payload)
        # Extract transaction components
        transaction_components = TransactionProcessor.extract_transaction_components(decrypted_payload)

        # Validate target exists (will be handled by downstream manager)
        target_key = transaction_components.get('target')
        if not target_key:
            raise ValueError("Missing target in transaction")

        # Log the forwarding action
        print(f"DEBUG: Processing transaction for target: {target_key}")
        print(f"DEBUG: Transaction components: {transaction_components}")

        # Anti-replay check
        nonce = transaction_components.get('nonce')
        timestamp = transaction_components.get('timestamp')

        if not nonce or not timestamp:
            raise ValueError("Nonce and timestamp are required.")

        # Check if nonce has been used
        if UsedNonce.objects.filter(nonce=nonce).exists():
            raise ValueError("Replay attack detected: nonce already used.")

        # Check if timestamp is recent (e.g., within 5 minutes)
        if time.time() - timestamp > 300:
            raise ValueError("Replay attack detected: timestamp is too old.")
            
        # Verify client's signature
        signature_is_valid = TransactionProcessor.verify_transaction_signature(
            transaction_components['transaction_data'],
            transaction_components['client_signature'], 
            transaction_components['client_public_key']
        )
        
        if signature_is_valid:
            # Record the nonce as used
            UsedNonce.objects.create(nonce=nonce)

            # Forward the validated transaction data to the downstream service
            try:
                # Use the new downstream service manager
                downstream_manager = DownstreamServiceManager()
                response_data, status_code = downstream_manager.route_transaction(transaction_components)
                
            except ValueError as e:
                print(f"Downstream service error: {e}")
                error_response = TransactionProcessor.create_error_response(str(e))
                encrypted_error = CryptoHandler.encrypt_response(error_response, session_key)
                return Response(encrypted_error, status=500)
                
            # Handle error responses from downstream service
            if status_code >= 400:
                encrypted_error = CryptoHandler.encrypt_response(response_data, session_key)
                return Response(encrypted_error, status=status_code)
                
            # Encrypt successful response from the downstream service
            encrypted_response = CryptoHandler.encrypt_response(response_data, session_key)
            
            return Response(encrypted_response)
        else:
            # Create error response and encrypt it
            error_response = TransactionProcessor.create_error_response(
                "Client signature verification failed"
            )
            encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
            
            return Response(encrypted_response, status=400)
            
    except Exception as error:
        print(f"DEBUG: SecureCipher gateway exception: {error}")
        traceback.print_exc()
        # Encrypt the error response if session_key is available
        if session_key:
            error_response = TransactionProcessor.create_error_response(str(error))
            encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
            return Response(encrypted_response, status=500)
        else:
            return Response({"error": "An internal error occurred during decryption"}, status=500)
