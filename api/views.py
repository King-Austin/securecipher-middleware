from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.models import User
from api.models import MiddlewareKey, UsedNonce
from scripts import generate_keypair 
from .crypto_utils import CryptoHandler, TransactionHandler
import traceback
import time
import requests
import hashlib

# Define the routing table for downstream services
ROUTING_TABLE = {
    # Auth
    'register': {'url': 'http://localhost:8001/api/auth/register/', 'method': 'POST'},
    'login': {'url': 'http://localhost:8001/api/auth/login/', 'method': 'POST'},
    'logout': {'url': 'http://localhost:8001/api/auth/logout/', 'method': 'POST'},
    'set_pin': {'url': 'http://localhost:8001/api/auth/set_pin/', 'method': 'POST'},
    'verify_pin': {'url': 'http://localhost:8001/api/auth/verify_pin/', 'method': 'POST'},

    # User Profile
    'get_profile': {'url': 'http://localhost:8001/api/user/profile/', 'method': 'GET'},
    'update_profile': {'url': 'http://localhost:8001/api/user/update_profile/', 'method': 'PUT'},
    'change_password': {'url': 'http://localhost:8001/api/user/change_password/', 'method': 'POST'},

    # Bank Accounts
    'list_accounts': {'url': 'http://localhost:8001/api/accounts/', 'method': 'GET'},
    'get_account': {'url': 'http://localhost:8001/api/accounts/{account_id}/', 'method': 'GET'},
    'get_account_transactions': {'url': 'http://localhost:8001/api/accounts/{account_id}/transactions/', 'method': 'GET'},
    'get_account_balance': {'url': 'http://localhost:8001/api/accounts/{account_id}/balance/', 'method': 'GET'},

    # Transactions
    'list_transactions': {'url': 'http://localhost:8001/api/transactions/', 'method': 'GET'},
    'get_transaction': {'url': 'http://localhost:8001/api/transactions/{transaction_id}/', 'method': 'GET'},
    'transfer': {'url': 'http://localhost:8001/api/transactions/transfer/', 'method': 'POST'},

    # Beneficiaries
    'list_beneficiaries': {'url': 'http://localhost:8001/api/beneficiaries/', 'method': 'GET'},
    'add_beneficiary': {'url': 'http://localhost:8001/api/beneficiaries/', 'method': 'POST'},
    'get_beneficiary': {'url': 'http://localhost:8001/api/beneficiaries/{beneficiary_id}/', 'method': 'GET'},
    'update_beneficiary': {'url': 'http://localhost:8001/api/beneficiaries/{beneficiary_id}/', 'method': 'PUT'},
    'delete_beneficiary': {'url': 'http://localhost:8001/api/beneficiaries/{beneficiary_id}/', 'method': 'DELETE'},

    # Cards
    'list_cards': {'url': 'http://localhost:8001/api/cards/', 'method': 'GET'},
    'add_card': {'url': 'http://localhost:8001/api/cards/', 'method': 'POST'},
    'get_card': {'url': 'http://localhost:8001/api/cards/{card_id}/', 'method': 'GET'},
    'update_card': {'url': 'http://localhost:8001/api/cards/{card_id}/', 'method': 'PUT'},
    'delete_card': {'url': 'http://localhost:8001/api/cards/{card_id}/', 'method': 'DELETE'},
}

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
        server_private_key = CryptoHandler.load_private_key(middleware_key.private_key_pem)
        
        # Decrypt the payload and get session key
        decrypted_payload, session_key = CryptoHandler.decrypt_payload(encrypted_payload, server_private_key)
        
        # Extract transaction components
        transaction_components = TransactionHandler.extract_transaction_components(decrypted_payload)

        # Get the target route details
        target_key = transaction_components.get('target')
        if not target_key or target_key not in ROUTING_TABLE:
            raise ValueError(f"Invalid or missing target: {target_key}")
        
        route_info = ROUTING_TABLE[target_key]
        downstream_url = route_info['url']
        http_method = route_info['method']

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
        signature_is_valid = TransactionHandler.verify_transaction_signature(
            transaction_components['transaction_data'],
            transaction_components['client_signature'], 
            transaction_components['client_public_key']
        )
        
        if signature_is_valid:
            # Record the nonce as used
            UsedNonce.objects.create(nonce=nonce)

            # --- MOCKING LOGIC ---
            # If the target has a mock response, return it instead of making a real request.
            if target_key in MOCK_RESPONSES:
                print(f"DEBUG: Using mock response for target: {target_key}")
                mock_response_data = MOCK_RESPONSES[target_key]
                encrypted_response = CryptoHandler.encrypt_response(mock_response_data, session_key)
                return Response(encrypted_response)
            # --- END MOCKING LOGIC ---

            # Forward the validated transaction data to the downstream service
            try:
                # Replace placeholders in URL if any, ensuring url_params is a dict
                url_params = transaction_components.get('url_params') or {}
                formatted_url = downstream_url.format(**url_params)

                downstream_response = requests.request(
                    method=http_method,
                    url=formatted_url, 
                    json=transaction_components.get('transaction_data'),
                    headers={'Content-Type': 'application/json'},
                    timeout=10 # 10-second timeout
                )
                downstream_response.raise_for_status() # Raise an exception for bad status codes
                response_data = downstream_response.json()

            except requests.exceptions.RequestException as e:
                print(f"Downstream service error: {e}")
                raise ValueError("Failed to communicate with the downstream service.")

            # Encrypt the response from the downstream service
            encrypted_response = CryptoHandler.encrypt_response(response_data, session_key)
            
            return Response(encrypted_response)
        else:
            # Create error response and encrypt it
            error_response = TransactionHandler.create_error_response(
                "Client signature verification failed"
            )
            encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
            
            return Response(encrypted_response, status=400)
            
    except Exception as error:
        print(f"DEBUG: SecureCipher gateway exception: {error}")
        traceback.print_exc()
        # Encrypt the error response if session_key is available
        if 'session_key' in locals():
            error_response = TransactionHandler.create_error_response(str(error))
            encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
            return Response(encrypted_response, status=500)
        else:
            return Response({"error": "An internal error occurred during decryption"}, status=500)

# New view for cryptographic login
@api_view(['POST'])
def crypto_login(request):
    """
    Authenticates a user based on a signed challenge.
    If successful, returns JWT access and refresh tokens.
    """
    session_key = None
    try:
        encrypted_payload = request.data
        
        # Load server's private key
        middleware_key = get_or_create_active_key()
        server_private_key = CryptoHandler.load_private_key(middleware_key.private_key_pem)
        
        # Decrypt the payload and get session key
        decrypted_payload, session_key = CryptoHandler.decrypt_payload(encrypted_payload, server_private_key)

        # Extract components
        client_public_key_pem = decrypted_payload.get('public_key')
        challenge = decrypted_payload.get('challenge')
        signature_hex = decrypted_payload.get('signature')

        if not all([client_public_key_pem, challenge, signature_hex]):
            return Response({"error": "Missing required fields for authentication."}, status=400)

        # For this example, we'll use the public key's SHA256 hash as the username.
        # This ensures a unique, deterministic username for each key.
        username = hashlib.sha256(client_public_key_pem.encode()).hexdigest()

        # Verify the signature of the challenge
        is_valid = CryptoHandler.verify_signature(
            challenge.encode(), 
            bytes.fromhex(signature_hex), 
            CryptoHandler.load_public_key(client_public_key_pem)
        )

        if not is_valid:
            return Response({"error": "Invalid signature."}, status=401)

        # If the signature is valid, get or create the user
        # In a real app, you'd also store the public key linked to the user profile.
        user, created = User.objects.get_or_create(username=username)
        if created:
            # You might want to set other user properties here
            user.save()

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        
        return Response({
            'refresh': str(refresh),
            'access': str(refresh.access_token),
            'username': user.username, # Return username for frontend use
        })

    except Exception as e:
        traceback.print_exc()
        error_message = f"An error occurred during login: {str(e)}"
        # If we have a session key, encrypt the error response
        if session_key:
            encrypted_error = CryptoHandler.encrypt_response({"error": error_message}, session_key)
            return Response(encrypted_error, status=500)
        # Otherwise, return a generic plaintext error
        return Response({"error": "An internal error occurred during decryption"}, status=500)


MOCK_RESPONSES = {
    'register': {"status": "success", "user_id": 123, "message": "User registered successfully (mocked)."},
    'login': {"status": "success", "token": "mock_jwt_token_12345", "message": "Login successful (mocked)."},
    'get_profile': {"username": "mock_user", "email": "mock@example.com", "last_login": "2025-07-09T12:00:00Z"},
    'list_accounts': [{"id": 1, "account_number": "123456789", "balance": "1000.00"}, {"id": 2, "account_number": "987654321", "balance": "5000.00"}],
    'transfer': {"status": "success", "transaction_id": "txn_mock_987", "message": "Transfer completed (mocked)."}
}