from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.conf import settings
from api.models import MiddlewareKey, UsedNonce

from scripts import generate_keypair 
from .crypto_utils import CryptoHandler, TransactionProcessor
from .downstream_handler import DownstreamServiceManager
import traceback
import time
import base64
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



def get_or_create_active_key():
    """Get active middleware key or create one if it doesn't exist"""
    try:
        return MiddlewareKey.objects.get(label="active")
    except MiddlewareKey.DoesNotExist:
        print("DEBUG: No active middleware key found, generating new one...")
        generate_keypair.generate()
        return MiddlewareKey.objects.get(label="active")

def verify_ecdsa_signature(payload_dict, signature_b64, public_key_b64):
    """Verify ECDSA signature over the canonicalized payload dict."""
    public_key_der = base64.b64decode(public_key_b64)
    public_key = serialization.load_der_public_key(public_key_der)
    signature = base64.b64decode(signature_b64)
    # Canonicalize payload for signing
    message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def sign_payload(payload_dict, private_key_pem):
    """Sign canonicalized payload dict with middleware private key, return base64 DER."""
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()

ROUTING_TABLE = getattr(settings, 'ROUTING_TABLE', {})

def get_route_from_request(request):
    """Infer route context from request path using ROUTING_TABLE from settings."""
    for key in ROUTING_TABLE:
        if key in request.path:
            return ROUTING_TABLE[key]
    raise ValueError("Unknown route context")

#==============================================================================#
@api_view(["GET"])
def get_public_key(request):
    print("DEBUG: Client requesting server public key...")
    middleware_key = get_or_create_active_key()
    print(f"DEBUG: Server public key retrieved: {middleware_key.public_key_pem[:50]}...")
    return Response({"public_key": middleware_key.public_key_pem})

@api_view(["POST"])
def secure_gateway(request):
    print("DEBUG: SecureCipher gateway called")
    session_key = None
    try:
        # --- Step 1: Parse and validate outer envelope ---
        encrypted_payload = request.data
        client_ephemeral_pub_b64 = encrypted_payload.get("ephemeral_pubkey")
        ciphertext_b64 = encrypted_payload.get("ciphertext")
        iv_b64 = encrypted_payload.get("iv")
        if not (client_ephemeral_pub_b64 and ciphertext_b64 and iv_b64):
            raise ValueError("Missing required envelope fields.")

        # --- Step 2: Derive session key using ECDH ---
        middleware_key = get_or_create_active_key()
        middleware_private_key = CryptoHandler.load_private_key(middleware_key.private_key_pem)
        client_ephemeral_pub_der = base64.b64decode(client_ephemeral_pub_b64)
        client_ephemeral_pub = serialization.load_der_public_key(client_ephemeral_pub_der)
        session_key = CryptoHandler.derive_session_key(middleware_private_key, client_ephemeral_pub)

        # --- Step 3: Decrypt AES-GCM payload ---
        aesgcm = AESGCM(session_key)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
        inner_payload = json.loads(decrypted_bytes.decode())

        # --- Step 4: Extract and validate inner payload fields ---
        transaction_data = inner_payload.get("transaction_data")
        client_signature = inner_payload.get("client_signature")
        client_public_key = inner_payload.get("client_public_key")
        timestamp = inner_payload.get("timestamp")
        nonce = inner_payload.get("nonce")
        if not nonce or not timestamp:
            raise ValueError("Nonce and timestamp are required.")
        if UsedNonce.objects.filter(nonce=nonce).exists():
            raise ValueError("Replay attack detected: nonce already used.")
        if time.time() - timestamp > 300:
            raise ValueError("Replay attack detected: timestamp is too old.")
        UsedNonce.objects.create(nonce=nonce)

        # --- Step 5: Verify client signature ---
        sign_payload_dict = {
            "transaction_data": transaction_data,
            "timestamp": timestamp,
            "nonce": nonce
        }
        if not verify_ecdsa_signature(sign_payload_dict, client_signature, client_public_key):
            error_response = {"error": "Client signature verification failed"}
            encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
            return Response(encrypted_response, status=400)

        # --- Step 6: Add middleware signature/public key ---
        middleware_signature = sign_payload(sign_payload_dict, middleware_key.private_key_pem)
        middleware_public_key_der = middleware_key.public_key_der  # Should be base64 DER
        forwarded_payload = {
            "transaction_data": transaction_data,
            "client_signature": client_signature,
            "client_public_key": client_public_key,
            "middleware_signature": middleware_signature,
            "middleware_public_key": middleware_public_key_der,
            "timestamp": timestamp,
            "nonce": nonce
        }

        # --- Step 7: Encrypt forwarded payload for banking API ---
        downstream_ephemeral_key = CryptoHandler.generate_ephemeral_key()
        bank_public_key_pem = DownstreamServiceManager.get_bank_public_key()
        bank_public_key = serialization.load_pem_public_key(bank_public_key_pem.encode())
        downstream_session_key = CryptoHandler.derive_session_key(
            downstream_ephemeral_key.private_key, 
            bank_public_key
        )
        downstream_aesgcm = AESGCM(downstream_session_key)
        downstream_iv = CryptoHandler.generate_iv()
        downstream_ciphertext = downstream_aesgcm.encrypt(
            downstream_iv, 
            json.dumps(forwarded_payload, separators=(',', ':'), sort_keys=True).encode(), 
            None
        )
        downstream_envelope = {
            "ephemeral_pubkey": base64.b64encode(
                downstream_ephemeral_key.public_key_der
            ).decode(),
            "ciphertext": base64.b64encode(downstream_ciphertext).decode(),
            "iv": base64.b64encode(downstream_iv).decode()
        }

        # --- Step 8: Route to downstream using ROUTING_TABLE from settings ---
        downstream_url = get_route_from_request(request)
        response_data, status_code = DownstreamServiceManager.route_transaction(
            downstream_envelope, downstream_url
        )

        # --- Step 9: Decrypt banking API response and verify signature ---
        if status_code == 200 and isinstance(response_data, dict):
            resp_iv_b64 = response_data.get("iv")
            resp_ciphertext_b64 = response_data.get("ciphertext")
            if resp_iv_b64 and resp_ciphertext_b64:
                resp_iv = base64.b64decode(resp_iv_b64)
                resp_ciphertext = base64.b64decode(resp_ciphertext_b64)
                decrypted_response = downstream_aesgcm.decrypt(resp_iv, resp_ciphertext, None)
                response_payload = json.loads(decrypted_response.decode())

                bank_signature = response_payload.get("bank_signature")
                bank_public_key = response_payload.get("bank_public_key")
                verify_payload_dict = {
                    "transaction_data": response_payload.get("transaction_data"),
                    "middleware_signature": response_payload.get("middleware_signature"),
                    "middleware_public_key": response_payload.get("middleware_public_key"),
                    "timestamp": response_payload.get("timestamp"),
                    "nonce": response_payload.get("nonce")
                }
                if not verify_banking_api_signature(verify_payload_dict, bank_signature, bank_public_key):
                    error_response = {"error": "Banking API signature verification failed"}
                    encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
                    return Response(encrypted_response, status=400)
                # Optionally, re-encrypt the verified response for the client
                encrypted_response = CryptoHandler.encrypt_response(response_payload, session_key)
                return Response(encrypted_response, status=200)

        # --- Step 10: Encrypt response for client (fallback) ---
        encrypted_response = CryptoHandler.encrypt_response(response_data, session_key)
        return Response(encrypted_response, status=status_code)

    except Exception as error:
        print(f"DEBUG: SecureCipher gateway exception: {error}")
        traceback.print_exc()
        if session_key:
            error_response = {"error": str(error)}
            encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
            return Response(encrypted_response, status=500)
        else:
            return Response({"error": "An internal error occurred during decryption"}, status=500)

def verify_banking_api_signature(payload_dict, signature_b64, bank_public_key_pem):
    """Verify ECDSA signature from banking API over the canonicalized payload dict."""
    public_key = serialization.load_pem_public_key(bank_public_key_pem.encode())
    signature = base64.b64decode(signature_b64)
    message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
