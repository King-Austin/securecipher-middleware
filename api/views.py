import os
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
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
import os
import hashlib



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
    session_key = None
    try:
        # --- Step 1: Parse and validate outer envelope ---
        encrypted_payload = request.data
        client_ephemeral_pub_b64 = encrypted_payload.get("ephemeral_pubkey")
        ciphertext_b64 = encrypted_payload.get("ciphertext")
        iv_b64 = encrypted_payload.get("iv")
        if not (client_ephemeral_pub_b64 and ciphertext_b64 and iv_b64):
            raise ValueError("Missing required envelope fields.")

        # --- Step 2: Derive session key using ECDH (P-384, SHA-384, info, salt) ---
        middleware_key = get_or_create_active_key()
        middleware_private_key = serialization.load_pem_private_key(
            middleware_key.private_key_pem.encode(), password=None
        )
        client_ephemeral_pub_der = base64.b64decode(client_ephemeral_pub_b64)
        client_ephemeral_pub = serialization.load_der_public_key(client_ephemeral_pub_der)
        shared_key = middleware_private_key.exchange(ec.ECDH(), client_ephemeral_pub)
        session_key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=b'',
            info=b'secure-cipher-session-key'
        ).derive(shared_key)
        print("DEBUG: Session key derived.")

        # --- Step 3: Decrypt AES-GCM payload ---
        aesgcm = AESGCM(session_key)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
        inner_payload = json.loads(decrypted_bytes.decode())
        print("DEBUG: Payload decrypted.")

        # --- Step 4: Extract and validate inner payload fields ---
        transaction_data = inner_payload.get("transaction_data")
        client_signature = inner_payload.get("client_signature")
        client_public_key_b64 = inner_payload.get("client_public_key")
        timestamp = inner_payload.get("timestamp")
        nonce = inner_payload.get("nonce")

        #---- Check for required fields ---
        if not nonce or not timestamp:
            raise ValueError("Nonce and timestamp are required.")
        if UsedNonce.objects.filter(nonce=nonce).exists():
            raise ValueError("Replay attack detected: nonce already used.")
        if time.time() - timestamp > 300:
            raise ValueError("Replay attack detected: timestamp is too old.")
        UsedNonce.objects.create(nonce=nonce)

        # --- Step 5: Verify client signature ---
        def verify_ecdsa_signature(payload_dict, signature_b64, public_key_b64_or_pem):
            try:
                # Try to load as PEM first
                if "-----BEGIN PUBLIC KEY-----" in public_key_b64_or_pem:
                    public_key = serialization.load_pem_public_key(public_key_b64_or_pem.encode())
                else:
                    # Otherwise, treat as base64 DER
                    public_key_der = base64.b64decode(public_key_b64_or_pem)
                    public_key = serialization.load_der_public_key(public_key_der)
                signature = base64.b64decode(signature_b64)
                print("DEBUG: [VERIFY] Signature (base64):", signature_b64)
                message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
                print("DEBUG: [VERIFY] Canonical JSON to verify:", message.decode())
                hash_hex = hashlib.sha256(message).hexdigest()
                print("DEBUG: [VERIFY] data hash:", hash_hex)
                print("===============================================================")

                print("DEBUG: [VERIFY] Signature (base64):", signature_b64)
                print("===============================================================")
                print("DEBUG: [VERIFY] Public key (PEM or b64):", public_key_b64_or_pem)
                print("===============================================================")
                public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
                return True
            except Exception as e:
                print(f"Signature verification failed: {e}")
                return False

        sign_payload_dict = {
            "transaction_data": transaction_data,
            "timestamp": timestamp,
            "nonce": nonce
        }
        if not verify_ecdsa_signature(sign_payload_dict, client_signature, client_public_key_b64):
            error_response = {"error": "Client signature verification failed"}
            # Encrypt error response
            error_bytes = json.dumps(error_response).encode()
            error_iv = os.urandom(12)
            error_ciphertext = aesgcm.encrypt(error_iv, error_bytes, None)
            encrypted_response = {
                "iv": base64.b64encode(error_iv).decode(),
                "ciphertext": base64.b64encode(error_ciphertext).decode()
            }
            return Response(encrypted_response, status=400)

        # --- Step 6: Add middleware signature/public key ---
        def sign_payload(payload_dict, private_key_pem):
            private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
            message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
            signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
            return base64.b64encode(signature).decode()

        middleware_signature = sign_payload(sign_payload_dict, middleware_key.private_key_pem)
        middleware_public_key_der = base64.b64encode(
            serialization.load_pem_public_key(middleware_key.public_key_pem.encode()).public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()

        forwarded_payload = {
            "transaction_data": transaction_data,
            "client_signature": client_signature,
            "client_public_key": client_public_key_b64,
            "middleware_signature": middleware_signature,
            "middleware_public_key": middleware_public_key_der,
            "timestamp": timestamp,
            "nonce": nonce
        }

        # --- Step 7: Downstream handler (P-384, SHA-384, info, salt, os.urandom IV) ---
        downstream_ephemeral_key = ec.generate_private_key(ec.SECP384R1())
        downstream_ephemeral_public_key = downstream_ephemeral_key.public_key()
        downstream_ephemeral_pub_der = downstream_ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Get bank public key (PEM) and load it
        bank_public_key_pem = DownstreamServiceManager.get_bank_public_key()
        bank_public_key = serialization.load_pem_public_key(bank_public_key_pem.encode())

        # Derive session key for downstream (P-384, SHA-384, info, salt)
        downstream_shared_key = downstream_ephemeral_key.exchange(ec.ECDH(), bank_public_key)
        downstream_session_key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=b'',
            info=b'secure-cipher-session-key'
        ).derive(downstream_shared_key)

        # Encrypt forwarded payload for downstream
        downstream_aesgcm = AESGCM(downstream_session_key)
        downstream_iv = os.urandom(12)
        downstream_ciphertext = downstream_aesgcm.encrypt(
            downstream_iv,
            json.dumps(forwarded_payload, separators=(',', ':'), sort_keys=True).encode(),
            None
        )
        downstream_envelope = {
            "ephemeral_pubkey": base64.b64encode(downstream_ephemeral_pub_der).decode(),
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
            aesgcm = AESGCM(session_key)
            error_bytes = json.dumps(error_response).encode()
            error_iv = os.urandom(12)
            error_ciphertext = aesgcm.encrypt(error_iv, error_bytes, None)
            encrypted_response = {
                "iv": base64.b64encode(error_iv).decode(),
                "ciphertext": base64.b64encode(error_ciphertext).decode()
            }
            return Response(encrypted_response, status=500)
        else:
            return Response({"error": "An internal error occurred during decryption"}, status=500)

def verify_banking_api_signature(payload_dict, signature_b64, bank_public_key_pem):
    """Verify ECDSA signature from banking API over the canonicalized payload dict."""
    public_key = serialization.load_pem_public_key(bank_public_key_pem.encode())
    signature = base64.b64decode(signature_b64)
    message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
    print("DEBUG: [BANK VERIFY] Canonical JSON to verify:", message.decode())
    print("===============================================================")
    print("DEBUG: [BANK VERIFY] Signature (base64):", signature_b64)
    print("===============================================================")

    print("DEBUG: [BANK VERIFY] Public key (PEM):", bank_public_key_pem)
    print("===============================================================")
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"Bank signature verification failed: {e}")
        return False
