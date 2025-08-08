import os
import base64
import json
import hashlib
import traceback
import time

from rest_framework.decorators import api_view
from rest_framework.response import Response
from django.conf import settings

from api.models import MiddlewareKey, UsedNonce
from scripts import generate_keypair
from .crypto_utils import CryptoHandler
from .downstream_handler import (
    send_downstream_request,
    get_bank_public_key,
    get_target_url
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature


def get_or_create_active_key():
    """Get active middleware key or create one if it doesn't exist"""
    try:
        return MiddlewareKey.objects.get(label="active")
    except MiddlewareKey.DoesNotExist:
        print("DEBUG: No active middleware key found, generating new one...")
        generate_keypair.generate()
        return MiddlewareKey.objects.get(label="active")


def verify_signature(payload_dict, signature_b64, public_key_str):
    """
    Unified ECDSA signature verification for both PEM and DER/BASE64 public keys.
    """
    try:
        # Load public key (PEM or DER/BASE64)
        if "-----BEGIN PUBLIC KEY-----" in public_key_str:
            public_key = serialization.load_pem_public_key(public_key_str.encode())
        else:
            public_key = serialization.load_der_public_key(base64.b64decode(public_key_str))

        # Canonical JSON encoding
        message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
        signature_bytes = base64.b64decode(signature_b64)

        # If signature is raw (r||s), convert to DER
        if len(signature_bytes) == 96:
            r = int.from_bytes(signature_bytes[:48], byteorder='big')
            s = int.from_bytes(signature_bytes[48:], byteorder='big')
            signature_bytes = encode_dss_signature(r, s)

        public_key.verify(signature_bytes, message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception as e:
        print(f"DEBUG: Signature verification failed: {e}")
        return False


def sign_payload(payload_dict, private_key_pem:str):
    private_key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    message = json.dumps(payload_dict, separators=(',', ':'), sort_keys=True).encode()
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()



@api_view(["GET"])
def get_public_key(request):
    print("DEBUG: Client requesting server public key...")
    middleware_key = get_or_create_active_key()
    print(f"DEBUG: Server public key retrieved: {middleware_key.public_key_pem[:50]}...")
    return Response({"public_key": middleware_key.public_key_pem})


@api_view(["POST"])
def secure_gateway(request):
    print("DEBUG: [STEP 0] SecureCipher gateway called")
    session_key = None
    try:
        # --- Step 1: Parse and validate outer envelope ---
        print("DEBUG: [STEP 1] Parsing and validating outer envelope...")
        encrypted_payload = request.data
        print(f"DEBUG: [STEP 1] Incoming payload: {encrypted_payload}")
        client_ephemeral_pub_b64 = encrypted_payload.get("ephemeral_pubkey")
        ciphertext_b64 = encrypted_payload.get("ciphertext")
        iv_b64 = encrypted_payload.get("iv")
        if not (client_ephemeral_pub_b64 and ciphertext_b64 and iv_b64):
            print("DEBUG: [STEP 1] Missing required envelope fields.")
            raise ValueError("Missing required envelope fields.")

        # --- Step 2: Derive session key using ECDH ---
        print("DEBUG: [STEP 2] Deriving session key using ECDH...")
        middleware_key = get_or_create_active_key()
        print(f"DEBUG: [STEP 2] Middleware key loaded: {middleware_key}")
        middleware_private_key = serialization.load_pem_private_key(
            middleware_key.private_key_pem.encode(), password=None
        )
        client_ephemeral_pub_der = base64.b64decode(client_ephemeral_pub_b64)
        print(f"DEBUG: [STEP 2] Client ephemeral pubkey DER: {client_ephemeral_pub_der.hex()}")
        client_ephemeral_pub = serialization.load_der_public_key(client_ephemeral_pub_der)
        shared_key = middleware_private_key.exchange(ec.ECDH(), client_ephemeral_pub)
        print(f"DEBUG: [STEP 2] Shared key: {shared_key.hex()}")
        session_key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=b'',
            info=b'secure-cipher-session-key'
        ).derive(shared_key)
        print(f"DEBUG: [STEP 2] Session key derived: {session_key.hex()}")

        # --- Step 3: Decrypt AES-GCM payload ---
        print("DEBUG: [STEP 3] Decrypting AES-GCM payload...")
        aesgcm = AESGCM(session_key)
        iv = base64.b64decode(iv_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
        print(f"DEBUG: [STEP 3] IV in Hex: {iv.hex()},\n Ciphertext in Hex: {ciphertext.hex()}")
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext, None)
        print(f"DEBUG: [STEP 3] Decrypted bytes: {decrypted_bytes}")
        inner_payload = json.loads(decrypted_bytes.decode())
        print(f"DEBUG: [STEP 3] Inner payload: {inner_payload}")

        # --- Step 4: Extract and validate inner payload fields ---
        print("DEBUG: [STEP 4] Extracting and validating inner payload fields...")
        target_url = inner_payload.get("target")
        transaction_data = inner_payload.get("transaction_data")
        client_signature = inner_payload.get("client_signature")
        client_public_key_b64 = inner_payload.get("client_public_key")
        nonce = inner_payload.get("nonce")
        print(f"DEBUG: [STEP 4] target_url: {target_url}, nonce: {nonce}")

        if not nonce:
            print("DEBUG: [STEP 4] Nonce is missing!")
            raise ValueError("Nonce is required.")
        if UsedNonce.objects.filter(nonce=nonce).exists():
            print("DEBUG: [STEP 4] Replay attack detected: nonce already used.")
            raise ValueError("Replay attack detected: nonce already used.")
        UsedNonce.objects.create(nonce=nonce)
        print("DEBUG: [STEP 4] Nonce stored.")

        # --- Step 5: Verify client signature ---
        print("DEBUG: [STEP 5] Verifying client signature...")
        sign_payload_dict = {
            "transaction_data": transaction_data,
        }
        if not verify_signature(sign_payload_dict, client_signature, client_public_key_b64):
            print("DEBUG: [STEP 5] Client signature verification failed.")
            error_response = {"error": "Client signature verification failed"}
            error_bytes = json.dumps(error_response).encode()
            error_iv = os.urandom(12)
            error_ciphertext = aesgcm.encrypt(error_iv, error_bytes, None)
            encrypted_response = {
                "iv": base64.b64encode(error_iv).decode(),
                "ciphertext": base64.b64encode(error_ciphertext).decode()
            }
            return Response(encrypted_response, status=400)
        
        
        print("DEBUG: [STEP 5] Client signature verified.")

        # --- Step 6: Add middleware signature/public key ---
        print("DEBUG: [STEP 6] Adding middleware signature and public key...")
        forwarded_payload = {
            "transaction_data": transaction_data,
            "client_signature": client_signature,
            "client_public_key": client_public_key_b64,
            "nonce": nonce
        }
        middleware_signature = sign_payload(forwarded_payload, middleware_key.private_key_pem)
        print(f"DEBUG: [STEP 6] Middleware signature: {middleware_signature}")
        middleware_public_key_der = base64.b64encode(
            serialization.load_pem_public_key(middleware_key.public_key_pem.encode()).public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode()
        print(f"DEBUG: [STEP 6] Middleware public key DER: {middleware_public_key_der}")

        forwarded_payload["middleware_signature"] = middleware_signature
        forwarded_payload["middleware_public_key"] = middleware_public_key_der

        # --- Step 7: Downstream handler ---
        print("DEBUG: [STEP 7] Preparing downstream envelope...")
        downstream_ephemeral_key = ec.generate_private_key(ec.SECP384R1())
        downstream_ephemeral_public_key = downstream_ephemeral_key.public_key()
        downstream_ephemeral_pub_der = downstream_ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"DEBUG: [STEP 7] Downstream ephemeral pubkey DER: {downstream_ephemeral_pub_der.hex()}")

        bank_public_key_pem = get_bank_public_key()
        print(f"DEBUG: [STEP 7] Bank public key PEM: {bank_public_key_pem[:50]}...")
        bank_public_key = serialization.load_pem_public_key(bank_public_key_pem.encode())

        downstream_shared_key = downstream_ephemeral_key.exchange(ec.ECDH(), bank_public_key)
        print(f"DEBUG: [STEP 7] Downstream shared key: {downstream_shared_key.hex()}")
        downstream_session_key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=b'',
            info=b'secure-cipher-session-key'
        ).derive(downstream_shared_key)
        print(f"DEBUG: [STEP 7] Downstream session key: {downstream_session_key.hex()}")

        downstream_aesgcm = AESGCM(downstream_session_key)
        downstream_iv = os.urandom(12)
        print(f"DEBUG: [STEP 7] Downstream IV: {downstream_iv.hex()}")
        downstream_ciphertext = downstream_aesgcm.encrypt(
            downstream_iv,
            json.dumps(forwarded_payload, separators=(',', ':'), sort_keys=True).encode(),
            None
        )
        print(f"DEBUG: [STEP 7] Downstream ciphertext: {downstream_ciphertext.hex()}")
        downstream_envelope = {
            "ephemeral_pubkey": base64.b64encode(downstream_ephemeral_pub_der).decode(),
            "ciphertext": base64.b64encode(downstream_ciphertext).decode(),
            "iv": base64.b64encode(downstream_iv).decode()
        }
        print(f"DEBUG: [STEP 7] Downstream envelope: {downstream_envelope}")

        # --- Step 8: Route to downstream ---
        print("DEBUG: [STEP 8] Routing to downstream...")
        downstream_url = get_target_url(target_url)
        print(f"DEBUG: [STEP 8] Downstream URL: {downstream_url}")
        response_data, status_code = send_downstream_request(
            "POST", downstream_url, data=downstream_envelope
        )
        print(f"DEBUG: [STEP 8] Downstream response: {response_data}, status: {status_code}")

        # --- Step 9: Decrypt banking API response and verify signature ---
        print("DEBUG: [STEP 9] Decrypting and verifying banking API response...")
        if status_code == 200 and isinstance(response_data, dict):
            resp_iv_b64 = response_data.get("iv")
            resp_ciphertext_b64 = response_data.get("ciphertext")
            if resp_iv_b64 and resp_ciphertext_b64:
                resp_iv = base64.b64decode(resp_iv_b64)
                resp_ciphertext = base64.b64decode(resp_ciphertext_b64)
                print(f"DEBUG: [STEP 9] Response IV: {resp_iv.hex()}, Ciphertext: {resp_ciphertext.hex()}")
                decrypted_response = downstream_aesgcm.decrypt(resp_iv, resp_ciphertext, None)
                print(f"DEBUG: [STEP 9] Decrypted response: {decrypted_response}")
                response_payload = json.loads(decrypted_response.decode())
                print(f"DEBUG: [STEP 9] Response payload: {response_payload}")

                bank_signature = response_payload.get("bank_signature")
                bank_public_key = response_payload.get("bank_public_key")
                verify_payload_dict = {
                    "transaction_data": response_payload.get("transaction_data"),
                    "middleware_signature": response_payload.get("middleware_signature"),
                    "middleware_public_key": response_payload.get("middleware_public_key"),
                    "timestamp": response_payload.get("timestamp"),
                    "nonce": response_payload.get("nonce")
                }
                print(f"DEBUG: [STEP 9] Verifying banking API signature...")
                if not verify_signature(verify_payload_dict, bank_signature, bank_public_key):
                    print("DEBUG: [STEP 9] Banking API signature verification failed.")
                    error_response = {"error": "Banking API signature verification failed"}
                    encrypted_response = CryptoHandler.encrypt_response(error_response, session_key)
                    return Response(encrypted_response, status=400)
                print("DEBUG: [STEP 9] Banking API signature verified.")
                encrypted_response = CryptoHandler.encrypt_response(response_payload, session_key)
                print("DEBUG: [STEP 9] Encrypted response for client ready.")
                return Response(encrypted_response, status=200)

        # --- Step 10: Encrypt response for client (fallback) ---
        print("DEBUG: [STEP 10] Encrypting fallback response for client...")
        encrypted_response = CryptoHandler.encrypt_response(response_data, session_key)
        print("DEBUG: [STEP 10] Encrypted fallback response ready.")
        return Response(encrypted_response, status=status_code)

    except Exception as error:
        print(f"DEBUG: [EXCEPTION] SecureCipher gateway exception: {error}")
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
            print("DEBUG: [EXCEPTION] Encrypted error response ready.")
            return Response(encrypted_response, status=500)
        else:
            print("DEBUG: [EXCEPTION] No session key, returning plain error.")
            return Response({"error": "An internal error occurred during decryption"}, status=500)
