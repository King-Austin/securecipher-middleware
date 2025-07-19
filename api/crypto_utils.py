from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import base64
import json
import os


class CryptoHandler:
    """Handles all cryptographic operations for the middleware"""
    
    @staticmethod
    def load_private_key(pem_data):
        """Load private key from PEM format"""
        return serialization.load_pem_private_key(pem_data.encode(), password=None)
    
    @staticmethod
    def load_public_key_from_der(der_data):
        """Load public key from DER format"""
        return serialization.load_der_public_key(der_data)
    
    @staticmethod
    def perform_ecdh(private_key, public_key):
        """Perform ECDH key exchange"""
        return private_key.exchange(ec.ECDH(), public_key)

    @staticmethod
    def derive_session_key(shared_secret):
        """Derive session key using HKDF - standardized method for consistency."""
        # Create a new HKDF instance for each derivation (HKDF can only be used once)
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=32,  # AES-256 key
            salt=None,
            info=b'secure-cipher-session-key'
        )
        
        session_key = hkdf.derive(shared_secret)
        print(f"DEBUG: Session key derived via HKDF: {len(session_key)} bytes")
        return session_key
    
    @staticmethod
    def encrypt_aes_gcm(plaintext_bytes, session_key):
        """Encrypt data using AES-GCM - matches frontend encryption"""
        # Generate random IV (nonce)
        iv = os.urandom(12)  # 96-bit IV for GCM
        
        # Create AES-GCM cipher
        aesgcm = AESGCM(session_key)
        
        # Encrypt and get ciphertext with authentication tag
        ciphertext = aesgcm.encrypt(iv, plaintext_bytes, None)
        
        # Return IV and ciphertext (authentication tag is included in ciphertext)
        print(f"DEBUG: AES-GCM encryption - IV: {len(iv)} bytes, Encrypted: {len(ciphertext)} bytes")
        return ciphertext, iv

    @staticmethod
    def decrypt_aes_gcm(encrypted_ciphertext, initialization_vector, session_key):
        """Decrypt AES-GCM encrypted data using cryptography library"""
        # Create AES-GCM cipher
        aesgcm = AESGCM(session_key)
        
        # Decrypt and verify (authentication tag is included in ciphertext)
        decrypted_data = aesgcm.decrypt(initialization_vector, encrypted_ciphertext, None)
        
        return decrypted_data
    
    @staticmethod
    def decrypt_payload(encrypted_payload, private_key):
        """Decrypt incoming payload using ECDH + AES-GCM"""
        # Decode the encrypted payload components
        ephemeral_public_key_spki = base64.b64decode(encrypted_payload["ephemeral_pubkey"])
        encrypted_ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        initialization_vector = base64.b64decode(encrypted_payload["iv"])
        
        # Load client's ephemeral public key
        ephemeral_public_key = CryptoHandler.load_public_key_from_der(ephemeral_public_key_spki)
        
        # Perform ECDH key exchange to derive shared secret
        shared_secret = CryptoHandler.perform_ecdh(private_key, ephemeral_public_key)
        
        # Derive session key from shared secret (standardized method)
        session_key = CryptoHandler.derive_session_key(shared_secret)
        
        # Decrypt the payload
        decrypted_payload_bytes = CryptoHandler.decrypt_aes_gcm(encrypted_ciphertext, initialization_vector, session_key)
        decrypted_payload = json.loads(decrypted_payload_bytes)
        
        return decrypted_payload, session_key
    
    @staticmethod
    def encrypt_response(response_data, session_key):
        """Encrypt response data using the same session key"""
        response_json = json.dumps(response_data, sort_keys=True, separators=(',', ':'))
        response_bytes = response_json.encode('utf-8')
        
        # Encrypt the response
        encrypted_response, iv = CryptoHandler.encrypt_aes_gcm(response_bytes, session_key)
        
        encrypted_payload = {
            "ciphertext": base64.b64encode(encrypted_response).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
        return encrypted_payload

    @staticmethod
    def convert_raw_to_der(raw_signature):
        """Convert Web Crypto API raw ECDSA signature to DER format"""
        if len(raw_signature) != 96:
            raise ValueError("Invalid raw signature length for P-384 (expected 96 bytes)")
        
        r_component = raw_signature[:48]
        s_component = raw_signature[48:]
        
        from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
        
        r_integer = int.from_bytes(r_component, 'big')
        s_integer = int.from_bytes(s_component, 'big')
        
        der_formatted_signature = encode_dss_signature(r_integer, s_integer)
        
        return der_formatted_signature

    @staticmethod
    def verify_signature(client_public_key_pem, transaction_bytes, client_signature_base64):
        """Verify ECDSA signature with automatic format conversion"""
        try:
            client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode())
            client_signature_bytes = base64.b64decode(client_signature_base64)
            
            try:
                client_public_key.verify(client_signature_bytes, transaction_bytes, ec.ECDSA(hashes.SHA384()))
                return True
            except InvalidSignature:
                if len(client_signature_bytes) == 96:
                    try:
                        der_formatted_signature = CryptoHandler.convert_raw_to_der(client_signature_bytes)
                        client_public_key.verify(der_formatted_signature, transaction_bytes, ec.ECDSA(hashes.SHA384()))
                        return True
                    except Exception:
                        return False
                else:
                    return False
            
        except Exception as verification_error:
            print(f"DEBUG: ❌ Signature verification error: {verification_error}")
            return False


class TransactionProcessor:
    """Handles transaction processing and validation - business logic only"""
    
    @staticmethod
    def extract_transaction_components(decrypted_payload):
        """Extracts transaction data, signature, and public key from payload"""
        print(f"DEBUG: Extracting from payload: {decrypted_payload.keys()}")
        
        return {
            'target': decrypted_payload.get("target"),
            'transaction_data': decrypted_payload.get("transaction_data"),
            'url_params': decrypted_payload.get("url_params"),
            'client_signature': decrypted_payload["client_signature"],
            'client_public_key': decrypted_payload["client_public_key"],
            'timestamp': decrypted_payload.get("timestamp"),
            'nonce': decrypted_payload.get("nonce"),
            'auth_token': decrypted_payload.get("auth_token")
        }

    @staticmethod
    def prepare_transaction_for_verification(transaction_data):
        """Prepare transaction data for signature verification - optimized JSON serialization"""
        # Use separators for minimal JSON output (performance optimization)
        transaction_json = json.dumps(transaction_data, sort_keys=True, separators=(',', ':'))
        transaction_bytes = transaction_json.encode('utf-8')
        
        print(f"DEBUG: Transaction JSON for verification: {transaction_json}")
        print(f"DEBUG: Transaction bytes length: {len(transaction_bytes)} bytes")
        
        return transaction_bytes
    
    @staticmethod
    def create_success_response(transaction_data):
        """Create a successful transaction response"""
        return {
            "status": "verified", 
            "message": "Transaction processed successfully",
            "transaction_id": f"tx_{hash(str(transaction_data))}"
        }
    
    @staticmethod
    def create_error_response(error_message):
        """Create an error response"""
        return {
            "status": "error",
            "error": error_message
        }
    
    @staticmethod
    def verify_transaction_signature(transaction_data, client_signature, client_public_key):
        """Verify client's transaction signature - uses consolidated crypto handler"""
        transaction_bytes = TransactionProcessor.prepare_transaction_for_verification(transaction_data)
        
        print(f"DEBUG: User transaction data: {transaction_data}")
        print(f"DEBUG: Client signature: {client_signature[:50]}...")
        print(f"DEBUG: Client public key: {client_public_key[:100]}...")
        
        # Use the centralized crypto handler for consistency
        is_valid = CryptoHandler.verify_signature(client_public_key, transaction_bytes, client_signature)
        
        if is_valid:
            print("DEBUG: ✅ Client signature verified successfully")
        else:
            print("DEBUG: ❌ Client signature verification failed")
        
        return is_valid

    @staticmethod
    def decrypt_response(encrypted_response, session_key):
        """Decrypts server response using the session key - consolidated method"""
        encrypted_ciphertext = base64.b64decode(encrypted_response["ciphertext"])
        initialization_vector = base64.b64decode(encrypted_response["iv"])
        
        try:
            decrypted_response_bytes = CryptoHandler.decrypt_aes_gcm(encrypted_ciphertext, initialization_vector, session_key)
            decrypted_response = json.loads(decrypted_response_bytes)
            
            print(f"DEBUG: ✅ Server response decrypted successfully: {decrypted_response}")
            return decrypted_response
            
        except Exception as error:
            print(f"DEBUG: Failed to decrypt server response: {error}")
            raise error
