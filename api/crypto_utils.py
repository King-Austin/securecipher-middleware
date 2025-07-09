from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from crypto_engine.crypto_engine import derive_session_key, decrypt_aes_gcm, verify_signature
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64
import json


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
    def encrypt_aes_gcm(plaintext_bytes, session_key):
        """Encrypt data using AES-GCM - matches frontend encryption"""
        # Generate random IV
        iv = get_random_bytes(12)  # 96-bit IV for GCM
        
        # Create AES-GCM cipher
        aes_gcm_cipher = AES.new(session_key, AES.MODE_GCM, nonce=iv)
        
        # Encrypt and get authentication tag
        ciphertext, auth_tag = aes_gcm_cipher.encrypt_and_digest(plaintext_bytes)
        
        # Combine ciphertext with auth tag (append tag to ciphertext)
        encrypted_data = ciphertext + auth_tag
        
        print(f"DEBUG: AES-GCM encryption - IV: {len(iv)} bytes, Encrypted: {len(encrypted_data)} bytes")
        return encrypted_data, iv
    
    @staticmethod
    def decrypt_payload(encrypted_payload, private_key):
        """Decrypt incoming payload using ECDH + AES-GCM"""
        # Decode the encrypted payload components
        ephemeral_public_key_spki = base64.b64decode(encrypted_payload["ephemeral_pubkey"])
        encrypted_ciphertext = base64.b64decode(encrypted_payload["ciphertext"])
        initialization_vector = base64.b64decode(encrypted_payload["iv"])
        
        print(f"DEBUG: Ephemeral public key length: {len(ephemeral_public_key_spki)} bytes")
        print(f"DEBUG: Encrypted ciphertext length: {len(encrypted_ciphertext)} bytes")
        print(f"DEBUG: IV length: {len(initialization_vector)} bytes")
        
        # Load client's ephemeral public key
        ephemeral_public_key = CryptoHandler.load_public_key_from_der(ephemeral_public_key_spki)
        print("DEBUG: Ephemeral public key loaded successfully")
        
        # Perform ECDH key exchange to derive shared secret
        shared_secret = CryptoHandler.perform_ecdh(private_key, ephemeral_public_key)
        print(f"DEBUG: ECDH shared secret derived, length: {len(shared_secret)} bytes")
        
        # Derive session key from shared secret
        session_key = derive_session_key(shared_secret)
        print(f"DEBUG: Session key derived, length: {len(session_key)} bytes")
        
        # Decrypt the payload
        decrypted_payload_bytes = decrypt_aes_gcm(encrypted_ciphertext, initialization_vector, session_key)
        decrypted_payload = json.loads(decrypted_payload_bytes)
        
        return decrypted_payload, session_key
    
    @staticmethod
    def encrypt_response(response_data, session_key):
        """Encrypt response data using the same session key"""
        response_json = json.dumps(response_data, sort_keys=True, separators=(',', ':'))
        response_bytes = response_json.encode('utf-8')
        
        print(f"DEBUG: Encrypting response: {response_json}")
        
        # Encrypt the response
        encrypted_response, iv = CryptoHandler.encrypt_aes_gcm(response_bytes, session_key)
        
        encrypted_payload = {
            "ciphertext": base64.b64encode(encrypted_response).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
        print("DEBUG: Response encrypted successfully")
        return encrypted_payload


class TransactionHandler:
    """Handles transaction processing and validation"""
    
    @staticmethod
    def prepare_transaction_for_verification(transaction_data):
        """Prepare transaction data for signature verification"""
        transaction_json = json.dumps(transaction_data, sort_keys=True, separators=(',', ':'))
        transaction_bytes = transaction_json.encode('utf-8')
        
        print(f"DEBUG: Transaction JSON for verification: {transaction_json}")
        print(f"DEBUG: Transaction bytes for verification: {list(transaction_bytes)}")
        
        return transaction_bytes
    
    @staticmethod
    def extract_transaction_components(decrypted_payload):
        """Extract transaction components from decrypted payload"""
        return {
            'transaction_data': decrypted_payload["tx"],
            'client_signature': decrypted_payload["sig_p"],
            'client_public_key': decrypted_payload["q_p"]
        }
    
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
        """Verify client's transaction signature"""
        transaction_bytes = TransactionHandler.prepare_transaction_for_verification(transaction_data)
        
        print(f"DEBUG: User transaction data: {transaction_data}")
        print(f"DEBUG: Client signature: {client_signature[:50]}...")
        print(f"DEBUG: Client public key: {client_public_key[:100]}...")
        
        return verify_signature(client_public_key, transaction_bytes, client_signature)


class ClientCryptoHandler:
    """Handles client-side cryptographic operations for response decryption"""
    
    @staticmethod
    def decrypt_server_response(encrypted_response, session_key):
        """
        Decrypt server response using the same session key from ECDH exchange.
        This function can be used by clients to decrypt the server's encrypted response.
        
        Args:
            encrypted_response (dict): Server's encrypted response containing 'ciphertext' and 'iv'
            session_key (bytes): The same session key derived from ECDH exchange
            
        Returns:
            dict: Decrypted response data
        """
        try:
            # Decode the encrypted response components
            encrypted_ciphertext = base64.b64decode(encrypted_response["ciphertext"])
            initialization_vector = base64.b64decode(encrypted_response["iv"])
            
            print(f"DEBUG: Decrypting server response - Ciphertext: {len(encrypted_ciphertext)} bytes, IV: {len(initialization_vector)} bytes")
            
            # Decrypt the response using the same session key
            decrypted_response_bytes = decrypt_aes_gcm(encrypted_ciphertext, initialization_vector, session_key)
            decrypted_response = json.loads(decrypted_response_bytes)
            
            print(f"DEBUG: Server response decrypted successfully: {decrypted_response}")
            return decrypted_response
            
        except Exception as error:
            print(f"DEBUG: Failed to decrypt server response: {error}")
            raise error
