from Crypto.Cipher import AES
from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA384
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
import base64, json

def base64_decode(base64_data): 
    return base64.b64decode(base64_data)

def derive_session_key(shared_secret):
    """Derive session key from ECDH shared secret - matches frontend derivation"""
    # Use first 32 bytes of shared secret for AES-256 key
    session_key = shared_secret[:32]
    print(f"DEBUG: Session key derived from shared secret: {len(session_key)} bytes")
    return session_key

def decrypt_aes_gcm(encrypted_ciphertext, initialization_vector, session_key):
    """Decrypt AES-GCM encrypted data using PyCryptodome"""
    # Separate authentication tag from ciphertext
    authentication_tag = encrypted_ciphertext[-16:]  # Last 16 bytes are the auth tag
    actual_ciphertext = encrypted_ciphertext[:-16]  # Everything except last 16 bytes
    
    print(f"DEBUG: Separating auth tag: {len(authentication_tag)} bytes")
    print(f"DEBUG: Actual ciphertext: {len(actual_ciphertext)} bytes")
    
    # Create AES-GCM cipher
    aes_gcm_cipher = AES.new(session_key, AES.MODE_GCM, nonce=initialization_vector)
    
    # Decrypt and verify authentication tag
    decrypted_data = aes_gcm_cipher.decrypt_and_verify(actual_ciphertext, authentication_tag)
    
    print(f"DEBUG: Decryption successful: {len(decrypted_data)} bytes")
    return decrypted_data

def verify_signature(client_public_key_pem, transaction_bytes, client_signature_base64):
    """Verify ECDSA signature with automatic format conversion"""
    try:
        print(f"DEBUG: === CLIENT SIGNATURE VERIFICATION START ===")
        print(f"DEBUG: Client public key (first 100 chars): {client_public_key_pem[:100]}...")
        print(f"DEBUG: Client signature (first 50 chars): {client_signature_base64[:50]}...")
        print(f"DEBUG: Transaction data to verify: {transaction_bytes}")
        print(f"DEBUG: Transaction data length: {len(transaction_bytes)} bytes")
        
        # Load client's public key
        client_public_key = serialization.load_pem_public_key(client_public_key_pem.encode())
        print(f"DEBUG: ✅ Client public key loaded successfully")
        
        # Decode client's signature
        client_signature_bytes = base64.b64decode(client_signature_base64)
        print(f"DEBUG: Client signature decoded, length: {len(client_signature_bytes)} bytes")
        
        # Try different signature formats
        try:
            # Try DER format first (standard server format)
            client_public_key.verify(client_signature_bytes, transaction_bytes, ec.ECDSA(hashes.SHA384()))
            print("DEBUG: ✅ DER format signature verification SUCCESS")
            return True
        except InvalidSignature:
            print("DEBUG: ⚠️ DER format verification failed, trying Web Crypto API raw format...")
            
            # Try raw format (Web Crypto API format - 96 bytes for P-384)
            if len(client_signature_bytes) == 96:
                print("DEBUG: Converting Web Crypto API raw signature to DER format...")
                try:
                    der_formatted_signature = convert_raw_to_der(client_signature_bytes)
                    print(f"DEBUG: Converted to DER format, length: {len(der_formatted_signature)} bytes")
                    
                    client_public_key.verify(der_formatted_signature, transaction_bytes, ec.ECDSA(hashes.SHA384()))
                    print("DEBUG: ✅ Raw format signature verification SUCCESS")
                    return True
                except Exception as conversion_error:
                    print(f"DEBUG: ❌ Raw signature conversion failed: {conversion_error}")
                    return False
            else:
                print(f"DEBUG: ❌ Invalid signature length: {len(client_signature_bytes)} bytes (expected 96 for P-384 raw)")
                return False
        
    except Exception as verification_error:
        print(f"DEBUG: ❌ Signature verification error: {verification_error}")
        import traceback
        traceback.print_exc()
        return False

def convert_raw_to_der(raw_signature):
    """Convert Web Crypto API raw ECDSA signature to DER format"""
    if len(raw_signature) != 96:
        raise ValueError("Invalid raw signature length for P-384 (expected 96 bytes)")
    
    # Split raw signature into r and s components (48 bytes each for P-384)
    r_component = raw_signature[:48]  # First 48 bytes
    s_component = raw_signature[48:]  # Last 48 bytes
    
    # Convert to DER format using cryptography library
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    
    # Convert byte components to integers
    r_integer = int.from_bytes(r_component, 'big')
    s_integer = int.from_bytes(s_component, 'big')
    
    der_formatted_signature = encode_dss_signature(r_integer, s_integer)
    
    print(f"DEBUG: Raw signature converted: {len(raw_signature)} bytes → {len(der_formatted_signature)} bytes")
    return der_formatted_signature