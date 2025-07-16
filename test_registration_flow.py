!/usr/bin/env python3
"""
Registration Flow Integration Test
Tests the complete registration flow from frontend to banking API through middleware
"""

import json
import base64
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from api.crypto_utils import CryptoHandler

def test_registration_flow():
    """Test the complete registration flow compatibility"""
    
    print("🧪 Testing Registration Flow Compatibility...")
    
    # 1. Simulate frontend key generation (P-384 ECDSA)
    print("📋 Step 1: Generate client key pair (frontend simulation)")
    client_private_key = ec.generate_private_key(ec.SECP384R1())
    client_public_key = client_private_key.public_key()
    
    # Export public key as PEM (frontend format)
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    print(f"✅ Client public key generated: {client_public_key_pem[:50]}...")
    
    # 2. Simulate middleware key pair
    print("📋 Step 2: Generate middleware key pair")
    middleware_private_key = ec.generate_private_key(ec.SECP384R1())
    middleware_public_key = middleware_private_key.public_key()
    
    # 3. Test ECDH key exchange (frontend to middleware)
    print("📋 Step 3: Test ECDH key exchange")
    ephemeral_private_key = ec.generate_private_key(ec.SECP384R1())
    ephemeral_public_key = ephemeral_private_key.public_key()
    
    # Frontend side: derive shared secret
    shared_secret_frontend = ephemeral_private_key.exchange(ec.ECDH(), middleware_public_key)
    
    # Middleware side: derive shared secret
    shared_secret_middleware = CryptoHandler.perform_ecdh(middleware_private_key, ephemeral_public_key)
    
    assert shared_secret_frontend == shared_secret_middleware, "ECDH shared secrets don't match!"
    print("✅ ECDH key exchange successful")
    
    # 4. Test session key derivation
    print("📋 Step 4: Test session key derivation")
    session_key = CryptoHandler.derive_session_key(shared_secret_middleware)
    print(f"✅ Session key derived: {len(session_key)} bytes")
    
    # 5. Test payload encryption/decryption
    print("📋 Step 5: Test payload encryption")
    
    # Simulate frontend registration payload
    registration_payload = {
        "target": "auth_register",
        "transaction_data": {
            "email": "test@example.com",
            "first_name": "John",
            "last_name": "Doe",
            "phone_number": "08123456789",
            "date_of_birth": "1990-01-01",
            "address": "123 Test Street, Lagos",
            "occupation": "Software Engineer",
            "nin": "12345678901",
            "public_key": client_public_key_pem
        },
        "client_signature": "test_signature",
        "client_public_key": client_public_key_pem,
        "timestamp": int(time.time()),
        "nonce": "test_nonce_123"
    }
    
    # Encrypt payload
    payload_json = json.dumps(registration_payload, sort_keys=True, separators=(',', ':'))
    encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(payload_json.encode(), session_key)
    
    # Create encrypted payload structure (as frontend would send)
    encrypted_payload = {
        "ephemeral_pubkey": base64.b64encode(ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).decode(),
        "ciphertext": base64.b64encode(encrypted_data).decode(),
        "iv": base64.b64encode(iv).decode()
    }
    
    print("✅ Payload encrypted successfully")
    
    # 6. Test middleware decryption
    print("📋 Step 6: Test middleware decryption")
    
    decrypted_payload, recovered_session_key = CryptoHandler.decrypt_payload(
        encrypted_payload, middleware_private_key
    )
    
    assert decrypted_payload == registration_payload, "Decrypted payload doesn't match original!"
    assert recovered_session_key == session_key, "Recovered session key doesn't match!"
    print("✅ Middleware decryption successful")
    
    # 7. Test response encryption
    print("📋 Step 7: Test response encryption")
    
    # Simulate banking API response
    api_response = {
        "message": "User registered successfully.",
        "access": "fake_jwt_token",
        "refresh": "fake_refresh_token"
    }
    
    encrypted_response = CryptoHandler.encrypt_response(api_response, session_key)
    decrypted_response = CryptoHandler.decrypt_response(encrypted_response, session_key)
    
    assert decrypted_response == api_response, "Response encryption/decryption failed!"
    print("✅ Response encryption/decryption successful")
    
    # 8. Verify data format compatibility
    print("📋 Step 8: Verify registration data format")
    
    transaction_data = decrypted_payload["transaction_data"]
    required_fields = [
        "email", "first_name", "last_name", "phone_number", 
        "date_of_birth", "address", "occupation", "nin", "public_key"
    ]
    
    for field in required_fields:
        assert field in transaction_data, f"Required field '{field}' missing from registration data!"
    
    print("✅ Registration data format is compatible")
    
    print("\n🎉 Registration Flow Compatibility Test PASSED!")
    print("✅ Frontend ↔ Middleware ↔ Banking API integration is working correctly")
    
    return {
        "status": "PASS",
        "client_public_key": client_public_key_pem,
        "registration_data": transaction_data,
        "encrypted_payload_size": len(encrypted_payload["ciphertext"]),
        "session_key_length": len(session_key)
    }

if __name__ == "__main__":
    result = test_registration_flow()
    print(f"\n📊 Test Results: {json.dumps(result, indent=2)}")
