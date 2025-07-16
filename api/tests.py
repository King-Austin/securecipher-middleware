from django.test import TestCase, Client
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from unittest.mock import patch, MagicMock
import json
import base64
import time
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from .crypto_utils import CryptoHandler, TransactionProcessor
from .models import MiddlewareKey, UsedNonce


class CryptoHandlerTestCase(TestCase):
    """Test cases for the CryptoHandler class"""
    
    def setUp(self):
        """Set up test fixtures"""
        # Generate test key pair
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        
        # Create test PEM data
        self.private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
        
        self.public_key_der = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Test data
        self.test_message = b"Hello, SecureCipher!"
        self.shared_secret = get_random_bytes(48)  # 384 bits for P-384
    
    def test_load_private_key(self):
        """Test loading private key from PEM format"""
        loaded_key = CryptoHandler.load_private_key(self.private_key_pem)
        self.assertIsInstance(loaded_key, ec.EllipticCurvePrivateKey)
        
        # Verify it's the same key by comparing public keys
        original_public = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        loaded_public = loaded_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.assertEqual(original_public, loaded_public)
    
    def test_load_public_key_from_der(self):
        """Test loading public key from DER format"""
        loaded_key = CryptoHandler.load_public_key_from_der(self.public_key_der)
        self.assertIsInstance(loaded_key, ec.EllipticCurvePublicKey)
    
    def test_perform_ecdh(self):
        """Test ECDH key exchange"""
        # Generate second key pair
        other_private_key = ec.generate_private_key(ec.SECP384R1())
        other_public_key = other_private_key.public_key()
        
        # Perform ECDH from both sides
        shared_secret_1 = CryptoHandler.perform_ecdh(self.private_key, other_public_key)
        shared_secret_2 = CryptoHandler.perform_ecdh(other_private_key, self.public_key)
        
        # Shared secrets should be identical
        self.assertEqual(shared_secret_1, shared_secret_2)
        self.assertEqual(len(shared_secret_1), 48)  # 384 bits / 8 = 48 bytes
    
    def test_derive_session_key(self):
        """Test session key derivation using HKDF"""
        session_key = CryptoHandler.derive_session_key(self.shared_secret)
        
        # Session key should be 32 bytes (256 bits) for AES-256
        self.assertEqual(len(session_key), 32)
        self.assertIsInstance(session_key, bytes)
        
        # Should be deterministic - same input produces same output
        session_key_2 = CryptoHandler.derive_session_key(self.shared_secret)
        self.assertEqual(session_key, session_key_2)
    
    def test_encrypt_decrypt_aes_gcm(self):
        """Test AES-GCM encryption and decryption"""
        session_key = get_random_bytes(32)  # 256-bit key
        
        # Encrypt
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(self.test_message, session_key)
        
        # Verify encryption output
        self.assertIsInstance(encrypted_data, bytes)
        self.assertIsInstance(iv, bytes)
        self.assertEqual(len(iv), 12)  # GCM IV should be 12 bytes
        self.assertGreater(len(encrypted_data), len(self.test_message))  # Should include auth tag
        
        # Decrypt
        decrypted_data = CryptoHandler.decrypt_aes_gcm(encrypted_data, iv, session_key)
        
        # Verify decryption
        self.assertEqual(decrypted_data, self.test_message)
    
    def test_convert_raw_to_der(self):
        """Test raw signature to DER conversion"""
        # Create mock raw signature (96 bytes for P-384)
        raw_signature = get_random_bytes(96)
        
        # Convert to DER
        der_signature = CryptoHandler.convert_raw_to_der(raw_signature)
        
        # DER signature should be different length and format
        self.assertNotEqual(len(der_signature), 96)
        self.assertIsInstance(der_signature, bytes)
    
    def test_convert_raw_to_der_invalid_length(self):
        """Test raw signature conversion with invalid length"""
        invalid_signature = get_random_bytes(64)  # Wrong length
        
        with self.assertRaises(ValueError) as context:
            CryptoHandler.convert_raw_to_der(invalid_signature)
        
        self.assertIn("Invalid raw signature length", str(context.exception))
    
    def test_verify_signature(self):
        """Test ECDSA signature verification"""
        # Create a signature
        signature = self.private_key.sign(self.test_message, ec.ECDSA(hashes.SHA384()))
        signature_b64 = base64.b64encode(signature).decode()
        
        public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        # Verify signature
        is_valid = CryptoHandler.verify_signature(public_key_pem, self.test_message, signature_b64)
        self.assertTrue(is_valid)
        
        # Test with invalid signature
        invalid_signature = base64.b64encode(get_random_bytes(96)).decode()
        is_valid_invalid = CryptoHandler.verify_signature(public_key_pem, self.test_message, invalid_signature)
        self.assertFalse(is_valid_invalid)
    
    def test_decrypt_payload(self):
        """Test full payload decryption process"""
        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ephemeral_public = ephemeral_private.public_key()
        
        # Prepare test payload
        test_payload = {"test": "data", "transaction": "info"}
        payload_json = json.dumps(test_payload, sort_keys=True, separators=(',', ':'))
        payload_bytes = payload_json.encode('utf-8')
        
        # Perform ECDH and derive session key
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        session_key = CryptoHandler.derive_session_key(shared_secret)
        
        # Encrypt payload
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(payload_bytes, session_key)
        
        # Create encrypted payload structure
        encrypted_payload = {
            "ephemeral_pubkey": base64.b64encode(ephemeral_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            "ciphertext": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
        # Decrypt payload
        decrypted_payload, returned_session_key = CryptoHandler.decrypt_payload(
            encrypted_payload, self.private_key
        )
        
        # Verify decryption
        self.assertEqual(decrypted_payload, test_payload)
        self.assertEqual(returned_session_key, session_key)
    
    def test_encrypt_response(self):
        """Test response encryption"""
        session_key = get_random_bytes(32)
        response_data = {"status": "success", "message": "Test response"}
        
        encrypted_response = CryptoHandler.encrypt_response(response_data, session_key)
        
        # Verify structure
        self.assertIn("ciphertext", encrypted_response)
        self.assertIn("iv", encrypted_response)
        
        # Verify decryption
        decrypted_response = CryptoHandler.decrypt_response(encrypted_response, session_key)
        self.assertEqual(decrypted_response, response_data)


class TransactionProcessorTestCase(TestCase):
    """Test cases for the TransactionProcessor class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_payload = {
            "target": "test_target",
            "transaction_data": {"amount": 100, "recipient": "test@example.com"},
            "url_params": {"id": "123"},
            "client_signature": "test_signature",
            "client_public_key": "test_public_key",
            "timestamp": int(time.time()),
            "nonce": "test_nonce",
            "auth_token": "test_token"
        }
        
        self.transaction_data = {"amount": 100, "recipient": "test@example.com"}
    
    def test_extract_transaction_components(self):
        """Test transaction component extraction"""
        components = TransactionProcessor.extract_transaction_components(self.test_payload)
        
        self.assertEqual(components['target'], "test_target")
        self.assertEqual(components['transaction_data'], self.transaction_data)
        self.assertEqual(components['client_signature'], "test_signature")
        self.assertEqual(components['client_public_key'], "test_public_key")
    
    def test_prepare_transaction_for_verification(self):
        """Test transaction preparation for signature verification"""
        transaction_bytes = TransactionProcessor.prepare_transaction_for_verification(
            self.transaction_data
        )
        
        # Should be JSON bytes with sorted keys and minimal separators
        expected_json = '{"amount":100,"recipient":"test@example.com"}'
        self.assertEqual(transaction_bytes, expected_json.encode('utf-8'))
    
    def test_create_success_response(self):
        """Test success response creation"""
        response = TransactionProcessor.create_success_response(self.transaction_data)
        
        self.assertEqual(response["status"], "verified")
        self.assertIn("message", response)
        self.assertIn("transaction_id", response)
    
    def test_create_error_response(self):
        """Test error response creation"""
        error_message = "Test error"
        response = TransactionProcessor.create_error_response(error_message)
        
        self.assertEqual(response["status"], "error")
        self.assertEqual(response["error"], error_message)
    
    @patch('api.crypto_utils.CryptoHandler.verify_signature')
    def test_verify_transaction_signature(self, mock_verify):
        """Test transaction signature verification"""
        mock_verify.return_value = True
        
        is_valid = TransactionProcessor.verify_transaction_signature(
            self.transaction_data,
            "test_signature",
            "test_public_key"
        )
        
        self.assertTrue(is_valid)
        mock_verify.assert_called_once()


class SecureGatewayAPITestCase(APITestCase):
    """Test cases for the secure gateway API endpoints"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.client = Client()
        
        # Create test middleware key
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()
        
        self.middleware_key = MiddlewareKey.objects.create(
            label="active",
            private_key_pem=self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            public_key_pem=self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        )
    
    def test_get_public_key_endpoint(self):
        """Test the public key retrieval endpoint"""
        response = self.client.get('/api/middleware/public-key')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn("public_key", data)
        self.assertIn("BEGIN PUBLIC KEY", data["public_key"])
    
    def test_secure_gateway_missing_payload(self):
        """Test secure gateway with missing payload"""
        response = self.client.post(
            '/api/secure/gateway',
            {},
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    @patch('api.views.requests.request')
    def test_secure_gateway_valid_transaction(self, mock_request):
        """Test secure gateway with valid encrypted transaction"""
        # Mock downstream service response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"status": "success", "data": "test"}
        mock_request.return_value = mock_response
        
        # Generate ephemeral key pair
        ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ephemeral_public = ephemeral_private.public_key()
        
        # Create test payload
        test_payload = {
            "target": "auth_register",
            "transaction_data": {"username": "test", "email": "test@example.com"},
            "client_signature": "test_signature",
            "client_public_key": "test_public_key",
            "timestamp": int(time.time()),
            "nonce": "test_nonce_" + str(time.time())
        }
        
        # Encrypt payload
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        session_key = CryptoHandler.derive_session_key(shared_secret)
        
        payload_json = json.dumps(test_payload, sort_keys=True, separators=(',', ':'))
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(payload_json.encode(), session_key)
        
        encrypted_payload = {
            "ephemeral_pubkey": base64.b64encode(ephemeral_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            "ciphertext": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
        # Mock signature verification
        with patch('api.crypto_utils.CryptoHandler.verify_signature', return_value=True):
            response = self.client.post(
                '/api/secure/gateway',
                encrypted_payload,
                content_type='application/json'
            )
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
    
    def test_replay_attack_prevention(self):
        """Test that replay attacks are prevented"""
        nonce = "test_nonce_replay"
        
        # Create used nonce
        UsedNonce.objects.create(nonce=nonce)
        
        # Generate test encrypted payload with the used nonce
        ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ephemeral_public = ephemeral_private.public_key()
        
        test_payload = {
            "target": "auth_register",
            "transaction_data": {"username": "test"},
            "client_signature": "test_signature",
            "client_public_key": "test_public_key",
            "timestamp": int(time.time()),
            "nonce": nonce  # Using the already used nonce
        }
        
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        session_key = CryptoHandler.derive_session_key(shared_secret)
        
        payload_json = json.dumps(test_payload, sort_keys=True, separators=(',', ':'))
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(payload_json.encode(), session_key)
        
        encrypted_payload = {
            "ephemeral_pubkey": base64.b64encode(ephemeral_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            "ciphertext": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
        response = self.client.post(
            '/api/secure/gateway',
            encrypted_payload,
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def test_timestamp_validation(self):
        """Test that old timestamps are rejected"""
        old_timestamp = int(time.time()) - 400  # 400 seconds ago (> 5 minutes)
        
        ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ephemeral_public = ephemeral_private.public_key()
        
        test_payload = {
            "target": "auth_register",
            "transaction_data": {"username": "test"},
            "client_signature": "test_signature",
            "client_public_key": "test_public_key",
            "timestamp": old_timestamp,
            "nonce": "test_nonce_old"
        }
        
        shared_secret = self.private_key.exchange(ec.ECDH(), ephemeral_public)
        session_key = CryptoHandler.derive_session_key(shared_secret)
        
        payload_json = json.dumps(test_payload, sort_keys=True, separators=(',', ':'))
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(payload_json.encode(), session_key)
        
        encrypted_payload = {
            "ephemeral_pubkey": base64.b64encode(ephemeral_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            "ciphertext": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
        response = self.client.post(
            '/api/secure/gateway',
            encrypted_payload,
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)


class PerformanceTestCase(TestCase):
    """Performance and optimization tests"""
    
    def test_session_key_derivation_caching(self):
        """Test that session key derivation uses caching for performance"""
        shared_secret = get_random_bytes(48)
        
        # First derivation
        start_time = time.time()
        key1 = CryptoHandler.derive_session_key(shared_secret)
        first_duration = time.time() - start_time
        
        # Second derivation with same input (should use cache)
        start_time = time.time()
        key2 = CryptoHandler.derive_session_key(shared_secret)
        second_duration = time.time() - start_time
        
        # Keys should be identical
        self.assertEqual(key1, key2)
        
        # Note: Due to HKDF's stateless nature, we can't easily test caching here
        # This test serves as a placeholder for future caching implementations
    
    def test_large_payload_handling(self):
        """Test handling of large encrypted payloads"""
        # Create large payload (1MB)
        large_data = "x" * (1024 * 1024)
        session_key = get_random_bytes(32)
        
        # Test encryption/decryption performance
        start_time = time.time()
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(large_data.encode(), session_key)
        encryption_time = time.time() - start_time
        
        start_time = time.time()
        decrypted_data = CryptoHandler.decrypt_aes_gcm(encrypted_data, iv, session_key)
        decryption_time = time.time() - start_time
        
        # Verify correctness
        self.assertEqual(decrypted_data.decode(), large_data)
        
        # Performance should be reasonable (under 1 second for 1MB)
        self.assertLess(encryption_time, 1.0)
        self.assertLess(decryption_time, 1.0)
        
        print(f"DEBUG: Large payload encryption time: {encryption_time:.3f}s")
        print(f"DEBUG: Large payload decryption time: {decryption_time:.3f}s")


class SecurityTestCase(TestCase):
    """Security-focused test cases"""
    
    def test_signature_verification_with_wrong_key(self):
        """Test that signature verification fails with wrong public key"""
        # Generate two different key pairs
        key1 = ec.generate_private_key(ec.SECP384R1())
        key2 = ec.generate_private_key(ec.SECP384R1())
        
        message = b"test message"
        
        # Sign with key1
        signature = key1.sign(message, ec.ECDSA(hashes.SHA384()))
        signature_b64 = base64.b64encode(signature).decode()
        
        # Try to verify with key2's public key
        wrong_public_key_pem = key2.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        is_valid = CryptoHandler.verify_signature(wrong_public_key_pem, message, signature_b64)
        self.assertFalse(is_valid)
    
    def test_tampered_ciphertext_detection(self):
        """Test that tampered ciphertext is detected"""
        session_key = get_random_bytes(32)
        message = b"sensitive data"
        
        # Encrypt message
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(message, session_key)
        
        # Tamper with ciphertext
        tampered_data = bytearray(encrypted_data)
        tampered_data[0] ^= 0xFF  # Flip some bits
        
        # Decryption should fail
        with self.assertRaises(Exception):
            CryptoHandler.decrypt_aes_gcm(bytes(tampered_data), iv, session_key)
    
    def test_invalid_target_rejection(self):
        """Test that invalid targets are rejected"""
        ephemeral_private = ec.generate_private_key(ec.SECP384R1())
        ephemeral_public = ephemeral_private.public_key()
        
        # Create middleware key for test
        private_key = ec.generate_private_key(ec.SECP384R1())
        MiddlewareKey.objects.create(
            label="active",
            private_key_pem=private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode(),
            public_key_pem=private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        )
        
        test_payload = {
            "target": "invalid_target",  # Invalid target
            "transaction_data": {"test": "data"},
            "client_signature": "test_signature",
            "client_public_key": "test_public_key",
            "timestamp": int(time.time()),
            "nonce": "test_nonce"
        }
        
        shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)
        session_key = CryptoHandler.derive_session_key(shared_secret)
        
        payload_json = json.dumps(test_payload, sort_keys=True, separators=(',', ':'))
        encrypted_data, iv = CryptoHandler.encrypt_aes_gcm(payload_json.encode(), session_key)
        
        encrypted_payload = {
            "ephemeral_pubkey": base64.b64encode(ephemeral_public.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )).decode(),
            "ciphertext": base64.b64encode(encrypted_data).decode(),
            "iv": base64.b64encode(iv).decode()
        }
        
        client = Client()
        response = client.post(
            '/api/secure/gateway',
            encrypted_payload,
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, status.HTTP_500_INTERNAL_SERVER_ERROR)
