"""
SecureCipher Crypto Utilities
Comprehensive cryptographic validation and processing utilities
"""

import json
import base64
import hashlib
import time
from datetime import datetime, timedelta
from django.utils import timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger('crypto_engine')

class CryptoValidator:
    """Comprehensive cryptographic validation utilities for SecureCipher"""
    
    @staticmethod
    def verify_ecdsa_signature(payload, signature, public_key_jwk):
        """
        Verify ECDSA P-384 signature from WebCrypto frontend
        
        Args:
            payload (dict): The signed data payload
            signature (str): Base64 encoded signature
            public_key_jwk (dict): Public key in JWK format
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        start_time = time.time()
        
        try:
            logger.info(f"🔍 Verifying ECDSA signature for request: {payload.get('request_id', 'unknown')}")
            
            # Convert JWK to cryptography public key
            public_key = CryptoValidator.jwk_to_ec_public_key(public_key_jwk)
            
            # Prepare payload exactly as frontend does
            # Important: Must match frontend signing exactly
            payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True)
            payload_bytes = payload_json.encode('utf-8')
            
            logger.debug(f"Payload to verify: {payload_json}")
            
            # Decode signature from base64
            signature_bytes = base64.b64decode(signature)
            
            # Verify signature using P-384 curve with SHA-384
            public_key.verify(
                signature_bytes,
                payload_bytes,
                ec.ECDSA(hashes.SHA384())
            )
            
            duration_ms = int((time.time() - start_time) * 1000)
            logger.info(f"✅ Signature verification successful for {payload.get('request_id', 'unknown')} ({duration_ms}ms)")
            return True
            
        except InvalidSignature:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.warning(f"❌ Invalid signature for {payload.get('request_id', 'unknown')} ({duration_ms}ms)")
            return False
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            logger.error(f"❌ Signature verification error for {payload.get('request_id', 'unknown')}: {str(e)} ({duration_ms}ms)")
            return False
    
    @staticmethod
    def jwk_to_ec_public_key(jwk):
        """
        Convert JWK format public key to cryptography EC public key
        
        Args:
            jwk (dict): Public key in JWK format from WebCrypto
            
        Returns:
            ECPublicKey: Cryptography public key object
        """
        try:
            logger.debug(f"Converting JWK to EC public key: {jwk.get('kty')}-{jwk.get('crv')}")
            
            # Validate JWK format
            if jwk.get('kty') != 'EC':
                raise ValueError(f"Invalid key type: {jwk.get('kty')}, expected 'EC'")
            
            if jwk.get('crv') != 'P-384':
                raise ValueError(f"Invalid curve: {jwk.get('crv')}, expected 'P-384'")
            
            # Extract and validate required fields
            required_fields = ['x', 'y']
            for field in required_fields:
                if field not in jwk:
                    raise ValueError(f"Missing required JWK field: {field}")
            
            # Decode coordinates from base64url (WebCrypto format)
            x_b64 = jwk['x']
            y_b64 = jwk['y']
            
            # Add padding if needed for base64url
            x_b64 += '=' * (4 - len(x_b64) % 4)
            y_b64 += '=' * (4 - len(y_b64) % 4)
            
            # Decode coordinates
            x_bytes = base64.urlsafe_b64decode(x_b64)
            y_bytes = base64.urlsafe_b64decode(y_b64)
            
            # Convert bytes to integers
            x_int = int.from_bytes(x_bytes, byteorder='big')
            y_int = int.from_bytes(y_bytes, byteorder='big')
            
            # Create public key using P-384 curve
            public_numbers = ec.EllipticCurvePublicNumbers(
                x=x_int,
                y=y_int,
                curve=ec.SECP384R1()  # P-384 curve
            )
            
            public_key = public_numbers.public_key()
            logger.debug("✅ JWK successfully converted to EC public key")
            return public_key
            
        except Exception as e:
            logger.error(f"❌ JWK conversion failed: {str(e)}")
            raise ValueError(f"Invalid JWK format: {str(e)}")
    
    @staticmethod
    def decrypt_aes_data(encrypted_data, aes_key_jwk, iv):
        """
        Decrypt AES-256-GCM data from frontend
        
        Args:
            encrypted_data (str): Base64 encoded encrypted data
            aes_key_jwk (dict): AES key in JWK format
            iv (str): Base64 encoded initialization vector
            
        Returns:
            dict: Decrypted data as dictionary
        """
        try:
            logger.info("🔓 Decrypting AES-256-GCM data")
            
            # Validate AES key format
            if aes_key_jwk.get('kty') != 'oct':
                raise ValueError(f"Invalid AES key type: {aes_key_jwk.get('kty')}")
            
            if aes_key_jwk.get('alg') != 'A256GCM':
                raise ValueError(f"Invalid AES algorithm: {aes_key_jwk.get('alg')}")
            
            # Extract AES key from JWK format
            key_b64 = aes_key_jwk['k']
            key_b64 += '=' * (4 - len(key_b64) % 4)  # Add padding
            key_bytes = base64.urlsafe_b64decode(key_b64)
            
            # Validate key length (256 bits = 32 bytes)
            if len(key_bytes) != 32:
                raise ValueError(f"Invalid AES key length: {len(key_bytes)} bytes, expected 32")
            
            # Decode encrypted data and IV
            encrypted_bytes = base64.b64decode(encrypted_data)
            iv_bytes = base64.b64decode(iv)
            
            # Validate IV length (96 bits = 12 bytes for GCM)
            if len(iv_bytes) != 12:
                raise ValueError(f"Invalid IV length: {len(iv_bytes)} bytes, expected 12")
            
            # Decrypt using AES-256-GCM
            aesgcm = AESGCM(key_bytes)
            decrypted_bytes = aesgcm.decrypt(iv_bytes, encrypted_bytes, None)
            
            # Parse as JSON
            decrypted_text = decrypted_bytes.decode('utf-8')
            decrypted_data = json.loads(decrypted_text)
            
            logger.info("✅ AES decryption successful")
            return decrypted_data
            
        except Exception as e:
            logger.error(f"❌ AES decryption failed: {str(e)}")
            raise ValueError(f"Decryption failed: {str(e)}")
    
    @staticmethod
    def generate_fingerprint(public_key_jwk):
        """
        Generate fingerprint for public key (same algorithm as frontend)
        
        Args:
            public_key_jwk (dict): Public key in JWK format
            
        Returns:
            str: 16-character fingerprint
        """
        try:
            logger.debug("🔍 Generating public key fingerprint")
            
            # Create deterministic string from JWK (same as frontend)
            key_string = json.dumps(public_key_jwk, sort_keys=True, separators=(',', ':'))
            
            # Generate SHA-256 hash
            hash_bytes = hashlib.sha256(key_string.encode('utf-8')).digest()
            hash_hex = hash_bytes.hex()
            
            # Return first 16 characters as fingerprint
            fingerprint = hash_hex[:16]
            logger.debug(f"✅ Generated fingerprint: {fingerprint}")
            return fingerprint
            
        except Exception as e:
            logger.error(f"❌ Fingerprint generation failed: {str(e)}")
            raise ValueError(f"Failed to generate fingerprint: {str(e)}")
    
    @staticmethod
    def validate_timestamp(timestamp_str, max_age_seconds=300):
        """
        Validate request timestamp to prevent replay attacks
        
        Args:
            timestamp_str (str): ISO format timestamp from request
            max_age_seconds (int): Maximum allowed age in seconds (default: 5 minutes)
            
        Returns:
            bool: True if timestamp is valid, False otherwise
        """
        try:
            logger.debug(f"🕐 Validating timestamp: {timestamp_str}")
            
            # Parse timestamp (handle both with and without Z)
            if timestamp_str.endswith('Z'):
                timestamp_str = timestamp_str[:-1] + '+00:00'
            
            # Parse ISO format timestamp
            request_time = datetime.fromisoformat(timestamp_str)
            
            # Ensure timezone awareness
            if request_time.tzinfo is None:
                request_time = request_time.replace(tzinfo=timezone.utc)
            
            # Check if timestamp is within acceptable range
            now = timezone.now()
            time_diff = abs((now - request_time).total_seconds())
            
            if time_diff > max_age_seconds:
                logger.warning(f"❌ Timestamp too old: {time_diff:.1f}s > {max_age_seconds}s")
                return False
            
            logger.debug(f"✅ Timestamp valid (age: {time_diff:.1f}s)")
            return True
            
        except Exception as e:
            logger.error(f"❌ Timestamp validation failed: {str(e)}")
            return False
    
    @staticmethod
    def is_sensitive_endpoint(endpoint):
        """
        Determine if an endpoint requires encryption
        
        Args:
            endpoint (str): The API endpoint path
            
        Returns:
            bool: True if endpoint is sensitive, False otherwise
        """
        sensitive_patterns = [
            '/transactions/',
            '/transfer/',
            '/accounts/',
            '/auth/login/',
            '/auth/change-password/',
            '/profile/',
            '/balance/',
            '/statements/',
            '/cards/',
            '/beneficiaries/',
        ]
        
        is_sensitive = any(pattern in endpoint.lower() for pattern in sensitive_patterns)
        logger.debug(f"Endpoint {endpoint} is {'sensitive' if is_sensitive else 'not sensitive'}")
        return is_sensitive
    
    @staticmethod
    def sanitize_audit_data(data):
        """
        Sanitize data for audit logging (remove sensitive information)
        
        Args:
            data (dict): Request data to sanitize
            
        Returns:
            dict: Sanitized data safe for logging
        """
        if not isinstance(data, dict):
            return {}
        
        # Fields to exclude from audit logs
        sensitive_fields = [
            'password', 'pin', 'cvv', 'account_number', 
            'card_number', 'ssn', 'private_key', 'secret'
        ]
        
        sanitized = {}
        for key, value in data.items():
            if any(field in key.lower() for field in sensitive_fields):
                sanitized[key] = '[REDACTED]'
            elif isinstance(value, dict):
                sanitized[key] = CryptoValidator.sanitize_audit_data(value)
            elif isinstance(value, str) and len(value) > 100:
                sanitized[key] = value[:97] + '...'
            else:
                sanitized[key] = value
        
        return sanitized


# Export main utilities
__all__ = ['CryptoValidator']
