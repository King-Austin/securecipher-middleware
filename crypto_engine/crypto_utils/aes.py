"""
SecureCipher AES-GCM Encryption Module
Provides functions for symmetric encryption using AES-256-GCM
"""

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger('crypto_engine')

def encrypt_payload(key, plaintext, aad=None):
    """
    Encrypt data using AES-256-GCM
    
    Args:
        key (bytes): 32-byte (256-bit) key for AES-GCM
        plaintext (bytes): Data to encrypt
        aad (bytes, optional): Additional authenticated data. Defaults to None.
        
    Returns:
        tuple: (iv, ciphertext) where iv is a 12-byte nonce and ciphertext is the encrypted data
    """
    if len(key) != 32:
        raise ValueError(f"Invalid key length: {len(key)} bytes, expected 32 bytes")
    
    try:
        # Create AESGCM cipher with the key
        aesgcm = AESGCM(key)
        
        # Generate a random 12-byte IV (nonce)
        iv = os.urandom(12)
        
        # Encrypt the plaintext
        ciphertext = aesgcm.encrypt(iv, plaintext, aad)
        
        logger.debug(f"✅ AES-GCM encryption successful: {len(plaintext)} bytes → {len(ciphertext)} bytes")
        return iv, ciphertext
        
    except Exception as e:
        logger.error(f"❌ AES-GCM encryption failed: {str(e)}")
        raise RuntimeError(f"Encryption failed: {str(e)}")

def decrypt_payload(key, iv, ciphertext, aad=None):
    """
    Decrypt data using AES-256-GCM
    
    Args:
        key (bytes): 32-byte (256-bit) key for AES-GCM
        iv (bytes): 12-byte initialization vector/nonce
        ciphertext (bytes): Encrypted data
        aad (bytes, optional): Additional authenticated data. Defaults to None.
        
    Returns:
        bytes: Decrypted data
    """
    if len(key) != 32:
        raise ValueError(f"Invalid key length: {len(key)} bytes, expected 32 bytes")
    
    if len(iv) != 12:
        raise ValueError(f"Invalid IV length: {len(iv)} bytes, expected 12 bytes")
    
    try:
        # Create AESGCM cipher with the key
        aesgcm = AESGCM(key)
        
        # Decrypt the ciphertext
        plaintext = aesgcm.decrypt(iv, ciphertext, aad)
        
        logger.debug(f"✅ AES-GCM decryption successful: {len(ciphertext)} bytes → {len(plaintext)} bytes")
        return plaintext
        
    except Exception as e:
        logger.error(f"❌ AES-GCM decryption failed: {str(e)}")
        raise RuntimeError(f"Decryption failed: {str(e)}")

def encode_binary(data):
    """
    Encode binary data to base64 string
    
    Args:
        data (bytes): Binary data
        
    Returns:
        str: Base64 encoded string
    """
    return base64.b64encode(data).decode('utf-8')

def decode_binary(data):
    """
    Decode base64 string to binary data
    
    Args:
        data (str): Base64 encoded string
        
    Returns:
        bytes: Binary data
    """
    return base64.b64decode(data)
