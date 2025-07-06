"""
SecureCipher ECDSA Signature Module
Provides functions for digital signature creation and verification
"""

import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.exceptions import InvalidSignature
import logging

logger = logging.getLogger('crypto_engine')

def sign_payload(private_key, payload):
    """
    Sign a payload using ECDSA with SHA-384
    
    Args:
        private_key (EllipticCurvePrivateKey): Private key for signing
        payload (bytes): Data to sign
        
    Returns:
        bytes: The signature
    """
    try:
        # Sign the payload using ECDSA with SHA-384
        signature = private_key.sign(
            payload,
            ec.ECDSA(hashes.SHA384())
        )
        
        logger.debug(f"✅ ECDSA signature created: {len(signature)} bytes")
        return signature
        
    except Exception as e:
        logger.error(f"❌ ECDSA signing failed: {str(e)}")
        raise RuntimeError(f"Signing failed: {str(e)}")

def verify_signature(public_key, payload, signature):
    """
    Verify an ECDSA signature
    
    Args:
        public_key (EllipticCurvePublicKey): Public key for verification
        payload (bytes): The signed data
        signature (bytes): The signature to verify
        
    Returns:
        bool: True if signature is valid, False otherwise
    """
    try:
        # Verify the signature using ECDSA with SHA-384
        public_key.verify(
            signature,
            payload,
            ec.ECDSA(hashes.SHA384())
        )
        
        logger.debug("✅ ECDSA signature verified successfully")
        return True
        
    except InvalidSignature:
        logger.warning("❌ Invalid ECDSA signature")
        return False
    except Exception as e:
        logger.error(f"❌ ECDSA verification error: {str(e)}")
        return False

def load_pem_private_key(pem_data, password=None):
    """
    Load PEM formatted private key
    
    Args:
        pem_data (bytes): PEM encoded private key
        password (bytes, optional): Password if key is encrypted. Defaults to None.
        
    Returns:
        EllipticCurvePrivateKey: The loaded private key
    """
    try:
        return serialization.load_pem_private_key(pem_data, password)
    except Exception as e:
        logger.error(f"❌ Failed to load PEM private key: {str(e)}")
        raise ValueError(f"Invalid PEM private key format: {str(e)}")

def load_pem_public_key(pem_data):
    """
    Load PEM formatted public key
    
    Args:
        pem_data (bytes): PEM encoded public key
        
    Returns:
        EllipticCurvePublicKey: The loaded public key
    """
    try:
        return serialization.load_pem_public_key(pem_data)
    except Exception as e:
        logger.error(f"❌ Failed to load PEM public key: {str(e)}")
        raise ValueError(f"Invalid PEM public key format: {str(e)}")

def encode_signature(signature):
    """
    Encode signature to base64 string
    
    Args:
        signature (bytes): Signature bytes
        
    Returns:
        str: Base64 encoded signature
    """
    return base64.b64encode(signature).decode('utf-8')

def decode_signature(signature):
    """
    Decode base64 signature to bytes
    
    Args:
        signature (str): Base64 encoded signature
        
    Returns:
        bytes: Signature bytes
    """
    return base64.b64decode(signature)
