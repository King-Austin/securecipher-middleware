"""
SecureCipher ECDH Key Exchange Module
Provides functions for ECDHE key exchange and session key derivation
"""

import os
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import logging

logger = logging.getLogger('crypto_engine')

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

def derive_session_key(private_key, peer_public_key, salt=None, info=b"SecureCipher-ECDHE"):
    """
    Derive a session key using ECDH + HKDF-SHA384
    
    Args:
        private_key (EllipticCurvePrivateKey): Local private key
        peer_public_key (EllipticCurvePublicKey): Peer's public key
        salt (bytes, optional): Salt for HKDF. Defaults to None.
        info (bytes, optional): Info for HKDF. Defaults to b"SecureCipher-ECDHE".
        
    Returns:
        bytes: 32-byte (256-bit) key for AES-GCM
    """
    try:
        # Compute shared secret via ECDH
        shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
        
        # Derive key using HKDF-SHA384
        derived_key = HKDF(
            algorithm=hashes.SHA384(),
            length=32,  # 256 bits for AES-256-GCM
            salt=salt,
            info=info
        ).derive(shared_secret)
        
        logger.info(f"✅ Successfully derived {len(derived_key) * 8}-bit session key")
        return derived_key
        
    except Exception as e:
        logger.error(f"❌ Session key derivation failed: {str(e)}")
        raise ValueError(f"Failed to derive session key: {str(e)}")

def generate_ephemeral_keypair():
    """
    Generate an ephemeral ECDH key pair on P-384 curve
    
    Returns:
        tuple: (private_key, public_key_pem)
    """
    try:
        # Generate private key on P-384 curve
        private_key = ec.generate_private_key(ec.SECP384R1())
        
        # Export public key in PEM format
        public_key_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        logger.info("✅ Generated ephemeral ECDH key pair on P-384 curve")
        return private_key, public_key_pem
        
    except Exception as e:
        logger.error(f"❌ Failed to generate ephemeral keypair: {str(e)}")
        raise RuntimeError(f"Failed to generate ephemeral keypair: {str(e)}")

def public_key_to_pem(public_key):
    """
    Convert a public key to PEM format
    
    Args:
        public_key (EllipticCurvePublicKey): Public key
        
    Returns:
        bytes: PEM encoded public key
    """
    try:
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    except Exception as e:
        logger.error(f"❌ Failed to convert public key to PEM: {str(e)}")
        raise ValueError(f"Failed to convert public key to PEM: {str(e)}")
