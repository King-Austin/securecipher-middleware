"""
SecureCipher Crypto Utils Package
A collection of cryptographic utilities for the SecureCipher middleware
"""

from .ecdh import (
    derive_session_key,
    generate_ephemeral_keypair,
    load_pem_public_key,
    public_key_to_pem
)

from .aes import (
    encrypt_payload,
    decrypt_payload,
    encode_binary,
    decode_binary
)

from .ecdsa import (
    sign_payload,
    verify_signature,
    load_pem_private_key,
    load_pem_public_key as load_pem_public_key_ecdsa,
    encode_signature,
    decode_signature
)

# Resolve duplicate function name
# load_pem_public_key is imported from ecdh, so rename the one from ecdsa
# to avoid naming conflicts
__all__ = [
    # ECDH functions
    'derive_session_key',
    'generate_ephemeral_keypair',
    'load_pem_public_key',
    'public_key_to_pem',
    
    # AES functions
    'encrypt_payload',
    'decrypt_payload',
    'encode_binary',
    'decode_binary',
    
    # ECDSA functions
    'sign_payload',
    'verify_signature',
    'load_pem_private_key',
    'load_pem_public_key_ecdsa',
    'encode_signature',
    'decode_signature'
]
