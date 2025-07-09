from api.models import MiddlewareKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization


class KeyPairGenerator:
    """Handles ECC key pair generation and storage"""
    
    @staticmethod
    def generate_private_key():
        """Generate a new ECC private key"""
        return ec.generate_private_key(ec.SECP384R1())
    
    @staticmethod
    def serialize_private_key(private_key):
        """Serialize private key to PEM format"""
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()
    
    @staticmethod
    def serialize_public_key(public_key):
        """Serialize public key to PEM format"""
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    
    @classmethod
    def generate_and_store_keypair(cls, label="active"):
        """Generate and store a new key pair"""
        # Generate keys
        private_key = cls.generate_private_key()
        public_key = private_key.public_key()
        
        # Serialize keys
        private_pem = cls.serialize_private_key(private_key)
        public_pem = cls.serialize_public_key(public_key)
        
        # Store in database
        MiddlewareKey.objects.create(
            label=label, 
            private_key_pem=private_pem, 
            public_key_pem=public_pem
        )
        
        print(f"[✅] Middleware keypair '{label}' saved.")


def generate():
    """Legacy function for backward compatibility"""
    KeyPairGenerator.generate_and_store_keypair()
