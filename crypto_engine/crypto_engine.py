from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidSignature
import base64, json

def base64_decode(data): return base64.b64decode(data)

def derive_session_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=None,
        info=b'securecipher-session',
    ).derive(shared_secret)

def decrypt_aes_gcm(ciphertext, iv, session_key):
    decryptor = Cipher(algorithms.AES(session_key), modes.GCM(iv)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

def verify_signature(public_pem, tx_bytes, sig_b64):
    public_key = serialization.load_pem_public_key(public_pem.encode())
    sig = base64.b64decode(sig_b64)
    try:
        public_key.verify(sig, tx_bytes, ec.ECDSA(hashes.SHA384()))
        return True
    except InvalidSignature:
        return False
