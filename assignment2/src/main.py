from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend


def generate_key_pair(private_key_pass):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(private_key_pass, 'utf-8'))
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def sign(private_key_pem,private_key_pass, message):
    private_key = serialization.load_pem_private_key(
        private_key_pem, password=bytes(private_key_pass, 'utf-8'), backend=default_backend())
    prehashed = hashlib.sha256(bytes(message, 'utf-8')).hexdigest()
    sig = private_key.sign(
        bytes(prehashed.encode('ascii')),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())

    return base64.b64encode(sig).decode("utf-8")


def verify(public_key_pem, message, signed):
    try:
        public_key = serialization.load_pem_public_key(
            public_key_pem, backend=default_backend())
        prehashed = hashlib.sha256(bytes(message, 'utf-8')).hexdigest()
        sig = bytes(signed, 'utf-8')
        decoded_sig = base64.b64decode(sig)
        public_key.verify(
            decoded_sig,
            bytes(prehashed.encode('ascii')),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256())
        return True
    except InvalidSignature as error:
        print(error)
        return False



__all__ = [
    "generate_key_pair",
    "sign",
    "verify"
    ]