"""
Module for verifying certificate signatures.
"""

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def verify_signature(ca_cert: x509.Certificate, cert: x509.Certificate) -> bool:
    """
    Verify the signature of a certificate using the CA's public key.

    Args:
        ca_cert: The CA certificate that issued the certificate
        cert: The certificate to verify

    Returns:
        bool: True if the signature is valid, False otherwise
    """
    public_key = ca_cert.public_key()
    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm
        )
        print(f"Signature RSA valide entre {ca_cert.subject.rfc4514_string()} et {cert.subject.rfc4514_string()}.")
        return True
    except Exception as e:
        print(f"Erreur de vérification de signature : {e}")
        return False