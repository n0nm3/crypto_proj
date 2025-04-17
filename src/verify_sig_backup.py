"""
Signature verification module.

This module provides functions to verify RSA and ECDSA signatures.
"""

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding
from cryptography.hazmat.primitives import hashes

# Vérification de la signature RSA avec padding PKCS1v15
def verify_rsa_signature(issuer_cert: x509.Certificate, subject_cert: x509.Certificate) -> bool:
    public_key = issuer_cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        print("Erreur : La clé publique de l'émetteur n'est pas RSA.")
        return False

    signature = subject_cert.signature
    tbs_data = subject_cert.tbs_certificate_bytes
    hash_algo = subject_cert.signature_hash_algorithm

    try:
        public_key.verify(
            signature,
            tbs_data,
            padding.PKCS1v15(),
            hash_algo
        )
        print(f"Signature RSA valide entre {issuer_cert.subject.rfc4514_string()} et {subject_cert.subject.rfc4514_string()}.")
        return True
    except Exception as e:
        print(f"Erreur lors de la vérification RSA : {e}")
        return False

# Vérification générique de la signature (ECDSA non utilisé ici)
def verify_signature(issuer_cert: x509.Certificate, subject_cert: x509.Certificate) -> bool:
    public_key = issuer_cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        return verify_rsa_signature(issuer_cert, subject_cert)
    else:
        print("Type de clé non supporté (seul RSA est implémenté pour ce test).")
        return False