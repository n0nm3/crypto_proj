"""
Module for loading certificates and coordinating chain verification.
"""

from cryptography import x509
from src.verify_sig import verify_signature
from src.verify_key import verify_key_usage, verify_basic_constraints
from src.verify_ocsp_crl import check_revocation_status

def load_cert(file_format: str, file_name: str) -> x509.Certificate:
    """
    Load an X.509 certificate from a file.

    Args:
        file_format (str): 'PEM' or 'DER'
        file_name (str): Path to the certificate file

    Returns:
        x509.Certificate: Loaded certificate object or None if loading fails
    """
    try:
        with open(file_name, "rb") as fd:
            file_data = fd.read()
        if not file_data:
            print(f"Erreur : Fichier {file_name} vide.")
            return None
        if file_format.upper() == "PEM":
            return x509.load_pem_x509_certificate(file_data)
        elif file_format.upper() == "DER":
            return x509.load_der_x509_certificate(file_data)
        else:
            raise ValueError("Format doit être 'DER' ou 'PEM'")
    except Exception as e:
        print(f"Erreur lors du chargement de {file_name} : {e}")
        return None

def verify_cert(cert: x509.Certificate, ca_cert: x509.Certificate = None) -> bool:
    """
    Verify an individual certificate's validity, signature, and extensions.

    Args:
        cert: The certificate to verify
        ca_cert: The issuing CA certificate (optional)

    Returns:
        bool: True if valid, False otherwise
    """
    from datetime import datetime, timezone

    # Vérifier la période de validité
    current_time = datetime.now(timezone.utc)
    if current_time < cert.not_valid_before_utc or current_time > cert.not_valid_after_utc:
        print(f"Erreur : Certificat expiré (valide de {cert.not_valid_before_utc} à {cert.not_valid_after_utc}).")
        return False

    # Afficher sujet et émetteur
    print(f"Émetteur : {cert.issuer.rfc4514_string()}")
    print(f"Sujet : {cert.subject.rfc4514_string()}")

    # Déterminer si c’est une CA via BasicConstraints
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        is_ca = bc.value.ca
    except x509.ExtensionNotFound:
        is_ca = False

    # Vérifier les extensions
    if not verify_key_usage(cert, is_ca):
        return False
    if not verify_basic_constraints(cert, is_ca, 0, 1):
        return False

    # Vérifier la signature si un CA est fourni
    if ca_cert and not verify_signature(ca_cert, cert):
        print("Erreur : Signature invalide.")
        return False

    return True

def verify_certificate_chain(file_format: str, cert_files: list) -> bool:
    """
    Verify a certificate chain including revocation status.

    Args:
        file_format (str): 'PEM' or 'DER'
        cert_files (list): List of certificate file paths (root CA to leaf)

    Returns:
        bool: True if the chain is valid and not revoked, False otherwise
    """
    if not cert_files:
        print("Erreur : Liste de certificats vide.")
        return False

    # Charger tous les certificats
    cert_chain = []
    for i, file_name in enumerate(cert_files):
        cert = load_cert(file_format, file_name)
        if cert is None:
            print(f"Erreur : Échec du chargement de {file_name}.")
            return False
        cert_chain.append(cert)

    # Vérification de la chaîne
    for i in range(len(cert_chain)):
        cert = cert_chain[i]
        ca_cert = cert_chain[i - 1] if i > 0 else None

        # Vérifier la correspondance sujet/émetteur
        if ca_cert and cert.issuer != ca_cert.subject:
            print(f"Erreur : L'émetteur de {cert_files[i]} ne correspond pas au sujet de {cert_files[i-1]}.")
            return False

        # Vérifier le certificat
        if not verify_cert(cert, ca_cert):
            print(f"Erreur : Vérification échouée pour {cert_files[i]}.")
            return False

        # Vérifier BasicConstraints avec le niveau dans la chaîne
        try:
            bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
            is_ca = bc.value.ca
        except x509.ExtensionNotFound:
            is_ca = False
        if not verify_basic_constraints(cert, is_ca, i, len(cert_chain)):
            return False

        # Vérifier le statut de révocation (sauf pour la racine)
        if ca_cert and not check_revocation_status(cert, ca_cert, cert_files[i]):
            return False

    return True