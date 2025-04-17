"""
Module for verifying key-related extensions (KeyUsage, BasicConstraints).
"""

from cryptography import x509

def verify_key_usage(cert: x509.Certificate, is_ca: bool) -> bool:
    """
    Verify the KeyUsage extension matches the certificate's role.

    Args:
        cert: The certificate to verify
        is_ca: Whether the certificate is a CA

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage)
        if is_ca:
            if not (key_usage.value.key_cert_sign and key_usage.value.crl_sign):
                print("Erreur : CA doit avoir KeyCertSign et CRLSign.")
                return False
        else:
            if key_usage.value.key_cert_sign:
                print("Erreur : Certificat feuille ne doit pas avoir KeyCertSign.")
                return False
            if not key_usage.value.digital_signature:
                print("Erreur : Certificat feuille doit avoir DigitalSignature.")
                return False
        return True
    except x509.ExtensionNotFound:
        print("Aucune extension KeyUsage trouvée.")
        return False

def verify_basic_constraints(cert: x509.Certificate, is_ca: bool, level: int, chain_length: int) -> bool:
    """
    Verify the BasicConstraints extension matches the certificate's role and chain length.

    Args:
        cert: The certificate to verify
        is_ca: Whether the certificate is a CA
        level: The certificate's level in the chain (0 = root)
        chain_length: Total length of the chain

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if is_ca:
            if not bc.value.ca:
                print("Erreur : CA doit avoir ca=True.")
                return False
            if bc.value.path_length is not None:
                remaining_intermediates = chain_length - level - 2
                if remaining_intermediates > bc.value.path_length:
                    print(f"Erreur : Longueur de chemin dépassée (max {bc.value.path_length}, trouvé {remaining_intermediates}).")
                    return False
        else:
            if bc.value.ca:
                print("Erreur : Certificat feuille ne doit pas être une CA.")
                return False
        return True
    except x509.ExtensionNotFound:
        if is_ca:
            print("Erreur : CA doit avoir BasicConstraints avec ca=True.")
            return False
        return True  # Absence de BasicConstraints est acceptable pour une feuille