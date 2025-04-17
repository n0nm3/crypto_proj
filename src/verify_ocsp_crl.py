"""
Module for verifying certificate revocation status via CRL and OCSP.
"""

from datetime import datetime, timezone
from cryptography import x509
from cryptography.x509 import CRLDistributionPoints, AuthorityInformationAccess
from cryptography.x509.oid import AuthorityInformationAccessOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response, OCSPResponseStatus, OCSPCertStatus
import requests

# Cache global pour les CRLs
crl_cache = {}

def get_crl_urls(cert: x509.Certificate) -> list:
    """Extracts CRL distribution point URLs from the certificate."""
    try:
        crl_dp = cert.extensions.get_extension_for_class(CRLDistributionPoints).value
        return [dp.full_name[0].value for dp in crl_dp if dp.full_name]
    except x509.ExtensionNotFound:
        return []

def download_crl(crl_url: str) -> bytes:
    """Downloads the CRL from the given URL."""
    response = requests.get(crl_url, timeout=10)
    if response.status_code != 200:
        raise Exception(f"Échec du téléchargement de la CRL depuis {crl_url} (statut {response.status_code})")
    return response.content

def load_crl(crl_data: bytes) -> x509.CertificateRevocationList:
    """Loads a CRL from raw data, trying PEM then DER."""
    try:
        return x509.load_pem_x509_crl(crl_data)
    except ValueError:
        try:
            return x509.load_der_x509_crl(crl_data)
        except ValueError as e:
            raise Exception(f"Impossible de charger la CRL : format invalide ({e})")

def verify_crl_signature(crl: x509.CertificateRevocationList, ca_cert: x509.Certificate) -> bool:
    """Verifies the CRL signature using the CA's public key."""
    public_key = ca_cert.public_key()
    try:
        public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            crl.signature_hash_algorithm
        )
        return True
    except Exception as e:
        print(f"Erreur lors de la vérification de la signature de la CRL : {e}")
        return False

def is_revoked(cert: x509.Certificate, crl: x509.CertificateRevocationList) -> bool:
    """Checks if the certificate is revoked in the CRL."""
    revoked_cert = crl.get_revoked_certificate_by_serial_number(cert.serial_number)
    return revoked_cert is not None

def get_crl(crl_url: str, ca_cert: x509.Certificate) -> x509.CertificateRevocationList:
    """Fetches and verifies a CRL, using cache if available and not expired."""
    now = datetime.now(timezone.utc)
    if crl_url in crl_cache:
        crl = crl_cache[crl_url]
        if crl.next_update_utc > now:
            print(f"Utilisation de la CRL en cache pour {crl_url}")
            return crl
    
    print(f"Téléchargement de la CRL depuis {crl_url}")
    crl_data = download_crl(crl_url)
    crl = load_crl(crl_data)
    if not verify_crl_signature(crl, ca_cert):
        raise Exception(f"Signature de la CRL invalide pour {crl_url}")
    if crl.next_update_utc < now:
        raise Exception(f"CRL obsolète pour {crl_url} (expire le {crl.next_update_utc})")
    if crl.last_update_utc > now:
        raise Exception(f"CRL non encore valide pour {crl_url} (valide à partir de {crl.last_update_utc})")
    crl_cache[crl_url] = crl
    return crl

def get_ocsp_url(cert: x509.Certificate) -> str:
    """Extracts the OCSP URL from the certificate, if available."""
    try:
        aia = cert.extensions.get_extension_for_class(AuthorityInformationAccess).value
        for ad in aia:
            if ad.access_method == AuthorityInformationAccessOID.OCSP:
                return ad.access_location.value
        return None
    except x509.ExtensionNotFound:
        return None

def verify_ocsp(cert: x509.Certificate, ca_cert: x509.Certificate, ocsp_url: str) -> bool:
    """Verifies the certificate revocation status via OCSP."""
    builder = OCSPRequestBuilder()
    builder = builder.add_certificate(cert, ca_cert, hashes.SHA256())
    req = builder.build()
    req_data = req.public_bytes(serialization.Encoding.DER)
    
    try:
        response = requests.post(ocsp_url, data=req_data, headers={'Content-Type': 'application/ocsp-request'}, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        raise Exception(f"Requête OCSP échouée pour {ocsp_url} : {e}")
    
    ocsp_resp = load_der_ocsp_response(response.content)
    if ocsp_resp.response_status != OCSPResponseStatus.SUCCESSFUL:
        raise Exception(f"Réponse OCSP non réussie : {ocsp_resp.response_status.value}")
    
    if ocsp_resp.certificate_status == OCSPCertStatus.REVOKED:
        return False
    elif ocsp_resp.certificate_status == OCSPCertStatus.GOOD:
        return True
    else:
        raise Exception("Statut OCSP inconnu")

def check_revocation_status(cert: x509.Certificate, ca_cert: x509.Certificate, cert_file: str) -> bool:
    """
    Check the revocation status of a certificate using OCSP and CRL.

    Args:
        cert: The certificate to check
        ca_cert: The issuing CA certificate
        cert_file: Path to the certificate file (for logging)

    Returns:
        bool: True if not revoked, False otherwise
    """
    # Essayer OCSP en premier
    ocsp_url = get_ocsp_url(cert)
    if ocsp_url:
        try:
            if not verify_ocsp(cert, ca_cert, ocsp_url):
                print(f"Erreur : Certificat révoqué via OCSP : {cert_file}")
                return False
            print(f"Statut OCSP : Certificat {cert_file} valide")
            return True
        except Exception as e:
            print(f"Avertissement : Vérification OCSP échouée pour {cert_file} : {e}. Passage à la CRL.")

    # Vérification CRL si OCSP indisponible ou échoué
    crl_urls = get_crl_urls(cert)
    if crl_urls:
        for crl_url in crl_urls:
            try:
                crl = get_crl(crl_url, ca_cert)
                if is_revoked(cert, crl):
                    print(f"Erreur : Certificat révoqué dans la CRL : {cert_file}")
                    return False
                print(f"Statut CRL : Certificat {cert_file} valide via {crl_url}")
                return True
            except Exception as e:
                print(f"Erreur : Vérification CRL échouée pour {cert_file} depuis {crl_url} : {e}")
                return False
    else:
        print(f"Avertissement : Aucune information de révocation (OCSP ou CRL) disponible pour {cert_file}")
        return True  # Pas de révocation détectée par défaut si aucune info