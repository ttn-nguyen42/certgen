from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
import os


from cryptography.hazmat.primitives import serialization


def open_cert(path: str) -> x509.Certificate:
    if os.path.exists(path) is False:
        raise Exception("certificate file not found")
    with open(path, 'r') as cert:
        return x509.load_pem_x509_certificate(data=cert.read().encode(encoding='utf-8'))


def open_private_key(path: str) -> rsa.RSAPrivateKey:
    if os.path.exists(path) is False:
        raise Exception("private key file not found")
    with open(path, 'r') as key:
        return serialization.load_pem_private_key(data=key.read().encode(encoding='utf-8'), password=None)


def open_csr(path: str) -> x509.CertificateSigningRequest:
    if os.path.exists(path) is False:
        raise Exception("csr file not found")
    with open(path, 'r') as csr:
        return x509.load_pem_x509_csr(data=csr.read().encode(encoding='utf-8'))
