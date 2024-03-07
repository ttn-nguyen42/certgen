from cryptography import x509
from prettytable import PrettyTable
from cryptography.hazmat.primitives._serialization import PublicFormat, Encoding
import datetime
from typing import Dict
from collections import defaultdict


def read(data: bytes):
    if data is None:
        raise Exception("certificate data is null")
    CSRDisplay().render(data=data)


class Displayer():
    def render(self, data: bytes) -> str:
        pass


class CertificateDisplay(Displayer):
    def render(self, data: bytes) -> str:
        print("X509 Certificate")
        cert: x509.Certificate = x509.load_pem_x509_certificate(data=data)

        t = _cert_table(c=cert)

        mapped_subjects = map_subject(s=cert.subject)
        subject_t = _subject_table(mapped_subjects=mapped_subjects)

        mapped_issuer = map_subject(s=cert.issuer)
        issuer_t = _subject_table(mapped_subjects=mapped_issuer)

        pk = cert.public_key().public_bytes(encoding=Encoding.PEM,
                                            format=PublicFormat.SubjectPublicKeyInfo)
        print(t)
        print(pk.decode())

        print("Subject:")
        print(subject_t)

        print("Issuer:")
        print(issuer_t)


class CSRDisplay(Displayer):
    def render(self, data: bytes) -> str:
        print("Certificate Signing Request")
        csr: x509.CertificateSigningRequest = x509.load_pem_x509_csr(data=data)

        t = _csr_table(c=csr)

        mapped_subjects = map_subject(s=csr.subject)
        subject_t = _subject_table(mapped_subjects=mapped_subjects)

        print(t)

        print("Subject:")
        print(subject_t)


def _cert_table(c: x509.Certificate) -> str:

    table = PrettyTable()
    table.add_row(["Version", c.version], divider=True)

    table.add_row(["Serial Number", c.serial_number], divider=True)

    table.add_row(["Not Before", c.not_valid_before_utc.isoformat()])
    table.add_row(["Not After", c.not_valid_after_utc.isoformat()])
    table.add_row(["Expiration", format_timedelta(
        c.not_valid_after_utc - c.not_valid_before_utc)])
    return table.get_string(header=False)


def _csr_table(c: x509.CertificateSigningRequest) -> str:
    table = PrettyTable()

    table.add_row(["Algorithm", c.signature_hash_algorithm.name])
    table.add_row(["Signature Valid", c.is_signature_valid])

    return table.get_string(header=False)


def _subject_table(mapped_subjects: Dict[str, str]) -> str:
    table = PrettyTable(["Attribute", "Value"])

    table.add_row(["Common Name", mapped_subjects["CN"]])
    table.add_row(["Country", mapped_subjects["C"]])
    table.add_row(["Organization", mapped_subjects["O"]])
    table.add_row(["Organizational Unit", mapped_subjects["OU"]])
    table.add_row(["State", mapped_subjects["ST"]])
    table.add_row(["Locality", mapped_subjects["L"]])
    table.add_row(["Street", mapped_subjects["STREET"]], divider=True)

    return table


def map_subject(s: x509.Name) -> Dict[str, str]:
    subject = s.rdns
    mapped_subjects = defaultdict(str)
    for s in subject:
        attrs = s._attributes[0]
        mapped_subjects[attrs.rfc4514_attribute_name] = attrs.value
    return mapped_subjects


def format_timedelta(td: datetime.timedelta) -> str:
    years = td.days // 365
    months = (td.days % 365) // 30
    days = (td.days % 365) % 30
    return f"{years} years, {months} months, {days} days"
