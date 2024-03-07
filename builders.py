import datetime
import enum
import os
from typing import List
from typing_extensions import Self
import uuid
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization


class TemplateType(enum.Enum):
    PRIVATE_KEY = 1
    CERTIFICATE = 2
    CERTIFICATE_SIGNING_REQUEST = 3


class Byteserializable:
    def bytes(self) -> bytes:
        pass


class X509SubjectBuilder:
    def __init__(self,
                 common_name: str = None,
                 country: str = None,
                 organization: str = None,
                 org_unit: str = None,
                 state: str = None,
                 locality: str = None,
                 street: str = None) -> None:
        self._common_name = common_name
        self._country = country
        self._organization = organization
        self._org_unit = org_unit
        self._state = state
        self._locality = locality
        self._street = street

        self._attrs: List[x509.NameAttribute] = []

    def common_name(self, name: str) -> Self:
        if len(name) == 0:
            raise Exception("common name must not be empty")
        self._common_name = name
        self._attrs.append(x509.NameAttribute(
            NameOID.COMMON_NAME, self._common_name))
        return self

    def country(self, country: str) -> Self:
        if len(country) == 0:
            raise Exception("country must not be empty")
        self._country = country
        self._attrs.append(x509.NameAttribute(
            NameOID.COUNTRY_NAME, self._country))
        return self

    def organization(self, org: str) -> Self:
        if len(org) == 0:
            raise Exception("organization must not be empty")
        self._organization = org
        self._attrs.append(x509.NameAttribute(
            NameOID.ORGANIZATION_NAME, self._organization))
        return self

    def org_unit(self, unit: str) -> Self:
        if len(unit) == 0:
            raise Exception("organization unit must not be empty")
        self._org_unit = unit
        self._attrs.append(x509.NameAttribute(
            NameOID.ORGANIZATIONAL_UNIT_NAME, self._org_unit))
        return self

    def state(self, state: str) -> Self:
        if len(state) == 0:
            raise Exception("state must not be empty")
        self._state = state
        self._attrs.append(x509.NameAttribute(
            NameOID.STATE_OR_PROVINCE_NAME, self._state))
        return self

    def locality(self, locality: str) -> Self:
        if len(locality) == 0:
            raise Exception("locality must not be empty")
        self._locality = locality
        self._attrs.append(x509.NameAttribute(
            NameOID.LOCALITY_NAME, self._locality))
        return self

    def street(self, street: str) -> Self:
        if len(street) == 0:
            raise Exception("street must not be empty")
        self._street = street
        self._attrs.append(x509.NameAttribute(
            NameOID.STREET_ADDRESS, self._street))
        return self

    def to_x509_name(self) -> x509.Name:
        return x509.Name(attributes=self._attrs)


class RSAPrivateKeyBuilder(Byteserializable):
    """
    Generates a RSA Private key
    """

    def __init__(self) -> None:
        self.reset()

    def reset(self):
        self._key_size = 2048
        self._public_exponent = 65537
        self._backend = default_backend
        self._product = None

    @property
    def private_key(self) -> rsa.RSAPrivateKey:
        product = rsa.generate_private_key(
            public_exponent=self._public_exponent,
            key_size=self._key_size,
            backend=self._backend()
        )
        self.reset()
        return product

    def bytes(self) -> bytes:
        pk = self.private_key
        return pk.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def key_size(self, size: int) -> None:
        if size < 1:
            raise Exception("key size is too small")
        self._key_size = size

    def public_exponent(self, exp: int) -> None:
        if exp not in (3, 65537):
            raise Exception("public exponent must be 3 or 65537")
        self._public_exponent = exp


class X509CertificateBuilder(Byteserializable):
    """
    Generates a self-signed X.509 certificate.
    Requires a private key associated with it
    """

    def __init__(self):
        self.reset()

    def reset(self) -> Self:
        self._builder = x509.CertificateBuilder()
        self._not_before = None
        self._not_after = None
        return self

    def private_key(self, private_key: rsa.RSAPrivateKey) -> Self:
        if private_key is None:
            raise Exception("private key must not be empty")
        self._private_key = private_key
        return self

    def subject(self, args: x509.Name) -> Self:
        if args is None:
            raise Exception("subject arguments must not be empty")
        self._builder = self._builder.subject_name(args)
        return self

    def issuer(self, args: x509.Name) -> Self:
        if args is None:
            raise Exception("issuer arguments must not be empty")
        self._builder = self._builder.issuer_name(args)
        return self

    def not_valid_before(self, date: datetime) -> Self:
        if date is None:
            raise Exception("start date must not be empty")
        if self._not_after is not None and date > self._not_after:
            raise Exception(
                "start date must be before expiration date")
        self._builder = self._builder.not_valid_before(date)
        return self

    def not_valid_after(self, date: datetime) -> Self:
        if date is None:
            raise Exception("expiration date must not be empty")
        if self._not_before is not None and date < self._not_before:
            raise Exception(
                "expiration date must be after start date")
        self._builder = self._builder.not_valid_after(date)
        return self

    @property
    def certificate(self) -> x509.Certificate:
        n = int.from_bytes(
            os.urandom(20), byteorder="big") >> 1
        self._builder = self._builder.serial_number(number=n)
        public_key = self._private_key.public_key()
        self._builder = self._builder.public_key(key=public_key)
        res = self._builder.sign(
            private_key=self._private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        self.reset()
        return res

    def bytes(self) -> bytes:
        return self.certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )


class CertificateSigningRequestBuilder(Byteserializable):
    """
    Create a Certificate Signing Request (CSR) that can be sent to a Certificate Authority (CA)
    to create a certificate used for servers or clients.
    """

    def __init__(self):
        self.reset()

    def reset(self) -> Self:
        self._req = x509.CertificateSigningRequestBuilder()
        return self

    def private_key(self, private_key: rsa.RSAPrivateKey) -> Self:
        if private_key is None:
            raise Exception("private key must not be empty")
        self._private_key = private_key
        return self

    def subject(self, args: x509.Name) -> Self:
        if args is None:
            raise Exception("subject arguments must not be empty")
        self._subject = args
        self._req = self._req.subject_name(self._subject)
        return self

    @property
    def request(self) -> x509.CertificateSigningRequest:
        req = self._req.sign(
            private_key=self._private_key,
            algorithm=hashes.SHA256(),
            backend=default_backend()
        )
        self.reset()
        return req

    def bytes(self) -> bytes:
        return self.request.public_bytes(
            encoding=serialization.Encoding.PEM
        )