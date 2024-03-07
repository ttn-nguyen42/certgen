import os
import yaml
from typing import List, Dict
from schema import Schema, And, Use, Optional, Or, SchemaError
import time
import builders
from datetime import datetime, timedelta


def validate_duration(value: str):
    is_valid_unit = value.endswith(("y", "m", "d"))
    if isinstance(value, str) and is_valid_unit and value[:-1].isdigit():
        return True
    raise ValueError(
        "Invalid duration format. Expected format: <number>y, m, d")


def parse_duration(value: str) -> timedelta:
    unit = value[-1]
    number = int(value[:-1])
    if unit == "y":
        return timedelta(days=number * 365)
    if unit == "m":
        return timedelta(days=number * 30)
    if unit == "d":
        return timedelta(days=number)
    raise ValueError("Invalid duration unit")


cert_schema = Schema({
    "name": str,
    "type": And(str, "Certificate"),
    "subject": {
        "common_name": Optional(str),
        "country": Optional(str),
        "organization": Optional(str),
        "org_unit": Optional(str),
        "state": Optional(str),
        "locality": Optional(str),
        "street": Optional(str),
    },
    "issuer": Optional(
        {
            "common_name": Optional(str),
            "country": Optional(str),
            "organization": Optional(str),
            "org_unit": Optional(str),
            "state": Optional(str),
            "locality": Optional(str),
            "street": Optional(str),
        }
    ),
    "ca": Optional(bool),
    "hostnames": Optional(Use(list, lambda h: And(str, h))),
    "ip_addr": Optional(Use(list, lambda h: And(str, h))),
    "duration": Use(validate_duration),
    "private_key": Or(
        {"path": str},
        {"reference": str},
    )
})

csr_schema = Schema({
    "name": str,
    "type": And(str, "CertificateSigningRequest"),
    "subject": {
        "common_name": Optional(str),
        "country": Optional(str),
        "organization": Optional(str),
        "org_unit": Optional(str),
        "state": Optional(str),
        "locality": Optional(str),
        "street": Optional(str),
    },
    "hostnames": Optional(Use(list, lambda h: And(str, h))),
    "ip_addr": Optional(Use(list, lambda h: And(str, h))),
    "duration": Use(validate_duration),
    "private_key": Or(
        {"path": str},
        {"reference": str},
    )
})

private_key_schema = Schema({
    "name": str,
    "type": And(str, "PrivateKey"),
    "key_size": int,
    "public_exponent": int,
})


schema = Schema({
    "templates": Use(list, lambda t: private_key_schema.validate(t) if t["type"] == "PrivateKey" else (
        cert_schema.validate(t) if t["type"] == "Certificate" else (csr_schema.validate(t) if t["type"] == "CertificateSigningRequest" else False))),
})


def read_template_file(path: str):
    if os.path.exists(path=path) is False:
        raise Exception("template file not found")

    with open(path, 'r') as template:
        tf = yaml.safe_load(template)

    try:
        schema.validate(tf)
        process_template(tf)
    except SchemaError as e:
        raise Exception(f"Invalid template file: {e}")


def process_template(tf: dict):
    private_keys = []
    certificates = []
    signing_requests = []

    for t in tf["templates"]:
        print("Processing template: ", t["name"])
        if t["type"] == "PrivateKey":
            private_keys.append(t)
        elif t["type"] == "Certificate":
            certificates.append(t)
        elif t["type"] == "CertificateSigningRequest":
            signing_requests.append(t)

    private_keys_map = {}
    for pk in private_keys:
        pk_builder = builders.RSAPrivateKeyBuilder()
        if pk["key_size"] is not None:
            pk_builder.key_size(pk["key_size"])
        if pk["public_exponent"] is not None:
            pk_builder.public_exponent(pk["public_exponent"])
        name = pk["name"]
        private_keys_map[name] = pk_builder

    certificates_map = {}
    for c in certificates:
        c_builder = builders.X509CertificateBuilder()
        if c["duration"] is not None:
            c_builder.not_valid_before(datetime.now()).not_valid_after(
                datetime.now() + parse_duration(c["duration"]))
        if c["subject"] is not None:
            subject_builder = builders.X509SubjectBuilder()
            subject = c["subject"]
            if subject["common_name"] is not None:
                subject_builder.common_name(
                    subject["common_name"])
            if subject["country"] is not None:
                subject_builder.country(subject["country"])
            if subject["organization"] is not None:
                subject_builder.organization(
                    subject["organization"])
            if subject["org_unit"] is not None:
                subject_builder.org_unit(subject["org_unit"])
            if subject["state"] is not None:
                subject_builder.state(subject["state"])
            if subject["locality"] is not None:
                subject_builder.locality(subject["locality"])
            if subject["street"] is not None:
                subject_builder.street(subject["street"])
            c_builder.subject(subject_builder.to_x509_name())
        if c["issuer"] is not None:
            issuer = c["issuer"]
            issuer_builder = builders.X509SubjectBuilder()
            if issuer["common_name"] is not None:
                issuer_builder.common_name(
                    issuer["common_name"])
            if issuer["country"] is not None:
                issuer_builder.country(issuer["country"])
            if issuer["organization"] is not None:
                issuer_builder.organization(
                    issuer["organization"])
            if issuer["org_unit"] is not None:
                issuer_builder.org_unit(issuer["org_unit"])
            if issuer["state"] is not None:
                issuer_builder.state(issuer["state"])
            if issuer["locality"] is not None:
                issuer_builder.locality(issuer["locality"])
            if issuer["street"] is not None:
                issuer_builder.street(issuer["street"])
            c_builder.issuer(issuer_builder.to_x509_name())
        if c["private_key"] is not None:
            if "path" in c["private_key"]:
                raise NotImplemented("File based private key not supported")
            else:
                ref = c["private_key"]["reference"]
                if ref not in private_keys_map:
                    raise Exception(
                        f"Private key reference {ref} not found in the template")
                c_builder.private_key(private_keys_map[ref].private_key)
        if c["hostnames"] is not None:
            for h in c["hostnames"]:
                c_builder.hostname(h=h)
        if c["ip_addr"] is not None:
            for i in c["ip_addr"]:
                c_builder.ip_address(ip=i)
        if c["ca"] is not None:
            c_builder.is_ca()
        name = c["name"]
        certificates_map[name] = c_builder

    csr_map = {}
    for csr in signing_requests:
        csr_builder = builders.CertificateSigningRequestBuilder()
        if csr["subject"] is not None:
            subject_builder = builders.X509SubjectBuilder()
            subject = csr["subject"]
            if subject["common_name"] is not None:
                subject_builder.common_name(
                    subject["common_name"])
            if subject["country"] is not None:
                subject_builder.country(subject["country"])
            if subject["organization"] is not None:
                subject_builder.organization(
                    subject["organization"])
            if subject["org_unit"] is not None:
                subject_builder.org_unit(subject["org_unit"])
            if subject["state"] is not None:
                subject_builder.state(subject["state"])
            if subject["locality"] is not None:
                subject_builder.locality(subject["locality"])
            if subject["street"] is not None:
                subject_builder.street(subject["street"])
            csr_builder.subject(subject_builder.to_x509_name())

        if csr["private_key"] is not None:
            if "path" in csr["private_key"]:
                raise NotImplemented("File based private key not supported")
            else:
                ref = csr["private_key"]["reference"]
                if ref not in private_keys_map:
                    raise Exception(
                        f"Private key reference {ref} not found in the template")
                csr_builder.private_key(private_keys_map[ref].private_key)
        if c["hostnames"] is not None:
            for h in c["hostnames"]:
                c_builder.hostname(h=h)
        if c["ip_addr"] is not None:
            for i in c["ip_addr"]:
                c_builder.ip_address(ip=i)
        name = csr["name"]
        csr_map[name] = csr_builder

    to_file(s=private_keys_map)
    to_file(s=certificates_map)
    to_file(s=csr_map)


def to_file(s: Dict[str, builders.Byteserializable]):
    def opener(path, flags):
        return os.open(path, flags, 0o500)

    if os.path.exists("./outputs") is False:
        os.mkdir("outputs")
    for k, v in s.items():
        with open(f"./outputs/{k}.pem", "wb", opener=opener) as f:
            f.write(v.bytes())
        print("File written: ", f"{k}.pem")
