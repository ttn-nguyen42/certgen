import typer
import describer
import template
import os
import builders
import loaders
from datetime import datetime, timezone
import pytz

app = typer.Typer()


@app.command()
def version():
    """
    Displays the current version of the CLI
    """
    print("0.0.1-beta")


@app.command()
def read(path: str):
    """
    Read the content of the certificates
    """
    if len(path) == 0:
        raise Exception("path must not be empty")
    if os.path.exists(path) is False:
        raise Exception("file not found")
    with open(path, 'rb') as f:
        describer.read(data=f.read())


@app.command()
def generate(path: str):
    """
    Generates certificates according to a YAML template
    """
    if len(path) == 0:
        raise Exception("path must not be empty")
    template.read_template_file(path=path)


@app.command()
def sign(csr: str, ca_key: str, ca_cert: str, output: str = "signed_cert.pem", duration: str = "1y"):
    """
    Signs a certificate
    """
    if len(csr) == 0:
        raise Exception("csr path must not be empty")
    if len(ca_key) == 0:
        raise Exception("ca_key path must not be empty")
    if len(ca_cert) == 0:
        raise Exception("ca_cert path must not be empty")
    if len(output) == 0:
        raise Exception("output must not be empty")
    dur = template.parse_duration(value=duration)
    if dur.total_seconds() <= 0:
        raise Exception("duration must be greater than 0")
    if os.path.exists(path=csr) is False:
        raise Exception("csr file not found")
    if os.path.exists(path=ca_key) is False:
        raise Exception("ca_key file not found")
    if os.path.exists(path=ca_cert) is False:
        raise Exception("ca_cert file not found")

    csr = loaders.open_csr(path=csr)
    ca_key = loaders.open_private_key(path=ca_key)
    ca_cert = loaders.open_cert(path=ca_cert)

    b = builders.SignedCertificateBuilder()
    b.ca_cert(ca_cert=ca_cert)
    b.ca_key(ca_key=ca_key)
    b.certificate_signing_request(csr=csr)
    b.not_valid_before(datetime.now(tz=pytz.timezone(zone="Asia/Saigon")))
    b.not_valid_after(datetime.now(tz=pytz.timezone(zone="Asia/Saigon")) + dur)
    out = b.bytes()
    with open(output, 'wb') as f:
        f.write(out)


if __name__ == "__main__":
    app()
