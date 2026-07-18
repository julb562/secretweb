"""
Generates the throwaway mTLS fixtures under tests/certs/: a test-only CA,
a server identity signed by it, a "good" client identity signed by it, a
second client identity whose CN is fully-qualified (to test that only the
leftmost/hostname label is compared against a share's owner field), a
third, distinct trusted client identity (to test that being trusted isn't
enough on its own - the owner must match this specific CN), and a "bad"
client identity signed by an unrelated rogue CA (so it fails verification
against tests/certs/ca.crt the same way a spoofed or unrelated host's
certificate would in production).

Not part of the test suite itself - run manually to (re)create the
checked-in fixtures under tests/certs/ if they ever need to change:

    python tests/generate_test_certs.py
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
VALID_FOR = datetime.timedelta(days=3650)


def _generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _write_key(key, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))


def _write_cert(cert, filename):
    with open(os.path.join(CERTS_DIR, filename), "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def _self_signed_ca(common_name):
    key = _generate_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + VALID_FOR)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _signed_leaf(common_name, issuer_name, issuer_key):
    key = _generate_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + VALID_FOR)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(
                __import__("ipaddress").ip_address("127.0.0.1")
            )]),
            critical=False,
        )
        .sign(issuer_key, hashes.SHA256())
    )
    return key, cert


def main():
    os.makedirs(CERTS_DIR, exist_ok=True)

    ca_key, ca_cert = _self_signed_ca("secretweb-test-ca")
    _write_key(ca_key, "ca.key")
    _write_cert(ca_cert, "ca.crt")

    server_key, server_cert = _signed_leaf("test-server", ca_cert.subject, ca_key)
    _write_key(server_key, "server.key")
    _write_cert(server_cert, "server.crt")

    good_key, good_cert = _signed_leaf("good-client", ca_cert.subject, ca_key)
    _write_key(good_key, "good_client.key")
    _write_cert(good_cert, "good_client.crt")

    domain_key, domain_cert = _signed_leaf("good-client.example.org", ca_cert.subject, ca_key)
    _write_key(domain_key, "domain_client.key")
    _write_cert(domain_cert, "domain_client.crt")

    # trusted (signed by the real CA) but a distinct identity from
    # good-client/good-client.example.org - for proving that being trusted
    # isn't enough on its own, the owner must also match this CN
    other_key, other_cert = _signed_leaf("other-client", ca_cert.subject, ca_key)
    _write_key(other_key, "other_client.key")
    _write_cert(other_cert, "other_client.crt")

    # signed by a different, unrelated CA - must fail verification against ca.crt
    rogue_ca_key, rogue_ca_cert = _self_signed_ca("secretweb-rogue-test-ca")
    bad_key, bad_cert = _signed_leaf("bad-client", rogue_ca_cert.subject, rogue_ca_key)
    _write_key(bad_key, "bad_client.key")
    _write_cert(bad_cert, "bad_client.crt")

    print(f"wrote test certificates to {CERTS_DIR}")


if __name__ == "__main__":
    main()
