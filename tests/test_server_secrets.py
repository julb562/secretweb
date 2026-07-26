import configparser
import http.client
import json
import os
import shutil
import socket
import ssl
import subprocess
import time

import pytest

import cryptofile
import initiator
import server

KEY1 = "test-key1-0123456789abcdef"
TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

GOOD_CLIENT_CERT = os.path.join(TEST_CERTS_DIR, "good_client.crt")
GOOD_CLIENT_KEY = os.path.join(TEST_CERTS_DIR, "good_client.key")
OTHER_CLIENT_CERT = os.path.join(TEST_CERTS_DIR, "other_client.crt")
OTHER_CLIENT_KEY = os.path.join(TEST_CERTS_DIR, "other_client.key")


def test_ensure_secrets_file_creates_empty_default_on_first_boot(tmp_path):
    data = server.ensure_secrets_file(str(tmp_path), KEY1)

    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    assert os.path.exists(secrets_path)
    assert data == {"secrets": {}}


def test_ensure_secrets_file_never_writes_a_plaintext_mirror(tmp_path):
    server.ensure_secrets_file(str(tmp_path), KEY1)

    data_dir = os.path.join(tmp_path, "data")
    assert os.listdir(data_dir) == [server.SECRETS_FILENAME]


def test_ensure_secrets_file_persists_encrypted_with_key1(tmp_path):
    server.ensure_secrets_file(str(tmp_path), KEY1)
    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    reloaded = cryptofile.load(secrets_path, KEY1, server.SECRETS_FILE_PURPOSE)
    assert reloaded == {"secrets": {}}


def test_ensure_secrets_file_does_not_overwrite_existing_data(tmp_path):
    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    custom_data = {"secrets": {"my-secret": {"treshold": 3, "shares": 5}}}
    cryptofile.save(secrets_path, KEY1, server.SECRETS_FILE_PURPOSE, custom_data)

    result = server.ensure_secrets_file(str(tmp_path), KEY1)

    assert result == custom_data


def test_ensure_secrets_file_raises_if_existing_file_undecryptable(tmp_path):
    secrets_path = os.path.join(tmp_path, "data", server.SECRETS_FILENAME)
    cryptofile.save(secrets_path, "a-different-key1", server.SECRETS_FILE_PURPOSE, {"secrets": {}})

    with pytest.raises(cryptofile.InvalidCryptoFileError):
        server.ensure_secrets_file(str(tmp_path), KEY1)


# --- /secrets/<name> route ---------------------------------------------
#
# store_secret_metadata() checks the connecting client's certificate
# against *this server's own* identity (its hosts.dta "local" entry), not
# a caller-supplied owner field - so these tests pre-seed hosts.dta,
# before spawning, with "good-client" marked local, matching the
# good_client.crt test identity already used for the /shares owner tests.

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_port(port: int, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"nothing listening on port {port} after {timeout}s")


def _spawn_server_with_own_name(tmp_path, own_name: str):
    cert_dir = tmp_path / "certificates"
    cert_dir.mkdir()
    for name in ("server.crt", "server.key", "ca.crt"):
        shutil.copy(os.path.join(TEST_CERTS_DIR, name), cert_dir / name)

    data_dir = tmp_path / "data"
    data_dir.mkdir()
    port = _free_port()

    config_file = data_dir / "config.ini"
    config = configparser.ConfigParser()
    config["secretweb"] = {
        "initiated": "False",
        "server-port": str(port),
        "bind-address": "127.0.0.1",
        "cert-file": "server.crt",
        "key-file": "server.key",
        "ca-file": "ca.crt",
    }
    with open(config_file, "w") as f:
        config.write(f)

    hosts_path = data_dir / server.HOSTS_FILENAME
    cryptofile.save(
        str(hosts_path), KEY1, server.HOSTS_FILE_PURPOSE,
        {"hosts": {own_name: {"status": "local", "address": "127.0.0.1", "port": port}}},
    )

    proc = initiator.start_server(str(tmp_path), str(config_file), KEY1)
    _wait_for_port(port)
    return proc, port


def _https_request(port, method, path, cert_file=None, key_file=None, body=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(TEST_CERTS_DIR, "ca.crt"))
    ctx.check_hostname = False
    if cert_file:
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    conn = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=3)
    try:
        headers = {"Content-Type": "application/json"} if body is not None else {}
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@pytest.fixture
def server_as_good_client(tmp_path):
    proc, port = _spawn_server_with_own_name(tmp_path, "good-client")
    try:
        yield port
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()


def test_store_secret_metadata_succeeds_from_own_cert(server_as_good_client):
    port = server_as_good_client
    payload = json.dumps({"uuid": "abc-123", "treshold": 2, "shares_saved": 3}).encode("utf-8")

    status, body = _https_request(
        port, "POST", "/secrets/my-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=payload,
    )

    assert status == 201
    record = json.loads(body)
    assert record["uuid"] == "abc-123"
    assert record["treshold"] == 2
    assert record["shares_saved"] == 3
    assert "last_updated" in record


def test_store_secret_metadata_overwrites_on_repeat_post(server_as_good_client):
    port = server_as_good_client
    first = json.dumps({"uuid": "uuid-1", "treshold": 2, "shares_saved": 3}).encode("utf-8")
    _https_request(port, "POST", "/secrets/my-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=first)

    second = json.dumps({"uuid": "uuid-2", "treshold": 3, "shares_saved": 4}).encode("utf-8")
    status, body = _https_request(
        port, "POST", "/secrets/my-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=second,
    )

    assert status == 201
    record = json.loads(body)
    assert record["uuid"] == "uuid-2"
    assert record["shares_saved"] == 4


def test_store_secret_metadata_rejects_a_different_hosts_own_cert(server_as_good_client):
    port = server_as_good_client
    payload = json.dumps({"uuid": "abc-123", "treshold": 2, "shares_saved": 3}).encode("utf-8")

    status, _ = _https_request(
        port, "POST", "/secrets/my-secret", OTHER_CLIENT_CERT, OTHER_CLIENT_KEY, body=payload,
    )

    assert status == 403


def test_store_secret_metadata_rejects_malformed_body(server_as_good_client):
    port = server_as_good_client
    payload = json.dumps({"uuid": "abc-123"}).encode("utf-8")  # missing treshold/shares_saved

    status, _ = _https_request(
        port, "POST", "/secrets/my-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=payload,
    )

    assert status == 400


def test_get_secret_metadata_returns_a_previously_stored_record(server_as_good_client):
    port = server_as_good_client
    payload = json.dumps({"uuid": "abc-123", "treshold": 2, "shares_saved": 3}).encode("utf-8")
    _https_request(port, "POST", "/secrets/my-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=payload)

    status, body = _https_request(port, "GET", "/secrets/my-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY)

    assert status == 200
    record = json.loads(body)
    assert record["uuid"] == "abc-123"
    assert record["treshold"] == 2
    assert record["shares_saved"] == 3


def test_get_secret_metadata_404s_for_unknown_name(server_as_good_client):
    port = server_as_good_client

    status, _ = _https_request(port, "GET", "/secrets/no-such-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY)

    assert status == 404


def test_get_secret_metadata_rejects_a_different_hosts_own_cert(server_as_good_client):
    port = server_as_good_client
    payload = json.dumps({"uuid": "abc-123", "treshold": 2, "shares_saved": 3}).encode("utf-8")
    _https_request(port, "POST", "/secrets/my-secret", GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=payload)

    status, _ = _https_request(port, "GET", "/secrets/my-secret", OTHER_CLIENT_CERT, OTHER_CLIENT_KEY)

    assert status == 403
