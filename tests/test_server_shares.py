import http.client
import json
import os
import ssl

import pytest

import cryptofile
import server
import shamir

KEY1 = "test-key1-0123456789abcdef"
TEST_CERTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

GOOD_CLIENT_CERT = os.path.join(TEST_CERTS_DIR, "good_client.crt")
GOOD_CLIENT_KEY = os.path.join(TEST_CERTS_DIR, "good_client.key")
DOMAIN_CLIENT_CERT = os.path.join(TEST_CERTS_DIR, "domain_client.crt")
DOMAIN_CLIENT_KEY = os.path.join(TEST_CERTS_DIR, "domain_client.key")
OTHER_CLIENT_CERT = os.path.join(TEST_CERTS_DIR, "other_client.crt")
OTHER_CLIENT_KEY = os.path.join(TEST_CERTS_DIR, "other_client.key")


def _sample_share(owner="good-client", name="test-secret"):
    """A real participant_data dict, as shamir.ShamirSecret.iterate_participants()
    would yield it - not hand-rolled, so it's guaranteed to be exactly the
    shape the server's validation expects."""
    secret = shamir.ShamirSecret(name, owner, shares=5, treshold=3)
    secret.create_secret("hello world")
    return next(secret.iterate_participants())


def _https_request(port, method, path, cert_file=None, key_file=None, body=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=os.path.join(TEST_CERTS_DIR, "ca.crt"))
    ctx.check_hostname = False  # test certs are issued for "localhost", dialing by IP
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


def _post_share(port, share, cert_file=GOOD_CLIENT_CERT, key_file=GOOD_CLIENT_KEY):
    return _https_request(
        port, "POST", f"/shares/{share['uuid']}",
        cert_file, key_file, body=json.dumps(share).encode("utf-8"),
    )


def _get_share(port, share_uuid, cert_file=GOOD_CLIENT_CERT, key_file=GOOD_CLIENT_KEY):
    return _https_request(port, "GET", f"/shares/{share_uuid}", cert_file, key_file)


# --- ensure_shares_file() ---------------------------------------------

def test_ensure_shares_file_creates_empty_default_on_first_boot(tmp_path):
    data = server.ensure_shares_file(str(tmp_path), KEY1)

    shares_path = os.path.join(tmp_path, "data", server.SHARES_FILENAME)
    assert os.path.exists(shares_path)
    assert data == {"shares": {}}


def test_ensure_shares_file_never_writes_a_plaintext_mirror(tmp_path):
    server.ensure_shares_file(str(tmp_path), KEY1)

    data_dir = os.path.join(tmp_path, "data")
    assert os.listdir(data_dir) == [server.SHARES_FILENAME]


def test_ensure_shares_file_persists_encrypted_with_key1(tmp_path):
    server.ensure_shares_file(str(tmp_path), KEY1)
    shares_path = os.path.join(tmp_path, "data", server.SHARES_FILENAME)
    reloaded = cryptofile.load(shares_path, KEY1, server.SHARES_FILE_PURPOSE)
    assert reloaded == {"shares": {}}


def test_ensure_shares_file_does_not_overwrite_existing_data(tmp_path):
    shares_path = os.path.join(tmp_path, "data", server.SHARES_FILENAME)
    custom_data = {"shares": {"some-uuid": {"owner": "good-client"}}}
    cryptofile.save(shares_path, KEY1, server.SHARES_FILE_PURPOSE, custom_data)

    result = server.ensure_shares_file(str(tmp_path), KEY1)

    assert result == custom_data


def test_ensure_shares_file_raises_if_existing_file_undecryptable(tmp_path):
    shares_path = os.path.join(tmp_path, "data", server.SHARES_FILENAME)
    cryptofile.save(shares_path, "a-different-key1", server.SHARES_FILE_PURPOSE, {"shares": {}})

    with pytest.raises(cryptofile.InvalidCryptoFileError):
        server.ensure_shares_file(str(tmp_path), KEY1)


# --- /shares/<uuid> routes ---------------------------------------------

def test_store_then_get_share_round_trips(spawned_server):
    port = spawned_server
    share = _sample_share()

    status, _ = _post_share(port, share)
    assert status == 201

    status, body = _get_share(port, share["uuid"])
    assert status == 200
    # keys are (x, y) tuples in `share` but come back as JSON arrays -
    # round-trip both sides the same way before comparing.
    assert json.loads(body) == json.loads(json.dumps(share))


def test_get_unknown_uuid_is_404(spawned_server):
    status, _ = _get_share(spawned_server, "no-such-uuid")
    assert status == 404


def test_post_uuid_mismatch_between_path_and_body_is_400(spawned_server):
    port = spawned_server
    share = _sample_share()
    status, _ = _https_request(
        port, "POST", f"/shares/not-{share['uuid']}",
        GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=json.dumps(share).encode("utf-8"),
    )
    assert status == 400


def test_post_malformed_share_is_400(spawned_server):
    port = spawned_server
    payload = {"uuid": "some-uuid"}
    status, _ = _https_request(
        port, "POST", "/shares/some-uuid",
        GOOD_CLIENT_CERT, GOOD_CLIENT_KEY, body=json.dumps(payload).encode("utf-8"),
    )
    assert status == 400


def test_reposting_identical_share_is_200(spawned_server):
    port = spawned_server
    share = _sample_share()

    status, _ = _post_share(port, share)
    assert status == 201
    status, _ = _post_share(port, share)
    assert status == 200


def test_posting_different_share_for_existing_uuid_is_409(spawned_server):
    port = spawned_server
    share = _sample_share()
    status, _ = _post_share(port, share)
    assert status == 201

    conflicting = dict(share)
    conflicting["secret_hash"] = "0" * 64
    status, _ = _post_share(port, conflicting)
    assert status == 409


def test_post_with_owner_not_matching_client_cert_is_403(spawned_server):
    port = spawned_server
    share = _sample_share(owner="someone-else")
    status, _ = _post_share(port, share)
    assert status == 403


def test_get_share_stored_under_different_owner_is_403(spawned_server):
    port = spawned_server
    share = _sample_share(owner="good-client")
    status, _ = _post_share(port, share)
    assert status == 201

    status, _ = _get_share(port, share["uuid"], OTHER_CLIENT_CERT, OTHER_CLIENT_KEY)
    assert status == 403


def test_domain_qualified_cn_is_stripped_to_hostname_for_owner_check(spawned_server):
    """domain_client.crt's CN is "good-client.example.org" - only the
    leftmost label should be compared against owner, so this succeeds the
    same way good_client.crt (CN "good-client") does."""
    port = spawned_server
    share = _sample_share(owner="good-client")

    status, _ = _post_share(port, share, DOMAIN_CLIENT_CERT, DOMAIN_CLIENT_KEY)
    assert status == 201

    status, body = _get_share(port, share["uuid"], DOMAIN_CLIENT_CERT, DOMAIN_CLIENT_KEY)
    assert status == 200
    assert json.loads(body) == json.loads(json.dumps(share))
